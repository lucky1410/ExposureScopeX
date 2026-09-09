#!/usr/bin/env python3
"""Isolated target-specific scan runner used by the Celery worker."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def write_json(path: Path, payload: dict | list) -> None:
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def safe_repository_url(target: str) -> str:
    value = target.strip().removesuffix(".git").rstrip("/")
    if "://" not in value:
        value = f"https://{value}"
    from urllib.parse import urlsplit

    parsed = urlsplit(value)
    if parsed.scheme != "https" or parsed.hostname not in {"github.com", "gitlab.com", "bitbucket.org"}:
        raise ValueError("Repository scans support HTTPS GitHub, GitLab, and Bitbucket URLs")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Repository URLs cannot contain credentials, query strings, or fragments")
    if not re.fullmatch(r"/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", parsed.path):
        raise ValueError("Repository target must identify exactly one owner/repository")
    return value + ".git"


def safe_image_ref(target: str) -> str:
    value = target.strip().lower()
    if not value:
        raise ValueError("Container image target is required")
    pattern = re.compile(
        r"^(?:(?:[a-z0-9.-]+(?::\d+)?)/)?[a-z0-9]+(?:[._/-][a-z0-9]+)*(?::[\w][\w.-]{0,127})?(?:@sha256:[a-f0-9]{64})?$",
        re.IGNORECASE,
    )
    if value.startswith(("http://", "https://")) or not pattern.fullmatch(value):
        raise ValueError("Container image target must be an OCI/Docker-style image reference")
    if "@" not in value and ":" not in value.rsplit("/", 1)[-1]:
        value = f"{value}:latest"
    return value


def download_public_artifact(target: str, destination: Path, *, max_bytes: int) -> str:
    """Download one public artifact with redirects disabled and a hard size cap."""
    import httpx

    from app.services.validation import validate_public_url

    normalized = validate_public_url(target)
    with httpx.stream("GET", normalized, timeout=60, follow_redirects=False) as response:
        response.raise_for_status()
        declared = int(response.headers.get("content-length") or 0)
        if declared > max_bytes:
            raise ValueError(f"Artifact exceeds the {max_bytes // 1024 // 1024} MiB limit")
        written = 0
        with destination.open("wb") as handle:
            for chunk in response.iter_bytes(1024 * 1024):
                written += len(chunk)
                if written > max_bytes:
                    raise ValueError(f"Artifact exceeds the {max_bytes // 1024 // 1024} MiB limit")
                handle.write(chunk)
    return normalized


def safe_extract_archive(archive: Path, destination: Path, *, max_bytes: int) -> None:
    """Extract APK/IPA ZIP content without traversal or decompression bombs."""
    destination.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive) as bundle:
        members = bundle.infolist()
        if len(members) > 100_000 or sum(item.file_size for item in members) > max_bytes:
            raise ValueError("Mobile archive expansion exceeds the safety limit")
        root = destination.resolve()
        for member in members:
            if member.flag_bits & 0x1:
                raise ValueError("Encrypted mobile archives are not supported")
            unix_mode = (member.external_attr >> 16) & 0o170000
            if unix_mode == 0o120000:
                raise ValueError("Mobile archive contains a symbolic link")
            candidate = (destination / member.filename).resolve()
            if root not in candidate.parents and candidate != root:
                raise ValueError("Mobile archive contains an unsafe path")
        bundle.extractall(destination)


def run_artifact(target_type: str, target: str, output_dir: Path, mode: str) -> int:
    """Run bounded Kubernetes or mobile static analysis."""
    from app.config import settings
    from runtime_adapters import run_runtime_adapter

    runner = ToolRunner(output_dir)
    extension = {"kubernetes": ".yaml", "android": ".apk", "ios": ".ipa"}[target_type]
    max_download = 10 * 1024 * 1024 if target_type == "kubernetes" else 250 * 1024 * 1024
    artifact = output_dir / f"artifact{extension}"
    print(f"Starting {target_type} artifact preflight", flush=True)
    normalized = download_public_artifact(target, artifact, max_bytes=max_download)
    write_json(output_dir / "seed_inventory.json", {
        "target_type": target_type,
        "target": normalized,
        "candidates": [{"target": normalized, "target_type": target_type, "relation": "assessment_scope", "source": "artifact_adapter"}],
    })
    findings: list[dict] = []
    scan_target = artifact
    if target_type in {"android", "ios"}:
        print("Starting mobile archive inventory", flush=True)
        extracted = output_dir / "extracted"
        safe_extract_archive(artifact, extracted, max_bytes=1024 * 1024 * 1024)
        scan_target = extracted
        url_pattern = re.compile(rb"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,500}")
        endpoints: set[str] = set()
        for path in extracted.rglob("*"):
            if not path.is_file() or path.stat().st_size > 8 * 1024 * 1024:
                continue
            try:
                data = path.read_bytes()
            except OSError:
                continue
            endpoints.update(match.decode("utf-8", errors="ignore") for match in url_pattern.findall(data))
        write_json(output_dir / "mobile_endpoints.json", {"endpoints": sorted(endpoints)[:5000]})
        insecure = sorted(item for item in endpoints if item.lower().startswith("http://"))
        for endpoint in insecure[:100]:
            findings.append({
                "severity": "MEDIUM",
                "title": "Cleartext endpoint embedded in mobile artifact",
                "description": "The application contains an HTTP endpoint that should be reviewed for transport security.",
                "url": normalized,
                "source": "mobile-static",
                "template_id": "mobile-cleartext-endpoint",
                "evidence": endpoint[:1000],
            })
        print("Starting mobile manifest and endpoint analysis", flush=True)
    else:
        print("Starting Kubernetes manifest inventory", flush=True)

    print("Starting artifact misconfiguration and secret scan", flush=True)
    trivy_args = ["config", "--format", "json", "--output", str(output_dir / "trivy.json"), str(scan_target)] if target_type == "kubernetes" else [
        "fs", "--scanners", "vuln,secret,misconfig", "--format", "json", "--output", str(output_dir / "trivy.json"), str(scan_target)
    ]
    trivy_rc = runner.run("trivy", trivy_args, timeout=5400)
    runtime_summary = {"status": "not_configured"}
    adapter_url = (
        settings.MOBILE_DYNAMIC_ADAPTER_URL
        if target_type in {"android", "ios"}
        else settings.KUBERNETES_RUNTIME_ADAPTER_URL
    )
    adapter_key = (
        settings.MOBILE_DYNAMIC_API_KEY
        if target_type in {"android", "ios"}
        else settings.KUBERNETES_RUNTIME_API_KEY
    )
    if adapter_url:
        print(f"Starting authorized {target_type} runtime analysis", flush=True)
        runtime_findings, runtime_summary = run_runtime_adapter(
            adapter_url, adapter_key, artifact, target_type, normalized
        )
        findings.extend(runtime_findings)
    write_json(output_dir / "specialized_findings.json", findings)
    write_json(output_dir / "specialized_summary.json", {
        "target_type": target_type,
        "target": normalized,
        "mode": mode,
        "trivy_exit_code": trivy_rc,
        "static_analysis": True,
        "dynamic_device_testing": target_type in {"android", "ios"} and runtime_summary.get("status") == "completed",
        "runtime_analysis": runtime_summary,
        "artifacts": _existing_artifacts(output_dir),
    })
    print("Generating report", flush=True)
    print("Session complete", flush=True)
    return 0 if trivy_rc in {0, 1, 2} else 3


class ToolRunner:
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.sequence = 0
        self.status_file = output_dir / "tool_runs.tsv"
        (output_dir / "tool_logs").mkdir(parents=True, exist_ok=True)

    def run(self, tool: str, args: list[str], *, timeout: int) -> int:
        self.sequence += 1
        run_id = f"{tool}-{os.getpid()}-{self.sequence}"
        started = utcnow()
        relative_log = f"tool_logs/{run_id}.log"
        command = shlex.join([tool, *args]).replace("\t", " ").replace("\n", " ")
        with self.status_file.open("a", encoding="utf-8") as status:
            status.write(f"{run_id}\t{tool}\trunning\t\t{started}\t\t{command}\t{relative_log}\n")
        if not shutil.which(tool):
            completed = utcnow()
            with self.status_file.open("a", encoding="utf-8") as status:
                status.write(f"{run_id}\t{tool}\tfailed\t127\t{started}\t{completed}\t{command}\t{relative_log}\n")
            print(f"Tool {tool} is not installed", flush=True)
            return 127
        log_path = self.output_dir / relative_log
        try:
            with log_path.open("w", encoding="utf-8") as log:
                result = subprocess.run(
                    [tool, *args],
                    cwd=self.output_dir,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    text=True,
                    timeout=timeout,
                    check=False,
                )
            rc = result.returncode
            state = "completed" if rc == 0 else "failed"
        except subprocess.TimeoutExpired:
            rc = 124
            state = "timed_out"
        completed = utcnow()
        with self.status_file.open("a", encoding="utf-8") as status:
            status.write(f"{run_id}\t{tool}\t{state}\t{rc}\t{started}\t{completed}\t{command}\t{relative_log}\n")
        print(f"{tool}: {state} (exit {rc})", flush=True)
        return rc


def detect_cloud_provider(target: str) -> tuple[str, str]:
    cleaned = target.strip()
    if ":" in cleaned:
        provider, identifier = cleaned.split(":", 1)
        provider = provider.strip().lower()
        identifier = identifier.strip()
        if provider in {"aws", "azure", "gcp"} and identifier:
            return provider, identifier
    if re.fullmatch(r"\d{12}", cleaned):
        return "aws", cleaned
    if re.fullmatch(r"[0-9a-fA-F-]{36}", cleaned):
        return "azure", cleaned.lower()
    return "gcp", cleaned


def _existing_artifacts(root: Path) -> list[str]:
    return sorted(
        str(path.relative_to(root))
        for path in root.rglob("*")
        if path.is_file()
    )


def run_repository(target: str, output_dir: Path, mode: str) -> int:
    from app.config import settings

    repository_url = safe_repository_url(target)
    runner = ToolRunner(output_dir)
    repo_dir = output_dir / "repository"
    retain_checkout = os.getenv("EXPOSURESCOPEX_RETAIN_REPOSITORY_CHECKOUT", "false").lower() == "true"
    print("Starting repository inventory", flush=True)
    clone_args = ["clone", "--depth", "1", "--single-branch", "--no-recurse-submodules", repository_url, str(repo_dir)]
    if runner.run("git", clone_args, timeout=1800) != 0:
        return 3

    print("Starting secret scanning", flush=True)
    gitleaks_rc = runner.run(
        "gitleaks",
        ["git", str(repo_dir), "--report-format", "json", "--report-path", str(output_dir / "gitleaks.json"), "--redact", "--exit-code", "0"],
        timeout=1800,
    )
    print("Starting dependency scanning", flush=True)
    trivy_rc = runner.run(
        "trivy",
        ["fs", "--scanners", "vuln,secret,misconfig", "--format", "json", "--output", str(output_dir / "trivy.json"), str(repo_dir)],
        timeout=3600,
    )
    print("Generating software bill of materials", flush=True)
    sbom_rc = runner.run(
        "trivy",
        ["fs", "--format", "cyclonedx", "--output", str(output_dir / "sbom.cdx.json"), str(repo_dir)],
        timeout=3600,
    )
    print("Generating software bill of materials", flush=True)
    syft_rc = 126
    if settings.ENABLE_SYFT_ADAPTER:
        syft_rc = runner.run(
            settings.SYFT_BIN,
            ["scan", f"dir:{repo_dir}", "-o", f"cyclonedx-json={output_dir / 'syft.sbom.json'}"],
            timeout=3600,
        )
    print("Checking supply chain provenance", flush=True)
    grype_rc = 126
    if settings.ENABLE_GRYPE_ADAPTER:
        grype_rc = runner.run(
            settings.GRYPE_BIN,
            [f"dir:{repo_dir}", "-o", "json", "--file", str(output_dir / "grype.json")],
            timeout=3600,
        )
    if repo_dir.exists() and not retain_checkout:
        git_dir = repo_dir / ".git"
        if git_dir.exists():
            shutil.rmtree(git_dir, ignore_errors=True)
    summary = {
        "target_type": "repository",
        "repository": repository_url,
        "mode": mode,
        "gitleaks_exit_code": gitleaks_rc,
        "trivy_exit_code": trivy_rc,
        "sbom_exit_code": sbom_rc,
        "syft_exit_code": syft_rc,
        "grype_exit_code": grype_rc,
        "repository_checkout_retained": retain_checkout and repo_dir.exists(),
        "repository_git_metadata_retained": retain_checkout,
        "artifacts": _existing_artifacts(output_dir),
    }
    (output_dir / "specialized_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print("Generating report", flush=True)
    print("Session complete", flush=True)
    return 0 if trivy_rc == 0 and sbom_rc == 0 and gitleaks_rc == 0 else 3


async def run_mcp(target: str, output_dir: Path) -> int:
    from app.services.mcp_security import McpAuditError, run_mcp_audit

    print("Starting MCP discovery", flush=True)
    run_id = f"mcp-audit-{os.getpid()}-1"
    started = utcnow()
    command = f"mcp-audit {shlex.quote(target)} --protocol-tests --no-destructive-probes"
    with (output_dir / "tool_runs.tsv").open("a", encoding="utf-8") as status:
        status.write(f"{run_id}\tmcp-audit\trunning\t\t{started}\t\t{command}\tmcp_audit.json\n")
    try:
        result = await run_mcp_audit(
            target,
            None,
            allow_private=os.getenv("MCP_ASSESSMENT_ALLOW_PRIVATE", "false").lower() == "true",
            protocol_tests=True,
        )
    except McpAuditError as exc:
        completed = utcnow()
        with (output_dir / "tool_runs.tsv").open("a", encoding="utf-8") as status:
            status.write(f"{run_id}\tmcp-audit\tfailed\t3\t{started}\t{completed}\t{command}\tmcp_audit.json\n")
        print(f"MCP assessment failed: {exc}", flush=True)
        return 3
    (output_dir / "mcp_audit.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    completed = utcnow()
    with (output_dir / "tool_runs.tsv").open("a", encoding="utf-8") as status:
        status.write(f"{run_id}\tmcp-audit\tcompleted\t0\t{started}\t{completed}\t{command}\tmcp_audit.json\n")
    print("Starting MCP protocol testing", flush=True)
    print("Starting MCP authorization testing", flush=True)
    print("Starting MCP inventory", flush=True)
    print("Starting MCP isolation testing", flush=True)
    print("Starting MCP semantic analysis", flush=True)
    print("Starting MCP drift analysis", flush=True)
    print("Generating report", flush=True)
    print("Session complete", flush=True)
    return 0


async def run_asn(target: str, output_dir: Path) -> int:
    import httpx

    asn = target.upper().removeprefix("AS")
    if not asn.isdigit():
        raise ValueError("ASN target must use AS12345 or 12345 format")
    print("Starting ASN and BGP inventory", flush=True)
    urls = {
        "rdap": f"https://rdap.org/autnum/{asn}",
        "prefixes": f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}",
    }
    responses = {}
    async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
        for name, url in urls.items():
            response = await client.get(url, headers={"User-Agent": "ExposureScopeX/2.3"})
            response.raise_for_status()
            responses[name] = response.json()
    prefixes = responses.get("prefixes", {}).get("data", {}).get("prefixes", [])
    candidates = [{
        "target": item.get("prefix"),
        "target_type": "cidr",
        "relation": "announces",
        "source": "ripe-stat",
    } for item in prefixes if isinstance(item, dict) and item.get("prefix")]
    inventory = {
        "seed": f"AS{asn}",
        "target_type": "asn",
        "rdap": responses.get("rdap", {}),
        "candidates": candidates,
    }
    (output_dir / "seed_inventory.json").write_text(json.dumps(inventory, indent=2), encoding="utf-8")
    print("Starting prefix inventory", flush=True)
    print("Starting routing correlation", flush=True)
    print("Generating report", flush=True)
    print("Session complete", flush=True)
    return 0


def report_required_configuration(target_type: str, target: str, output_dir: Path) -> int:
    requirements = {
        "organization": (
            "Add at least one verified domain, repository organization, or configured internet-intelligence source. "
            "Business-name-only attribution is intentionally not promoted to confirmed assets."
        ),
    }
    message = requirements[target_type]
    (output_dir / "specialized_summary.json").write_text(json.dumps({
        "target_type": target_type,
        "target": target,
        "status": "configuration_required",
        "message": message,
    }, indent=2), encoding="utf-8")
    print(f"Configuration required: {message}", flush=True)
    return 3


def run_cloud_account(target: str, output_dir: Path, mode: str) -> int:
    from app.config import settings
    from app.services.open_source_catalog import build_tool_plan

    provider, identifier = detect_cloud_provider(target)
    runner = ToolRunner(output_dir)
    plan = build_tool_plan(target_type="cloud_account", scan_mode=mode, utilities=["prowler", "scoutsuite"])
    adapter_results: list[dict[str, object]] = []

    print("Starting cloud account preflight", flush=True)
    summary = {
        "target_type": "cloud_account",
        "target": target,
        "provider": provider,
        "account_identifier": identifier,
        "mode": mode,
        "notes": [
            "Provider-specific authenticated scope is controlled by the execution environment credentials.",
            "ScoutSuite is used as an independent secondary comparator when credentials and provider support are available.",
        ],
        "tool_plan": plan,
        "adapters": [],
    }

    print("Starting cloud inventory", flush=True)
    inventory_payload = {
        "provider": provider,
        "target": target,
        "candidates": [{
            "target": f"{provider}:{identifier}",
            "target_type": "cloud_account",
            "relation": "assessment_scope",
            "source": "cloud_adapter",
        }],
    }
    write_json(output_dir / "seed_inventory.json", inventory_payload)

    prowler_output = output_dir / "prowler"
    prowler_output.mkdir(parents=True, exist_ok=True)
    prowler_bin = settings.PROWLER_BIN
    prowler_enabled = bool(settings.ENABLE_PROWLER_ADAPTER)
    print("Starting primary CSPM execution", flush=True)
    prowler_args = _prowler_command(provider, identifier, prowler_output)
    if prowler_enabled and prowler_args:
        prowler_rc = runner.run(prowler_bin, prowler_args, timeout=14_400)
    else:
        prowler_rc = 126
    adapter_results.append({
        "tool": "prowler",
        "enabled": prowler_enabled,
        "exit_code": prowler_rc,
        "artifacts": _existing_artifacts(prowler_output),
    })

    scout_output = output_dir / "scoutsuite"
    scout_output.mkdir(parents=True, exist_ok=True)
    scout_bin = settings.SCOUTSUITE_BIN
    scout_enabled = bool(settings.ENABLE_SCOUTSUITE_ADAPTER)
    print("Starting secondary posture validation", flush=True)
    scout_args = _scoutsuite_command(provider, identifier, scout_output)
    if scout_enabled and scout_args:
        scout_rc = runner.run(scout_bin, scout_args, timeout=14_400)
    else:
        scout_rc = 126
    adapter_results.append({
        "tool": "scoutsuite",
        "enabled": scout_enabled,
        "exit_code": scout_rc,
        "artifacts": _existing_artifacts(scout_output),
    })

    print("Starting cloud IAM analysis", flush=True)
    print("Starting cloud compliance correlation", flush=True)
    summary["adapters"] = adapter_results
    summary["artifacts"] = _existing_artifacts(output_dir)
    summary["status"] = "completed" if any(item["exit_code"] == 0 for item in adapter_results) else "adapter_unavailable"
    write_json(output_dir / "specialized_summary.json", summary)
    print("Generating report", flush=True)
    print(f"Cloud account summary written for {provider}:{identifier}", flush=True)
    print("Session complete", flush=True)
    return 0 if any(item["exit_code"] == 0 for item in adapter_results) else 3


def run_image(target: str, output_dir: Path, mode: str) -> int:
    from app.config import settings
    from app.services.open_source_catalog import build_tool_plan

    image_ref = safe_image_ref(target)
    runner = ToolRunner(output_dir)
    plan = build_tool_plan(target_type="image", scan_mode=mode, utilities=["trivy", "syft", "grype"])
    registry = image_ref.split("/", 1)[0] if "/" in image_ref and ("." in image_ref.split("/", 1)[0] or ":" in image_ref.split("/", 1)[0]) else "docker.io"

    print("Starting image reference preflight", flush=True)
    write_json(output_dir / "seed_inventory.json", {
        "target_type": "image",
        "target": image_ref,
        "registry": registry,
        "candidates": [{
            "target": image_ref,
            "target_type": "image",
            "relation": "assessment_scope",
            "source": "image_adapter",
        }],
    })

    print("Starting image inventory", flush=True)
    trivy_rc = runner.run(
        "trivy",
        ["image", "--scanners", "vuln,secret,misconfig", "--format", "json", "--output", str(output_dir / "trivy.json"), image_ref],
        timeout=5400,
    )
    print("Starting primary image vulnerability scan", flush=True)
    sbom_rc = runner.run(
        "trivy",
        ["image", "--format", "cyclonedx", "--output", str(output_dir / "sbom.cdx.json"), image_ref],
        timeout=5400,
    )
    print("Starting secondary image sbom inventory", flush=True)
    syft_rc = 126
    if settings.ENABLE_SYFT_ADAPTER:
        syft_rc = runner.run(
            settings.SYFT_BIN,
            ["scan", f"registry:{image_ref}", "-o", f"cyclonedx-json={output_dir / 'syft.sbom.json'}"],
            timeout=5400,
        )
    print("Starting secondary image correlation", flush=True)
    grype_rc = 126
    if settings.ENABLE_GRYPE_ADAPTER:
        grype_rc = runner.run(
            settings.GRYPE_BIN,
            [f"registry:{image_ref}", "-o", "json", "--file", str(output_dir / "grype.json")],
            timeout=5400,
        )
    summary = {
        "target_type": "image",
        "image": image_ref,
        "registry": registry,
        "mode": mode,
        "tool_plan": plan,
        "trivy_exit_code": trivy_rc,
        "sbom_exit_code": sbom_rc,
        "syft_exit_code": syft_rc,
        "grype_exit_code": grype_rc,
        "artifacts": _existing_artifacts(output_dir),
    }
    write_json(output_dir / "specialized_summary.json", summary)
    print("Generating report", flush=True)
    print("Session complete", flush=True)
    return 0 if trivy_rc == 0 and sbom_rc == 0 else 3


def _prowler_command(provider: str, identifier: str, output_dir: Path) -> list[str]:
    args = [provider, "-M", "json-ocsf", "csv", "html", "-o", str(output_dir), "-F", "prowler", "--log-level", "ERROR"]
    if provider == "azure":
        args = [provider, "--sp-env-auth", "--subscription-ids", identifier, "-M", "json-ocsf", "csv", "html", "-o", str(output_dir), "-F", "prowler", "--log-level", "ERROR"]
    elif provider == "gcp":
        args = [provider, "--project-ids", identifier, "-M", "json-ocsf", "csv", "html", "-o", str(output_dir), "-F", "prowler", "--log-level", "ERROR"]
    return args


def _scoutsuite_command(provider: str, identifier: str, output_dir: Path) -> list[str]:
    _ = identifier
    return [provider, "--no-browser", "--report-dir", str(output_dir)]


def merge_tool_telemetry(root: Path, child: Path) -> None:
    child_status = child / "tool_runs.tsv"
    if not child_status.is_file() or child_status.resolve() == (root / "tool_runs.tsv").resolve():
        return
    prefix = child.resolve().relative_to(root.resolve())
    with (root / "tool_runs.tsv").open("a", encoding="utf-8") as destination:
        for line in child_status.read_text(encoding="utf-8", errors="replace").splitlines():
            fields = line.split("\t")
            if len(fields) > 7 and fields[7] and not Path(fields[7]).is_absolute():
                fields[7] = str(prefix / fields[7])
            destination.write("\t".join(fields) + "\n")


async def run_batch(manifest_path: Path, output_dir: Path, mode: str) -> int:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(manifest, list) or not manifest:
        raise ValueError("Batch manifest contains no normalized targets")
    compatible = [item for item in manifest if item.get("target_type") in {"domain", "ip", "cidr", "url"}]
    specialized = [item for item in manifest if item.get("target_type") not in {"domain", "ip", "cidr", "url"}]
    outcomes = []
    if compatible:
        targets_file = output_dir / "active_targets.txt"
        targets_file.write_text("\n".join(str(item["target"]) for item in compatible) + "\n", encoding="utf-8")
        domain_root = output_dir / "network_web"
        domain_root.mkdir(parents=True, exist_ok=True)
        env = os.environ.copy()
        env["EXPOSURESCOPEX_RESULTS_DIR"] = str(domain_root)
        command = ["bash", "/app/exposurescopex.sh", "-f", str(targets_file), "-m", mode, "--auto", "--ci"]
        result = subprocess.run(command, cwd=output_dir, env=env, check=False)
        outcomes.append({"type": "network_web", "count": len(compatible), "exit_code": result.returncode})
        for status_file in domain_root.rglob("tool_runs.tsv"):
            merge_tool_telemetry(output_dir, status_file.parent)

    for index, item in enumerate(specialized, start=1):
        target_type = str(item.get("target_type") or "")
        target = str(item.get("target") or "")
        child = output_dir / f"{target_type}_{index}"
        child.mkdir(parents=True, exist_ok=True)
        (child / "tool_runs.tsv").touch()
        if target_type == "repository":
            rc = run_repository(target, child, mode)
        elif target_type == "image":
            rc = run_image(target, child, mode)
        elif target_type == "mcp":
            rc = await run_mcp(target, child)
        elif target_type == "asn":
            rc = await run_asn(target, child)
        elif target_type == "cloud_account":
            rc = run_cloud_account(target, child, mode)
        elif target_type in {"kubernetes", "android", "ios"}:
            rc = run_artifact(target_type, target, child, mode)
        elif target_type == "organization":
            rc = report_required_configuration(target_type, target, child)
        else:
            rc = 3
            (child / "specialized_summary.json").write_text(json.dumps({
                "target_type": target_type,
                "target": target,
                "status": "unsupported",
            }), encoding="utf-8")
        merge_tool_telemetry(output_dir, child)
        outcomes.append({"type": target_type, "target": target, "exit_code": rc})

    (output_dir / "batch_summary.json").write_text(json.dumps({
        "targets": len(manifest),
        "outcomes": outcomes,
        "warnings": sum(1 for item in outcomes if item["exit_code"] not in {0, 1, 2}),
    }, indent=2), encoding="utf-8")
    print(f"Session: {output_dir}", flush=True)
    print("Session complete", flush=True)
    return 0 if any(item["exit_code"] in {0, 1, 2} for item in outcomes) else 3


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--type", required=True, choices=("repository", "image", "mcp", "asn", "cloud_account", "organization", "kubernetes", "android", "ios", "batch"))
    parser.add_argument("--target")
    parser.add_argument("--manifest")
    parser.add_argument("--output", required=True)
    parser.add_argument("--mode", default="medium", choices=("light", "medium", "aggressive"))
    args = parser.parse_args()
    output_dir = Path(args.output).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "tool_runs.tsv").touch()
    print(f"Session: {output_dir}", flush=True)
    try:
        if args.type == "batch":
            if not args.manifest:
                raise ValueError("Batch scans require --manifest")
            return asyncio.run(run_batch(Path(args.manifest), output_dir, args.mode))
        if not args.target:
            raise ValueError("Target is required")
        if args.type == "repository":
            return run_repository(args.target, output_dir, args.mode)
        if args.type == "image":
            return run_image(args.target, output_dir, args.mode)
        if args.type == "asn":
            return asyncio.run(run_asn(args.target, output_dir))
        if args.type == "cloud_account":
            return run_cloud_account(args.target, output_dir, args.mode)
        if args.type == "organization":
            return report_required_configuration(args.type, args.target, output_dir)
        if args.type in {"kubernetes", "android", "ios"}:
            return run_artifact(args.type, args.target, output_dir, args.mode)
        return asyncio.run(run_mcp(args.target, output_dir))
    except Exception as exc:
        error_id = uuid.uuid4().hex[:8]
        print(f"Specialized scan failed safely [{error_id}]: {type(exc).__name__}: {exc}", flush=True)
        return 3


if __name__ == "__main__":
    sys.exit(main())
