"""Idempotent ingestion of one launched assessment scan into platform records."""

from __future__ import annotations

import uuid
import json
import hashlib
import mimetypes
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from sqlalchemy import and_, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.database import async_session_factory
from app.models.assessment import Assessment
from app.models.asset import Asset
from app.models.finding import Finding, FindingIdentity, FindingObservation
from app.models.port import Port
from app.models.scan import Scan
from app.models.scan_runtime import ScanArtifact
from app.services.parsers.arjun_parser import parse_arjun_results
from app.services.parsers.api_security_parser import parse_api_security
from app.services.parsers.cloud_parser import parse_cloud_buckets, parse_cloud_results
from app.services.parsers.cspm_parser import parse_prowler_ocsf, parse_scoutsuite_report
from app.services.parsers.email_parser import parse_email_security
from app.services.parsers.ffuf_parser import parse_ffuf_results
from app.services.parsers.headers_parser import parse_http_headers
from app.services.parsers.nikto_parser import parse_nikto
from app.services.parsers.nmap_parser import parse_nmap_xml
from app.services.parsers.nuclei_parser import parse_nuclei_results
from app.services.parsers.sqlmap_parser import parse_sqlmap_results
from app.services.parsers.ssl_parser import parse_ssl_results
from app.services.parsers.subdomain_parser import parse_subdomains
from app.services.real_data_importer import _calculate_risk_score, _count_severity
from app.services.asset_inventory import normalize_target
from app.services.asset_graph import persist_scan_graph
from app.services.risk_engine import confidence_score, contextual_risk_score
from app.services.scan_authorization import target_matches_scope
from app.config import settings

INGESTION_NAMESPACE = uuid.UUID("7abf4252-fd41-4d4f-a919-5576ae9d7fa0")
_SENSITIVE_RUNTIME_ARTIFACTS = {
    "web-auth-cookie.txt",
    "web-auth-storage-state.json",
}

_FINDING_STAGES = {
    "ssl_tls", "cloud", "web_testing", "api_security", "nuclei", "exploitation",
    "secrets", "dependencies", "image_vulnerability", "image_correlation",
    "mcp_protocol", "mcp_auth", "mcp_isolation", "mcp_semantic", "cspm_primary",
    "cspm_secondary", "misconfiguration_scan", "secret_scan",
}


def _stable_id(kind: str, scan_id: str, key: str) -> uuid.UUID:
    return uuid.uuid5(INGESTION_NAMESPACE, f"{kind}:{scan_id}:{key}")


def finding_scope_signature(metadata: dict | None) -> str:
    """Identify scans whose negative results are safe to compare."""
    data = metadata or {}
    profile = data.get("profile") or {}
    scope = {
        "target_type": profile.get("target_type") or data.get("target_type"),
        "scan_strategy": profile.get("scan_strategy") or data.get("scan_strategy"),
        "phases": profile.get("phases") or data.get("phases_requested") or {},
        "flags": profile.get("flags") or data.get("flags_requested") or {},
        "utilities": sorted(profile.get("utilities") or data.get("utilities") or []),
        "nuclei_tags": sorted(profile.get("nuclei_tags") or data.get("nuclei_tags") or []),
    }
    return hashlib.sha256(json.dumps(scope, sort_keys=True, default=str).encode()).hexdigest()


def finding_resolution_eligible(metadata: dict | None) -> bool:
    """Require a complete finding-producing stage before treating absence as remediation."""
    data = metadata or {}
    if (data.get("scan_strategy") or (data.get("profile") or {}).get("scan_strategy")) in {"import", "inventory"}:
        return False
    planned = [item for item in data.get("execution_manifest") or [] if item.get("planned")]
    relevant = [item for item in planned if item.get("id") in _FINDING_STAGES]
    if not relevant:
        return False
    if any(item.get("status") in {"failed", "cancelled", "not_run"} for item in planned):
        return False
    return any(item.get("status") in {"completed", "warning"} for item in relevant)


def _hostname(value: str | None) -> str:
    if not value:
        return ""
    candidate = value.strip()
    parsed = urlparse(candidate if "://" in candidate else f"//{candidate}")
    return (parsed.hostname or candidate.split("/")[0].split(":")[0]).lower().rstrip(".")


def _finding_asset_id(url: str, assets: dict[str, Asset], fallback: uuid.UUID) -> uuid.UUID:
    hostname = _hostname(url)
    if hostname in assets:
        return assets[hostname].id
    for value, asset in assets.items():
        if hostname and (hostname.endswith(f".{value}") or value.endswith(f".{hostname}")):
            return asset.id
    return fallback


def _finding_evidence_key(item: dict) -> str:
    """Return the stable key shared by capture and ingestion for one observation."""
    return "|".join((
        str(item.get("source") or "unknown"),
        str(item.get("template_id") or ""),
        str(item.get("url") or ""),
        str(item.get("title") or "Unknown finding"),
    ))


def _collect_findings(scan_dir: Path, target: str) -> list[dict]:
    findings: list[dict] = []
    for path in scan_dir.rglob("safe_web_findings.json"):
        for item in _read_json(path, []):
            if isinstance(item, dict):
                item["_artifact_path"] = str(path.relative_to(scan_dir))
                findings.append(item)
    for path in scan_dir.rglob("nuclei_results.txt"):
        parsed = parse_nuclei_results(path)
        for item in parsed:
            item["_artifact_path"] = str(path.relative_to(scan_dir))
            item["evidence"] = item.get("extra") or ""
        findings.extend(parsed)
    for path in scan_dir.rglob("cloud_results.txt"):
        parsed = parse_cloud_results(path)
        for item in parsed:
            item["_artifact_path"] = str(path.relative_to(scan_dir))
            item["evidence"] = item.get("extra") or ""
        findings.extend(parsed)
    for path in scan_dir.rglob("api_security.txt"):
        parsed = parse_api_security(path)
        for item in parsed:
            item["_artifact_path"] = str(path.relative_to(scan_dir))
            item["evidence"] = item.get("title") or ""
        findings.extend(parsed)

    for path in scan_dir.rglob("cloud_buckets.txt"):
        for bucket in parse_cloud_buckets(path):
            findings.append({
                "severity": bucket.get("severity", "HIGH"),
                "title": f"{bucket.get('bucket_type', 'Cloud')} bucket {bucket.get('access', 'exposure')}: {bucket.get('url', '')}",
                "url": bucket.get("url", ""),
                "source": "cloud",
                "evidence": "",
                "_artifact_path": str(path.relative_to(scan_dir)),
            })

    for path in scan_dir.rglob("ssl_results.txt"):
        ssl_data = parse_ssl_results(path)
        for item in (ssl_data or {}).get("findings", []):
            findings.append({
                "severity": item.get("severity", "INFO"),
                "title": item.get("title", "TLS finding"),
                "url": f"https://{target}",
                "source": "ssl_check",
                "evidence": "",
                "_artifact_path": str(path.relative_to(scan_dir)),
            })

    for path in scan_dir.rglob("email_security.txt"):
        email_data = parse_email_security(path)
        for item in (email_data or {}).get("findings", []):
            findings.append({
                "severity": item.get("severity", "INFO"),
                "title": item.get("title", "Email security finding"),
                "url": f"https://{target}",
                "source": "email_security",
                "evidence": "",
                "_artifact_path": str(path.relative_to(scan_dir)),
            })

    for path in scan_dir.rglob("http_headers.txt"):
        for block in parse_http_headers(path):
            for item in block.get("findings", []):
                findings.append({
                    "severity": item.get("severity", "INFO"),
                    "title": item.get("title", "HTTP header finding"),
                    "url": block.get("url", f"https://{target}"),
                    "source": "http_headers",
                    "evidence": "",
                    "_artifact_path": str(path.relative_to(scan_dir)),
                })

    for nikto_file in scan_dir.rglob("nikto_*.txt"):
        nikto = parse_nikto(nikto_file) or {}
        for item in nikto.get("findings", []):
            findings.append({
                "severity": "MEDIUM",
                "title": item.get("description", "Nikto finding"),
                "url": f"https://{nikto.get('target', target)}:{nikto.get('port', 443)}",
                "source": "nikto",
                "evidence": item.get("reference", ""),
                "_artifact_path": str(nikto_file.relative_to(scan_dir)),
            })
    for report_path in scan_dir.rglob("ffuf_*.json"):
        for item in parse_ffuf_results(report_path):
            findings.append({
                "severity": "LOW" if item.get("status") in {401, 403} else "INFO",
                "title": f"Content discovery hit: {item.get('url')}",
                "description": "The content discovery pass found a reachable path worth analyst review.",
                "url": str(item.get("url") or target),
                "source": "ffuf",
                "template_id": "ffuf-content-discovery",
                "evidence": (
                    f"Input: {item.get('input') or 'n/a'}; "
                    f"status: {item.get('status')}; "
                    f"length: {item.get('length')}; "
                    f"words: {item.get('words')}"
                )[:4000],
                "_artifact_path": str(report_path.relative_to(scan_dir)),
            })
    for report_path in scan_dir.rglob("arjun_*.json"):
        for item in parse_arjun_results(report_path):
            findings.append({
                "severity": "INFO",
                "title": f"Parameter discovered: {item.get('parameter')}",
                "description": "The parameter discovery pass identified an application parameter not previously modeled.",
                "url": str(item.get("url") or target),
                "source": "arjun",
                "template_id": "arjun-parameter-discovery",
                "evidence": f"Method: {item.get('method') or 'GET'}; parameter: {item.get('parameter')}"[:4000],
                "_artifact_path": str(report_path.relative_to(scan_dir)),
            })
    for report_path in scan_dir.rglob("sqlmap_results.csv"):
        for item in parse_sqlmap_results(report_path):
            findings.append({
                "severity": "HIGH",
                "title": f"SQL injection signal on parameter {item.get('parameter')}",
                "description": "The active validation workflow observed a sqlmap finding. Analyst review is still required before escalation.",
                "url": str(item.get("url") or target),
                "source": "sqlmap",
                "template_id": "sqlmap-sqli",
                "evidence": (
                    f"Place: {item.get('place')}; "
                    f"parameter: {item.get('parameter')}; "
                    f"techniques: {item.get('techniques')}; "
                    f"notes: {item.get('notes') or 'none'}"
                )[:4000],
                "_artifact_path": str(report_path.relative_to(scan_dir)),
            })
    findings.extend(_collect_specialized_findings(scan_dir, target))
    return findings


def _read_json(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else default
    except (OSError, json.JSONDecodeError):
        return default


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _artifact_type(path: Path) -> str:
    name = path.name.lower()
    if "sbom" in name:
        return "sbom"
    if "report" in name or path.suffix.lower() in {".html", ".pdf", ".docx", ".md", ".sarif"}:
        return "report"
    if "screenshot" in name or path.suffix.lower() in {".png", ".jpg", ".jpeg", ".webp"}:
        return "screenshot"
    if "log" in name or path.suffix.lower() in {".log", ".txt"}:
        return "scanner_output"
    return "evidence"


def _screenshot_evidence_by_url(scan_path: Path) -> dict[str, dict]:
    """Index only screenshots whose immutable sidecar matches the original bytes."""
    evidence_by_url: dict[str, dict] = {}
    for sidecar in scan_path.rglob("*.png.json"):
        metadata = _read_json(sidecar, {})
        screenshot = Path(str(sidecar)[:-5])
        if not isinstance(metadata, dict) or not screenshot.is_file():
            continue
        try:
            digest = _file_sha256(screenshot)
        except OSError:
            continue
        if digest != metadata.get("screenshot_sha256"):
            continue
        record = {
            "evidence_id": metadata.get("evidence_id"),
            "path": str(screenshot.relative_to(scan_path))[:1000],
            "sha256": digest,
            "captured_at": metadata.get("captured_at"),
            "task_id": metadata.get("task_id"),
            "capture_tool": metadata.get("capture_tool"),
        }
        for field in ("requested_url", "final_url"):
            url = str(metadata.get(field) or "").rstrip("/")
            if url:
                evidence_by_url[url] = record
    return evidence_by_url


def _terminal_evidence_by_finding_key(scan_path: Path) -> dict[str, dict]:
    """Index finding terminal captures only when both image and source hashes verify."""
    evidence_by_key: dict[str, dict] = {}
    root = scan_path.resolve()
    for sidecar in scan_path.rglob("finding-terminal-*.png.json"):
        metadata = _read_json(sidecar, {})
        screenshot = Path(str(sidecar)[:-5])
        if not isinstance(metadata, dict) or not screenshot.is_file():
            continue
        finding_key = str(metadata.get("finding_key") or "")
        source = (root / str(metadata.get("source_artifact") or "")).resolve()
        try:
            if not source.is_relative_to(root):
                continue
            screenshot_hash = _file_sha256(screenshot)
            source_hash = _file_sha256(source)
        except (OSError, ValueError):
            continue
        if (
            not finding_key
            or screenshot_hash != metadata.get("screenshot_sha256")
            or source_hash != metadata.get("source_artifact_sha256")
        ):
            continue
        evidence_by_key[finding_key] = {
            "evidence_id": metadata.get("evidence_id"),
            "path": str(screenshot.relative_to(scan_path))[:1000],
            "sha256": screenshot_hash,
            "captured_at": metadata.get("captured_at"),
            "source_artifact_sha256": source_hash,
        }
    return evidence_by_key


async def _persist_artifact_manifest(session, scan: Scan, scan_path: Path) -> dict:
    entries: list[dict] = []
    for path in sorted(scan_path.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        relative = str(path.relative_to(scan_path))[:1000]
        if path.name.lower() in _SENSITIVE_RUNTIME_ARTIFACTS:
            continue
        try:
            size = path.stat().st_size
            digest = _file_sha256(path)
        except OSError:
            continue
        artifact_type = _artifact_type(path)
        mime_type = mimetypes.guess_type(path.name)[0]
        provenance = {"scanner_image": settings.SCANNER_IMAGE_IDENTITY}
        if path.suffix.lower() == ".png":
            sidecar = Path(f"{path}.json")
            metadata = _read_json(sidecar, {})
            if isinstance(metadata, dict) and metadata.get("screenshot_sha256") == digest:
                provenance.update({
                    "evidence_id": metadata.get("evidence_id"),
                    "capture_metadata": metadata,
                    "metadata_sha256": _file_sha256(sidecar),
                    "metadata_verified": True,
                })
        await session.execute(
            pg_insert(ScanArtifact).values(
                scan_id=scan.id, path=relative, artifact_type=artifact_type,
                mime_type=mime_type, size_bytes=size, sha256=digest, retained=True,
                provenance=provenance,
            ).on_conflict_do_update(
                constraint="uq_scan_artifact_path",
                set_={"artifact_type": artifact_type, "mime_type": mime_type, "size_bytes": size,
                      "sha256": digest, "retained": True,
                      "provenance": provenance},
            )
        )
        entries.append({"path": relative, "type": artifact_type, "size_bytes": size, "sha256": digest})
    root_hash = hashlib.sha256("\n".join(f"{item['path']}:{item['sha256']}" for item in entries).encode()).hexdigest()
    return {"count": len(entries), "size_bytes": sum(item["size_bytes"] for item in entries), "sha256": root_hash}


def _collect_specialized_findings(scan_dir: Path, target: str) -> list[dict]:
    findings: list[dict] = []
    for report_path in scan_dir.rglob("specialized_findings.json"):
        for item in _read_json(report_path, []):
            if isinstance(item, dict):
                item["_artifact_path"] = str(report_path.relative_to(scan_dir))
                findings.append(item)
    for report_path in scan_dir.rglob("gitleaks.json"):
        for item in _read_json(report_path, []):
            if not isinstance(item, dict):
                continue
            rule_id = str(item.get("RuleID") or "secret")
            path = str(item.get("File") or "repository")
            line = item.get("StartLine")
            findings.append({
                "severity": "HIGH",
                "title": str(item.get("Description") or f"Repository secret detected ({rule_id})"),
                "description": "A credential-like value was detected in repository history. Secret values are redacted.",
                "url": target,
                "source": "gitleaks",
                "template_id": rule_id,
                "evidence": f"File: {path}; line: {line or 'unknown'}; fingerprint: {item.get('Fingerprint') or 'unavailable'}",
                "_artifact_path": str(report_path.relative_to(scan_dir)),
            })

    for report_path in scan_dir.rglob("trivy.json"):
        trivy = _read_json(report_path, {})
        for result in trivy.get("Results", []) if isinstance(trivy, dict) else []:
            if not isinstance(result, dict):
                continue
            result_target = str(result.get("Target") or target)
            for vulnerability in result.get("Vulnerabilities") or []:
                severity = str(vulnerability.get("Severity") or "UNKNOWN").upper()
                findings.append({
                    "severity": severity if severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"} else "INFO",
                    "title": str(vulnerability.get("Title") or vulnerability.get("VulnerabilityID") or "Dependency vulnerability"),
                    "description": str(vulnerability.get("Description") or "")[:10000],
                    "url": target,
                    "source": "trivy",
                    "template_id": str(vulnerability.get("VulnerabilityID") or "dependency-vulnerability"),
                    "evidence": f"Artifact: {result_target}; package: {vulnerability.get('PkgName')}; installed: {vulnerability.get('InstalledVersion')}; fixed: {vulnerability.get('FixedVersion') or 'not published'}",
                    "_artifact_path": str(report_path.relative_to(scan_dir)),
                })
            for misconfiguration in result.get("Misconfigurations") or []:
                severity = str(misconfiguration.get("Severity") or "MEDIUM").upper()
                findings.append({
                    "severity": severity if severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"} else "MEDIUM",
                    "title": str(misconfiguration.get("Title") or misconfiguration.get("ID") or "IaC misconfiguration"),
                    "description": str(misconfiguration.get("Description") or "")[:10000],
                    "url": target,
                    "source": "trivy-misconfiguration",
                    "template_id": str(misconfiguration.get("ID") or "iac-misconfiguration"),
                    "evidence": f"Artifact: {result_target}; cause: {misconfiguration.get('CauseMetadata') or 'see scanner artifact'}",
                    "_artifact_path": str(report_path.relative_to(scan_dir)),
                })
            for secret in result.get("Secrets") or []:
                findings.append({
                    "severity": str(secret.get("Severity") or "HIGH").upper(),
                    "title": str(secret.get("Title") or secret.get("RuleID") or "Repository secret detected"),
                    "description": "A credential-like value was detected. Secret content is intentionally not ingested.",
                    "url": target,
                    "source": "trivy-secret",
                    "template_id": str(secret.get("RuleID") or "secret"),
                    "evidence": f"Artifact: {result_target}; line: {secret.get('StartLine') or 'unknown'}",
                    "_artifact_path": str(report_path.relative_to(scan_dir)),
                })
    for report_path in scan_dir.rglob("grype.json"):
        grype = _read_json(report_path, {})
        for match in grype.get("matches", []) if isinstance(grype, dict) else []:
            if not isinstance(match, dict):
                continue
            vulnerability = match.get("vulnerability") or {}
            artifact = match.get("artifact") or {}
            findings.append({
                "severity": str(vulnerability.get("severity") or "MEDIUM").upper(),
                "title": str(vulnerability.get("description") or vulnerability.get("id") or "Package vulnerability")[:500],
                "description": str(vulnerability.get("fix", {}).get("versions") or vulnerability.get("dataSource") or "")[:10000],
                "url": target,
                "source": "grype",
                "template_id": str(vulnerability.get("id") or "grype-vulnerability"),
                "evidence": (
                    f"Package: {artifact.get('name') or 'unknown'}; "
                    f"version: {artifact.get('version') or 'unknown'}; "
                    f"location: {((artifact.get('locations') or [{}])[0] or {}).get('path') or 'n/a'}"
                )[:4000],
                "_artifact_path": str(report_path.relative_to(scan_dir)),
            })

    for report_path in scan_dir.rglob("mcp_audit.json"):
        mcp = _read_json(report_path, {})
        for item in mcp.get("findings", []) if isinstance(mcp, dict) else []:
            if not isinstance(item, dict):
                continue
            findings.append({
                "severity": str(item.get("severity") or "INFO").upper(),
                "title": str(item.get("title") or "MCP security finding"),
                "description": str(item.get("remediation") or ""),
                "url": str(mcp.get("endpoint") or target),
                "source": "mcp",
                "template_id": str(item.get("category") or item.get("id") or "mcp-security"),
                "evidence": str(item.get("evidence") or "")[:4000],
                "_artifact_path": str(report_path.relative_to(scan_dir)),
            })
    for report_path in scan_dir.rglob("*.json"):
        if "prowler" not in report_path.name.lower():
            continue
        parsed = parse_prowler_ocsf(report_path)
        for item in parsed.get("findings", []):
            item["_artifact_path"] = str(report_path.relative_to(scan_dir))
            findings.append(item)
    for report_path in list(scan_dir.rglob("scoutsuite_results*.js")) + list(scan_dir.rglob("scoutsuite_results*.json")):
        parsed = parse_scoutsuite_report(report_path)
        for item in parsed.get("findings", []):
            item["_artifact_path"] = str(report_path.relative_to(scan_dir))
            findings.append(item)
    return findings


async def ingest_assessment_scan(
    *,
    org_id: str,
    assessment_id: str,
    scan_id: str,
    session_dir: str,
) -> dict:
    """Import one scan's artifacts without crossing assessment or tenant boundaries."""
    scan_path = Path(session_dir)
    if not scan_path.is_dir():
        raise FileNotFoundError(f"Scan session directory was not found: {session_dir}")

    assessment_uuid = uuid.UUID(assessment_id)
    scan_uuid = uuid.UUID(scan_id)
    org_uuid = uuid.UUID(org_id)
    now = datetime.now(timezone.utc)

    async with async_session_factory() as session:
        row = (
            await session.execute(
                select(Assessment, Scan)
                .join(Scan, Scan.assessment_id == Assessment.id)
                .where(
                    and_(
                        Assessment.id == assessment_uuid,
                        Assessment.org_id == org_uuid,
                        Scan.id == scan_uuid,
                    )
                )
            )
        ).one_or_none()
        if not row:
            raise ValueError("Assessment scan does not exist in the requested organization")
        assessment, scan = row

        existing_assets = (
            await session.execute(select(Asset).where(Asset.assessment_id == assessment_uuid))
        ).scalars().all()
        assets = {asset.value.lower().rstrip("."): asset for asset in existing_assets}
        root_asset = assets.get(_hostname(assessment.target))
        if root_asset is None and existing_assets:
            root_asset = existing_assets[0]
        if root_asset is None:
            value = assessment.target if assessment.target_type != "file" else "batch"
            try:
                normalized_root = normalize_target(value, assessment.target_type if assessment.target_type != "file" else "auto")
            except Exception:
                normalized_root = None
            root_asset = Asset(
                id=_stable_id("asset", scan_id, value),
                assessment_id=assessment_uuid,
                asset_type=assessment.target_type if assessment.target_type != "file" else "domain",
                value=value,
                canonical_key=normalized_root.canonical_key if normalized_root else None,
                root_domain=normalized_root.root_domain if normalized_root else None,
                is_live=True,
                first_seen=now,
                last_seen=now,
                metadata_={"source": "scan_target"},
                is_demo=False,
            )
            session.add(root_asset)
            assets[value.lower()] = root_asset
            await session.flush()

        mcp_path = next(scan_path.rglob("mcp_audit.json"), None)
        mcp_audit = _read_json(mcp_path, {}) if mcp_path else {}
        if mcp_audit:
            root_asset.metadata_ = {
                **(root_asset.metadata_ or {}),
                "mcp_inventory": mcp_audit.get("inventory", {}),
                "mcp_summary": mcp_audit.get("summary", {}),
            }
        sbom_path = next(scan_path.rglob("sbom.cdx.json"), None)
        sbom = _read_json(sbom_path, {}) if sbom_path else {}
        if sbom:
            root_asset.metadata_ = {
                **(root_asset.metadata_ or {}),
                "sbom": {
                    "format": sbom.get("bomFormat"),
                    "spec_version": sbom.get("specVersion"),
                    "components": len(sbom.get("components") or []),
                },
            }
        syft_path = next(scan_path.rglob("syft.sbom.json"), None)
        syft_sbom = _read_json(syft_path, {}) if syft_path else {}
        if syft_sbom:
            root_asset.metadata_ = {
                **(root_asset.metadata_ or {}),
                "secondary_sbom": {
                    "format": syft_sbom.get("bomFormat"),
                    "spec_version": syft_sbom.get("specVersion"),
                    "components": len(syft_sbom.get("components") or []),
                    "source": "syft",
                },
            }

        discovered = [
            (value, "subdomain", "discovered_subdomain")
            for pattern in ("subdomains_discovered.txt", "subdomains.txt")
            for path in scan_path.rglob(pattern)
            for value in parse_subdomains(path)
        ]
        nmap_files = sorted(scan_path.rglob("nmap_scan*.xml"))
        nmap_hosts = [
            host
            for nmap_file in nmap_files
            for host in parse_nmap_xml(nmap_file)
        ]
        discovered.extend((host.get("ip", ""), "ip", "resolved_to") for host in nmap_hosts)
        seed_inventory = {}
        cloud_resource_metadata: dict[str, dict] = {}
        cloud_summaries: list[dict] = []
        for inventory_path in scan_path.rglob("seed_inventory.json"):
            current_inventory = _read_json(inventory_path, {})
            if not isinstance(current_inventory, dict):
                continue
            seed_inventory = current_inventory
            for candidate in current_inventory.get("candidates", []):
                if isinstance(candidate, dict):
                    discovered.append((
                        str(candidate.get("target") or ""),
                        str(candidate.get("target_type") or "domain"),
                        str(candidate.get("relation") or "discovered_from"),
                    ))
        for report_path in scan_path.rglob("*.json"):
            if "prowler" not in report_path.name.lower():
                continue
            parsed = parse_prowler_ocsf(report_path)
            if parsed.get("summary"):
                cloud_summaries.append({"source": "prowler", **parsed["summary"]})
            for resource in parsed.get("resources", []):
                if not isinstance(resource, dict):
                    continue
                value = str(resource.get("value") or "").strip()
                if not value:
                    continue
                cloud_resource_metadata[value.lower()] = resource
                discovered.append((value, "cloud_resource", "cloud_resource"))
        scout_reports = list(scan_path.rglob("scoutsuite_results*.js")) + list(scan_path.rglob("scoutsuite_results*.json"))
        for report_path in scout_reports:
            parsed = parse_scoutsuite_report(report_path)
            if parsed.get("summary"):
                cloud_summaries.append({"source": "scoutsuite", **parsed["summary"]})
            for resource in parsed.get("resources", []):
                if not isinstance(resource, dict):
                    continue
                value = str(resource.get("value") or "").strip()
                if not value:
                    continue
                cloud_resource_metadata[value.lower()] = resource
                discovered.append((value, "cloud_resource", "cloud_resource"))
        if cloud_summaries:
            root_asset.metadata_ = {
                **(root_asset.metadata_ or {}),
                "cloud_summary": cloud_summaries,
            }
        added_assets = 0
        for value, asset_type, relation_type in discovered:
            normalized = value.lower().rstrip(".")
            if not normalized or normalized in assets:
                continue
            try:
                normalized_asset = normalize_target(normalized, asset_type)
            except Exception:
                normalized_asset = None
            asset = Asset(
                id=_stable_id("asset", scan_id, normalized),
                assessment_id=assessment_uuid,
                asset_type=asset_type,
                value=normalized,
                canonical_key=normalized_asset.canonical_key if normalized_asset else None,
                root_domain=normalized_asset.root_domain if normalized_asset else None,
                parent_id=root_asset.id,
                is_live=True,
                first_seen=now,
                last_seen=now,
                metadata_={
                    "source": (
                        "cloud_adapter"
                        if asset_type == "cloud_resource"
                        else "enumeration"
                        if asset_type == "subdomain"
                        else "seed_expansion"
                        if seed_inventory
                        else "nmap"
                    ),
                    "relation_type": relation_type,
                    "cloud_resource": cloud_resource_metadata.get(normalized),
                },
                is_demo=False,
            )
            session.add(asset)
            assets[normalized] = asset
            added_assets += 1
        await session.flush()

        existing_ports = {
            (port.asset_id, port.port_number, port.protocol)
            for port in (
                await session.execute(select(Port).where(Port.scan_id == scan_uuid))
            ).scalars().all()
        }
        added_ports = 0
        for host in nmap_hosts:
            asset = assets.get((host.get("ip") or "").lower()) or root_asset
            for item in host.get("ports", []):
                key = (asset.id, item["port"], item["protocol"])
                if key in existing_ports:
                    continue
                session.add(Port(
                    id=_stable_id("port", scan_id, f"{asset.id}:{item['port']}:{item['protocol']}"),
                    asset_id=asset.id,
                    scan_id=scan_uuid,
                    port_number=item["port"],
                    protocol=item["protocol"],
                    state=item.get("state", "open"),
                    service_name=item.get("service"),
                    service_version=item.get("product", ""),
                    banner=item.get("version", ""),
                    first_seen=now,
                    last_seen=now,
                    is_demo=False,
                ))
                existing_ports.add(key)
                added_ports += 1

        parsed_findings = _collect_findings(scan_path, assessment.target)
        existing_finding_ids = set(
            (
                await session.execute(select(Finding.id).where(Finding.scan_id == scan_uuid))
            ).scalars().all()
        )
        observed_identity_ids: set[uuid.UUID] = set(
            identity_id for identity_id in (
                await session.execute(select(Finding.identity_id).where(
                    Finding.scan_id == scan_uuid, Finding.identity_id.is_not(None)
                ))
            ).scalars().all() if identity_id
        )
        screenshot_evidence = _screenshot_evidence_by_url(scan_path)
        terminal_evidence = _terminal_evidence_by_finding_key(scan_path)
        added_findings = 0
        out_of_scope_findings_rejected = 0
        seen_keys: set[str] = set()
        for item in parsed_findings:
            title = str(item.get("title") or "Unknown finding")[:500]
            url = str(item.get("url") or "")[:2000]
            if url and not target_matches_scope(url, "url", assessment.target):
                out_of_scope_findings_rejected += 1
                continue
            source = str(item.get("source") or "unknown")
            template_id = item.get("template_id")
            key = f"{source}|{template_id or ''}|{url}|{title}"
            if key in seen_keys:
                continue
            seen_keys.add(key)
            finding_id = _stable_id("finding", scan_id, key)
            if finding_id in existing_finding_ids:
                continue
            evidence = str(item.get("evidence") or "")
            confidence = confidence_score(source, evidence)
            reachable = bool(url)
            screenshot = screenshot_evidence.get(url.rstrip("/")) if url else None
            terminal_capture = terminal_evidence.get(_finding_evidence_key(item))
            asset_id = _finding_asset_id(url, assets, root_asset.id)
            identity_fingerprint = hashlib.sha256(
                f"{source}|{template_id or ''}|{url.lower()}|{title.lower()}".encode()
            ).hexdigest()
            identity_id = (
                await session.execute(
                    pg_insert(FindingIdentity).values(
                        org_id=org_uuid, fingerprint=identity_fingerprint, source=source,
                        template_id=template_id, title=title,
                        severity=str(item.get("severity") or "INFO").upper(), status="open",
                        first_seen=now, last_seen=now,
                    ).on_conflict_do_update(
                        constraint="uq_finding_identity_org_fingerprint",
                        set_={"last_seen": now, "severity": str(item.get("severity") or "INFO").upper(), "title": title, "status": "open"},
                    ).returning(FindingIdentity.id)
                )
            ).scalar_one()
            observed_identity_ids.add(identity_id)
            session.add(Finding(
                id=finding_id,
                assessment_id=assessment_uuid,
                scan_id=scan_uuid,
                asset_id=asset_id,
                identity_id=identity_id,
                source=source,
                template_id=template_id,
                severity=str(item.get("severity") or "INFO").upper(),
                title=title,
                description=str(item.get("description") or ""),
                url=url or None,
                evidence=evidence,
                status="new",
                confidence_score=confidence,
                reachability="reachable" if reachable else "unknown",
                exploitability="unknown",
                risk_score=contextual_risk_score(
                    str(item.get("severity") or "INFO"), confidence, reachable=reachable
                ),
                evidence_metadata={
                    "artifact_source": source,
                    "source_artifact": item.get("_artifact_path"),
                    "scan_id": scan_id,
                    "has_direct_evidence": bool(evidence.strip()),
                    "reproduction_steps": item.get("reproduction_steps") or item.get("steps_to_reproduce"),
                    "screenshot_evidence_id": screenshot.get("evidence_id") if screenshot else None,
                    "screenshot_path": screenshot.get("path") if screenshot else None,
                    "screenshot_sha256": screenshot.get("sha256") if screenshot else None,
                    "screenshot_captured_at": screenshot.get("captured_at") if screenshot else None,
                    "terminal_evidence_id": terminal_capture.get("evidence_id") if terminal_capture else None,
                    "terminal_screenshot_path": terminal_capture.get("path") if terminal_capture else None,
                    "terminal_screenshot_sha256": terminal_capture.get("sha256") if terminal_capture else None,
                    "source_artifact_sha256": terminal_capture.get("source_artifact_sha256") if terminal_capture else None,
                },
                first_seen=now,
                last_seen=now,
                is_demo=False,
            ))
            session.add(FindingObservation(
                identity_id=identity_id,
                finding_id=finding_id,
                scan_id=scan_uuid,
                assessment_id=assessment_uuid,
                observed_at=now,
                evidence_sha256=hashlib.sha256(evidence.encode()).hexdigest() if evidence else None,
                payload={
                    "severity": str(item.get("severity") or "INFO").upper(),
                    "asset_id": str(asset_id), "url": url or None,
                    "source": source, "template_id": template_id,
                    "confidence": float(confidence),
                },
            ))
            existing_finding_ids.add(finding_id)
            added_findings += 1

        resolved_findings = 0
        if finding_resolution_eligible(scan.scan_metadata):
            current_signature = finding_scope_signature(scan.scan_metadata)
            prior_scans = (
                await session.execute(
                    select(Scan).where(
                        Scan.assessment_id == assessment_uuid,
                        Scan.id != scan_uuid,
                        Scan.status == "completed",
                    )
                )
            ).scalars().all()
            comparable_scan_ids = [
                item.id for item in prior_scans
                if finding_scope_signature(item.scan_metadata) == current_signature
            ]
            if comparable_scan_ids:
                previously_observed = select(FindingObservation.identity_id).where(
                    FindingObservation.scan_id.in_(comparable_scan_ids)
                )
                resolution_filter = [
                    FindingIdentity.org_id == org_uuid,
                    FindingIdentity.status == "open",
                    FindingIdentity.id.in_(previously_observed),
                ]
                if observed_identity_ids:
                    resolution_filter.append(FindingIdentity.id.not_in(observed_identity_ids))
                resolution_result = await session.execute(
                    update(FindingIdentity).where(*resolution_filter).values(status="resolved")
                )
                resolved_findings = int(resolution_result.rowcount or 0)

        counts = _count_severity(parsed_findings)
        assessment.risk_score = _calculate_risk_score(counts)
        await session.flush()
        graph_result = await persist_scan_graph(
            session,
            org_id=org_uuid,
            assessment_id=assessment_uuid,
            scan_id=scan_uuid,
            assets=list(assets.values()),
        )
        artifact_manifest = await _persist_artifact_manifest(session, scan, scan_path)
        metadata = dict(scan.scan_metadata or {})
        metadata["ingestion"] = {
            "completed_at": now.isoformat(),
            "assets_added": added_assets,
            "ports_added": added_ports,
            "findings_added": added_findings,
            "out_of_scope_findings_rejected": out_of_scope_findings_rejected,
            "finding_identities_resolved": resolved_findings,
            "finding_scope_signature": finding_scope_signature(scan.scan_metadata),
            "files": sorted(str(path.relative_to(scan_path)) for path in scan_path.rglob("*") if path.is_file()),
            "graph": graph_result,
            "artifact_manifest": artifact_manifest,
        }
        scan.scan_metadata = metadata
        scan.session_dir = str(scan_path)
        await session.commit()
        return metadata["ingestion"]
