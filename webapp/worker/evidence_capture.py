"""Capture original browser and terminal PNG evidence during scan execution."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import socket
import subprocess
import time
import uuid
from datetime import datetime, timezone
from importlib.metadata import version
from pathlib import Path
from urllib.parse import urlparse


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_metadata(path: Path, payload: dict) -> None:
    payload = {
        "schema_version": 1,
        "evidence_id": str(uuid.uuid4()),
        "organization_id": os.getenv("EXPOSURESCOPEX_ORG_ID") or None,
        "assessment_id": os.getenv("EXPOSURESCOPEX_ASSESSMENT_ID") or None,
        "scan_id": os.getenv("EXPOSURESCOPEX_SCAN_ID") or None,
        "task_id": os.getenv("EXPOSURESCOPEX_TASK_ID") or None,
        "scanner_image": os.getenv("EXPOSURESCOPEX_SCANNER_IMAGE") or None,
        **payload,
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "screenshot_path": path.name,
        "screenshot_size_bytes": path.stat().st_size,
        "screenshot_sha256": _sha256(path),
    }
    path.with_suffix(path.suffix + ".json").write_text(
        json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8"
    )


def capture_browser(urls_file: Path, output_dir: Path, limit: int) -> int:
    from playwright.sync_api import sync_playwright

    output_dir.mkdir(parents=True, exist_ok=True)
    urls = []
    for raw in urls_file.read_text(encoding="utf-8", errors="replace").splitlines():
        url = raw.strip()
        if urlparse(url).scheme in {"http", "https"} and url not in urls:
            urls.append(url)
        if len(urls) >= limit:
            break
    captured = 0
    failures = 0
    source_list_sha256 = _sha256(urls_file)
    resolver_mappings: dict[str, str] = {}
    for url in urls:
        hostname = (urlparse(url).hostname or "").lower()
        if hostname.endswith(".localhost"):
            try:
                resolver_mappings[hostname] = socket.gethostbyname(hostname)
            except OSError:
                continue
    browser_args = []
    if resolver_mappings:
        rules = ",".join(f"MAP {host} {address}" for host, address in sorted(resolver_mappings.items()))
        browser_args.append(f"--host-resolver-rules={rules}")
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True, args=browser_args)
        context_args = {
            "viewport": {"width": 1440, "height": 1000},
            "accept_downloads": False,
            "service_workers": "block",
            "ignore_https_errors": True,
        }
        auth_state = next(
            (parent / "web-auth-storage-state.json" for parent in [output_dir, *output_dir.parents]
             if (parent / "web-auth-storage-state.json").is_file()),
            None,
        )
        auth_metadata_path = next(
            (parent / "web-auth-session.json" for parent in [output_dir, *output_dir.parents]
             if (parent / "web-auth-session.json").is_file()),
            None,
        )
        auth_metadata = json.loads(auth_metadata_path.read_text(encoding="utf-8")) if auth_metadata_path else {}
        login_url = str(auth_metadata.get("login_url") or "").rstrip("/")
        if auth_state:
            context_args["storage_state"] = str(auth_state)
        context = browser.new_context(
            **context_args,
        )
        for index, url in enumerate(urls, start=1):
            page = context.new_page()
            try:
                response = page.goto(url, wait_until="domcontentloaded", timeout=30_000)
                page.wait_for_timeout(1_000)
                final_url = page.url.rstrip("/")
                redirected_to_login = bool(
                    auth_state and login_url and url.rstrip("/") != login_url and final_url == login_url
                )
                login_form_visible = bool(
                    auth_state
                    and url.rstrip("/") != login_url
                    and page.locator('input[type="password"]').count()
                    and page.locator('input[type="password"]').first.is_visible()
                )
                if redirected_to_login or login_form_visible:
                    raise RuntimeError("Authenticated session was redirected to a login boundary")
                slug = re.sub(r"[^A-Za-z0-9._-]", "_", url)[:100]
                screenshot = output_dir / f"playwright-{index:03d}-{slug}.png"
                page.screenshot(path=str(screenshot), full_page=True)
                _write_metadata(screenshot, {
                    "capture_type": "playwright_browser",
                    "capture_tool": "playwright-screenshot",
                    "source_list": urls_file.name,
                    "source_list_sha256": source_list_sha256,
                    "capture_sequence": index,
                    "requested_url": url,
                    "final_url": page.url,
                    "http_status": response.status if response else None,
                    "resolved_ip": resolver_mappings.get((urlparse(url).hostname or "").lower()),
                    "browser_engine": "chromium",
                    "playwright_version": version("playwright"),
                    "authenticated_session": bool(auth_state),
                    "authentication_verified": bool(auth_state),
                })
                captured += 1
            except Exception as exc:
                slug = re.sub(r"[^A-Za-z0-9._-]", "_", url)[:100]
                screenshot = output_dir / f"playwright-{index:03d}-{slug}-error.png"
                try:
                    page.screenshot(path=str(screenshot), full_page=True)
                    _write_metadata(screenshot, {
                        "capture_type": "playwright_browser_error_state",
                        "capture_tool": "playwright-screenshot",
                        "source_list": urls_file.name,
                        "source_list_sha256": source_list_sha256,
                        "capture_sequence": index,
                        "requested_url": url,
                        "final_url": page.url,
                        "browser_engine": "chromium",
                        "playwright_version": version("playwright"),
                        "capture_error": f"{type(exc).__name__}: {exc}"[:1000],
                        "authenticated_session": bool(auth_state),
                        "authentication_verified": False,
                    })
                    failures += 1
                except Exception as screenshot_exc:
                    failures += 1
                    (output_dir / f"playwright-{index:03d}-error.json").write_text(json.dumps({
                        "capture_type": "playwright_browser",
                        "requested_url": url,
                        "captured_at": datetime.now(timezone.utc).isoformat(),
                        "error": f"{type(screenshot_exc).__name__}: {screenshot_exc}"[:1000],
                    }, indent=2), encoding="utf-8")
            finally:
                page.close()
        context.close()
        browser.close()
    (output_dir / "capture-summary.json").write_text(json.dumps({
        "schema_version": 1,
        "source_list": urls_file.name,
        "source_list_sha256": source_list_sha256,
        "requested": len(urls),
        "valid_captures": captured,
        "failed_captures": failures,
        "resolver_mappings": resolver_mappings,
        "completed_at": datetime.now(timezone.utc).isoformat(),
    }, indent=2, sort_keys=True), encoding="utf-8")
    return captured


def capture_terminal(transcript: Path, output: Path, scan_id: str, task_id: str) -> int:
    output.parent.mkdir(parents=True, exist_ok=True)
    display = f":{100 + (os.getpid() % 500)}"
    environment = {**os.environ, "DISPLAY": display}
    xvfb = subprocess.Popen(
        ["Xvfb", display, "-screen", "0", "1440x900x24", "-nolisten", "tcp"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    terminal = None
    try:
        time.sleep(0.5)
        command = f"printf 'ExposureScopeX scan {scan_id}\\nTask {task_id}\\n\\n'; tail -n 45 -- {shlex.quote(str(transcript))}; sleep 8"
        terminal = subprocess.Popen(
            ["xterm", "-title", f"ExposureScopeX forensic capture {scan_id}", "-geometry", "160x48",
             "-fa", "DejaVu Sans Mono", "-fs", "10", "-e", "/bin/sh", "-c", command],
            env=environment, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        time.sleep(1.5)
        subprocess.run(["scrot", "-o", str(output)], env=environment, check=True, timeout=15)
        _write_metadata(output, {
            "capture_type": "xvfb_xterm_runtime",
            "capture_tool": "xvfb-xterm-scrot",
            "scan_id": scan_id,
            "task_id": task_id,
            "source_transcript": transcript.name,
            "source_transcript_sha256": _sha256(transcript),
            "display": display,
        })
        return 0
    finally:
        if terminal and terminal.poll() is None:
            terminal.terminate()
        if xvfb.poll() is None:
            xvfb.terminate()


def capture_finding_terminal(
    source_artifact: Path,
    source_label: str,
    output: Path,
    scan_id: str,
    task_id: str,
    finding_key: str,
    match_terms: list[str],
    *,
    capture_type: str = "xvfb_xterm_finding_source",
    display_title: str = "finding evidence",
    extra_metadata: dict | None = None,
) -> int:
    """Capture an actual xterm displaying matching lines from an immutable scanner artifact."""
    source_artifact = source_artifact.resolve()
    if not source_artifact.is_file():
        raise FileNotFoundError(source_artifact)
    output.parent.mkdir(parents=True, exist_ok=True)
    display = f":{100 + (os.getpid() % 500)}"
    environment = {**os.environ, "DISPLAY": display}
    xvfb = subprocess.Popen(
        ["Xvfb", display, "-screen", "0", "1440x900x24", "-nolisten", "tcp"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    terminal = None
    try:
        time.sleep(0.5)
        usable_terms = [term.strip()[:300] for term in match_terms if term and term.strip()]
        grep_args = " ".join(f"-e {shlex.quote(term)}" for term in usable_terms)
        source_arg = shlex.quote(str(source_artifact))
        source_hash = _sha256(source_artifact)
        header = shlex.quote(
            f"ExposureScopeX {display_title}\nScan {scan_id}\nTask {task_id}\n"
            f"Source {source_label}\nSHA-256 {source_hash}\n\n"
        )
        if grep_args:
            evidence_command = (
                f"matches=$(grep -a -n -F {grep_args} -- {source_arg} | head -n 45); "
                f"if [ -n \"$matches\" ]; then printf '%s\\n' \"$matches\"; "
                f"else tail -n 45 -- {source_arg}; fi"
            )
        else:
            evidence_command = f"tail -n 45 -- {source_arg}"
        command = f"printf %s {header}; {evidence_command}; sleep 8"
        terminal = subprocess.Popen(
            ["xterm", "-title", f"ExposureScopeX {display_title} {scan_id}", "-geometry", "160x48",
             "-fa", "DejaVu Sans Mono", "-fs", "10", "-e", "/bin/sh", "-c", command],
            env=environment, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        time.sleep(1.5)
        subprocess.run(["scrot", "-o", str(output)], env=environment, check=True, timeout=15)
        _write_metadata(output, {
            "capture_type": capture_type,
            "capture_tool": "xvfb-xterm-scrot",
            "scan_id": scan_id,
            "task_id": task_id,
            "finding_key": finding_key,
            "source_artifact": source_label,
            "source_artifact_sha256": source_hash,
            "match_terms": usable_terms,
            "display": display,
            **(extra_metadata or {}),
        })
        return 0
    finally:
        if terminal and terminal.poll() is None:
            terminal.terminate()
        if xvfb.poll() is None:
            xvfb.terminate()


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    browser = subparsers.add_parser("browser")
    browser.add_argument("--urls-file", type=Path, required=True)
    browser.add_argument("--output-dir", type=Path, required=True)
    browser.add_argument("--limit", type=int, default=20)
    terminal = subparsers.add_parser("terminal")
    terminal.add_argument("--transcript", type=Path, required=True)
    terminal.add_argument("--output", type=Path, required=True)
    terminal.add_argument("--scan-id", required=True)
    terminal.add_argument("--task-id", required=True)
    finding_terminal = subparsers.add_parser("finding-terminal")
    finding_terminal.add_argument("--source-artifact", type=Path, required=True)
    finding_terminal.add_argument("--source-label", required=True)
    finding_terminal.add_argument("--output", type=Path, required=True)
    finding_terminal.add_argument("--scan-id", required=True)
    finding_terminal.add_argument("--task-id", required=True)
    finding_terminal.add_argument("--finding-key", required=True)
    finding_terminal.add_argument("--match", action="append", default=[])
    tool_terminal = subparsers.add_parser("tool-terminal")
    tool_terminal.add_argument("--source-artifact", type=Path, required=True)
    tool_terminal.add_argument("--source-label", required=True)
    tool_terminal.add_argument("--output", type=Path, required=True)
    tool_terminal.add_argument("--scan-id", required=True)
    tool_terminal.add_argument("--task-id", required=True)
    tool_terminal.add_argument("--run-id", required=True)
    tool_terminal.add_argument("--tool", required=True)
    tool_terminal.add_argument("--status", required=True)
    tool_terminal.add_argument("--command", default="")
    args = parser.parse_args()
    if args.command == "browser":
        return 0 if capture_browser(args.urls_file, args.output_dir, max(1, args.limit)) > 0 else 2
    if args.command == "terminal":
        return capture_terminal(args.transcript, args.output, args.scan_id, args.task_id)
    if args.command == "tool-terminal":
        return capture_finding_terminal(
            args.source_artifact, args.source_label, args.output, args.scan_id, args.task_id,
            f"tool-run:{args.run_id}", [],
            capture_type="xvfb_xterm_tool_output",
            display_title=f"{args.tool} execution evidence",
            extra_metadata={
                "tool_run_id": args.run_id,
                "tool": args.tool,
                "tool_status": args.status,
                "command": args.command,
            },
        )
    return capture_finding_terminal(
        args.source_artifact, args.source_label, args.output, args.scan_id, args.task_id,
        args.finding_key, args.match,
    )


if __name__ == "__main__":
    raise SystemExit(main())
