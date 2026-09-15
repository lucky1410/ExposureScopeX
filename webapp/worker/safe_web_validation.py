#!/usr/bin/env python3
"""Bounded, non-destructive validation of authenticated web application inputs."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import socket
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

DATABASE_ERRORS = re.compile(
    r"(sql syntax|mysql_fetch|mysqli_|pdoexception|postgresql.*error|sqlite.*error|"
    r"ora-\d{4,5}|unclosed quotation mark|unterminated quoted string|database error)",
    re.IGNORECASE,
)
STATE_CHANGING_PATHS = re.compile(
    r"/(logout|logoff|signout|delete|remove|setup|install|reset)(?:[/?#]|$)", re.IGNORECASE
)


def passive_baseline_findings(
    url: str,
    headers: dict[str, str],
    cookies: list[dict],
    *,
    has_password_form: bool,
) -> list[dict]:
    """Create evidence-backed findings from one non-mutating page response."""
    normalized = {str(key).lower(): str(value) for key, value in headers.items()}
    content_type = normalized.get("content-type", "").lower()
    if content_type and "text/html" not in content_type and "application/xhtml" not in content_type:
        return []
    evidence = f"Observed response headers: {', '.join(sorted(normalized)) or 'none'}"
    results: list[dict] = []

    def add(severity: str, title: str, description: str, template_id: str, detail: str = evidence) -> None:
        results.append({
            "severity": severity,
            "title": title,
            "description": description,
            "url": url,
            "source": "safe-web-baseline",
            "template_id": template_id,
            "confidence": 95,
            "evidence": detail,
            "reproduction_steps": [
                f"Send an authorized GET request to {url}.",
                "Inspect the response headers without submitting forms or changing application state.",
                f"Confirm: {title}.",
            ],
        })

    if has_password_form and urlsplit(url).scheme == "http":
        add(
            "HIGH",
            "Password form is served over unencrypted HTTP",
            "Credentials submitted to this page can traverse the network without transport encryption.",
            "password-form-over-http",
            "Password input observed on an HTTP page; no credential value was captured.",
        )
    if "content-security-policy" not in normalized:
        add("LOW", "Content-Security-Policy header is missing", "The page does not declare a browser-enforced content policy.", "missing-content-security-policy")
    if "x-content-type-options" not in normalized:
        add("LOW", "X-Content-Type-Options header is missing", "The response does not disable browser MIME-type sniffing.", "missing-x-content-type-options")
    if "x-frame-options" not in normalized and "frame-ancestors" not in normalized.get("content-security-policy", "").lower():
        add("LOW", "Clickjacking protection header is missing", "Neither X-Frame-Options nor a CSP frame-ancestors directive protects the page.", "missing-clickjacking-protection")
    if urlsplit(url).scheme == "https" and "strict-transport-security" not in normalized:
        add("LOW", "Strict-Transport-Security header is missing", "HTTPS is available but the response does not instruct browsers to enforce it.", "missing-hsts")

    for cookie in cookies:
        name = str(cookie.get("name") or "unnamed")
        cookie_scope = f"domain={cookie.get('domain') or 'unknown'}; path={cookie.get('path') or '/'}"
        if not cookie.get("httpOnly"):
            add(
                "LOW",
                f"Cookie {name} is missing HttpOnly",
                "Client-side scripts can access this cookie, increasing session exposure if script injection occurs.",
                "cookie-without-httponly",
                f"Cookie attributes observed for {name} ({cookie_scope}): HttpOnly=false; cookie value was not captured.",
            )
        if urlsplit(url).scheme == "https" and not cookie.get("secure"):
            add(
                "MEDIUM",
                f"Cookie {name} is missing Secure",
                "The cookie may be transmitted over an unencrypted connection.",
                "cookie-without-secure",
                f"Cookie attributes observed for {name} ({cookie_scope}): Secure=false; cookie value was not captured.",
            )
    return results


def deduplicate_findings(findings: list[dict]) -> list[dict]:
    """Remove repeat observations while retaining distinct page-level evidence."""
    unique: list[dict] = []
    seen: set[tuple[str, ...]] = set()
    for finding in findings:
        source = str(finding.get("source") or "")
        template_id = str(finding.get("template_id") or "")
        title = str(finding.get("title") or "")
        if template_id.startswith("cookie-without-"):
            key = (source, template_id, title, str(finding.get("evidence") or ""))
        else:
            key = (source, template_id, title, str(finding.get("url") or ""))
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def scoped_urls(root: Path, target: str, limit: int) -> list[str]:
    target_host = (urlsplit(target).hostname or target.split("/")[0]).lower()
    candidates = [target]
    for name in ("crawl_results.txt", "katana_crawl.txt", "nuclei_targets.txt"):
        path = root / name
        if path.is_file():
            candidates.extend(path.read_text(encoding="utf-8", errors="replace").splitlines())
    result: list[str] = []
    for candidate in candidates:
        value = candidate.strip()
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or (parsed.hostname or "").lower() != target_host:
            continue
        if STATE_CHANGING_PATHS.search(parsed.path):
            continue
        clean = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))
        if clean not in result:
            result.append(clean)
        if len(result) >= limit:
            break
    return result


def main() -> int:
    from playwright.sync_api import sync_playwright

    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--mode", choices=("light", "medium", "aggressive"), required=True)
    parser.add_argument("--allow-probes", action="store_true")
    args = parser.parse_args()
    root = Path(args.output_dir).resolve()
    state = root / "web-auth-storage-state.json"

    url_limit = {"light": 20, "medium": 60, "aggressive": 150}[args.mode]
    probe_limit = {"light": 0, "medium": 25, "aggressive": 100}[args.mode] if args.allow_probes else 0
    urls = scoped_urls(root, args.target, url_limit)
    evidence_dir = root / "safe-validation-evidence"
    evidence_dir.mkdir(exist_ok=True)
    findings: list[dict] = []
    inventory: list[dict] = []
    probes = 0

    mappings: dict[str, str] = {}
    for url in urls:
        host = (urlsplit(url).hostname or "").lower()
        if host.endswith(".localhost"):
            mappings[host] = socket.gethostbyname(host)
    launch_args = []
    if mappings:
        launch_args.append("--host-resolver-rules=" + ",".join(
            f"MAP {host} {ip}" for host, ip in sorted(mappings.items())
        ))

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True, args=launch_args)
        context_options = {"ignore_https_errors": True}
        if state.is_file():
            context_options["storage_state"] = str(state)
        context = browser.new_context(**context_options)
        page = context.new_page()
        for url in urls:
            try:
                response = page.goto(url, wait_until="domcontentloaded", timeout=20_000)
                baseline = page.content()
                forms = page.locator("form").evaluate_all("""forms => forms.map(form => ({
                    action: form.action || location.href,
                    method: (form.method || 'get').toLowerCase(),
                    fields: Array.from(form.elements).filter(e => e.name && !['submit','button','reset','file','password','hidden'].includes((e.type || '').toLowerCase())).map(e => e.name),
                    submit: Array.from(form.elements).filter(e => e.name && ['submit','button'].includes((e.type || '').toLowerCase())).map(e => [e.name, e.value || 'Submit']),
                    hasCsrf: Array.from(form.elements).some(e => /csrf|token|nonce/i.test(e.name || '')),
                    hasPassword: Array.from(form.elements).some(e => (e.type || '').toLowerCase() === 'password')
                }))""")
            except Exception:
                continue
            observed_url = page.url
            response_headers = response.headers if response else {}
            page_cookies = context.cookies([observed_url])
            has_password_form = any(bool(form.get("hasPassword")) for form in forms)
            findings.extend(passive_baseline_findings(
                observed_url, response_headers, page_cookies, has_password_form=has_password_form
            ))
            inventory.append({
                "requested_url": url,
                "url": observed_url,
                "http_status": response.status if response else None,
                "forms": forms,
                "authentication_boundary": has_password_form and not state.is_file(),
            })
            if has_password_form and not state.is_file():
                print(f"Authentication boundary detected at {observed_url}; application coverage is limited to public pages")
            if probe_limit == 0:
                continue
            for form in forms:
                if probes >= probe_limit or form.get("method") != "get" or not form.get("fields"):
                    continue
                action = str(form.get("action") or observed_url)
                if STATE_CHANGING_PATHS.search(urlsplit(action).path):
                    continue
                target_host = (urlsplit(args.target).hostname or args.target.split("/")[0]).lower()
                if (urlsplit(action).hostname or "").lower() != target_host:
                    continue
                field = str(form["fields"][0])
                parsed = urlsplit(action)
                query = dict(parse_qsl(parsed.query, keep_blank_values=True))
                for name, value in form.get("submit") or []:
                    query[str(name)] = str(value)
                query[field] = "'"
                probe_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(query), ""))
                probes += 1
                try:
                    probe_response = page.goto(probe_url, wait_until="domcontentloaded", timeout=20_000)
                    probe_html = page.content()
                except Exception:
                    continue
                baseline_match = DATABASE_ERRORS.search(baseline)
                probe_match = DATABASE_ERRORS.search(probe_html)
                if probe_match and not baseline_match:
                    screenshot = evidence_dir / f"safe-validation-{probes:03d}-database-error.png"
                    page.screenshot(path=str(screenshot), full_page=True)
                    findings.append({
                        "severity": "MEDIUM",
                        "title": "Malformed input triggered a database error response",
                        "description": "A single apostrophe supplied to a GET form produced a database-specific error that was absent from the baseline response. This is an injection indicator, not proof of exploitability.",
                        "url": probe_url,
                        "source": "safe-web-validator",
                        "template_id": "database-error-input-indicator",
                        "confidence": 85,
                        "evidence": f"New response marker: {probe_match.group(0)}; HTTP status: {probe_response.status if probe_response else 'unknown'}; screenshot: {screenshot.relative_to(root)}; sha256: {sha256(screenshot)}",
                        "reproduction_steps": [f"Authenticate using the approved assessment session.", f"Open {action}.", f"Submit a single apostrophe in GET parameter {field}.", "Confirm that the database-specific error is newly present in the response."],
                    })
        context.close()
        browser.close()

    findings = deduplicate_findings(findings)
    (root / "safe_web_findings.json").write_text(json.dumps(findings, indent=2), encoding="utf-8")
    (root / "safe_web_validation.json").write_text(json.dumps({
        "schema_version": 1,
        "mode": args.mode,
        "policy": "non-destructive-get-only",
        "active_probes_authorized": args.allow_probes,
        "urls_attempted": len(urls),
        "forms_inventory": inventory,
        "probes_attempted": probes,
        "findings": len(findings),
        "completed_at": datetime.now(timezone.utc).isoformat(),
    }, indent=2), encoding="utf-8")
    print(f"Safe validation complete: {len(urls)} URLs, {probes} probes, {len(findings)} findings")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
