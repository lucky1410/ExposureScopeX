from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import os
import re
import signal
import socket
import ssl
import tempfile
import xml.etree.ElementTree as ET
from contextlib import suppress
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from uuid import UUID
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .artifact_store import artifact_path, persist_bytes, persist_json
from .config import settings
from .db import pool
from .evidence_capture import authenticated_context, capture_page, close_context, enforce_browser_scope, safe_route, same_origin
from .methodology_cases import canonical_observation_key, evaluate_evidence_oracle
from .nuclei_validation import evaluate_nuclei_replay, has_safe_replay_oracle
from .nuclei_profiles import inventory_manifest, maximum_template_count, selection_arguments
from .secrets import decrypt_secret
from .redaction import redact_object, redact_text
from .target_planning import canonical_http_url, nuclei_targets
from .scope_files import path_is_in_scope, scope_dispatch_error


SECURITY_HEADERS = {
    "content-security-policy": ("Response observation: Content-Security-Policy header absent", "info", "Define and test a restrictive Content-Security-Policy before enforcement."),
    "strict-transport-security": ("Response observation: Strict-Transport-Security header absent", "info", "Serve exclusively over HTTPS and configure an approved Strict-Transport-Security policy."),
    "x-content-type-options": ("Response observation: X-Content-Type-Options header absent", "info", "Set X-Content-Type-Options: nosniff on applicable responses."),
    "x-frame-options": ("Response observation: X-Frame-Options header absent", "info", "Define CSP frame-ancestors and retain X-Frame-Options for legacy clients where required."),
    "referrer-policy": ("Response observation: Referrer-Policy header absent", "info", "Set an explicit Referrer-Policy aligned with application navigation requirements."),
}

PROFILE_POLICY = {
    "light": {
        "nmap": ["-p", "80,443,3000,3001,8000,8001,8080,8443"],
        "nmap_label": "fixed-common-web-ports",
        "nmap_host_timeout": "120s",
        "subdomain_limit": 100,
        "crawl_depth": 2, "crawl_urls": 25, "screenshots": 12, "surface_urls": 20,
        "nuclei_urls": 1, "rate": 2, "concurrency": 1, "bulk": 1,
    },
    "medium": {
        "nmap": ["--top-ports", "100"],
        "nmap_label": "top-100-tcp-ports",
        "nmap_host_timeout": "240s",
        "crawl_depth": 3, "crawl_urls": 100, "screenshots": 30, "surface_urls": 50,
        "nuclei_urls": 100, "rate": 40, "concurrency": 10, "bulk": 10,
    },
    "aggressive": {
        "nmap": ["--top-ports", "1000"],
        "nmap_label": "top-1000-tcp-ports",
        "nmap_host_timeout": "600s",
        "crawl_depth": 5, "crawl_urls": 300, "screenshots": 75, "surface_urls": 150,
        "nuclei_urls": 300, "rate": 75, "concurrency": 20, "bulk": 20,
    },
}


def profile_policy(stage: dict) -> tuple[str, dict]:
    mode = str(stage.get("mode") or "light")
    if mode not in PROFILE_POLICY:
        raise RuntimeError(f"Unsupported assessment profile: {mode}")
    return mode, PROFILE_POLICY[mode]


def route_is_in_scope(stage: dict, url: str) -> bool:
    scope = dict(stage["scope"]) if stage.get("scope") else None
    return same_origin(stage["target"], url) and safe_route(url) and path_is_in_scope(url, scope)


def _has_primary_nonvisual_evidence(evidence: dict, source_payload: object | None) -> bool:
    """Return True when a finding can stand on request/response or source metadata alone."""
    if evidence.get("request") or evidence.get("response"):
        return True
    if not isinstance(source_payload, dict):
        return False
    request = source_payload.get("request")
    headers = source_payload.get("headers")
    return bool(
        isinstance(request, dict) and request.get("url")
        or isinstance(headers, dict) and source_payload.get("status") is not None
    )


def _screenshot_failure_blocks_finding(evidence: dict, source_payload: object | None) -> bool:
    return bool(evidence.get("requires_screenshot")) and not _has_primary_nonvisual_evidence(evidence, source_payload)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ScopedRedirectHandler(HTTPRedirectHandler):
    def __init__(self, original_url: str):
        self.original_url = original_url

    def redirect_request(self, request, fp, code, message, headers, new_url):
        original, redirected = urlsplit(self.original_url), urlsplit(new_url)
        original_port = original.port or (443 if original.scheme == "https" else 80)
        redirected_port = redirected.port or (443 if redirected.scheme == "https" else 80)
        if (
            redirected.scheme not in {"http", "https"}
            or redirected.scheme != original.scheme
            or redirected.hostname != original.hostname
            or redirected_port != original_port
            or redirected.username
            or redirected.password
        ):
            raise RuntimeError(f"Cross-origin redirect blocked: {new_url}")
        return super().redirect_request(request, fp, code, message, headers, new_url)


async def load_authentication(assessment_id) -> dict | None:
    row = await pool().fetchrow("SELECT * FROM assessment_authentication WHERE assessment_id = $1", assessment_id)
    if row is None:
        return None
    return {
        "login_url": row["login_url"],
        "username": decrypt_secret(bytes(row["username_ciphertext"])),
        "password": decrypt_secret(bytes(row["password_ciphertext"])),
        "username_selector": row["username_selector"],
        "password_selector": row["password_selector"],
        "submit_selector": row["submit_selector"],
    }


def _public_cookie_metadata(headers) -> list[dict]:
    """Preserve cookie controls without retaining cookie values in evidence."""
    cookies = []
    for value in headers.get_all("Set-Cookie", []):
        parts = [part.strip() for part in value.split(";") if part.strip()]
        if not parts or "=" not in parts[0]:
            continue
        name = parts[0].split("=", 1)[0][:160]
        attributes = {part.split("=", 1)[0].strip().lower() for part in parts[1:]}
        same_site = next((part.split("=", 1)[1].strip().lower() for part in parts[1:] if part.lower().startswith("samesite=")), None)
        cookies.append({"name": name, "secure": "secure" in attributes, "http_only": "httponly" in attributes, "same_site": same_site})
    return cookies


def fetch_url(url: str, *, request_headers: dict[str, str] | None = None) -> dict:
    headers = {"User-Agent": "ExposureScopeX/3.0 deterministic-assessment"}
    headers.update(request_headers or {})
    request = Request(url, headers=headers, method="GET")
    try:
        response = build_opener(ScopedRedirectHandler(url)).open(request, timeout=settings().request_timeout_seconds)
    except HTTPError as exc:
        response = exc
    with response:
        body = response.read(512 * 1024)
        return {
            "request": {
                "method": "GET",
                "url": url,
                "headers": {key.lower(): value for key, value in headers.items()},
            },
            "requested_url": url, "final_url": response.geturl(), "status": response.status,
            "headers": {key.lower(): value for key, value in response.headers.items() if key.lower() != "set-cookie"},
            "set_cookies": _public_cookie_metadata(response.headers),
            "body_preview": body[:8192].decode("utf-8", errors="replace"),
            "body_sha256": hashlib.sha256(body).hexdigest(), "body_truncated": len(body) >= 512 * 1024,
            "observed_at": utcnow().isoformat(),
        }


def _certificate_transparency_names(payload: object, hostname: str, limit: int) -> list[str]:
    """Return only descendant FQDNs from a crt.sh response, without probing them."""
    if not isinstance(payload, list):
        raise ValueError("Certificate-transparency response was not a JSON array")
    hostname = hostname.lower().rstrip(".")
    discovered: set[str] = set()
    for record in payload:
        if not isinstance(record, dict):
            continue
        names = str(record.get("name_value") or "").splitlines()
        for raw_name in names:
            name = raw_name.strip().lower().rstrip(".")
            if (
                name.startswith("*.")
                or name == hostname
                or not name.endswith("." + hostname)
                or len(name) > 253
                or not all(label and len(label) <= 63 and re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in name.split("."))
            ):
                continue
            discovered.add(name)
    return sorted(discovered)[:limit]


def _passive_certificate_transparency(hostname: str, limit: int) -> dict:
    """Fetch a bounded CT inventory from a fixed public source without host validation."""
    try:
        ipaddress.ip_address(hostname)
        return {"status": "not_applicable", "reason": "The target is an IP address, not a domain name.", "subdomains": []}
    except ValueError:
        pass
    if "." not in hostname:
        return {"status": "not_applicable", "reason": "The target is not a fully-qualified domain name.", "subdomains": []}
    query = urlencode({"q": f"%.{hostname}", "output": "json"})
    url = f"https://crt.sh/?{query}"
    request = Request(url, headers={"Accept": "application/json", "User-Agent": "ExposureScopeX/3.0 passive-subdomain-inventory"}, method="GET")
    try:
        with build_opener().open(request, timeout=45) as response:
            content = response.read(2_097_153)
    except HTTPError as exc:
        return {"status": "unavailable", "reason": f"Certificate-transparency source returned HTTP {exc.code}.", "subdomains": [], "source": "crt.sh"}
    except (URLError, TimeoutError, OSError) as exc:
        return {"status": "unavailable", "reason": f"Certificate-transparency source could not be reached: {type(exc).__name__}.", "subdomains": [], "source": "crt.sh"}
    if len(content) > 2_097_152:
        return {"status": "unavailable", "reason": "Certificate-transparency response exceeded the 2 MB safety limit.", "subdomains": [], "source": "crt.sh"}
    try:
        records = json.loads(content.decode("utf-8"))
        subdomains = _certificate_transparency_names(records, hostname, limit)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        return {"status": "unavailable", "reason": f"Certificate-transparency response could not be parsed: {type(exc).__name__}.", "subdomains": [], "source": "crt.sh"}
    return {
        "status": "completed",
        "source": "crt.sh",
        "query": url,
        "subdomains": subdomains,
        "discovered_count": len(subdomains),
        "limit": limit,
        "limitations": "Passive certificate-transparency records only. Names were not resolved, reached, crawled, or scanned.",
    }


async def run_command(stage: dict, command: list[str], cwd: Path) -> tuple[int, str]:
    from .runner import ScanCancellationRequested, scan_cancel_requested
    process = await asyncio.create_subprocess_exec(
        *command, cwd=cwd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
        start_new_session=True,
    )
    lines: list[str] = []

    async def publish_output(output_lines: list[str]) -> None:
        if not output_lines:
            return
        chunk = redact_text("".join(output_lines))
        await pool().execute(
            """
            UPDATE stage_runs
            SET live_output = right(live_output || $2, 16000),
                last_output_at = now(), output_sequence = output_sequence + 1
            WHERE id = $1 AND status = 'running'
            """,
            stage["id"],
            chunk,
        )

    async def read_output() -> None:
        assert process.stdout is not None
        pending: list[str] = []
        last_publish = asyncio.get_running_loop().time()
        while line := await process.stdout.readline():
            decoded = line.decode("utf-8", errors="replace")
            lines.append(decoded)
            pending.append(decoded)
            now = asyncio.get_running_loop().time()
            if len(pending) >= 25 or now - last_publish >= 1:
                await publish_output(pending)
                pending.clear()
                last_publish = now
        await publish_output(pending)

    await publish_output([f"$ {redact_text(' '.join(command))}\n"])
    reader = asyncio.create_task(read_output())
    deadline = asyncio.get_running_loop().time() + max(1, int(stage["timeout_seconds"]))

    async def terminate() -> None:
        if process.returncode is not None:
            return
        with suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGTERM)
        try:
            await asyncio.wait_for(process.wait(), timeout=5)
        except TimeoutError:
            with suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            await process.wait()

    try:
        while process.returncode is None:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                await terminate()
                raise TimeoutError("Tool process exceeded its configured stage deadline")
            if await scan_cancel_requested(stage["scan_id"]):
                await publish_output(["[esx] cancellation requested by operator\n"])
                await terminate()
                raise ScanCancellationRequested("Operator requested cancellation during tool execution")
            try:
                await asyncio.wait_for(process.wait(), timeout=min(5, remaining))
            except TimeoutError:
                if asyncio.get_running_loop().time() >= deadline:
                    await terminate()
                    raise TimeoutError("Tool process exceeded its configured stage deadline")
                if await scan_cancel_requested(stage["scan_id"]):
                    await publish_output(["[esx] cancellation requested by operator\n"])
                    await terminate()
                    raise ScanCancellationRequested("Operator requested cancellation during tool execution")
                await pool().execute(
                    "UPDATE stage_runs SET heartbeat_at = now(), lease_expires_at = now() + interval '2 minutes' WHERE id = $1",
                    stage["id"],
                )
        await reader
    except BaseException:
        await terminate()
        reader.cancel()
        with suppress(asyncio.CancelledError):
            await reader
        raise
    return process.returncode or 0, "".join(lines)


async def scope_preflight(stage: dict) -> dict:
    scope = dict(stage["scope"]) if stage.get("scope") else None
    scope_error = scope_dispatch_error(scope, stage["target"])
    if scope_error:
        raise RuntimeError(scope_error)
    parsed = urlsplit(stage["target"])
    addresses = sorted({item[4][0] for item in await asyncio.to_thread(socket.getaddrinfo, parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM)})
    forbidden = []
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if ip.is_link_local or ip.is_multicast or ip.is_unspecified:
            forbidden.append(address)
    if forbidden:
        raise RuntimeError(f"Target resolves to prohibited address class: {', '.join(forbidden)}")
    payload = {"target": stage["target"], "scheme": parsed.scheme, "hostname": parsed.hostname, "port": parsed.port, "resolved_addresses": addresses, "scope_status": "authorized", "scope": scope, "observed_at": utcnow().isoformat()}
    await persist_json(stage, payload, kind="scope_manifest", name="scope-preflight.json")
    return {"command": "scope-policy validate [AUTHORIZED_TARGET]", "transcript": json.dumps(payload, indent=2)}


async def subdomain_enumeration(stage: dict) -> dict:
    """Record a passive CT-only descendant inventory for the exact target hostname."""
    mode, policy = profile_policy(stage)
    if mode != "light":
        raise RuntimeError("Passive subdomain enumeration is currently available only in the light profile")
    hostname = str(urlsplit(stage["target"]).hostname or "").lower()
    result = await asyncio.to_thread(_passive_certificate_transparency, hostname, int(policy["subdomain_limit"]))
    result.update({
        "target_hostname": hostname,
        "mode": mode,
        "observed_at": utcnow().isoformat(),
        "safety_policy": "passive CT only; no DNS resolution, HTTP requests, crawling, or port scanning of discovered names",
    })
    await persist_json(
        stage,
        redact_object(result),
        kind="passive_subdomain_inventory",
        name="passive-subdomains.json",
        metadata={"source": "crt.sh", "target_hostname": hostname, "mode": mode, "active_validation": False},
    )
    transcript = (
        f"Passive certificate-transparency subdomain inventory for {hostname}\n"
        f"Status: {result['status']}\n"
        f"Discovered descendants: {len(result['subdomains'])}\n"
        "No discovered name was resolved, reached, crawled, or scanned."
    )
    if result.get("reason"):
        transcript += f"\nReason: {result['reason']}"
    return {"command": "passive-ct-enumeration --source crt.sh --descendants-only", "transcript": transcript}


async def http_profile(stage: dict) -> dict:
    result = await asyncio.to_thread(fetch_url, stage["target"])
    await persist_json(stage, redact_object(result), kind="raw_tool_output", name="http-profile.json", metadata={"tool": "python-urllib", "target": stage["target"], "secret_redacted": True})
    transcript = f"HTTP profile for {stage['target']}\nStatus: {result['status']}\nFinal URL: {result['final_url']}\nHeaders:\n" + "\n".join(f"{key}: {value}" for key, value in result["headers"].items())
    return {"command": "http-profile --target [AUTHORIZED_TARGET]", "transcript": transcript}


async def tls_service_discovery(stage: dict) -> dict:
    mode, policy = profile_policy(stage)
    parsed = urlsplit(stage["target"])
    host = parsed.hostname
    assert host
    with tempfile.TemporaryDirectory(prefix="esx-nmap-") as temporary:
        directory = Path(temporary)
        xml_path = directory / "nmap.xml"
        nmap_scope = list(policy["nmap"])
        scope = dict(stage["scope"]) if stage.get("scope") else None
        if scope:
            nmap_scope = ["-p", ",".join(str(port) for port in scope["allowed_ports"])]
        if mode == "light" and parsed.port:
            configured = set(nmap_scope[1].split(","))
            configured.add(str(parsed.port))
            nmap_scope[1] = ",".join(sorted(configured, key=int))
        command = ["nmap", "-Pn", "-sT", "-sV", "--version-light", "--host-timeout", policy["nmap_host_timeout"], *nmap_scope, "-oX", str(xml_path), host]
        code, transcript = await run_command(stage, command, directory)
        if xml_path.exists():
            xml_artifact = await persist_bytes(stage, xml_path.read_bytes(), kind="raw_tool_output", name="nmap.xml", media_type="application/xml", metadata={"tool": "nmap", "profile": mode, "command_policy": policy["nmap_label"]})
            services = []
            root = ET.fromstring(xml_path.read_bytes())
            for port in root.findall(".//port"):
                state, service = port.find("state"), port.find("service")
                if state is not None and state.attrib.get("state") == "open":
                    services.append({"port": int(port.attrib["portid"]), "protocol": port.attrib.get("protocol"), "service": service.attrib.get("name") if service is not None else None, "product": service.attrib.get("product") if service is not None else None, "version": service.attrib.get("version") if service is not None else None})
            await persist_json(stage, {"host": host, "services": services, "source_artifact_id": str(xml_artifact["id"])}, kind="service_inventory", name="services.json")
        if code != 0:
            raise RuntimeError(f"Nmap exited with status {code}")

    tls_result = {"attempted": True, "certificate": None, "error": None}
    try:
        context = ssl.create_default_context()
        with await asyncio.to_thread(socket.create_connection, (host, parsed.port or 443), 10) as raw:
            with context.wrap_socket(raw, server_hostname=host) as secure:
                certificate = secure.getpeercert()
                tls_result["certificate"] = {"protocol": secure.version(), "cipher": secure.cipher(), "subject": certificate.get("subject"), "issuer": certificate.get("issuer"), "notBefore": certificate.get("notBefore"), "notAfter": certificate.get("notAfter")}
    except Exception as exc:
        if parsed.scheme == "https":
            tls_result["error"] = f"{type(exc).__name__}: {exc}"
    await persist_json(stage, tls_result, kind="tls_observation", name="tls.json", metadata={"tool": "python-ssl"})
    return {"command": f"nmap [{mode.upper()}_{policy['nmap_label'].upper()}] {host}; openssl-compatible TLS inspection", "transcript": transcript + "\n\nTLS observation:\n" + json.dumps(tls_result, indent=2, default=str)}


async def authenticated_crawl(stage: dict) -> dict:
    mode, policy = profile_policy(stage)
    auth = await load_authentication(stage["assessment_id"])
    playwright, browser, context, authentication = await authenticated_context(auth)
    await enforce_browser_scope(context, stage["target"])
    queue = [(stage["target"], 0)]
    visited: list[str] = []
    seen: set[str] = set()
    skipped_urls: list[dict[str, str]] = []
    screenshot_records = []
    try:
        while queue and len(visited) < policy["crawl_urls"]:
            url, depth = queue.pop(0)
            if url in seen or not route_is_in_scope(stage, url):
                continue
            seen.add(url)
            page = await context.new_page()
            try:
                try:
                    response = await page.goto(url, wait_until="domcontentloaded", timeout=30_000)
                except Exception as exc:
                    detail = redact_text(f"{type(exc).__name__}: {exc}")[:1000]
                    category = "download_or_non_document" if "Download is starting" in detail else "navigation_error"
                    skipped_urls.append({"url": url, "category": category, "detail": detail})
                    continue
                await page.wait_for_timeout(350)
                if not route_is_in_scope(stage, page.url):
                    skipped_urls.append({"url": url, "category": "out_of_scope_redirect", "detail": f"Browser navigation ended outside authorized scope: {page.url}"})
                    continue
                visited.append(url)
                if len(screenshot_records) < policy["screenshots"]:
                    image = await page.screenshot(full_page=True)
                    record = await persist_bytes(stage, image, kind="browser_screenshot", name=f"page-{len(screenshot_records)+1:03d}.png", media_type="image/png", metadata={"capture_type": "playwright_browser", "requested_url": url, "final_url": page.url, "http_status": response.status if response else None, "authenticated": authentication["verified"], "browser_engine": "chromium"})
                    screenshot_records.append({"artifact_id": str(record["id"]), "sha256": record["sha256"], "requested_url": url, "final_url": page.url})
                if depth < policy["crawl_depth"]:
                    links = await page.locator("a[href]").evaluate_all("els => els.map(e => e.href)")
                    for link in links:
                        normalized = str(link).split("#", 1)[0]
                        if normalized not in visited and route_is_in_scope(stage, normalized):
                            queue.append((normalized, depth + 1))
            finally:
                await page.close()
    finally:
        await close_context(playwright, browser, context)
    manifest = {"target": stage["target"], "profile": mode, "authentication": {key: value for key, value in authentication.items() if key != "login_url"}, "urls": visited, "skipped_urls": skipped_urls, "screenshots": screenshot_records, "limits": {"depth": policy["crawl_depth"], "urls": policy["crawl_urls"], "screenshots": policy["screenshots"]}, "excluded_route_terms": ["logout", "signout", "reset", "setup", "install", "delete", "remove"]}
    await persist_json(stage, manifest, kind="crawl_manifest", name="crawl-manifest.json", metadata={"tool": "playwright", "profile": mode, "authenticated": authentication["verified"]})
    if not visited:
        raise RuntimeError("Authenticated crawler could not load any in-scope document URL")
    skipped_summary = "\n".join(f"SKIPPED {item['category']}: {item['url']}" for item in skipped_urls)
    return {"command": f"playwright-crawl --same-origin --depth {policy['crawl_depth']} --limit {policy['crawl_urls']}", "transcript": f"Profile: {mode}\nAuthentication configured: {authentication['configured']}\nAuthentication verified: {authentication['verified']}\nCrawled {len(visited)} URLs\nSkipped {len(skipped_urls)} non-document or failed URLs\nCaptured {len(screenshot_records)} original screenshots\n" + "\n".join(visited) + ("\n" + skipped_summary if skipped_summary else "")}


async def standards_discovery(stage: dict) -> dict:
    paths = ["/robots.txt", "/sitemap.xml", "/.well-known/security.txt", "/.well-known/openid-configuration"]
    observations = []
    for suffix in paths:
        url = urljoin(stage["target"].rstrip("/") + "/", suffix.lstrip("/"))
        if not route_is_in_scope(stage, url):
            continue
        try:
            observations.append(await asyncio.to_thread(fetch_url, url))
        except Exception as exc:
            observations.append({"requested_url": url, "error": f"{type(exc).__name__}: {exc}", "observed_at": utcnow().isoformat()})
    await persist_json(stage, {"target": stage["target"], "observations": observations}, kind="standards_discovery", name="standards-discovery.json", metadata={"tool": "passive-http-discovery"})
    return {"command": "standards-discovery [ROBOTS_SITEMAP_SECURITY_OPENID]", "transcript": json.dumps(observations, indent=2)}


class _SurfaceParser(HTMLParser):
    """Extract inventory metadata only; this parser never submits or executes forms."""

    def __init__(self) -> None:
        super().__init__()
        self.forms: list[dict] = []
        self.scripts: list[str] = []
        self.meta: dict[str, str] = {}
        self._form: dict | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key.lower(): value or "" for key, value in attrs}
        if tag == "form":
            self._form = {"action": values.get("action", ""), "method": values.get("method", "get").lower(), "fields": []}
            self.forms.append(self._form)
        elif tag in {"input", "select", "textarea"} and self._form is not None:
            name = values.get("name")
            if name:
                self._form["fields"].append({"name": name, "type": values.get("type", tag)})
        elif tag == "script" and values.get("src"):
            self.scripts.append(values["src"])
        elif tag == "meta" and values.get("name"):
            self.meta[values["name"].lower()] = values.get("content", "")

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._form = None


async def _crawl_urls(stage: dict, limit: int) -> list[str]:
    row = await pool().fetchrow(
        "SELECT storage_key FROM artifacts WHERE scan_id = $1 AND kind = 'crawl_manifest' ORDER BY captured_at DESC LIMIT 1",
        stage["scan_id"],
    )
    if row is None:
        return [stage["target"]]
    payload = json.loads(artifact_path(row["storage_key"]).read_text(encoding="utf-8"))
    urls = [url for url in payload.get("urls", []) if isinstance(url, str) and route_is_in_scope(stage, url)]
    return (urls or [stage["target"]])[:limit]


async def application_surface_inventory(stage: dict) -> dict:
    mode, policy = profile_policy(stage)
    urls = await _crawl_urls(stage, int(policy["surface_urls"]))
    pages = []
    for url in urls:
        try:
            response = await asyncio.to_thread(fetch_url, url)
            parser = _SurfaceParser()
            parser.feed(str(response.get("body_preview") or ""))
            pages.append({
                "url": response["final_url"], "status": response["status"],
                "forms": parser.forms, "scripts": parser.scripts, "meta": parser.meta,
                "source_body_sha256": response["body_sha256"],
            })
        except Exception as exc:
            pages.append({"url": url, "error": f"{type(exc).__name__}: {exc}"})
    payload = {"target": stage["target"], "profile": mode, "request_method": "GET", "submitted_forms": False, "pages": pages}
    await persist_json(stage, payload, kind="application_surface_inventory", name="application-surface-inventory.json", metadata={"tool": "stdlib-html-parser", "profile": mode, "url_limit": len(urls)})
    form_count = sum(len(page.get("forms", [])) for page in pages)
    script_count = sum(len(page.get("scripts", [])) for page in pages)
    return {"command": f"application-surface-inventory --get-only --limit {len(urls)}", "transcript": f"Profile: {mode}\nInspected {len(urls)} crawled routes using GET only\nRecorded {form_count} forms and {script_count} external scripts\nNo forms, payloads, or state-changing requests were submitted."}


async def authenticated_session_review(stage: dict) -> dict:
    auth = await load_authentication(stage["assessment_id"])
    if auth is None:
        payload = {"target": stage["target"], "authentication_configured": False, "status": "not_applicable", "reason": "No supplied authenticated role is available for session review."}
        await persist_json(stage, payload, kind="session_review", name="session-review.json")
        return {"command": "session-cookie-review --authentication [NOT_CONFIGURED]", "transcript": json.dumps(payload, indent=2)}
    playwright, browser, context, authentication = await authenticated_context(auth)
    try:
        cookies = await context.cookies()
    finally:
        await close_context(playwright, browser, context)
    safe_cookies = [{key: cookie.get(key) for key in ("name", "domain", "path", "secure", "httpOnly", "sameSite", "expires")} for cookie in cookies]
    payload = {"target": stage["target"], "authentication": {key: value for key, value in authentication.items() if key != "login_url"}, "cookies": safe_cookies}
    source = await persist_json(stage, payload, kind="session_review", name="session-review.json", metadata={"tool": "playwright", "authenticated": authentication["verified"]})
    created = 0
    target_https = urlsplit(stage["target"]).scheme == "https"
    for cookie in safe_cookies:
        name = str(cookie["name"])
        session_like = any(token in name.lower() for token in ("session", "sess", "auth", "token", "php"))
        for control, absent, severity, remediation in (
            ("HttpOnly", session_like and not bool(cookie["httpOnly"]), "medium", "Set the session cookie HttpOnly attribute so browser scripts cannot read it."),
            ("Secure", session_like and target_https and not bool(cookie["secure"]), "medium", "Set the session cookie Secure attribute for HTTPS deployments."),
        ):
            if not absent:
                continue
            fingerprint = hashlib.sha256(f"{stage['target']}|session-cookie|{name}|{control}".encode()).hexdigest()
            evidence = {"evidence_type": "session_cookie_control", "cookie_name": name, "control": control, "source_artifact_id": str(source["id"]), "source_sha256": source["sha256"], "observed_at": utcnow().isoformat(), "requires_screenshot": False}
            status = await pool().execute(
                """INSERT INTO findings (scan_id, stage_run_id, source_artifact_id, fingerprint, title, severity, confidence, target, description, business_impact, remediation, evidence)
                   VALUES ($1,$2,$3,$4,$5,$6,90,$7,$8,$9,$10,$11::jsonb) ON CONFLICT (scan_id, fingerprint) DO NOTHING""",
                stage["scan_id"], stage["id"], source["id"], fingerprint, f"Session cookie {control} protection is missing", severity, stage["target"], f"The authenticated browser context observed session-like cookie {name!r} without the {control} attribute.", "A browser-accessible or transport-permissive session cookie can increase session exposure where a compatible attack path exists.", remediation, evidence,
            )
            created += status.endswith("1")
    return {"command": "session-cookie-review --authenticated-browser-context", "transcript": f"Authentication verified: {authentication['verified']}\nObserved {len(safe_cookies)} cookies\nCreated {created} evidence-linked cookie-control findings."}


async def api_contract_review(stage: dict) -> dict:
    paths = ["/openapi.json", "/swagger.json", "/v3/api-docs", "/api-docs", "/.well-known/openapi"]
    contracts = []
    for suffix in paths:
        url = urljoin(stage["target"].rstrip("/") + "/", suffix.lstrip("/"))
        if not route_is_in_scope(stage, url):
            continue
        try:
            response = await asyncio.to_thread(fetch_url, url)
            parsed = json.loads(response.get("body_preview") or "{}")
            if isinstance(parsed, dict) and (parsed.get("openapi") or parsed.get("swagger")):
                contracts.append({"url": response["final_url"], "status": response["status"], "specification": parsed.get("openapi") or parsed.get("swagger"), "path_count": len(parsed.get("paths") or {}), "security_schemes": sorted((parsed.get("components") or {}).get("securitySchemes", {}).keys()), "body_sha256": response["body_sha256"]})
        except Exception:
            continue
    payload = {"target": stage["target"], "request_method": "GET", "contracts": contracts, "tested_paths": paths}
    await persist_json(stage, payload, kind="api_contract_review", name="api-contract-review.json", metadata={"tool": "safe-http-contract-discovery"})
    return {"command": "api-contract-review --get-only [OPENAPI_SWAGGER_COMMON_PATHS]", "transcript": f"Tested {len(paths)} conventional contract locations with GET only\nIdentified {len(contracts)} published API contract(s)\nNo API operations were invoked."}


async def route_security_policy_review(stage: dict) -> dict:
    mode, policy = profile_policy(stage)
    urls = await _crawl_urls(stage, int(policy["surface_urls"]))
    observations = []
    for url in urls:
        try:
            response = await asyncio.to_thread(fetch_url, url)
            observed = set(response["headers"])
            observations.append({"url": response["final_url"], "status": response["status"], "missing_headers": sorted(header for header in SECURITY_HEADERS if header not in observed), "body_sha256": response["body_sha256"]})
        except Exception as exc:
            observations.append({"url": url, "error": f"{type(exc).__name__}: {exc}"})
    payload = {"target": stage["target"], "profile": mode, "request_method": "GET", "submitted_forms": False, "routes": observations}
    await persist_json(stage, payload, kind="route_security_policy_review", name="route-security-policy-review.json", metadata={"tool": "safe-http-policy-review", "url_limit": len(urls)})
    completed = sum("status" in item for item in observations)
    return {"command": f"route-security-policy-review --get-only --limit {len(urls)}", "transcript": f"Reviewed HTTP policy-header consistency across {completed}/{len(urls)} approved routes using GET only. No forms, payloads, or state-changing requests were submitted."}


async def _matching_screenshot(stage: dict, url: str):
    return await pool().fetchrow(
        """SELECT id, sha256, storage_key FROM artifacts WHERE scan_id = $1 AND kind = 'browser_screenshot'
           AND metadata->>'final_url' = $2 ORDER BY captured_at DESC LIMIT 1""",
        stage["scan_id"], url,
    )


async def security_headers(stage: dict) -> dict:
    result = await asyncio.to_thread(fetch_url, stage["target"])
    source = await persist_json(stage, redact_object(result), kind="raw_tool_output", name="security-headers.json", metadata={"tool": "header-audit", "secret_redacted": True})
    screenshot = await _matching_screenshot(stage, result["final_url"]) or await _matching_screenshot(stage, stage["target"])
    created = 0
    for header, (title, severity, remediation) in SECURITY_HEADERS.items():
        if header in result["headers"] or (header == "strict-transport-security" and urlsplit(stage["target"]).scheme != "https"):
            continue
        # CSP frame-ancestors is the modern, equivalent framing control. Do not
        # report a legacy X-Frame-Options absence as a finding when it is present.
        if header == "x-frame-options" and "frame-ancestors" in result["headers"].get("content-security-policy", "").lower():
            continue
        fingerprint = hashlib.sha256(f"{stage['target']}|headers|{header}".encode()).hexdigest()
        evidence = {
            "evidence_type": "http_response_header_absence",
            "header_name": header,
            "observed_header_names": sorted(result["headers"]),
            "source_artifact_id": str(source["id"]),
            "source_sha256": source["sha256"],
            "requested_url": result["requested_url"],
            "final_url": result["final_url"],
            "coverage_scope": "single_response",
            "coverage_target": result["final_url"],
            "status": result["status"],
            "observed_at": result["observed_at"],
            "requires_screenshot": False,
            "screenshot_role": "contextual_browser_capture",
            "screenshot_artifact_id": str(screenshot["id"]) if screenshot else None,
            "screenshot_sha256": screenshot["sha256"] if screenshot else None,
        }
        status = await pool().execute(
            """INSERT INTO findings (scan_id, stage_run_id, source_artifact_id, fingerprint, title, severity, confidence, target, description, business_impact, remediation, evidence)
               VALUES ($1,$2,$3,$4,$5,$6,95,$7,$8,$9,$10,$11::jsonb) ON CONFLICT (scan_id, fingerprint) DO NOTHING""",
            stage["scan_id"], stage["id"], source["id"], fingerprint, title, severity, stage["target"], f"The {header} response header was absent from the observed response.", "A missing browser security policy can increase the impact of compatible client-side attacks or disclose navigation context. Actual impact depends on application behavior and compensating controls.", remediation, evidence,
        )
        created += status.endswith("1")
    return {"command": "security-header-audit [AUTHORIZED_TARGET]", "transcript": f"Inspected {len(SECURITY_HEADERS)} security headers\nCreated {created} evidence-linked findings\nHTTP status {result['status']}"}


async def external_web_posture(stage: dict) -> dict:
    """Check public browser-facing policy without using credentials or request bodies."""
    probe_origin = "https://esx-cors-probe.invalid"
    result = await asyncio.to_thread(fetch_url, stage["target"], request_headers={"Origin": probe_origin})
    headers = result["headers"]
    allow_origin = str(headers.get("access-control-allow-origin") or "").strip()
    allow_credentials = str(headers.get("access-control-allow-credentials") or "").strip().lower() == "true"
    source = await persist_json(
        stage,
        redact_object(result),
        kind="external_web_posture",
        name="external-web-posture.json",
        metadata={"tool": "safe-cors-and-cookie-review", "request_method": "GET", "probe_origin": probe_origin, "secret_redacted": True},
    )
    created = 0

    async def add_finding(title: str, severity: str, fingerprint_key: str, description: str, impact: str, remediation: str, evidence: dict) -> None:
        nonlocal created
        fingerprint = hashlib.sha256(f"{stage['target']}|external-web-posture|{fingerprint_key}".encode()).hexdigest()
        status = await pool().execute(
            """INSERT INTO findings (scan_id, stage_run_id, source_artifact_id, fingerprint, title, severity, confidence, target, description, business_impact, remediation, evidence)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb) ON CONFLICT (scan_id, fingerprint) DO NOTHING""",
            stage["scan_id"], stage["id"], source["id"], fingerprint, title, severity, 90, stage["target"], description, impact, remediation, evidence,
        )
        created += status.endswith("1")

    evidence_base = {
        "source_artifact_id": str(source["id"]), "source_sha256": source["sha256"],
        "requested_url": result["requested_url"], "final_url": result["final_url"],
        "status": result["status"], "observed_at": result["observed_at"], "requires_screenshot": False,
    }
    if allow_origin == probe_origin and allow_credentials:
        await add_finding(
            "Credentialed CORS accepted an arbitrary origin", "high", "credentialed-cors-reflection",
            "The target reflected the controlled arbitrary Origin value and allowed credentialed browser requests.",
            "A user with an active compatible session could expose cross-origin responses to an attacker-controlled website.",
            "Restrict Access-Control-Allow-Origin to approved origins and do not enable credentials for untrusted origins.",
            {**evidence_base, "evidence_type": "credentialed_cors_reflection", "probe_origin": probe_origin, "allow_origin": allow_origin, "allow_credentials": True},
        )
    for cookie in result["set_cookies"]:
        name = str(cookie["name"])
        session_like = any(token in name.lower() for token in ("session", "sess", "auth", "token", "php"))
        if not session_like:
            continue
        for control, missing, severity, remediation in (
            ("Secure", urlsplit(result["final_url"]).scheme == "https" and not cookie["secure"], "medium", "Set the Secure attribute on session-like cookies issued over HTTPS."),
            ("HttpOnly", not cookie["http_only"], "medium", "Set the HttpOnly attribute unless the cookie is intentionally designed for script access."),
        ):
            if missing:
                await add_finding(
                    f"Publicly issued session-like cookie lacks {control}", severity, f"cookie-{name}-{control.lower()}",
                    f"The unauthenticated response issued cookie {name!r} without the {control} attribute.",
                    "Cookie exposure can increase the impact of compatible browser or transport attack paths.",
                    remediation,
                    {**evidence_base, "evidence_type": "public_cookie_control", "cookie": cookie, "control": control},
                )
    payload = {
        "target": stage["target"], "probe_origin": probe_origin, "allow_origin": allow_origin or None,
        "allow_credentials": allow_credentials, "public_cookies": result["set_cookies"], "finding_count": created,
        "limitations": "One GET-only response using a controlled Origin header. No credentials, preflight requests, payloads, forms, or state-changing operations were sent.",
    }
    await persist_json(stage, payload, kind="external_web_posture_summary", name="external-web-posture-summary.json", metadata={"tool": "safe-cors-and-cookie-review"})
    return {"command": "external-web-posture --get-only --controlled-origin", "transcript": json.dumps(payload, indent=2)}


def _yaml_quote(value: str) -> str:
    return json.dumps(value)


async def _nuclei_secret_file(auth: dict, path: Path) -> None:
    playwright, browser, context, authentication = await authenticated_context(auth)
    try:
        cookies = await context.cookies()
    finally:
        await close_context(playwright, browser, context)
    if not authentication["verified"]:
        raise RuntimeError("Authenticated Nuclei session could not be established")
    host = urlsplit(auth["login_url"]).hostname
    lines = ["static:", "  - type: cookie", "    domains:", f"      - {_yaml_quote(host or '')}", "    cookies:"]
    for cookie in cookies:
        lines.extend([f"      - key: {_yaml_quote(cookie['name'])}", f"        value: {_yaml_quote(cookie['value'])}"])
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    path.chmod(0o600)


async def nuclei_baseline(stage: dict) -> dict:
    mode, policy = profile_policy(stage)
    auth = await load_authentication(stage["assessment_id"])
    crawl = await pool().fetchrow("SELECT storage_key FROM artifacts WHERE scan_id = $1 AND kind = 'crawl_manifest' ORDER BY captured_at DESC LIMIT 1", stage["scan_id"])
    discovered_urls: list[str] = []
    if crawl:
        payload = json.loads(artifact_path(crawl["storage_key"]).read_text(encoding="utf-8"))
        discovered_urls.extend(payload.get("urls") or [])
    # Light does not turn crawl output or redirect destinations into scanner targets.
    urls = [canonical_http_url(stage["target"])] if mode == "light" else nuclei_targets(stage["target"], discovered_urls)[:policy["nuclei_urls"]]
    with tempfile.TemporaryDirectory(prefix="esx-nuclei-") as temporary:
        directory = Path(temporary)
        targets = directory / "targets.txt"
        results = directory / "results.jsonl"
        targets.write_text("\n".join(urls) + "\n", encoding="utf-8")
        selection = selection_arguments(mode, settings().nuclei_templates_dir)
        template_signature_policy = [] if mode == "light" else ["-disable-unsigned-templates"]
        inventory_command = [
            "nuclei", *selection, "-tl", "-no-color",
            "-disable-update-check", *template_signature_policy,
        ]
        inventory_code, inventory_output = await run_command(stage, inventory_command, directory)
        template_paths = [
            line.strip() for line in inventory_output.splitlines()
            if line.strip().lower().endswith((".yaml", ".yml"))
        ]
        inventory = inventory_manifest(mode, template_paths)
        await persist_json(
            stage,
            inventory,
            kind="nuclei_template_inventory",
            name=f"nuclei-{mode}-template-inventory.json",
            metadata={
                "profile": mode,
                "template_release": inventory["template_release"],
                "selected_template_count": inventory["selected_template_count"],
            },
        )
        if inventory_code != 0:
            raise RuntimeError(f"Nuclei template inventory failed with status {inventory_code}: {inventory_output[-1000:]}")
        if not template_paths:
            raise RuntimeError("Nuclei profile resolved zero templates; refusing to claim coverage")
        if (maximum := maximum_template_count(mode)) is not None and len(template_paths) > maximum:
            raise RuntimeError(f"Light Nuclei profile resolved {len(template_paths)} templates; policy permits at most {maximum}")
        command = [
            "nuclei", "-list", str(targets), *selection,
            "-jsonl-export", str(results), "-include-rr", "-timestamp", "-no-color",
            "-stats", "-stats-json", "-stats-interval", "5", "-rate-limit", str(policy["rate"]),
            "-concurrency", str(policy["concurrency"]), "-bulk-size", str(policy["bulk"]),
            "-disable-update-check", *template_signature_policy,
            "-scan-strategy", "host-spray", "-project", "-project-path", str(directory / "project"),
        ]
        display_command = f"nuclei -list targets.txt [{mode.upper()}_PROFILE_{inventory['selected_template_count']}_VERSIONED_TEMPLATES] -scan-strategy host-spray -project -jsonl-export results.jsonl -stats-json"
        secret = directory / "auth-secrets.yaml"
        if auth:
            await _nuclei_secret_file(auth, secret)
            command.extend(["-secret-file", str(secret)])
            display_command += " -secret-file [REDACTED_EPHEMERAL_FILE]"
        code, transcript = await run_command(stage, command, directory)
        output = results.read_bytes() if results.exists() else b""
        parsed = []
        discarded_out_of_scope = 0
        for line in output.decode("utf-8", errors="replace").splitlines():
            try:
                item = redact_object(json.loads(line))
            except json.JSONDecodeError:
                continue
            matched_raw = str(item.get("matched-at") or item.get("host") or stage["target"])
            matched = canonical_http_url(matched_raw) if matched_raw.startswith(("http://", "https://")) else canonical_http_url(stage["target"])
            if not route_is_in_scope(stage, matched):
                discarded_out_of_scope += 1
                continue
            parsed.append(item)
        safe_output = ("\n".join(json.dumps(item, sort_keys=True) for item in parsed) + ("\n" if parsed else "")).encode("utf-8")
        source = await persist_bytes(stage, safe_output, kind="raw_tool_output", name="nuclei-results.jsonl", media_type="application/x-ndjson", metadata={"tool": "nuclei", "profile": mode, "policy": "versioned-get-only-light-allowlist" if mode == "light" else "profile-bounded-non-intrusive", "template_release": inventory["template_release"], "template_set_sha256": inventory["template_set_sha256"], "selected_template_count": inventory["selected_template_count"], "target_count": len(urls), "rate_limit": policy["rate"], "concurrency": policy["concurrency"], "discarded_out_of_scope_results": discarded_out_of_scope, "exit_code": code, "secret_redacted": True})
        screenshots: dict[str, dict] = {}
        if parsed:
            playwright, browser, context, authentication = await authenticated_context(auth)
            await enforce_browser_scope(context, stage["target"])
            try:
                for item in parsed[:25]:
                    matched_raw = str(item.get("matched-at") or item.get("host") or stage["target"])
                    url = canonical_http_url(matched_raw) if matched_raw.startswith(("http://", "https://")) else canonical_http_url(stage["target"])
                    if url in screenshots or not route_is_in_scope(stage, url):
                        continue
                    try:
                        image, metadata = await capture_page(context, url, stage["target"])
                        record = await persist_bytes(stage, image, kind="finding_screenshot", name=f"nuclei-finding-{len(screenshots)+1:03d}.png", media_type="image/png", metadata={**metadata, "authenticated": authentication["verified"], "source_artifact_id": str(source["id"])})
                        screenshots[url] = {**record, "final_url": metadata["final_url"]}
                    except Exception:
                        continue
            finally:
                await close_context(playwright, browser, context)
        created = 0
        for item in parsed:
            info = item.get("info") or {}
            template_id = str(item.get("template-id") or item.get("templateID") or "nuclei-observation")
            matched_raw = str(item.get("matched-at") or item.get("host") or stage["target"])
            matched = canonical_http_url(matched_raw) if matched_raw.startswith(("http://", "https://")) else canonical_http_url(stage["target"])
            url = matched
            screenshot = screenshots.get(url)
            fingerprint = hashlib.sha256(f"{stage['target']}|nuclei|{template_id}|{matched}".encode()).hexdigest()
            severity = str(info.get("severity") or "info").lower()
            if severity not in {"critical", "high", "medium", "low", "info"}:
                severity = "info"
            references = info.get("reference") or []
            remediation = str(info.get("remediation") or "Validate the affected component and apply the vendor or configuration remediation associated with the referenced template.")
            if screenshot and not route_is_in_scope(stage, str(screenshot.get("final_url") or "")):
                screenshot = None
            evidence = {
                "source_artifact_id": str(source["id"]),
                "source_sha256": source["sha256"],
                "template_id": template_id,
                "matcher_name": item.get("matcher-name"),
                "matched_at": matched,
                "scanner_matched_at_raw": matched_raw if matched_raw != matched else None,
                "request": item.get("request"),
                "response": item.get("response"),
                "references": references,
                "requires_screenshot": False,
                "screenshot_role": "contextual_browser_capture" if screenshot else None,
                "screenshot_artifact_id": str(screenshot["id"]) if screenshot else None,
                "screenshot_sha256": screenshot["sha256"] if screenshot else None,
                "observed_at": item.get("timestamp") or utcnow().isoformat(),
            }
            status = await pool().execute(
                """INSERT INTO findings (scan_id, stage_run_id, source_artifact_id, fingerprint, title, severity, confidence, target, description, business_impact, remediation, evidence)
                   VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb) ON CONFLICT (scan_id, fingerprint) DO NOTHING""",
                stage["scan_id"], stage["id"], source["id"], fingerprint, str(info.get("name") or template_id), severity, 90 if item.get("matcher-name") else 80, matched, str(info.get("description") or f"Nuclei template {template_id} matched the target."), f"The observed {severity}-severity condition may affect the confidentiality, integrity, or availability of the identified asset. Client context is required before assigning business risk.", remediation, evidence,
            )
            created += status.endswith("1")
        if code != 0:
            raise RuntimeError(f"Nuclei exited with status {code}: {transcript[-1000:]}")
        return {"command": display_command, "transcript": transcript + f"\nExecuted versioned {mode} inventory containing {inventory['selected_template_count']} templates against {len(urls)} declared target(s).\nIngested {created} findings from {len(parsed)} in-scope JSONL results; discarded {discarded_out_of_scope} out-of-scope result(s).\n"}


async def evidence_validation(stage: dict) -> dict:
    rows = await pool().fetch(
        """SELECT f.id, f.title, f.evidence, ar.storage_key, ar.sha256
           FROM findings f JOIN artifacts ar ON ar.id = f.source_artifact_id WHERE f.scan_id = $1""",
        stage["scan_id"],
    )
    failures = []
    verified = 0
    confirmed = 0
    candidates = 0
    rejected = 0
    for row in rows:
        path = artifact_path(row["storage_key"])
        finding_failures = []
        source_payload = None
        if not path.is_file():
            finding_failures.append("source artifact missing")
        else:
            source_bytes = path.read_bytes()
            if hashlib.sha256(source_bytes).hexdigest() != row["sha256"]:
                finding_failures.append("source artifact hash mismatch")
            try:
                source_payload = json.loads(source_bytes)
            except (json.JSONDecodeError, UnicodeDecodeError):
                source_payload = None
        evidence = row["evidence"] or {}
        if evidence.get("requires_screenshot") or evidence.get("screenshot_artifact_id"):
            screenshot_id = evidence.get("screenshot_artifact_id")
            try:
                screenshot_uuid = UUID(screenshot_id) if screenshot_id else None
            except ValueError:
                screenshot_uuid = None
            screenshot = await pool().fetchrow("SELECT storage_key, sha256, metadata FROM artifacts WHERE id = $1", screenshot_uuid) if screenshot_uuid else None
            screenshot_failure = None
            if not screenshot:
                screenshot_failure = "required original screenshot missing"
            else:
                screenshot_path = artifact_path(screenshot["storage_key"])
                if not screenshot_path.is_file() or hashlib.sha256(screenshot_path.read_bytes()).hexdigest() != screenshot["sha256"]:
                    screenshot_failure = "screenshot hash verification failed"
                elif not route_is_in_scope(stage, str((screenshot["metadata"] or {}).get("final_url") or "")):
                    screenshot_failure = "screenshot final URL is outside the authorized scope"
            if screenshot_failure and _screenshot_failure_blocks_finding(evidence, source_payload):
                finding_failures.append(screenshot_failure)
        oracle_status, oracle_rationale = evaluate_evidence_oracle(evidence, source_payload)
        validation_artifact_id = None
        template_id = str(evidence.get("template_id") or "")
        matched_url = str(evidence.get("matched_at") or "")
        if (
            not finding_failures
            and oracle_status == "not_evaluated"
            and has_safe_replay_oracle(template_id)
            and matched_url.startswith(("http://", "https://"))
            and route_is_in_scope(stage, matched_url)
        ):
            try:
                replay = await asyncio.to_thread(fetch_url, matched_url)
                replay_record = await persist_json(
                    stage,
                    redact_object(replay),
                    kind="validation_replay",
                    name=f"finding-{row['id']}-replay.json",
                    metadata={
                        "finding_id": str(row["id"]),
                        "template_id": template_id,
                        "validation_role": "independent_safe_get_replay",
                        "secret_redacted": True,
                    },
                )
                validation_artifact_id = replay_record["id"]
                oracle_status, oracle_rationale = evaluate_nuclei_replay(template_id, replay)
            except Exception as exc:
                oracle_rationale = f"Independent replay could not complete: {type(exc).__name__}: {exc}"
        if finding_failures:
            validation_status = "inconclusive"
            evidence_integrity = "failed"
            failures.append(f"{row['id']}: {', '.join(finding_failures)}")
        else:
            evidence_integrity = "passed"
            verified += 1
            if oracle_status == "passed":
                validation_status = "confirmed"
                confirmed += 1
            elif oracle_status == "failed":
                validation_status = "rejected"
                rejected += 1
            else:
                validation_status = "candidate"
                candidates += 1
        rationale = "; ".join([*finding_failures, oracle_rationale])
        await pool().execute(
            """
            INSERT INTO finding_assurance (
              finding_id, canonical_observation_key, validation_status,
              evidence_integrity, oracle_status, validation_artifact_id,
              rationale, validated_at
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,now())
            ON CONFLICT (finding_id) DO UPDATE SET
              canonical_observation_key = EXCLUDED.canonical_observation_key,
              validation_status = EXCLUDED.validation_status,
              evidence_integrity = EXCLUDED.evidence_integrity,
              oracle_status = EXCLUDED.oracle_status,
              validation_artifact_id = EXCLUDED.validation_artifact_id,
              rationale = EXCLUDED.rationale,
              validated_at = now(), updated_at = now()
            """,
            row["id"], canonical_observation_key(evidence), validation_status,
            evidence_integrity, oracle_status, validation_artifact_id, rationale,
        )
    result = {
        "finding_count": len(rows),
        "verified": verified,
        "confirmed": confirmed,
        "candidates": candidates,
        "rejected": rejected,
        "inconclusive": len(rows) - verified,
        "failures": failures,
        "validated_at": utcnow().isoformat(),
    }
    await persist_json(stage, result, kind="evidence_validation", name="evidence-validation.json")
    if failures:
        raise RuntimeError("; ".join(failures[:10]))
    return {"command": "evidence-integrity verify --scan [SCAN_ID]", "transcript": json.dumps(result, indent=2)}


ADAPTERS = {
    "scope_preflight": scope_preflight,
    "subdomain_enumeration": subdomain_enumeration,
    "http_profile": http_profile,
    "tls_service_discovery": tls_service_discovery,
    "authenticated_crawl": authenticated_crawl,
    "standards_discovery": standards_discovery,
    "application_surface_inventory": application_surface_inventory,
    "authenticated_session_review": authenticated_session_review,
    "api_contract_review": api_contract_review,
    "route_security_policy_review": route_security_policy_review,
    "security_headers": security_headers,
    "external_web_posture": external_web_posture,
    "nuclei_baseline": nuclei_baseline,
    "evidence_validation": evidence_validation,
}
