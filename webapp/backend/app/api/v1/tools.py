"""Security utility toolkit — DNS, WHOIS/RDAP, SSL, crt.sh, headers, Shodan."""

import asyncio
import re
import socket
import ssl
from datetime import datetime, timezone
from typing import Any

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.api.v1.auth import get_current_user
from app.config import settings
from app.services.open_source_catalog import get_open_source_tool_catalog
from app.services.validation import ValidationError, resolve_and_check, validate_public_url

router = APIRouter(prefix="/tools", tags=["tools"])

TIMEOUT = 15.0


# ── Schemas ──────────────────────────────────────────────────────────────────

class TargetRequest(BaseModel):
    target: str


@router.get("/catalog")
async def tool_catalog(_: Any = Depends(get_current_user)):
    """Return the curated open-source scanner catalog used by the platform."""
    return get_open_source_tool_catalog()


# ── Helpers ──────────────────────────────────────────────────────────────────

def _clean(target: str) -> str:
    target = target.strip()
    target = re.sub(r"^https?://", "", target)
    target = target.split("/")[0].split(":")[0]
    return target.lower()


def _is_ip(s: str) -> bool:
    return bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", s))


# ── DNS Lookup ────────────────────────────────────────────────────────────────

@router.post("/dns")
async def dns_lookup(req: TargetRequest, _: Any = Depends(get_current_user)):
    """Resolve DNS records via Cloudflare DoH."""
    domain = _clean(req.target)
    if not domain:
        raise HTTPException(400, "Invalid target")

    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"]
    results: dict[str, list] = {}

    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        for rtype in record_types:
            try:
                resp = await client.get(
                    "https://cloudflare-dns.com/dns-query",
                    params={"name": domain, "type": rtype},
                    headers={"Accept": "application/dns-json"},
                )
                data = resp.json()
                answers = data.get("Answer", [])
                results[rtype] = [a["data"] for a in answers]
            except Exception:
                results[rtype] = []

    return {"domain": domain, "records": results}


# ── WHOIS / RDAP ──────────────────────────────────────────────────────────────

@router.post("/whois")
async def whois_lookup(req: TargetRequest, _: Any = Depends(get_current_user)):
    """WHOIS information via public RDAP API."""
    target = _clean(req.target)
    if not target:
        raise HTTPException(400, "Invalid target")

    async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True) as client:
        try:
            if _is_ip(target):
                url = f"https://rdap.arin.net/registry/ip/{target}"
            else:
                url = f"https://rdap.org/domain/{target}"
            resp = await client.get(url)
            if resp.status_code == 404:
                raise HTTPException(404, f"No RDAP data found for {target}")
            resp.raise_for_status()
            data = resp.json()
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(502, f"RDAP lookup failed: {e}")

    result: dict[str, Any] = {"target": target}

    if _is_ip(target):
        result.update(
            {
                "type": "ip",
                "handle": data.get("handle"),
                "name": data.get("name"),
                "country": data.get("country"),
                "start_address": data.get("startAddress"),
                "end_address": data.get("endAddress"),
                "ip_version": data.get("ipVersion"),
                "status": data.get("status", []),
            }
        )
    else:
        events = {e["eventAction"]: e["eventDate"] for e in data.get("events", [])}
        nameservers = [ns.get("ldhName", "") for ns in data.get("nameservers", [])]
        result.update(
            {
                "type": "domain",
                "handle": data.get("handle"),
                "domain": data.get("ldhName"),
                "registered": events.get("registration"),
                "updated": events.get("last changed"),
                "expires": events.get("expiration"),
                "status": data.get("status", []),
                "nameservers": nameservers,
                "registrar": _extract_registrar(data),
            }
        )

    return result


def _extract_registrar(data: dict) -> str | None:
    for entity in data.get("entities", []):
        if "registrar" in entity.get("roles", []):
            vcard = entity.get("vcardArray", [])
            if len(vcard) > 1:
                for prop in vcard[1]:
                    if prop[0] == "fn":
                        return prop[3]
    return None


# ── SSL / TLS Check ───────────────────────────────────────────────────────────

@router.post("/ssl")
async def ssl_check(req: TargetRequest, _: Any = Depends(get_current_user)):
    """Check SSL/TLS certificate details for a host on port 443."""
    host = _clean(req.target)
    if not host:
        raise HTTPException(400, "Invalid target")
    try:
        connect_ip = resolve_and_check(host)
    except ValidationError as exc:
        raise HTTPException(400, str(exc))

    def _do_check():
        ctx = ssl.create_default_context()
        with socket.create_connection((connect_ip, 443), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                return ssock.getpeercert(), ssock.cipher(), ssock.version()

    try:
        cert, cipher_info, proto = await asyncio.get_event_loop().run_in_executor(None, _do_check)
    except ssl.SSLCertVerificationError as e:
        raise HTTPException(400, f"SSL verification failed: {e}")
    except ConnectionRefusedError:
        raise HTTPException(400, "Port 443 not open")
    except socket.gaierror:
        raise HTTPException(400, "DNS resolution failed")
    except socket.timeout:
        raise HTTPException(408, "Connection timed out")
    except Exception as e:
        raise HTTPException(502, str(e))

    subject = dict(x[0] for x in cert.get("subject", []))
    issuer = dict(x[0] for x in cert.get("issuer", []))
    san = [v for _t, v in cert.get("subjectAltName", [])]

    not_after = cert.get("notAfter", "")
    not_before = cert.get("notBefore", "")
    days_left: int | None = None
    try:
        expires_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days_left = (expires_dt - datetime.now(timezone.utc)).days
    except Exception:
        pass

    warnings = []
    if days_left is not None and days_left < 30:
        warnings.append(f"Certificate expires in {days_left} days")
    if proto in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3"):
        warnings.append(f"Weak protocol in use: {proto}")
    cipher_name = cipher_info[0] if cipher_info else ""
    if any(w in cipher_name for w in ("RC4", "DES", "NULL", "EXPORT", "MD5")):
        warnings.append(f"Weak cipher: {cipher_name}")

    return {
        "host": host,
        "subject": subject,
        "issuer": issuer,
        "san": san,
        "not_before": not_before,
        "not_after": not_after,
        "days_until_expiry": days_left,
        "cipher": cipher_name,
        "key_bits": cipher_info[2] if cipher_info else None,
        "protocol": proto,
        "serial": cert.get("serialNumber"),
        "warnings": warnings,
    }


# ── crt.sh Certificate Transparency ──────────────────────────────────────────

@router.post("/crtsh")
async def crtsh_search(req: TargetRequest, _: Any = Depends(get_current_user)):
    """Search certificate transparency logs for subdomains."""
    domain = _clean(req.target)
    if not domain:
        raise HTTPException(400, "Invalid target")

    # Connection: close forces HTTP/1.1; avoids Docker HTTP/2 keepalive hang
    _hdrs = {"User-Agent": "ExposureScopeX/2.2.0", "Connection": "close"}
    _timeout = httpx.Timeout(connect=10, read=60, write=10, pool=5)
    async with httpx.AsyncClient(timeout=_timeout, http2=False) as client:
        try:
            resp = await client.get(
                "https://crt.sh/",
                params={"q": f"%.{domain}", "output": "json"},
                headers=_hdrs,
            )
            resp.raise_for_status()
            data = resp.json()
        except httpx.HTTPStatusError as e:
            raise HTTPException(e.response.status_code, "crt.sh returned an error")
        except Exception as e:
            raise HTTPException(502, f"crt.sh request failed: {e}")

    seen: set[str] = set()
    subdomains = []
    for entry in data:
        for name in entry.get("name_value", "").split("\n"):
            name = name.strip().lower().lstrip("*.")
            if name and name not in seen and (name == domain or name.endswith(f".{domain}")):
                seen.add(name)
                subdomains.append(
                    {
                        "name": name,
                        "issuer": entry.get("issuer_name", ""),
                        "not_before": entry.get("not_before", ""),
                        "not_after": entry.get("not_after", ""),
                    }
                )

    subdomains.sort(key=lambda x: x["name"])
    return {"domain": domain, "count": len(subdomains), "subdomains": subdomains}


# ── Wayback Machine URL Discovery ────────────────────────────────────────────

@router.post("/wayback")
async def wayback_search(req: TargetRequest, _: Any = Depends(get_current_user)):
    """Query the Internet Archive CDX API for historical URLs."""
    domain = _clean(req.target)
    if not domain:
        raise HTTPException(400, "Invalid target")

    _hdrs = {"User-Agent": "ExposureScopeX/2.2.0", "Connection": "close"}
    _timeout = httpx.Timeout(connect=10, read=90, write=10, pool=5)
    async with httpx.AsyncClient(timeout=_timeout, http2=False) as client:
        try:
            resp = await client.get(
                "https://web.archive.org/cdx/search/cdx",
                params={
                    "url": f"*.{domain}/*",
                    "output": "text",
                    "fl": "original",
                    "collapse": "urlkey",
                    "limit": 500,
                },
                headers=_hdrs,
            )
            resp.raise_for_status()
        except httpx.HTTPStatusError as e:
            raise HTTPException(e.response.status_code, "Wayback Machine returned an error")
        except Exception as e:
            raise HTTPException(502, f"Wayback lookup failed: {e}")

    urls = sorted({line.strip() for line in resp.text.splitlines() if line.strip()})
    interesting = [
        url for url in urls
        if re.search(
            r"\.(php|asp|aspx|jsp|cgi|env|conf|ini|bak|sql|log|key|pem|xml|json|yaml|yml|git|svn)\b|admin|login|api|backup|secret|password|token|config",
            url,
            re.IGNORECASE,
        )
    ]

    return {
        "domain": domain,
        "count": len(urls),
        "urls": urls,
        "interesting_count": len(interesting),
        "interesting_urls": interesting,
    }


# ── HTTP Header Security Analysis ─────────────────────────────────────────────

_SECURITY_HEADERS = {
    "strict-transport-security": ("HSTS", "HIGH"),
    "content-security-policy": ("Content-Security-Policy", "HIGH"),
    "x-frame-options": ("X-Frame-Options", "MEDIUM"),
    "x-content-type-options": ("X-Content-Type-Options", "LOW"),
    "referrer-policy": ("Referrer-Policy", "LOW"),
    "permissions-policy": ("Permissions-Policy", "LOW"),
    "x-xss-protection": ("X-XSS-Protection", "LOW"),
}

_LEAK_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"]


@router.post("/headers")
async def headers_check(req: TargetRequest, _: Any = Depends(get_current_user)):
    """Fetch HTTP response headers and analyze security posture."""
    url = req.target.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    try:
        url = validate_public_url(url)
    except ValidationError as exc:
        raise HTTPException(400, str(exc))

    async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=False) as client:
        try:
            resp = await client.head(url)
        except Exception:
            try:
                resp = await client.get(url)
            except Exception as e:
                raise HTTPException(502, f"Request failed: {e}")

    headers = {k.lower(): v for k, v in resp.headers.items()}

    security_checks = []
    present_count = 0
    for header_lower, (label, severity) in _SECURITY_HEADERS.items():
        val = headers.get(header_lower)
        if val:
            present_count += 1
            security_checks.append(
                {"header": label, "present": True, "value": val, "severity": "OK"}
            )
        else:
            security_checks.append(
                {"header": label, "present": False, "value": None, "severity": severity}
            )

    # Information disclosure headers
    leaks = []
    for h in _LEAK_HEADERS:
        if headers.get(h):
            leaks.append({"header": h, "value": headers[h]})

    missing_high = [c["header"] for c in security_checks if not c["present"] and c["severity"] == "HIGH"]
    score = round(present_count / len(_SECURITY_HEADERS) * 100)

    return {
        "url": str(resp.url),
        "status_code": resp.status_code,
        "all_headers": dict(resp.headers),
        "security_analysis": security_checks,
        "info_disclosure": leaks,
        "missing_critical": missing_high,
        "security_score": score,
    }


# ── Shodan Host Lookup ────────────────────────────────────────────────────────

@router.post("/shodan")
async def shodan_lookup(req: TargetRequest, _: Any = Depends(get_current_user)):
    """Shodan host intelligence lookup (requires SHODAN_API_KEY in settings)."""
    if not settings.SHODAN_API_KEY:
        raise HTTPException(
            503,
            "SHODAN_API_KEY not configured — add it in Settings → API Keys.",
        )

    target = _clean(req.target)
    # Resolve domain → IP
    if not _is_ip(target):
        try:
            target = socket.gethostbyname(target)
        except socket.gaierror:
            raise HTTPException(400, f"Could not resolve '{target}' to an IP address")

    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        try:
            resp = await client.get(
                f"https://api.shodan.io/shodan/host/{target}",
                params={"key": settings.SHODAN_API_KEY},
            )
            if resp.status_code == 404:
                return {"ip": target, "found": False}
            resp.raise_for_status()
            data = resp.json()
        except HTTPException:
            raise
        except httpx.HTTPStatusError as e:
            raise HTTPException(e.response.status_code, f"Shodan API error: {e}")
        except Exception as e:
            raise HTTPException(502, str(e))

    ports = sorted({item.get("port") for item in data.get("data", []) if item.get("port")})
    services = [
        {
            "port": item.get("port"),
            "transport": item.get("transport", "tcp"),
            "product": item.get("product"),
            "version": item.get("version"),
            "banner": (item.get("data", "")[:200] if item.get("data") else None),
        }
        for item in data.get("data", [])
    ]

    return {
        "ip": target,
        "found": True,
        "organization": data.get("org"),
        "country": data.get("country_name"),
        "city": data.get("city"),
        "isp": data.get("isp"),
        "asn": data.get("asn"),
        "hostnames": data.get("hostnames", []),
        "domains": data.get("domains", []),
        "ports": ports,
        "services": services,
        "vulns": list(data.get("vulns", {}).keys()),
        "tags": data.get("tags", []),
        "last_update": data.get("last_update"),
    }
