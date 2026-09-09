"""Input validation and SSRF prevention for external targets.

All ASM targets and tool endpoints pass through these checks before
any network connection is made.
"""

import ipaddress
import re
import socket
from urllib.parse import urlparse
from typing import Literal

# RFC 1918 + link-local + loopback + documentation ranges
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),   # link-local
    ipaddress.ip_network("::1/128"),           # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),          # IPv6 ULA
    ipaddress.ip_network("fe80::/10"),         # IPv6 link-local
    ipaddress.ip_network("100.64.0.0/10"),     # CGNAT
    ipaddress.ip_network("192.0.2.0/24"),      # TEST-NET-1
    ipaddress.ip_network("198.51.100.0/24"),   # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),    # TEST-NET-3
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("255.255.255.255/32"),
]

_DOMAIN_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$",
    re.IGNORECASE,
)

_CIDR_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$")


class ValidationError(ValueError):
    pass


def is_private_ip(addr: str) -> bool:
    """Return True unless the address is globally routable."""
    try:
        ip = ipaddress.ip_address(addr)
        return not ip.is_global or any(ip in net for net in _PRIVATE_NETWORKS)
    except ValueError:
        return False


def validate_ip(value: str) -> str:
    """Validate and normalise an IP address. Raises ValidationError on bad input."""
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError:
        raise ValidationError(f"Invalid IP address: {value!r}")
    if is_private_ip(str(ip)):
        raise ValidationError(
            f"Private/reserved IP addresses are not allowed as ASM targets: {ip}"
        )
    return str(ip)


def validate_cidr(value: str) -> str:
    """Validate a CIDR block. Private ranges are blocked."""
    value = value.strip()
    if not _CIDR_RE.match(value):
        raise ValidationError(f"Invalid CIDR notation: {value!r}")
    try:
        net = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise ValidationError(str(exc))
    for priv in _PRIVATE_NETWORKS:
        if net.overlaps(priv):
            raise ValidationError(
                f"CIDR block {value} overlaps a private/reserved range — "
                "add it manually only if this is an authorised internal scan."
            )
    return str(net)


def validate_domain(value: str) -> str:
    """Validate a fully-qualified domain name."""
    value = value.strip().lower().rstrip(".")
    if not _DOMAIN_RE.match(value):
        raise ValidationError(f"Invalid domain name: {value!r}")
    if len(value) > 253:
        raise ValidationError("Domain name exceeds 253 characters")
    return value


def validate_url(value: str) -> str:
    """Validate an HTTP/S URL target and normalize it."""
    parsed = urlparse(value.strip())
    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValidationError(f"Invalid URL scheme: {value!r}")
    if not parsed.hostname:
        raise ValidationError(f"URL is missing a hostname: {value!r}")
    if parsed.username or parsed.password:
        raise ValidationError("Credentials are not allowed in target URLs")

    host = parsed.hostname.lower()
    try:
        host = validate_ip(host)
    except ValidationError:
        host = validate_domain(host)

    netloc = parsed.netloc.lower()
    path = parsed.path or "/"
    return parsed._replace(scheme=parsed.scheme.lower(), netloc=netloc, path=path, fragment="").geturl()


def validate_target(value: str, target_type: str) -> str:
    """Dispatcher — validates based on declared type. Returns normalised value."""
    clean = value.strip()
    if target_type == "ip":
        return validate_ip(clean)
    if target_type == "cidr":
        return validate_cidr(clean)
    if target_type == "url":
        return validate_url(clean)
    if target_type in ("domain", "hostname"):
        return validate_domain(clean)
    # auto-detect
    if re.match(r"^https?://", clean, re.IGNORECASE):
        return validate_url(clean)
    if re.match(r"^\d+\.\d+\.\d+\.\d+/\d+$", clean):
        return validate_cidr(clean)
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", clean):
        return validate_ip(clean)
    return validate_domain(clean)


def resolve_and_check(hostname: str) -> str:
    """Resolve every address for a hostname and reject non-public destinations.

    Call this before making any outbound HTTP request to a user-supplied host.
    Raises ValidationError if resolved IP is private.
    """
    try:
        infos = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValidationError(f"Cannot resolve {hostname!r}: {exc}")
    addresses = sorted({info[4][0] for info in infos})
    if not addresses:
        raise ValidationError(f"Cannot resolve {hostname!r}")
    blocked = [address for address in addresses if is_private_ip(address)]
    if blocked:
        raise ValidationError(
            f"Hostname {hostname!r} resolves to a private/reserved address; request blocked"
        )
    # Prefer IPv4 for scanner compatibility while validating every A/AAAA answer.
    return next((address for address in addresses if ":" not in address), addresses[0])


def validate_public_url(value: str) -> str:
    """Normalize an HTTP(S) URL and verify that all destination IPs are public."""
    normalized = validate_url(value)
    hostname = urlparse(normalized).hostname
    if not hostname:
        raise ValidationError("URL is missing a hostname")
    resolve_and_check(hostname)
    return normalized
