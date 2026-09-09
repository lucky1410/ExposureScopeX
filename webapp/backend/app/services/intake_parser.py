"""Flexible CSV intake parsing for assessments and inventory uploads."""

from __future__ import annotations

import re
from typing import Any

TARGET_FIELDS = [
    "target",
    "target_value",
    "url",
    "uri",
    "website",
    "domain",
    "hostname",
    "host",
    "fqdn",
    "ip",
    "cidr",
    "asset",
    "asset_value",
    "instance",
    "endpoint",
    "address",
    "ip_address",
    "ipaddress",
    "public_ip",
    "public_ipv4",
    "public_ipv4_address",
    "ipv4",
    "ipv4_address",
    "dns_name",
    "ip_addr",
    "ipv6",
    "ipv6_address",
    "asn",
    "as_number",
    "autonomous_system",
    "repo",
    "repository",
    "repo_url",
    "repository_url",
    "git_repository",
    "github_repository",
    "gitlab_repository",
    "organization",
    "org",
    "company",
    "account_id",
    "aws_account_id",
    "subscription_id",
    "project_id",
    "cloud_account",
    "mcp",
    "mcp_endpoint",
    "mcp_url",
    "image",
    "container_image",
    "image_ref",
    "image_uri",
    "container",
    "container_ref",
    "registry_image",
]
NAME_FIELDS = ["name", "title", "label", "asset_name", "service_name", "instance_name", "service"]
TYPE_FIELDS = ["target_type", "type", "asset_type", "kind"]
DESCRIPTION_FIELDS = ["description", "desc", "details", "summary", "eni_description", "service_resource"]
NOTES_FIELDS = ["notes", "note", "comment", "comments", "remark", "remarks"]
TAGS_FIELDS = ["tags", "labels", "categories", "security_groups_display"]
MODE_FIELDS = ["scan_mode", "mode", "profile", "scan_profile"]
SCAN_FIELDS = ["requested_scans", "scans", "modules", "scan_types", "scan_kind"]
UTILITY_FIELDS = ["requested_utilities", "utilities", "tools"]
NUCLEI_TAG_FIELDS = ["nuclei_tags", "tags_nuclei", "template_tags"]
AUTO_START_FIELDS = ["auto_start", "start_scan", "run_now", "queue_scan"]
_TARGETISH_KEYWORDS = ("target", "domain", "host", "fqdn", "url", "uri", "ip", "cidr", "address", "endpoint", "dns", "asn", "repo", "mcp", "account", "project", "subscription", "image", "container", "registry")
_NON_TARGET_FIELDS = {
    "address_type",
    "address_region",
    "network_border_group",
    "owner_id",
    "allocation_id",
    "network_interface_id",
    "instance_id",
    "ipam_resource_discovery_id",
    "sample_time",
    "public_ipv4_pool",
}
_DOMAIN_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$", re.IGNORECASE)
_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_CIDR_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}$")
_URL_RE = re.compile(r"^https?://", re.IGNORECASE)
_IPV6_RE = re.compile(r"^[0-9a-f:]+(?::[0-9a-f]+)+$", re.IGNORECASE)
_ASN_RE = re.compile(r"^(?:AS)?\d{1,10}$", re.IGNORECASE)
_REPO_RE = re.compile(r"^(?:(?:https?://)?(?:www\.)?)?(?:github\.com|gitlab\.com|bitbucket\.org)/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/?(?:\.git)?$", re.IGNORECASE)
_OWNER_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_CLOUD_ACCOUNT_RE = re.compile(r"^(?:\d{12}|[0-9a-f-]{36}|[a-z][a-z0-9-]{4,61}[a-z0-9]|(?:aws|azure|gcp):.+)$", re.IGNORECASE)
_IMAGE_RE = re.compile(
    r"^(?:(?:[a-z0-9.-]+(?::\d+)?)/)?[a-z0-9]+(?:[._/-][a-z0-9]+)*(?::[\w][\w.-]{0,127})?(?:@sha256:[a-f0-9]{64})?$",
    re.IGNORECASE,
)


def normalize_headers(row: dict[str, Any]) -> dict[str, str]:
    """Normalize incoming CSV row keys for fuzzy matching."""
    normalized: dict[str, str] = {}
    for key, value in row.items():
        if key is None:
            continue
        clean_key = _normalize_key(str(key))
        normalized[clean_key] = str(value).strip() if value is not None else ""
    return normalized


def parse_csv_row(row: dict[str, Any]) -> dict[str, Any]:
    """Extract a best-effort assessment import payload from a loose CSV row."""
    normalized = normalize_headers(row)
    target, inferred_key = _extract_target(normalized)
    if not target:
        raise ValueError("no recognizable target field found")

    name = _pick_first(normalized, NAME_FIELDS) or target
    explicit_type = _pick_first(normalized, TYPE_FIELDS)
    key_type = _infer_target_type_from_key(inferred_key)
    value_type = _infer_target_type_from_value(target)
    # Specialized headers carry semantic intent. Generic host/address headers
    # are only hints; mixed exports must be typed from each row's actual value.
    specialized_key_types = {"mcp", "repository", "asn", "cloud_account", "image", "organization"}
    target_type = explicit_type or (key_type if key_type in specialized_key_types else value_type or key_type) or "auto"
    description = _pick_first(normalized, DESCRIPTION_FIELDS) or None
    notes = _pick_first(normalized, NOTES_FIELDS) or None
    tags = _split_multi(_pick_first(normalized, TAGS_FIELDS))
    scan_mode = (_pick_first(normalized, MODE_FIELDS) or "medium").lower()
    requested_scans = _split_multi(_pick_first(normalized, SCAN_FIELDS))
    requested_utilities = _split_multi(_pick_first(normalized, UTILITY_FIELDS))
    nuclei_tags = _split_multi(_pick_first(normalized, NUCLEI_TAG_FIELDS))
    auto_start = _to_bool(_pick_first(normalized, AUTO_START_FIELDS))

    return {
        "name": name,
        "target": target,
        "target_type": target_type,
        "description": description or notes,
        "notes": notes,
        "tags": tags,
        "scan_mode": scan_mode,
        "requested_scans": requested_scans,
        "requested_utilities": requested_utilities,
        "nuclei_tags": nuclei_tags,
        "auto_start": auto_start,
        "raw": normalized,
    }


def _normalize_key(key: str) -> str:
    key = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", key.strip())
    return key.lower().replace("-", "_").replace(" ", "_")


def _pick_first(row: dict[str, str], aliases: list[str]) -> str:
    for alias in aliases:
        value = row.get(alias, "").strip()
        if value:
            return value
    return ""


def _extract_target(row: dict[str, str]) -> tuple[str, str]:
    explicit = _pick_first(row, TARGET_FIELDS)
    if explicit:
        for alias in TARGET_FIELDS:
            if row.get(alias, "").strip() == explicit:
                return explicit, alias
        return explicit, ""

    for key, value in row.items():
        candidate = value.strip()
        if not candidate or key in _NON_TARGET_FIELDS:
            continue
        if any(keyword in key for keyword in _TARGETISH_KEYWORDS) and _looks_like_target(candidate):
            return candidate, key

    for key, value in row.items():
        candidate = value.strip()
        if candidate and _looks_like_target(candidate):
            return candidate, key

    return "", ""


def _looks_like_target(value: str) -> bool:
    candidate = value.strip()
    return bool(
        _URL_RE.match(candidate)
        or _CIDR_RE.match(candidate)
        or _IP_RE.match(candidate)
        or _IPV6_RE.match(candidate)
        or _DOMAIN_RE.match(candidate)
        or _ASN_RE.match(candidate)
        or _REPO_RE.match(candidate)
        or _OWNER_REPO_RE.match(candidate)
        or _CLOUD_ACCOUNT_RE.match(candidate)
        or _looks_like_image(candidate)
    )


def _infer_target_type_from_key(key: str) -> str | None:
    if not key:
        return None
    if "mcp" in key:
        return "mcp"
    if "repo" in key or "git" in key:
        return "repository"
    if "asn" in key or "autonomous_system" in key:
        return "asn"
    if any(token in key for token in ("account", "subscription", "project")):
        return "cloud_account"
    if "image" in key or "container" in key or "registry" in key:
        return "image"
    if any(token in key for token in ("organization", "company", "org")):
        return "organization"
    if "url" in key or "uri" in key:
        return "url"
    if "cidr" in key:
        return "cidr"
    if "ip" in key or "ipv4" in key or "ipv6" in key:
        return "ip"
    if any(token in key for token in ("domain", "hostname", "host", "dns")):
        return "domain"
    return None


def _infer_target_type_from_value(value: str) -> str | None:
    candidate = value.strip()
    if _REPO_RE.match(candidate):
        return "repository"
    if _CIDR_RE.match(candidate):
        return "cidr"
    if _IP_RE.match(candidate) or _IPV6_RE.match(candidate):
        return "ip"
    if _URL_RE.match(candidate):
        return "url"
    if _DOMAIN_RE.match(candidate):
        return "domain"
    if _ASN_RE.match(candidate):
        return "asn"
    if _CLOUD_ACCOUNT_RE.match(candidate):
        return "cloud_account"
    if _looks_like_image(candidate):
        return "image"
    if _OWNER_REPO_RE.match(candidate):
        return "repository"
    return None


def _split_multi(value: str) -> list[str]:
    if not value:
        return []
    parts: list[str] = []
    for chunk in value.replace(";", ",").split(","):
        chunk = chunk.strip()
        if chunk:
            parts.append(chunk)
    return parts


def _to_bool(value: str) -> bool | None:
    if not value:
        return None
    lowered = value.strip().lower()
    if lowered in {"1", "true", "yes", "y", "on"}:
        return True
    if lowered in {"0", "false", "no", "n", "off"}:
        return False
    return None


def _looks_like_image(value: str) -> bool:
    candidate = value.strip()
    if candidate.startswith(("http://", "https://")):
        return False
    if "/" not in candidate and ":" not in candidate and "@" not in candidate:
        return False
    if _REPO_RE.match(candidate) or _OWNER_REPO_RE.match(candidate):
        return False
    return bool(_IMAGE_RE.match(candidate))
