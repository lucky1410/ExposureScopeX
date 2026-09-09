"""Canonical asset normalization and cross-source inventory helpers."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlparse, urlunparse

from app.models.asm import AsmTarget
from app.models.asset import Asset
from app.services.validation import ValidationError, validate_cidr, validate_domain, validate_ip

_URL_RE = re.compile(r"^https?://", re.IGNORECASE)
_ASN_RE = re.compile(r"^(?:AS)?(\d{1,10})$", re.IGNORECASE)
_REPOSITORY_RE = re.compile(
    r"^(?:(?:https?://)?(?:www\.)?(github\.com|gitlab\.com|bitbucket\.org)/)?([a-z0-9_.-]+)/([a-z0-9_.-]+?)(?:\.git)?/?$",
    re.IGNORECASE,
)
_AWS_ACCOUNT_RE = re.compile(r"^\d{12}$")
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.IGNORECASE)
_GCP_PROJECT_RE = re.compile(r"^[a-z][a-z0-9-]{4,61}[a-z0-9]$", re.IGNORECASE)
_ORG_SLUG_RE = re.compile(r"[^a-z0-9]+")
_IMAGE_RE = re.compile(
    r"^(?:(?:[a-z0-9.-]+(?::\d+)?)/)?[a-z0-9]+(?:[._/-][a-z0-9]+)*(?::[\w][\w.-]{0,127})?(?:@sha256:[a-f0-9]{64})?$",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class NormalizedTarget:
    """Normalized target identity shared across ASM and assessments."""

    target_type: str
    normalized_value: str
    canonical_key: str
    hostname: str | None = None
    root_domain: str | None = None
    parent_key: str | None = None
    relation_label: str | None = None
    seed_type: str | None = None


def detect_target_type(value: str) -> str:
    """Infer a supported target type from a raw string."""
    cleaned = value.strip()
    if _URL_RE.match(cleaned):
        if _looks_like_mcp_endpoint(cleaned):
            return "mcp"
        return "url"
    if _ASN_RE.match(cleaned):
        return "asn"
    if _looks_like_repository(cleaned):
        return "repository"
    if _looks_like_image(cleaned):
        return "image"
    if _looks_like_cloud_account(cleaned):
        return "cloud_account"
    try:
        ipaddress.ip_network(cleaned, strict=False)
        return "cidr" if "/" in cleaned else "ip"
    except ValueError:
        return "domain"


def normalize_target(value: str, target_type: str | None = None) -> NormalizedTarget:
    """Validate and normalize a user-supplied target into one canonical identity."""
    resolved_type = (target_type or "auto").lower()
    if resolved_type == "auto":
        resolved_type = detect_target_type(value)

    if resolved_type == "file":
        cleaned = value.strip()
        return NormalizedTarget(
            target_type="file",
            normalized_value=cleaned,
            canonical_key=f"file:{cleaned}",
            seed_type="file",
        )
    if resolved_type == "mcp":
        return _normalize_mcp(value)
    if resolved_type in {"url", "api", "kubernetes", "android", "ios"}:
        if resolved_type != "url":
            normalized = _normalize_url(value)
            return NormalizedTarget(
                target_type=resolved_type,
                normalized_value=normalized.normalized_value,
                canonical_key=f"{resolved_type}:{normalized.normalized_value}",
                hostname=normalized.hostname,
                root_domain=normalized.root_domain,
                seed_type=resolved_type,
            )
        return _normalize_url(value)
    if resolved_type == "ip":
        ip_value = validate_ip(value)
        return NormalizedTarget(
            target_type="ip",
            normalized_value=ip_value,
            canonical_key=f"ip:{ip_value}",
            seed_type="ip",
        )
    if resolved_type == "cidr":
        cidr_value = validate_cidr(value)
        return NormalizedTarget(
            target_type="cidr",
            normalized_value=cidr_value,
            canonical_key=f"cidr:{cidr_value}",
            seed_type="cidr",
        )
    if resolved_type in {"domain", "hostname", "subdomain"}:
        domain_value = validate_domain(value)
        root_domain = infer_root_domain(domain_value)
        parent_key = f"host:{root_domain}" if domain_value != root_domain else None
        relation_label = "subdomain_of" if parent_key else None
        return NormalizedTarget(
            target_type="domain",
            normalized_value=domain_value,
            canonical_key=f"host:{domain_value}",
            hostname=domain_value,
            root_domain=root_domain,
            parent_key=parent_key,
            relation_label=relation_label,
            seed_type="domain",
        )
    if resolved_type == "asn":
        match = _ASN_RE.match(value.strip())
        if not match:
            raise ValidationError(f"Invalid ASN target: {value!r}")
        asn = f"AS{match.group(1)}"
        return NormalizedTarget(
            target_type="asn",
            normalized_value=asn,
            canonical_key=f"asn:{asn}",
            seed_type="asn",
        )
    if resolved_type in {"repo", "repository"}:
        return _normalize_repository(value)
    if resolved_type in {"image", "container_image", "container"}:
        return _normalize_image(value)
    if resolved_type in {"cloud", "cloud_account", "account", "subscription", "project"}:
        return _normalize_cloud_account(value)
    if resolved_type in {"organization", "org", "company"}:
        return _normalize_organization(value)

    raise ValidationError(f"Unsupported target type: {resolved_type}")


def normalize_asset_identity(asset_type: str, value: str) -> NormalizedTarget:
    """Normalize a persisted asset/target record into a shared identity model."""
    asset_type = (asset_type or "domain").lower()
    if asset_type == "subdomain":
        asset_type = "domain"
    if asset_type == "file":
        cleaned = value.strip()
        return NormalizedTarget(
            target_type="file",
            normalized_value=cleaned,
            canonical_key=f"file:{cleaned}",
        )
    try:
        return normalize_target(value, asset_type)
    except Exception:
        cleaned = value.strip()
        return NormalizedTarget(
            target_type=asset_type,
            normalized_value=cleaned,
            canonical_key=f"{asset_type}:{cleaned.lower()}",
        )


def build_seed_metadata(value: str, target_type: str, *, source: str = "user", stage: str = "seed") -> dict[str, str | None]:
    """Build a normalized seed object shared across imports and discovery outputs."""
    normalized = normalize_target(value, target_type)
    return {
        "seed_type": normalized.seed_type or normalized.target_type,
        "value": normalized.normalized_value,
        "canonical_key": normalized.canonical_key,
        "source": source,
        "stage": stage,
        "hostname": normalized.hostname,
        "root_domain": normalized.root_domain,
        "parent_key": normalized.parent_key,
        "relation_label": normalized.relation_label,
    }


def infer_root_domain(host: str) -> str:
    """Best-effort apex extraction without external PSL dependencies."""
    labels = host.lower().strip(".").split(".")
    if len(labels) <= 2:
        return ".".join(labels)
    if labels[-2] in {"co", "com", "org", "net", "gov", "edu"} and len(labels[-1]) == 2:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def summarize_asset(asset: Asset) -> dict:
    """Serialize an assessment asset into an inventory-friendly dict."""
    normalized = normalize_asset_identity(asset.asset_type, asset.value)
    metadata = asset.metadata_ or {}
    return {
        "id": str(asset.id),
        "source": "assessment",
        "asset_type": asset.asset_type,
        "value": asset.value,
        "canonical_key": normalized.canonical_key,
        "normalized_value": normalized.normalized_value,
        "hostname": normalized.hostname,
        "root_domain": normalized.root_domain,
        "parent_key": normalized.parent_key,
        "relation_label": normalized.relation_label,
        "assessment_id": str(asset.assessment_id),
        "parent_id": str(asset.parent_id) if asset.parent_id else None,
        "is_live": asset.is_live,
        "metadata": metadata,
        "seed": metadata.get("seed") or build_seed_metadata(asset.value, normalized.target_type, source="assessment", stage="confirmed"),
        "first_seen": asset.first_seen.isoformat() if asset.first_seen else None,
        "last_seen": asset.last_seen.isoformat() if asset.last_seen else None,
    }


def summarize_asm_target(target: AsmTarget) -> dict:
    """Serialize an ASM target into an inventory-friendly dict."""
    normalized = normalize_asset_identity(target.target_type, target.target_value)
    summary = target.last_scan_summary or {}
    return {
        "id": str(target.id),
        "source": "asm",
        "asset_type": target.target_type,
        "value": target.target_value,
        "canonical_key": normalized.canonical_key,
        "normalized_value": normalized.normalized_value,
        "hostname": normalized.hostname,
        "root_domain": normalized.root_domain,
        "parent_key": normalized.parent_key,
        "relation_label": normalized.relation_label,
        "asm_target_id": str(target.id),
        "scan_status": target.scan_status,
        "metadata": {
            "source_type": target.source_type,
            "cloud_region": target.cloud_region,
            "cloud_account_id": target.cloud_account_id,
            "tags": target.tags or [],
            "last_scan_summary": summary,
        },
        "seed": summary.get("seed") or build_seed_metadata(target.target_value, normalized.target_type, source=target.source_type or "asm", stage="candidate"),
        "first_seen": target.created_at.isoformat() if target.created_at else None,
        "last_seen": target.updated_at.isoformat() if target.updated_at else None,
    }


def _normalize_url(value: str) -> NormalizedTarget:
    raw = value.strip()
    parsed = urlparse(raw)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ValidationError(f"Invalid URL target: {value!r}")

    hostname = parsed.hostname.lower()
    host_type = detect_target_type(hostname)
    if host_type == "domain":
        validate_domain(hostname)
        root_domain = infer_root_domain(hostname)
        parent_key = f"host:{hostname}"
    elif host_type == "ip":
        validate_ip(hostname)
        root_domain = None
        parent_key = f"ip:{hostname}"
    else:
        raise ValidationError(f"Unsupported URL hostname: {hostname!r}")

    normalized_path = parsed.path or "/"
    normalized_url = urlunparse(
        (
            parsed.scheme.lower(),
            parsed.netloc.lower(),
            normalized_path,
            "",
            parsed.query,
            "",
        )
    )
    return NormalizedTarget(
        target_type="url",
        normalized_value=normalized_url,
        canonical_key=f"url:{normalized_url}",
        hostname=hostname,
        root_domain=root_domain,
        parent_key=parent_key,
        relation_label="exposed_on",
        seed_type="url",
    )


def _normalize_mcp(value: str) -> NormalizedTarget:
    parsed = _normalize_url(value)
    if not _looks_like_mcp_endpoint(parsed.normalized_value):
        raise ValidationError(f"MCP endpoint should include an MCP-like path: {value!r}")
    return NormalizedTarget(
        target_type="mcp",
        normalized_value=parsed.normalized_value,
        canonical_key=f"mcp:{parsed.normalized_value}",
        hostname=parsed.hostname,
        root_domain=parsed.root_domain,
        parent_key=parsed.parent_key,
        relation_label="served_by",
        seed_type="mcp",
    )


def _normalize_repository(value: str) -> NormalizedTarget:
    cleaned = value.strip()
    match = _REPOSITORY_RE.match(cleaned)
    if not match:
        raise ValidationError(f"Invalid repository target: {value!r}")
    host = (match.group(1) or "github.com").lower()
    owner = match.group(2).lower()
    repo = match.group(3).lower()
    normalized_value = f"{host}/{owner}/{repo}"
    return NormalizedTarget(
        target_type="repository",
        normalized_value=normalized_value,
        canonical_key=f"repo:{normalized_value}",
        hostname=host,
        parent_key=f"host:{host}",
        relation_label="hosted_on",
        seed_type="repository",
    )


def _normalize_cloud_account(value: str) -> NormalizedTarget:
    cleaned = value.strip()
    lowered = cleaned.lower()
    if _AWS_ACCOUNT_RE.match(cleaned):
        normalized_value = f"aws:{cleaned}"
    elif _UUID_RE.match(cleaned):
        normalized_value = f"azure:{lowered}"
    elif _GCP_PROJECT_RE.match(cleaned):
        normalized_value = f"gcp:{lowered}"
    elif ":" in cleaned:
        provider, identifier = cleaned.split(":", 1)
        provider = provider.strip().lower()
        identifier = identifier.strip()
        if not provider or not identifier:
            raise ValidationError(f"Invalid cloud account target: {value!r}")
        normalized_value = f"{provider}:{identifier}"
    else:
        raise ValidationError(f"Invalid cloud account target: {value!r}")
    return NormalizedTarget(
        target_type="cloud_account",
        normalized_value=normalized_value,
        canonical_key=f"cloud:{normalized_value}",
        seed_type="cloud_account",
    )


def _normalize_image(value: str) -> NormalizedTarget:
    cleaned = value.strip().lower()
    if not _looks_like_image(cleaned):
        raise ValidationError(f"Invalid container image target: {value!r}")
    if "@" not in cleaned and ":" not in cleaned.rsplit("/", 1)[-1]:
        cleaned = f"{cleaned}:latest"
    repository = cleaned.split("@", 1)[0]
    registry = repository.split("/", 1)[0] if "/" in repository and ("." in repository.split("/", 1)[0] or ":" in repository.split("/", 1)[0]) else "docker.io"
    return NormalizedTarget(
        target_type="image",
        normalized_value=cleaned,
        canonical_key=f"image:{cleaned}",
        hostname=registry,
        parent_key=f"registry:{registry}",
        relation_label="stored_in",
        seed_type="image",
    )


def _normalize_organization(value: str) -> NormalizedTarget:
    cleaned = value.strip()
    if len(cleaned) < 2:
        raise ValidationError(f"Invalid organization target: {value!r}")
    slug = _ORG_SLUG_RE.sub("-", cleaned.lower()).strip("-")
    if not slug:
        raise ValidationError(f"Invalid organization target: {value!r}")
    return NormalizedTarget(
        target_type="organization",
        normalized_value=cleaned,
        canonical_key=f"org:{slug}",
        seed_type="organization",
    )


def _looks_like_repository(value: str) -> bool:
    return bool(_REPOSITORY_RE.match(value.strip()))


def _looks_like_cloud_account(value: str) -> bool:
    candidate = value.strip()
    return bool(
        _AWS_ACCOUNT_RE.match(candidate)
        or _UUID_RE.match(candidate)
        or _GCP_PROJECT_RE.match(candidate)
    )


def _looks_like_image(value: str) -> bool:
    candidate = value.strip()
    if candidate.startswith(("http://", "https://")):
        return False
    if _looks_like_repository(candidate) or _looks_like_cloud_account(candidate) or _ASN_RE.match(candidate):
        return False
    if "/" not in candidate and ":" not in candidate and "@" not in candidate:
        return False
    return bool(_IMAGE_RE.match(candidate))


def _looks_like_mcp_endpoint(value: str) -> bool:
    parsed = urlparse(value.strip())
    path = (parsed.path or "").lower()
    return path.endswith("/mcp") or "/mcp/" in path or "modelcontextprotocol" in path
