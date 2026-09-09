"""Target-aware authorization checks shared by every active scan entry point."""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urlparse

from fastapi import HTTPException, status
from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.scan_authorization import ScanAuthorization
from app.services.asset_inventory import normalize_asset_identity


@dataclass(frozen=True)
class AuthorizationCoverage:
    authorization_ids: tuple[str, ...]
    targets: tuple[str, ...]
    authorization_type: str

    def as_evidence(self) -> dict:
        return {
            "authorization_ids": list(self.authorization_ids),
            "covered_targets": list(self.targets),
            "authorization_type": self.authorization_type,
            "verified_at": datetime.now(timezone.utc).isoformat(),
        }


def _scope_entries(authorization: ScanAuthorization) -> list[str]:
    entries = [authorization.target.strip()]
    raw_scope = (authorization.scope_file or "").strip()
    if not raw_scope:
        return [entry for entry in entries if entry]
    try:
        decoded = json.loads(raw_scope)
    except json.JSONDecodeError:
        decoded = None
    if isinstance(decoded, list):
        entries.extend(str(item).strip() for item in decoded)
    elif isinstance(decoded, dict):
        for key in ("targets", "include", "scope", "assets"):
            values = decoded.get(key)
            if isinstance(values, list):
                entries.extend(str(item).strip() for item in values)
    else:
        entries.extend(
            part.strip()
            for part in re.split(r"[\n,;]+", raw_scope)
            if part.strip() and not part.lstrip().startswith("#")
        )
    return list(dict.fromkeys(entry for entry in entries if entry))


def _network(value: str):
    try:
        return ipaddress.ip_network(value.strip(), strict=False)
    except ValueError:
        return None


def _address(value: str):
    try:
        return ipaddress.ip_address(value.strip())
    except ValueError:
        return None


def target_matches_scope(target: str, target_type: str, scope: str) -> bool:
    """Return whether one normalized target is contained by one scope entry."""
    target = target.strip()
    scope = scope.strip()
    if not target or not scope:
        return False

    target_net = _network(target) if target_type == "cidr" else None
    target_ip = _address(target) if target_type == "ip" else None
    scope_net = _network(scope)
    if scope_net and (target_ip or target_net):
        if target_ip:
            return target_ip.version == scope_net.version and target_ip in scope_net
        return target_net.version == scope_net.version and target_net.subnet_of(scope_net)

    target_parsed = urlparse(target if "://" in target else f"//{target}")
    scope_parsed = urlparse(scope if "://" in scope else f"//{scope}")
    target_host = (target_parsed.hostname or target).lower().rstrip(".")
    scope_host = (scope_parsed.hostname or scope).lower().rstrip(".")
    wildcard = scope_host.startswith("*.")
    if wildcard:
        scope_host = scope_host[2:]

    host_matches = target_host == scope_host or target_host.endswith(f".{scope_host}")
    if wildcard and target_host == scope_host:
        host_matches = False
    if not host_matches:
        return False

    if "://" in scope:
        if "://" not in target:
            return False
        if target_parsed.scheme.lower() != scope_parsed.scheme.lower():
            return False
        if scope_parsed.port != target_parsed.port:
            return False
        scope_path = (scope_parsed.path or "/").rstrip("/") or "/"
        target_path = (target_parsed.path or "/").rstrip("/") or "/"
        return target_path == scope_path or target_path.startswith(f"{scope_path.rstrip('/')}/")
    return True


def _mode_allows(authorization_type: str, *, passive_only: bool) -> bool:
    if authorization_type == "full":
        return True
    return passive_only and authorization_type in {"passive_only", "read_only"}


async def require_scan_authorization(
    db: AsyncSession,
    *,
    org_id,
    targets: list[tuple[str, str]],
    passive_only: bool = False,
) -> AuthorizationCoverage:
    """Require complete, current scope coverage or reject before dispatch."""
    now = datetime.now(timezone.utc)
    rows = (
        await db.execute(
            select(ScanAuthorization).where(
                and_(
                    ScanAuthorization.org_id == org_id,
                    or_(ScanAuthorization.valid_from.is_(None), ScanAuthorization.valid_from <= now),
                    or_(ScanAuthorization.valid_until.is_(None), ScanAuthorization.valid_until >= now),
                )
            )
        )
    ).scalars().all()
    eligible = [row for row in rows if _mode_allows(row.authorization_type, passive_only=passive_only)]

    normalized_targets: list[tuple[str, str]] = []
    for value, target_type in targets:
        normalized = normalize_asset_identity(target_type, value)
        if normalized.target_type == "file":
            continue
        pair = (normalized.normalized_value, normalized.target_type)
        if pair not in normalized_targets:
            normalized_targets.append(pair)

    matched_ids: set[str] = set()
    uncovered: list[str] = []
    for value, target_type in normalized_targets:
        matches = [
            row for row in eligible
            if any(target_matches_scope(value, target_type, entry) for entry in _scope_entries(row))
        ]
        if not matches:
            uncovered.append(value)
        else:
            matched_ids.update(str(row.id) for row in matches)

    if not normalized_targets:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            {"code": "SCAN_TARGETS_EMPTY", "message": "No scannable targets were supplied."},
        )
    if uncovered:
        shown = uncovered[:20]
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            {
                "code": "SCAN_AUTHORIZATION_REQUIRED",
                "message": "Every target must be covered by a current scan authorization before execution.",
                "uncovered_targets": shown,
                "uncovered_count": len(uncovered),
                "truncated": len(uncovered) > len(shown),
                "required_type": "passive_only or full" if passive_only else "full",
            },
        )

    return AuthorizationCoverage(
        authorization_ids=tuple(sorted(matched_ids)),
        targets=tuple(value for value, _ in normalized_targets),
        authorization_type="passive_only" if passive_only else "full",
    )
