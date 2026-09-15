from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import json
import socket
from typing import Literal
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
from uuid import UUID

from fastapi import Depends, Header, HTTPException, status

from .auth import current_user
from .config import settings
from .db import pool
from .secrets import decrypt_secret


ExposureRole = Literal["owner", "admin", "analyst", "viewer"]


def require_exposure_role(workspace: dict, *allowed: ExposureRole) -> None:
    if workspace["membership_role"] not in allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Your workspace role does not permit this exposure-management action",
        )


async def exposure_workspace(
    user: dict = Depends(current_user),
    organization_id: UUID | None = Header(default=None, alias="X-ESX-Organization"),
) -> dict:
    """Resolve the active organization before accessing exposure-management data."""
    if organization_id is None:
        row = await pool().fetchrow(
            """
            SELECT o.id, o.name, o.slug, m.role AS membership_role
            FROM organization_memberships m
            JOIN organizations o ON o.id = m.organization_id
            WHERE m.user_id = $1 AND o.active = true
            ORDER BY CASE m.role
              WHEN 'owner' THEN 1 WHEN 'admin' THEN 2 WHEN 'analyst' THEN 3 ELSE 4 END,
              m.joined_at
            LIMIT 1
            """,
            user["id"],
        )
    else:
        row = await pool().fetchrow(
            """
            SELECT o.id, o.name, o.slug, m.role AS membership_role
            FROM organization_memberships m
            JOIN organizations o ON o.id = m.organization_id
            WHERE m.user_id = $1 AND m.organization_id = $2 AND o.active = true
            """,
            user["id"], organization_id,
        )
    if row is None:
        raise HTTPException(status_code=403, detail="No active workspace membership was found")
    return {**dict(row), "user_id": user["id"]}


async def workspace_assessment(workspace: dict, assessment_id: UUID, *, lock: bool = False) -> dict:
    row = await pool().fetchrow(
        f"""
        SELECT * FROM assessments
        WHERE id = $1 AND organization_id = $2
        {'FOR UPDATE' if lock else ''}
        """,
        assessment_id, workspace["id"],
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Assessment not found in this workspace")
    return dict(row)


async def record_exposure_audit_event(
    workspace: dict,
    event_type: str,
    *,
    target_type: str,
    target_id: UUID | None = None,
    payload: dict | None = None,
) -> None:
    """Write a non-sensitive, append-only record of a client-visible action."""
    await pool().execute(
        """
        INSERT INTO exposure_audit_events (
          organization_id, actor_id, event_type, target_type, target_id, payload
        ) VALUES ($1, $2, $3, $4, $5, $6::jsonb)
        """,
        workspace["id"], workspace["user_id"], event_type, target_type, target_id,
        payload or {},
    )


def _global_ownership_status(status: str) -> str:
    return {
        "approved": "verified",
        "excluded": "excluded",
        "client_declared": "client_declared",
        "candidate": "candidate",
    }.get(status, "candidate")


def _combine_ownership(existing: str, incoming: str) -> str:
    """Never let passive observation silently weaken or strengthen human review."""
    if existing == "excluded" or incoming == "excluded":
        return "excluded"
    if existing == "verified" or incoming == "verified":
        return "verified"
    if existing == "client_declared" or incoming == "client_declared":
        return "client_declared"
    return "candidate"


def _json_hash(payload: dict) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    ).hexdigest()


async def enqueue_integration_deliveries(
    conn,
    organization_id: UUID,
    event_type: str,
    payload: dict,
) -> None:
    """Create a durable outbox entry; the runner owns outbound delivery and retries."""
    integrations = await conn.fetch(
        """
        SELECT id FROM exposure_integrations
        WHERE organization_id = $1 AND status = 'active'
          AND event_types ? $2
          AND integration_type IN ('webhook', 'siem')
        """,
        organization_id, event_type,
    )
    public_payload = {"event_type": event_type, "data": payload}
    for integration in integrations:
        idempotency_key = _json_hash({"integration_id": str(integration["id"]), **public_payload})
        await conn.execute(
            """
            INSERT INTO exposure_delivery_events (
              integration_id, organization_id, event_type, idempotency_key, payload
            ) VALUES ($1, $2, $3, $4, $5::jsonb)
            ON CONFLICT (idempotency_key) DO NOTHING
            """,
            integration["id"], organization_id, event_type, idempotency_key, public_payload,
        )


async def upsert_exposure_asset(
    conn,
    organization_id: UUID,
    asset: dict,
    *,
    actor_id: UUID | None = None,
    parent_hostname: str | None = None,
) -> dict:
    """Correlate an assessment asset with the durable organization asset graph."""
    hostname = str(asset["hostname"]).lower()
    incoming_status = _global_ownership_status(str(asset["ownership_status"]))
    sources = list(asset.get("discovery_sources") or [])
    evidence = dict(asset.get("discovery_evidence") or {})
    existing = await conn.fetchrow(
        """SELECT * FROM exposure_assets
           WHERE organization_id = $1 AND hostname = $2 FOR UPDATE""",
        organization_id, hostname,
    )
    if existing is None:
        row = await conn.fetchrow(
            """
            INSERT INTO exposure_assets (
              organization_id, hostname, canonical_target, asset_type, ownership_status,
              ownership_confidence, ownership_evidence, discovery_sources, last_verified_at,
              reviewed_by, reviewed_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8::jsonb,
                      CASE WHEN $5 = 'verified' THEN now() ELSE NULL END,
                      CASE WHEN $5 = 'verified' THEN $9 ELSE NULL END,
                      CASE WHEN $5 = 'verified' THEN now() ELSE NULL END)
            RETURNING *
            """,
            organization_id, hostname, asset["canonical_target"],
            "api" if asset.get("asset_type") == "api" else asset.get("asset_type", "hostname"),
            incoming_status, int(asset.get("ownership_confidence") or 0), evidence, sources, actor_id,
        )
        event_type = "asset.discovered"
        event_payload = {"hostname": hostname, "sources": sources, "ownership_status": incoming_status}
        await conn.execute(
            """INSERT INTO exposure_asset_events (organization_id, asset_id, event_type, actor_id, payload)
               VALUES ($1, $2, $3, $4, $5::jsonb)""",
            organization_id, row["id"], event_type, actor_id, event_payload,
        )
        await enqueue_integration_deliveries(conn, organization_id, event_type, event_payload)
    else:
        merged_sources = sorted(set(list(existing["discovery_sources"] or []) + sources))
        merged_status = _combine_ownership(str(existing["ownership_status"]), incoming_status)
        row = await conn.fetchrow(
            """
            UPDATE exposure_assets
            SET canonical_target = $3,
                ownership_status = $4,
                ownership_confidence = GREATEST(ownership_confidence, $5),
                ownership_evidence = ownership_evidence || $6::jsonb,
                discovery_sources = $7::jsonb,
                lifecycle_status = 'active',
                last_seen_at = now(), updated_at = now()
            WHERE id = $1 AND organization_id = $2
            RETURNING *
            """,
            existing["id"], organization_id, asset["canonical_target"], merged_status,
            int(asset.get("ownership_confidence") or 0), evidence, merged_sources,
        )

    observation_payload = {"sources": sources, "evidence": evidence}
    await conn.execute(
        """
        INSERT INTO exposure_asset_observations (
          organization_id, asset_id, source, source_reference, payload_sha256, payload
        ) VALUES ($1, $2, $3, $4, $5, $6::jsonb)
        ON CONFLICT (asset_id, source, payload_sha256) DO UPDATE SET observed_at = now()
        """,
        organization_id, row["id"], sources[0] if sources else "unattributed",
        str(evidence.get("query") or evidence.get("source") or "")[:512],
        _json_hash(observation_payload), observation_payload,
    )

    if parent_hostname and parent_hostname.lower() != hostname:
        parent = await conn.fetchrow(
            """SELECT id FROM exposure_assets WHERE organization_id = $1 AND hostname = $2""",
            organization_id, parent_hostname.lower(),
        )
        if parent:
            await conn.execute(
                """
                INSERT INTO exposure_asset_relations (
                  organization_id, source_asset_id, target_asset_id, relation_type, confidence, evidence
                ) VALUES ($1, $2, $3, 'subdomain_of', 100, $4::jsonb)
                ON CONFLICT (source_asset_id, target_asset_id, relation_type)
                DO UPDATE SET last_seen_at = now(), evidence = exposure_asset_relations.evidence || EXCLUDED.evidence
                """,
                organization_id, row["id"], parent["id"], {"parent_hostname": parent_hostname.lower()},
            )
    return dict(row)


async def sync_assessment_asset(
    conn,
    organization_id: UUID,
    assessment_asset: dict,
    *,
    actor_id: UUID | None = None,
    parent_hostname: str | None = None,
) -> dict:
    exposure_asset = await upsert_exposure_asset(
        conn, organization_id, assessment_asset, actor_id=actor_id, parent_hostname=parent_hostname
    )
    await conn.execute(
        "UPDATE assessment_assets SET exposure_asset_id = $2 WHERE id = $1",
        assessment_asset["id"], exposure_asset["id"],
    )
    return exposure_asset


async def sync_scan_finding_lifecycle(scan_id: UUID, scan_status: str) -> None:
    """Promote confirmed scan observations into a durable, conservative finding history."""
    async with pool().acquire() as conn, conn.transaction():
        scan = await conn.fetchrow(
            """SELECT s.id, s.assessment_id, a.organization_id
               FROM scans s JOIN assessments a ON a.id = s.assessment_id WHERE s.id = $1""",
            scan_id,
        )
        if scan is None:
            return
        observed = await conn.fetch(
            """
            SELECT DISTINCT ON (f.id)
                   f.fingerprint, f.title, f.severity, f.scan_id,
                   aa.exposure_asset_id AS asset_id,
                   COALESCE(fa.validation_status, 'candidate') AS validation_status
            FROM findings f
            LEFT JOIN finding_assurance fa ON fa.finding_id = f.id
            LEFT JOIN assessment_asset_scans aas ON aas.scan_id = f.scan_id
            LEFT JOIN assessment_assets aa ON aa.id = aas.assessment_asset_id
            WHERE f.scan_id = $1 AND f.severity <> 'info'
            ORDER BY f.id, aa.exposure_asset_id NULLS LAST
            """,
            scan_id,
        )
        for item in observed:
            previous = await conn.fetchrow(
                """SELECT id, lifecycle_status FROM exposure_findings
                   WHERE organization_id = $1 AND fingerprint = $2 FOR UPDATE""",
                scan["organization_id"], item["fingerprint"],
            )
            if previous is None:
                finding = await conn.fetchrow(
                    """
                    INSERT INTO exposure_findings (
                      organization_id, asset_id, fingerprint, title, severity, validation_status,
                      first_seen_scan_id, last_seen_scan_id
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $7)
                    RETURNING *
                    """,
                    scan["organization_id"], item["asset_id"], item["fingerprint"], item["title"],
                    item["severity"], item["validation_status"], scan_id,
                )
                event_type = "finding.opened"
            else:
                finding = await conn.fetchrow(
                    """
                    UPDATE exposure_findings
                    SET asset_id = COALESCE($3, asset_id), title = $4, severity = $5,
                        validation_status = $6, last_seen_scan_id = $7, last_seen_at = now(),
                        lifecycle_status = CASE WHEN lifecycle_status = 'resolved' THEN 'open' ELSE lifecycle_status END,
                        resolved_at = CASE WHEN lifecycle_status = 'resolved' THEN NULL ELSE resolved_at END,
                        updated_at = now()
                    WHERE id = $1 AND organization_id = $2
                    RETURNING *
                    """,
                    previous["id"], scan["organization_id"], item["asset_id"], item["title"],
                    item["severity"], item["validation_status"], scan_id,
                )
                event_type = "finding.reopened" if previous["lifecycle_status"] == "resolved" else "finding.observed"
            event_payload = {"title": item["title"], "severity": item["severity"], "scan_id": str(scan_id)}
            await conn.execute(
                """INSERT INTO exposure_finding_events (organization_id, finding_id, event_type, payload)
                   VALUES ($1, $2, $3, $4::jsonb)""",
                scan["organization_id"], finding["id"], event_type, event_payload,
            )
            if event_type in {"finding.opened", "finding.reopened"}:
                await enqueue_integration_deliveries(conn, scan["organization_id"], "finding.opened", event_payload)

        # A clean lifecycle transition is allowed only after every required stage completed.
        if scan_status == "complete":
            resolved = await conn.fetch(
                """
                UPDATE exposure_findings
                SET lifecycle_status = 'resolved', resolved_at = now(), updated_at = now()
                WHERE organization_id = $1
                  AND lifecycle_status IN ('open', 'needs_revalidation')
                  AND asset_id IN (
                    SELECT DISTINCT aa.exposure_asset_id
                    FROM assessment_asset_scans aas
                    JOIN assessment_assets aa ON aa.id = aas.assessment_asset_id
                    WHERE aas.scan_id = $2 AND aa.exposure_asset_id IS NOT NULL
                  )
                  AND last_seen_scan_id IS DISTINCT FROM $2
                RETURNING id, title, severity
                """,
                scan["organization_id"], scan_id,
            )
            for finding in resolved:
                payload = {"title": finding["title"], "severity": finding["severity"], "scan_id": str(scan_id)}
                await conn.execute(
                    """INSERT INTO exposure_finding_events (organization_id, finding_id, event_type, payload)
                       VALUES ($1, $2, 'finding.resolved', $3::jsonb)""",
                    scan["organization_id"], finding["id"], payload,
                )
                await enqueue_integration_deliveries(conn, scan["organization_id"], "finding.resolved", payload)

        await enqueue_integration_deliveries(
            conn, scan["organization_id"], "scan.completed",
            {"scan_id": str(scan_id), "status": scan_status, "assessment_id": str(scan["assessment_id"])},
        )


def validate_integration_endpoint_url(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme not in {"https", "http"} or not parsed.hostname:
        raise ValueError("integration endpoint must be an absolute HTTP(S) URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("integration endpoint cannot contain credentials, a query string, or a fragment")
    hostname = parsed.hostname.lower()
    is_local = hostname == "localhost" or hostname.startswith("127.") or hostname == "::1"
    if parsed.scheme != "https" and (settings().deployment_mode == "production" or not is_local):
        raise ValueError("integration endpoints must use HTTPS outside local development")
    allowed = {item.strip().lower() for item in settings().exposure_integration_allowed_hosts.split(",") if item.strip()}
    if settings().deployment_mode == "production" and hostname not in allowed:
        raise ValueError("integration host is not in the production egress allowlist")
    return value


def assert_integration_network_allowed(endpoint: str) -> None:
    parsed = urlsplit(validate_integration_endpoint_url(endpoint))
    hostname = parsed.hostname
    assert hostname is not None
    try:
        resolved = socket.getaddrinfo(hostname, parsed.port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM)
    except OSError as exc:
        raise RuntimeError("integration host could not be resolved") from exc
    private_networks = [
        ipaddress.ip_network(value.strip(), strict=False)
        for value in settings().exposure_integration_private_networks.split(",") if value.strip()
    ]
    is_local = hostname.lower() == "localhost" or hostname.startswith("127.") or hostname == "::1"
    for record in resolved:
        address = ipaddress.ip_address(record[4][0])
        if address.is_global:
            continue
        if settings().deployment_mode != "production" and is_local:
            continue
        if any(address in network for network in private_networks):
            continue
        raise RuntimeError("integration destination resolved to a blocked private or reserved address")


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: N802
        return None


def send_integration_delivery(endpoint: str, signing_secret: str, event_type: str, payload: dict) -> None:
    """Deliver a signed webhook without following redirects across the egress boundary."""
    assert_integration_network_allowed(endpoint)
    content = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    signature = hmac.new(signing_secret.encode("utf-8"), content, hashlib.sha256).hexdigest()
    request = Request(
        endpoint, data=content, method="POST",
        headers={
            "Content-Type": "application/json",
            "User-Agent": "ExposureScopeX/3.0 delivery",
            "X-ESX-Event": event_type,
            "X-ESX-Signature-256": f"sha256={signature}",
        },
    )
    try:
        response = build_opener(_NoRedirect()).open(request, timeout=10)
        with response:
            if not 200 <= response.status < 300:
                raise RuntimeError(f"integration returned HTTP {response.status}")
    except HTTPError as exc:
        raise RuntimeError(f"integration returned HTTP {exc.code}") from exc
    except URLError as exc:
        raise RuntimeError("integration delivery could not reach its configured endpoint") from exc


async def deliver_one_pending_integration() -> bool:
    """Claim and deliver one outbox record with bounded retries for runner reliability."""
    async with pool().acquire() as conn, conn.transaction():
        row = await conn.fetchrow(
            """
            SELECT de.*, i.endpoint_ciphertext, i.secret_ciphertext, i.status AS integration_status
            FROM exposure_delivery_events de
            JOIN exposure_integrations i ON i.id = de.integration_id
            WHERE de.status = 'pending' AND de.next_attempt_at <= now() AND i.status = 'active'
            ORDER BY de.created_at
            FOR UPDATE OF de SKIP LOCKED
            LIMIT 1
            """
        )
        if row is None:
            return False
        if row["endpoint_ciphertext"] is None or row["secret_ciphertext"] is None:
            await conn.execute(
                """UPDATE exposure_delivery_events SET status = 'abandoned', last_error = 'Integration credentials are unavailable', updated_at = now()
                   WHERE id = $1""", row["id"]
            )
            return True
        attempt = int(row["attempts"]) + 1
        await conn.execute(
            """UPDATE exposure_delivery_events
               SET attempts = $2, next_attempt_at = now() + interval '5 minutes', updated_at = now()
               WHERE id = $1""", row["id"], attempt
        )

    try:
        endpoint = decrypt_secret(bytes(row["endpoint_ciphertext"]))
        secret = decrypt_secret(bytes(row["secret_ciphertext"]))
        await asyncio.to_thread(send_integration_delivery, endpoint, secret, row["event_type"], dict(row["payload"]))
    except Exception as exc:
        delay_minutes = min(60, 2 ** min(attempt, 6))
        terminal = attempt >= 5
        async with pool().acquire() as conn:
            await conn.execute(
                """UPDATE exposure_delivery_events
                   SET status = CASE WHEN $2 THEN 'abandoned' ELSE 'pending' END,
                       next_attempt_at = now() + make_interval(mins => $3),
                       last_error = $4, updated_at = now()
                   WHERE id = $1""",
                row["id"], terminal, delay_minutes, f"{type(exc).__name__}: {exc}"[:1000],
            )
        return True

    async with pool().acquire() as conn:
        await conn.execute(
            """UPDATE exposure_delivery_events
               SET status = 'delivered', delivered_at = now(), last_error = NULL, updated_at = now()
               WHERE id = $1""", row["id"]
        )
    return True
