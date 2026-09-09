"""Attack Surface Management — target inventory, cloud sources, scanning, findings."""

import asyncio
import csv
import io
import re
import socket
import ssl
import uuid
from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import urlparse

import httpx
from fastapi.encoders import jsonable_encoder
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, UploadFile, File, status
from pydantic import BaseModel
from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import async_session_factory, get_db
from app.dependencies import get_current_user, require_role
from app.models.asm import AsmCloudSource, AsmFinding, AsmTarget
from app.models.user import User
from app.services.asset_inventory import build_seed_metadata, detect_target_type, normalize_target
from app.services.audit import AuditEvent, write_audit
from app.services.encryption import decrypt_dict, encrypt_dict, mask_secrets
from app.services.intake_parser import parse_csv_row
from app.services.scan_profiles import get_scan_profile
from app.services.scan_authorization import require_scan_authorization
from app.services.validation import ValidationError as TargetValidationError
from app.services.validation import resolve_and_check, validate_target

router = APIRouter(prefix="/asm", tags=["asm"])

TIMEOUT = 15.0
_DOH = "https://cloudflare-dns.com/dns-query"
_SECURITY_HEADERS = {
    "strict-transport-security": ("HSTS", "HIGH"),
    "content-security-policy": ("Content-Security-Policy", "HIGH"),
    "x-frame-options": ("X-Frame-Options", "MEDIUM"),
    "x-content-type-options": ("X-Content-Type-Options", "LOW"),
    "referrer-policy": ("Referrer-Policy", "LOW"),
    "permissions-policy": ("Permissions-Policy", "LOW"),
}


# ── Schemas ───────────────────────────────────────────────────────────────────

class TargetCreate(BaseModel):
    name: str
    target_value: str
    target_type: str = "auto"  # ip / cidr / domain / hostname / asn / repository / cloud_account / organization / mcp
    source_type: str = "manual"
    cloud_region: Optional[str] = None
    cloud_account_id: Optional[str] = None
    tags: list[str] = []
    notes: Optional[str] = None


class TargetUpdate(BaseModel):
    name: Optional[str] = None
    tags: Optional[list[str]] = None
    notes: Optional[str] = None


class CloudSourceCreate(BaseModel):
    name: str
    provider: str  # aws / gcp / azure / onprem
    config: dict = {}


class FindingStatusUpdate(BaseModel):
    status: str  # new / confirmed / false_positive / remediated / approved_exception / accepted_risk / compensating_control / not_exploitable


# ── Helpers ───────────────────────────────────────────────────────────────────

def _clean(v: str) -> str:
    v = v.strip()
    v = re.sub(r"^https?://", "", v)
    return v.split("/")[0].split(":")[0].lower()


def _detect_type(value: str) -> str:
    return detect_target_type(value)


def _serialize(obj: AsmTarget | AsmCloudSource | AsmFinding) -> dict:
    return {
        c.name: getattr(obj, c.name)
        for c in obj.__table__.columns
    }


# ── Targets ───────────────────────────────────────────────────────────────────

@router.get("/targets")
async def list_targets(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(AsmTarget).where(AsmTarget.org_id == current_user.org_id)
        .order_by(AsmTarget.created_at.desc())
    )
    return [_serialize(t) for t in result.scalars().all()]


@router.post("/targets", status_code=status.HTTP_201_CREATED)
async def add_target(
    body: TargetCreate,
    request: Request,
    current_user: User = Depends(require_role("admin", "manager", "analyst")),
    db: AsyncSession = Depends(get_db),
):
    try:
        normalized = normalize_target(
            body.target_value.strip(),
            body.target_type if body.target_type != "auto" else _detect_type(body.target_value),
        )
    except TargetValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    existing = (
        await db.execute(
            select(AsmTarget).where(
                and_(
                    AsmTarget.org_id == current_user.org_id,
                    AsmTarget.target_type == normalized.target_type,
                    AsmTarget.target_value == normalized.normalized_value,
                )
            )
        )
    ).scalar_one_or_none()
    if existing:
        merged_tags = sorted(set((existing.tags or []) + (body.tags or [])))
        existing.name = body.name or existing.name
        existing.tags = merged_tags
        existing.notes = body.notes or existing.notes
        existing.source_type = existing.source_type or body.source_type
        existing.updated_at = datetime.now(timezone.utc)
        await db.flush()
        await db.refresh(existing)
        payload = _serialize(existing)
        payload["deduplicated"] = True
        return jsonable_encoder(payload)

    t = AsmTarget(
        id=uuid.uuid4(),
        org_id=current_user.org_id,
        created_by=current_user.id,
        name=body.name,
        target_value=normalized.normalized_value,
        target_type=normalized.target_type,
        source_type=body.source_type,
        cloud_region=body.cloud_region,
        cloud_account_id=body.cloud_account_id,
        tags=body.tags,
        notes=body.notes,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    db.add(t)
    await db.flush()
    await db.refresh(t)
    await write_audit(
        db,
        event=AuditEvent.ASM_TARGET_CREATE,
        user_id=str(current_user.id),
        org_id=str(current_user.org_id),
        resource_type="asm_target",
        resource_id=str(t.id),
        details={"name": t.name, "target_value": t.target_value},
        ip_address=request.client.host if request.client else None,
    )
    return _serialize(t)


@router.post("/targets/import")
async def import_csv(
    file: UploadFile = File(...),
    current_user: User = Depends(require_role("admin", "manager", "analyst")),
    db: AsyncSession = Depends(get_db),
):
    """Import ASM targets from a flexible CSV and normalize before persisting."""
    content = await file.read()
    try:
        text = content.decode("utf-8")
    except Exception:
        raise HTTPException(400, "File must be UTF-8 encoded CSV")

    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        raise HTTPException(400, "CSV is missing a header row")
    added, skipped = 0, 0
    errors = []
    seen_keys: set[str] = set()
    saw_row = False

    for i, row in enumerate(reader, start=2):
        saw_row = True
        try:
            parsed = parse_csv_row(row)
            normalized = normalize_target(
                parsed["target"],
                parsed["target_type"] if parsed["target_type"] != "auto" else _detect_type(parsed["target"]),
            )
            if normalized.canonical_key in seen_keys:
                skipped += 1
                continue

            existing = (
                await db.execute(
                    select(AsmTarget).where(
                        and_(
                            AsmTarget.org_id == current_user.org_id,
                            AsmTarget.target_type == normalized.target_type,
                            AsmTarget.target_value == normalized.normalized_value,
                        )
                    )
                )
            ).scalar_one_or_none()
            if existing:
                existing.tags = sorted(set((existing.tags or []) + (parsed["tags"] or [])))
                existing.notes = existing.notes or parsed["notes"]
                existing.updated_at = datetime.now(timezone.utc)
                skipped += 1
                seen_keys.add(normalized.canonical_key)
                continue
            t = AsmTarget(
                id=uuid.uuid4(),
                org_id=current_user.org_id,
                created_by=current_user.id,
                name=parsed["name"],
                target_value=normalized.normalized_value,
                target_type=normalized.target_type,
                source_type="csv",
                tags=parsed["tags"],
                notes=parsed["notes"],
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
            )
            db.add(t)
            added += 1
            seen_keys.add(normalized.canonical_key)
        except Exception as e:
            errors.append(f"Row {i}: {e}")

    if not saw_row:
        raise HTTPException(400, "CSV contains a header row but no data rows to import")

    await db.flush()
    return {"added": added, "skipped": skipped, "errors": errors}


@router.patch("/targets/{target_id}")
async def update_target(
    target_id: uuid.UUID,
    body: TargetUpdate,
    current_user: User = Depends(require_role("admin", "manager", "analyst")),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(AsmTarget).where(
            and_(AsmTarget.id == target_id, AsmTarget.org_id == current_user.org_id)
        )
    )
    t = result.scalar_one_or_none()
    if not t:
        raise HTTPException(404, "Target not found")
    if body.name is not None:
        t.name = body.name
    if body.tags is not None:
        t.tags = body.tags
    if body.notes is not None:
        t.notes = body.notes
    t.updated_at = datetime.now(timezone.utc)
    await db.flush()
    await db.refresh(t)
    return _serialize(t)


@router.delete("/targets/{target_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_target(
    target_id: uuid.UUID,
    request: Request,
    current_user: User = Depends(require_role("admin", "manager")),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(AsmTarget).where(
            and_(AsmTarget.id == target_id, AsmTarget.org_id == current_user.org_id)
        )
    )
    t = result.scalar_one_or_none()
    if not t:
        raise HTTPException(404, "Target not found")
    await write_audit(
        db,
        event=AuditEvent.ASM_TARGET_DELETE,
        user_id=str(current_user.id),
        org_id=str(current_user.org_id),
        resource_type="asm_target",
        resource_id=str(t.id),
        details={"target_value": t.target_value},
        ip_address=request.client.host if request.client else None,
    )
    await db.delete(t)
    await db.flush()


# ── Cloud Sources ─────────────────────────────────────────────────────────────

@router.get("/cloud-sources")
async def list_cloud_sources(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(AsmCloudSource).where(AsmCloudSource.org_id == current_user.org_id)
        .order_by(AsmCloudSource.created_at.desc())
    )
    sources = result.scalars().all()
    out = []
    for s in sources:
        d = _serialize(s)
        # strip secrets from config before returning
        safe_config = {k: v for k, v in (d.get("config") or {}).items()
                       if "secret" not in k.lower() and "key" not in k.lower() and "password" not in k.lower()}
        d["config"] = safe_config
        out.append(d)
    return out


@router.post("/cloud-sources", status_code=status.HTTP_201_CREATED)
async def add_cloud_source(
    body: CloudSourceCreate,
    request: Request,
    current_user: User = Depends(require_role("admin", "manager")),
    db: AsyncSession = Depends(get_db),
):
    # Encrypt credentials before persisting — stored as opaque ciphertext
    encrypted_config = encrypt_dict(body.config) if body.config else ""
    s = AsmCloudSource(
        id=uuid.uuid4(),
        org_id=current_user.org_id,
        created_by=current_user.id,
        name=body.name,
        provider=body.provider,
        config={"_encrypted": encrypted_config},   # stored as {"_encrypted": "<ciphertext>"}
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    db.add(s)
    await db.flush()
    await db.refresh(s)
    await write_audit(
        db,
        event=AuditEvent.ASM_CLOUD_SOURCE_CREATE,
        user_id=str(current_user.id),
        org_id=str(current_user.org_id),
        resource_type="asm_cloud_source",
        resource_id=str(s.id),
        details={"name": s.name, "provider": s.provider},
        ip_address=request.client.host if request.client else None,
    )
    result = _serialize(s)
    result["config"] = {}   # never return raw config
    return result


@router.delete("/cloud-sources/{source_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_cloud_source(
    source_id: uuid.UUID,
    current_user: User = Depends(require_role("admin", "manager")),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(AsmCloudSource).where(
            and_(AsmCloudSource.id == source_id, AsmCloudSource.org_id == current_user.org_id)
        )
    )
    s = result.scalar_one_or_none()
    if not s:
        raise HTTPException(404, "Cloud source not found")
    await db.delete(s)
    await db.flush()


# ── Scan dispatch helper ──────────────────────────────────────────────────────

def _dispatch_asm_scan(target_id: str, org_id: str) -> str:
    """Send scan to Celery queue; fall back to asyncio thread if broker unavailable."""
    try:
        from app.services.celery_app import run_asm_scan
        result = run_asm_scan.apply_async(args=[target_id, org_id], queue="scans")
        return result.id
    except Exception:
        # Celery not reachable (dev/test without worker) — run in-process
        import threading
        import asyncio

        def _thread():
            asyncio.run(_run_asm_scan(target_id, org_id))

        t = threading.Thread(target=_thread, daemon=True)
        t.start()
        return f"thread-{target_id[:8]}"


async def _mark_asm_cancel_requested(
    db: AsyncSession,
    target: AsmTarget,
    *,
    task_id: str | None = None,
) -> None:
    summary = dict(target.last_scan_summary or {})
    summary["cancel_requested"] = True
    summary["cancel_requested_at"] = datetime.now(timezone.utc).isoformat()
    if task_id:
        summary.setdefault("dispatch", {})
        summary["dispatch"]["task_id"] = task_id
    target.scan_status = "cancelled"
    target.last_scan_summary = summary
    target.updated_at = datetime.now(timezone.utc)
    await db.flush()


async def _asm_cancel_requested(target_id: str) -> bool:
    async with async_session_factory() as db:
        result = await db.execute(select(AsmTarget).where(AsmTarget.id == uuid.UUID(target_id)))
        target = result.scalar_one_or_none()
        if not target:
            return True
        summary = target.last_scan_summary or {}
        return target.scan_status == "cancelled" or bool(summary.get("cancel_requested"))


# ── Scan ──────────────────────────────────────────────────────────────────────

@router.post("/targets/{target_id}/scan")
async def scan_target(
    target_id: uuid.UUID,
    request: Request,
    current_user: User = Depends(require_role("admin", "manager", "analyst")),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(AsmTarget).where(
            and_(AsmTarget.id == target_id, AsmTarget.org_id == current_user.org_id)
        )
    )
    t = result.scalar_one_or_none()
    if not t:
        raise HTTPException(404, "Target not found")
    if t.scan_status == "scanning":
        raise HTTPException(409, "Scan already in progress")

    authorization = await require_scan_authorization(
        db,
        org_id=current_user.org_id,
        targets=[(t.target_value, t.target_type)],
    )

    t.scan_status = "scanning"
    t.last_scan_summary = {
        **(t.last_scan_summary or {}),
        "dispatch": {"status": "queued"},
        "cancel_requested": False,
        "authorization": authorization.as_evidence(),
    }
    t.updated_at = datetime.now(timezone.utc)
    await db.flush()

    # Dispatch to Celery; fall back to asyncio BackgroundTask if Celery unavailable
    celery_task_id = _dispatch_asm_scan(str(target_id), str(current_user.org_id))
    t.last_scan_summary = {
        **(t.last_scan_summary or {}),
        "dispatch": {
            "task_id": celery_task_id,
            "transport": "celery" if not celery_task_id.startswith("thread-") else "thread",
            "status": "queued",
        },
        "cancel_requested": False,
    }
    await db.flush()

    await write_audit(
        db,
        event=AuditEvent.ASM_SCAN_START,
        user_id=str(current_user.id),
        org_id=str(current_user.org_id),
        resource_type="asm_target",
        resource_id=str(target_id),
        details={"celery_task_id": celery_task_id},
        ip_address=request.client.host if request.client else None,
    )
    return {"message": "Scan queued", "target_id": str(target_id), "task_id": celery_task_id}


@router.post("/targets/{target_id}/cancel")
async def cancel_target_scan(
    target_id: uuid.UUID,
    request: Request,
    current_user: User = Depends(require_role("admin", "manager", "analyst")),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(AsmTarget).where(
            and_(AsmTarget.id == target_id, AsmTarget.org_id == current_user.org_id)
        )
    )
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(404, "Target not found")
    if target.scan_status != "scanning":
        raise HTTPException(409, "No ASM scan is currently running for this target")

    summary = dict(target.last_scan_summary or {})
    task_id = ((summary.get("dispatch") or {}).get("task_id"))
    await _mark_asm_cancel_requested(db, target, task_id=task_id)

    if task_id and not str(task_id).startswith("thread-"):
        try:
            from app.services.celery_app import celery_app

            celery_app.control.revoke(task_id, terminate=True)
        except Exception:
            pass

    await write_audit(
        db,
        event=AuditEvent.ASM_SCAN_START,
        user_id=str(current_user.id),
        org_id=str(current_user.org_id),
        resource_type="asm_target",
        resource_id=str(target_id),
        details={"action": "cancel_requested", "celery_task_id": task_id},
        ip_address=request.client.host if request.client else None,
    )
    return {"message": "Cancel requested", "target_id": str(target_id), "task_id": task_id}


@router.post("/scan-all")
async def scan_all_targets(
    request: Request,
    current_user: User = Depends(require_role("admin", "manager", "analyst")),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(AsmTarget).where(
            and_(
                AsmTarget.org_id == current_user.org_id,
                AsmTarget.scan_status != "scanning",
            )
        )
    )
    targets = result.scalars().all()
    if targets:
        authorization = await require_scan_authorization(
            db,
            org_id=current_user.org_id,
            targets=[(target.target_value, target.target_type) for target in targets],
        )
    started = []
    for t in targets:
        t.scan_status = "scanning"
        t.last_scan_summary = {
            **(t.last_scan_summary or {}),
            "dispatch": {"status": "queued"},
            "cancel_requested": False,
            "authorization": authorization.as_evidence(),
        }
        t.updated_at = datetime.now(timezone.utc)
        task_id = _dispatch_asm_scan(str(t.id), str(current_user.org_id))
        t.last_scan_summary = {
            **(t.last_scan_summary or {}),
            "dispatch": {
                "task_id": task_id,
                "transport": "celery" if not task_id.startswith("thread-") else "thread",
                "status": "queued",
            },
            "cancel_requested": False,
        }
        started.append({"target_id": str(t.id), "task_id": task_id})

    await db.flush()
    return {"message": f"Queued {len(started)} scans", "tasks": started}


# ── Findings ──────────────────────────────────────────────────────────────────

@router.get("/findings")
async def list_findings(
    target_id: Optional[str] = None,
    severity: Optional[str] = None,
    source: Optional[str] = None,
    finding_status: Optional[str] = None,
    page: int = 1,
    page_size: int = 100,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    q = select(AsmFinding).where(AsmFinding.org_id == current_user.org_id)
    if target_id:
        q = q.where(AsmFinding.target_id == uuid.UUID(target_id))
    if severity:
        q = q.where(AsmFinding.severity == severity.upper())
    if source:
        q = q.where(AsmFinding.source == source)
    if finding_status:
        q = q.where(AsmFinding.status == finding_status)

    count_q = q
    total_result = await db.execute(count_q)
    total = len(total_result.scalars().all())

    q = q.order_by(AsmFinding.created_at.desc()).offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(q)
    items = [_serialize(f) for f in result.scalars().all()]

    return {"items": items, "total": total, "page": page, "page_size": page_size}


@router.patch("/findings/{finding_id}/status")
async def update_finding_status(
    finding_id: uuid.UUID,
    body: FindingStatusUpdate,
    current_user: User = Depends(require_role("admin", "manager", "analyst")),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(AsmFinding).where(
            and_(AsmFinding.id == finding_id, AsmFinding.org_id == current_user.org_id)
        )
    )
    f = result.scalar_one_or_none()
    if not f:
        raise HTTPException(404, "Finding not found")
    f.status = body.status
    f.updated_at = datetime.now(timezone.utc)
    await db.flush()
    return _serialize(f)


# ── Background Scan Logic ─────────────────────────────────────────────────────

async def _run_asm_scan(target_id: str, org_id: str) -> None:
    """Run DNS, subdomains, SSL, headers checks on a target; persist findings."""
    async with async_session_factory() as db:
        try:
            result = await db.execute(
                select(AsmTarget).where(AsmTarget.id == uuid.UUID(target_id))
            )
            t = result.scalar_one_or_none()
            if not t:
                return

            normalized = normalize_target(t.target_value, t.target_type)
            host = normalized.hostname or _clean(t.target_value)
            findings: list[dict] = []
            started_at = datetime.now(timezone.utc)
            profile = get_scan_profile("medium", normalized.target_type)
            discoveries: dict[str, Any] = {
                "resolved_ips": [],
                "ipv6_addresses": [],
                "subdomains": [],
                "certificate_sans": [],
                "archived_urls": [],
                "interesting_urls": [],
                "api_docs": [],
                "graphql_endpoints": [],
                "open_ports": [],
                "page_titles": [],
                "javascript_assets": [],
            }
            t.last_scan_summary = {
                **(t.last_scan_summary or {}),
                "seed": build_seed_metadata(normalized.normalized_value, normalized.target_type, source=t.source_type or "asm", stage="seed"),
                "pipeline": profile.get("pipeline", []),
                "scan_strategy": profile.get("scan_strategy"),
                "dispatch": {
                    **((t.last_scan_summary or {}).get("dispatch") or {}),
                    "status": "running",
                    "started_at": started_at.isoformat(),
                },
                "cancel_requested": False,
            }
            t.updated_at = started_at
            await db.flush()

            async def _ensure_not_cancelled(phase: str) -> None:
                if await _asm_cancel_requested(target_id):
                    t.scan_status = "cancelled"
                    t.last_scan_summary = {
                        **(t.last_scan_summary or {}),
                        "dispatch": {
                            **((t.last_scan_summary or {}).get("dispatch") or {}),
                            "status": "cancelled",
                            "stopped_at": datetime.now(timezone.utc).isoformat(),
                            "phase": phase,
                        },
                        "cancelled_phase": phase,
                    }
                    t.updated_at = datetime.now(timezone.utc)
                    await db.commit()
                    raise asyncio.CancelledError()

            subdomains: list[str] = []
            if normalized.target_type in {"domain", "ip", "url", "mcp"}:
                # Resolve once up front, reject any mixed public/private answer set,
                # and pin raw socket probes to the checked address.
                connect_ip = await asyncio.to_thread(resolve_and_check, host)
                await _ensure_not_cancelled("dns")
                dns_summary = await _check_dns(host, findings)
                discoveries["resolved_ips"] = dns_summary.get("resolved_ips", [])
                discoveries["ipv6_addresses"] = dns_summary.get("ipv6_addresses", [])
                discoveries["mx_records"] = dns_summary.get("mx_records", [])
                discoveries["ns_records"] = dns_summary.get("ns_records", [])

                if normalized.target_type == "domain":
                    await _ensure_not_cancelled("crtsh")
                    subdomains = await _check_crtsh(host, findings)
                    discoveries["subdomains"] = subdomains[:100]

                await _ensure_not_cancelled("rdap")
                discoveries["network_context"] = await _check_network_context(host, normalized.target_type, discoveries, findings)

                await _ensure_not_cancelled("wayback")
                wayback_summary = await _check_wayback(host, findings)
                discoveries["archived_urls"] = wayback_summary.get("sample_urls", [])
                discoveries["interesting_urls"] = wayback_summary.get("interesting_urls", [])

                await _ensure_not_cancelled("ssl")
                tls_summary = await _check_ssl(host, findings, connect_ip)
                discoveries["certificate_sans"] = tls_summary.get("sans", [])
                discoveries["certificate_subject"] = tls_summary.get("subject")
                discoveries["certificate_issuer"] = tls_summary.get("issuer")

                await _ensure_not_cancelled("headers")
                await _check_headers(host, findings)

                await _ensure_not_cancelled("http_surface")
                http_summary = await _check_http_surface(host, findings)
                discoveries["page_titles"] = http_summary.get("page_titles", [])
                discoveries["api_docs"] = http_summary.get("api_docs", [])
                discoveries["graphql_endpoints"] = http_summary.get("graphql_endpoints", [])
                discoveries["javascript_assets"] = http_summary.get("javascript_assets", [])

                await _ensure_not_cancelled("ports")
                discoveries["open_ports"] = await _check_ports(connect_ip, findings, display_host=host)
            else:
                findings.append({
                    "severity": "INFO",
                    "title": f"Inventory-only ASM seed: {normalized.target_type}",
                    "description": f"{normalized.normalized_value} was normalized and retained as a seed. This seed type expands through relationship mapping rather than direct network probing.",
                    "source": "seed",
                    "evidence": ", ".join(profile.get("pipeline", [])[:12]),
                })

            # Persist findings
            now = datetime.now(timezone.utc)
            for f in findings:
                db.add(AsmFinding(
                    id=uuid.uuid4(),
                    org_id=uuid.UUID(org_id),
                    target_id=uuid.UUID(target_id),
                    severity=f["severity"],
                    title=f["title"],
                    description=f.get("description"),
                    source=f.get("source"),
                    url=f.get("url"),
                    evidence=f.get("evidence"),
                    status="new",
                    first_seen=now,
                    last_seen=now,
                    created_at=now,
                    updated_at=now,
                ))

            t.scan_status = "completed"
            t.last_scanned = now
            t.last_scan_summary = {
                "findings": len(findings),
                "subdomains": len(subdomains),
                "historical_urls": sum(1 for f in findings if f.get("source") == "wayback"),
                "api_docs": len(discoveries.get("api_docs") or []),
                "graphql_endpoints": len(discoveries.get("graphql_endpoints") or []),
                "open_ports": len(discoveries.get("open_ports") or []),
                "resolved_ips": len(discoveries.get("resolved_ips") or []),
                "ipv6_addresses": len(discoveries.get("ipv6_addresses") or []),
                "critical": sum(1 for f in findings if f["severity"] == "CRITICAL"),
                "high": sum(1 for f in findings if f["severity"] == "HIGH"),
                "medium": sum(1 for f in findings if f["severity"] == "MEDIUM"),
                "profile": profile["mode"],
                "utilities": profile["utilities"],
                "pipeline": profile.get("pipeline", []),
                "scan_strategy": profile.get("scan_strategy"),
                "business_logic": profile["business_logic"],
                "discoveries": discoveries,
                "seed": build_seed_metadata(normalized.normalized_value, normalized.target_type, source=t.source_type or "asm", stage="confirmed"),
                "dispatch": {
                    **((t.last_scan_summary or {}).get("dispatch") or {}),
                    "status": "completed",
                    "completed_at": now.isoformat(),
                },
                "cancel_requested": False,
            }
            t.updated_at = now
            await db.commit()
        except asyncio.CancelledError:
            return
        except Exception as e:
            async with async_session_factory() as db2:
                res2 = await db2.execute(select(AsmTarget).where(AsmTarget.id == uuid.UUID(target_id)))
                t2 = res2.scalar_one_or_none()
                if t2:
                    t2.scan_status = "failed"
                    t2.last_scan_summary = {"error": str(e)[:200], "failed_at": datetime.now(timezone.utc).isoformat()}
                    t2.updated_at = datetime.now(timezone.utc)
                    await db2.commit()


async def _check_dns(host: str, findings: list) -> dict[str, list[str]]:
    record_types = ["A", "AAAA", "MX", "TXT", "NS", "CAA"]
    has_spf = False
    has_dmarc = False
    has_caa = False
    is_ip_literal = bool(re.fullmatch(r"[0-9a-fA-F:.]+", host))
    summary: dict[str, list[str]] = {
        "resolved_ips": [],
        "ipv6_addresses": [],
        "mx_records": [],
        "ns_records": [],
    }
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            for rtype in record_types:
                try:
                    resp = await client.get(
                        _DOH,
                        params={"name": host, "type": rtype},
                        headers={"Accept": "application/dns-json"},
                    )
                    data = resp.json()
                    answers = [a["data"] for a in data.get("Answer", [])]
                    if rtype in ("A", "AAAA") and answers:
                        if rtype == "A":
                            summary["resolved_ips"].extend(answers)
                        else:
                            summary["ipv6_addresses"].extend(answers)
                        findings.append({
                            "severity": "INFO",
                            "title": f"Resolved {rtype} records for {host}",
                            "description": f"{host} resolves to {', '.join(answers[:5])}",
                            "source": "dns",
                            "evidence": "\n".join(answers[:20]),
                        })
                    if rtype == "MX" and answers:
                        summary["mx_records"].extend(answers)
                    if rtype == "NS" and answers:
                        summary["ns_records"].extend(answers)
                    if rtype == "TXT":
                        for ans in answers:
                            if "v=spf1" in ans:
                                has_spf = True
                            if "v=DMARC1" in ans:
                                has_dmarc = True
                    if rtype == "CAA" and answers:
                        has_caa = True
                except Exception:
                    pass

            # SPF check
            try:
                spf_resp = await client.get(
                    _DOH,
                    params={"name": host, "type": "TXT"},
                    headers={"Accept": "application/dns-json"},
                )
                for a in spf_resp.json().get("Answer", []):
                    if "v=spf1" in a.get("data", ""):
                        has_spf = True
            except Exception:
                pass

            # DMARC check
            try:
                dmarc_resp = await client.get(
                    _DOH,
                    params={"name": f"_dmarc.{host}", "type": "TXT"},
                    headers={"Accept": "application/dns-json"},
                )
                for a in dmarc_resp.json().get("Answer", []):
                    if "v=DMARC1" in a.get("data", ""):
                        has_dmarc = True
            except Exception:
                pass

    except Exception:
        return summary

    if summary["ipv6_addresses"]:
        findings.append({
            "severity": "INFO",
            "title": f"IPv6 surface discovered: {len(summary['ipv6_addresses'])} AAAA records",
            "description": f"{host} advertises public IPv6 addresses that should be tracked and scanned explicitly.",
            "source": "dns",
            "evidence": "\n".join(summary["ipv6_addresses"][:20]),
        })

    if not is_ip_literal and not has_spf:
        findings.append({
            "severity": "HIGH",
            "title": "No SPF record — domain can be spoofed",
            "description": f"No SPF TXT record found for {host}. Email spoofing is trivially possible.",
            "source": "dns",
        })
    if not is_ip_literal and not has_dmarc:
        findings.append({
            "severity": "MEDIUM",
            "title": "No DMARC record",
            "description": f"No _dmarc.{host} TXT record. DMARC policy is not enforced.",
            "source": "dns",
        })
    if not is_ip_literal and not has_caa:
        findings.append({
            "severity": "LOW",
            "title": "No CAA record",
            "description": f"No CAA DNS record found for {host}. Any public CA may be able to issue a certificate for this domain.",
            "source": "dns",
        })
    return summary


async def _check_crtsh(host: str, findings: list) -> list[str]:
    subdomains: list[str] = []
    try:
        _hdrs = {"User-Agent": "ExposureScopeX-ASM/2.2.0", "Connection": "close"}
        _timeout = httpx.Timeout(connect=10, read=60, write=10, pool=5)
        async with httpx.AsyncClient(timeout=_timeout, http2=False) as client:
            resp = await client.get(
                "https://crt.sh/",
                params={"q": f"%.{host}", "output": "json"},
                headers=_hdrs,
            )
            if resp.status_code == 200:
                seen: set[str] = set()
                for entry in resp.json():
                    for name in entry.get("name_value", "").split("\n"):
                        name = name.strip().lower().lstrip("*.")
                        if name and name not in seen and name.endswith(f".{host}"):
                            seen.add(name)
                            subdomains.append(name)

                if subdomains:
                    findings.append({
                        "severity": "INFO",
                        "title": f"Found {len(subdomains)} subdomains via certificate transparency",
                        "description": "Subdomains discovered from certificate transparency logs (crt.sh).",
                        "source": "subdomains",
                        "evidence": "\n".join(subdomains[:50]),
                    })
    except Exception:
        pass
    return subdomains


async def _check_ssl(host: str, findings: list, connect_ip: str | None = None) -> dict[str, Any]:
    def _do():
        ctx = ssl.create_default_context()
        try:
            with socket.create_connection((connect_ip or host, 443), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    proto = ssock.version()
                    cipher = ssock.cipher()
                    return cert, proto, cipher
        except Exception:
            return None, None, None

    try:
        cert, proto, cipher_info = await asyncio.get_event_loop().run_in_executor(None, _do)
    except Exception:
        return {}

    if cert is None:
        findings.append({
            "severity": "HIGH",
            "title": "Port 443 not open or SSL handshake failed",
            "description": f"Could not establish TLS connection to {host}:443.",
            "source": "ssl",
        })
        return {}

    sans = []
    for item_type, item_value in cert.get("subjectAltName", []):
        if item_type == "DNS" and item_value:
            sans.append(item_value.lower())

    subject_parts = cert.get("subject", ())
    subject = next((value for item in subject_parts for key, value in item if key == "commonName"), None)
    issuer_parts = cert.get("issuer", ())
    issuer = next((value for item in issuer_parts for key, value in item if key == "commonName"), None)
    if sans:
        findings.append({
            "severity": "INFO",
            "title": f"Certificate graph exposed {len(sans)} DNS names",
            "description": "The TLS certificate advertises additional hostnames that should be correlated into the attack-surface graph.",
            "source": "ssl",
            "evidence": "\n".join(sorted(set(sans))[:50]),
        })

    # Expiry
    not_after = cert.get("notAfter", "")
    try:
        expires_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days_left = (expires_dt - datetime.now(timezone.utc)).days
        if days_left < 14:
            findings.append({
                "severity": "CRITICAL",
                "title": f"TLS certificate expires in {days_left} days",
                "description": f"Certificate for {host} expires on {not_after}.",
                "source": "ssl",
            })
        elif days_left < 30:
            findings.append({
                "severity": "HIGH",
                "title": f"TLS certificate expires in {days_left} days",
                "description": f"Certificate for {host} expires on {not_after}.",
                "source": "ssl",
            })
    except Exception:
        pass

    # Weak protocols
    if proto in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3"):
        findings.append({
            "severity": "HIGH",
            "title": f"Weak TLS protocol in use: {proto}",
            "description": f"The server negotiated {proto}, which is deprecated and insecure.",
            "source": "ssl",
        })

    # Weak ciphers
    cipher_name = cipher_info[0] if cipher_info else ""
    if any(w in cipher_name for w in ("RC4", "DES", "NULL", "EXPORT", "MD5")):
        findings.append({
            "severity": "HIGH",
            "title": f"Weak cipher suite: {cipher_name}",
            "description": "Weak cipher suite negotiated during TLS handshake.",
            "source": "ssl",
        })
    return {
        "subject": subject,
        "issuer": issuer,
        "sans": sorted(set(sans)),
        "protocol": proto,
        "cipher": cipher_name,
    }


async def _check_headers(host: str, findings: list) -> None:
    url = f"https://{host}"
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=False) as client:
            try:
                resp = await client.head(url)
            except Exception:
                resp = await client.get(url)
    except Exception:
        return

    headers = {k.lower(): v for k, v in resp.headers.items()}

    for header_lower, (label, severity) in _SECURITY_HEADERS.items():
        if not headers.get(header_lower):
            findings.append({
                "severity": severity,
                "title": f"Missing security header: {label}",
                "description": f"The HTTP response from {host} does not include the {label} header.",
                "source": "headers",
                "url": url,
            })

    # Info disclosure
    for h in ["server", "x-powered-by", "x-aspnet-version"]:
        val = headers.get(h)
        if val:
            findings.append({
                "severity": "LOW",
                "title": f"Server information disclosed via {h} header",
                "description": f"Response header '{h}: {val}' reveals technology details.",
                "source": "headers",
                "url": url,
                "evidence": f"{h}: {val}",
            })


async def _check_http_surface(host: str, findings: list) -> dict[str, list[str]]:
    bases = [f"https://{host}", f"http://{host}"]
    seen_titles: set[str] = set()
    api_docs: list[str] = []
    graphql_endpoints: list[str] = []
    javascript_assets: list[str] = []
    sensitive_paths = {
        "/.git/HEAD": ("Exposed Git metadata", "HIGH"),
        "/.env": ("Exposed environment file", "CRITICAL"),
        "/server-status": ("Exposed server-status endpoint", "HIGH"),
        "/actuator/health": ("Exposed Spring actuator endpoint", "MEDIUM"),
        "/debug/default/view": ("Exposed debug endpoint", "MEDIUM"),
    }

    api_paths = (
        "/openapi.json",
        "/swagger.json",
        "/swagger/v1/swagger.json",
        "/api-docs",
        "/graphql",
        "/graphiql",
    )

    async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=False) as client:
        for base in bases:
            try:
                resp = await client.get(base)
            except Exception:
                continue

            title_match = re.search(r"<title[^>]*>(.*?)</title>", resp.text, re.IGNORECASE | re.DOTALL)
            if title_match:
                title = re.sub(r"\s+", " ", title_match.group(1)).strip()
                if title and title not in seen_titles:
                    seen_titles.add(title)
                    findings.append({
                        "severity": "INFO",
                        "title": f"Page title discovered: {title}",
                        "description": f"The landing page at {base} exposes the title '{title}'.",
                        "source": "http",
                        "url": str(resp.url),
                    })
            javascript_assets.extend(re.findall(r"""<script[^>]+src=["']([^"']+)["']""", resp.text, re.IGNORECASE))

            try:
                options_resp = await client.options(base)
                allow = options_resp.headers.get("allow", "")
                if any(method in allow.upper() for method in ("TRACE", "PUT", "DELETE")):
                    findings.append({
                        "severity": "MEDIUM",
                        "title": "Potentially risky HTTP methods enabled",
                        "description": f"{base} advertises potentially risky methods via Allow: {allow}",
                        "source": "http",
                        "url": str(options_resp.url),
                        "evidence": allow,
                    })
            except Exception:
                pass

            for path in ("/robots.txt", "/.well-known/security.txt", "/security.txt"):
                try:
                    info_resp = await client.get(f"{base}{path}")
                    if info_resp.status_code == 200 and info_resp.text.strip():
                        findings.append({
                            "severity": "INFO",
                            "title": f"Accessible informational file: {path}",
                            "description": f"{path} is reachable on {base}.",
                            "source": "http",
                            "url": str(info_resp.url),
                            "evidence": info_resp.text[:500],
                        })
                except Exception:
                    pass

            for path in api_paths:
                try:
                    probe = await client.get(f"{base}{path}")
                except Exception:
                    continue
                if probe.status_code >= 400:
                    continue
                target_url = str(probe.url)
                content_type = probe.headers.get("content-type", "").lower()
                body = probe.text[:1000]
                if path.startswith("/graphql") or "graphql" in body.lower():
                    graphql_endpoints.append(target_url)
                    findings.append({
                        "severity": "MEDIUM",
                        "title": "GraphQL surface detected",
                        "description": f"Potential GraphQL endpoint discovered at {target_url}.",
                        "source": "api",
                        "url": target_url,
                        "evidence": body[:500],
                    })
                elif "json" in content_type or "openapi" in body.lower() or "swagger" in body.lower():
                    api_docs.append(target_url)
                    findings.append({
                        "severity": "INFO",
                        "title": "API documentation or schema exposed",
                        "description": f"Potential API inventory endpoint discovered at {target_url}.",
                        "source": "api",
                        "url": target_url,
                        "evidence": body[:500],
                    })

            for path, (title, severity) in sensitive_paths.items():
                try:
                    probe = await client.get(f"{base}{path}")
                    if probe.status_code == 200:
                        findings.append({
                            "severity": severity,
                            "title": title,
                            "description": f"{path} is publicly reachable on {base}.",
                            "source": "http",
                            "url": str(probe.url),
                            "evidence": probe.text[:500],
                        })
                except Exception:
                    pass
    return {
        "page_titles": sorted(seen_titles),
        "api_docs": sorted(set(api_docs)),
        "graphql_endpoints": sorted(set(graphql_endpoints)),
        "javascript_assets": sorted(set(javascript_assets))[:100],
    }


async def _check_wayback(host: str, findings: list) -> dict[str, list[str]]:
    sample_urls: list[str] = []
    interesting = 0
    interesting_patterns = re.compile(r"(admin|login|api|backup|config|token|secret|debug|swagger|graphql)", re.IGNORECASE)

    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(connect=10, read=60, write=10, pool=5)) as client:
            resp = await client.get(
                "https://webcache.googleusercontent.com/search",
                params={"q": "cache:" + host},
            )
    except Exception:
        resp = None

    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(connect=10, read=60, write=10, pool=5)) as client:
            resp = await client.get(
                "https://web.archive.org/cdx/search/cdx",
                params={
                    "url": f"*.{host}/*",
                    "output": "json",
                    "fl": "original",
                    "filter": "statuscode:200",
                    "limit": "200",
                    "collapse": "urlkey",
                },
            )
            if resp.status_code == 200:
                data = resp.json()
                for row in data[1:]:
                    if not row:
                        continue
                    raw_url = row[0]
                    parsed = urlparse(raw_url)
                    if parsed.scheme not in ("http", "https"):
                        continue
                    sample_urls.append(raw_url)
                    if interesting_patterns.search(raw_url):
                        interesting += 1
                sample_urls = sorted(set(sample_urls))
    except Exception:
        return {"sample_urls": [], "interesting_urls": []}

    if sample_urls:
        findings.append({
            "severity": "INFO",
            "title": f"Historical URLs discovered: {len(sample_urls)}",
            "description": f"Archived URLs for {host} were discovered via the Wayback CDX index.",
            "source": "wayback",
            "evidence": "\n".join(sample_urls[:50]),
        })
    if interesting:
        findings.append({
            "severity": "MEDIUM",
            "title": f"Interesting archived endpoints discovered: {interesting}",
            "description": "Historical URLs include potentially sensitive paths such as admin, login, API, debug, or backup endpoints.",
            "source": "wayback",
            "evidence": "\n".join([u for u in sample_urls if interesting_patterns.search(u)][:50]),
        })
    return {
        "sample_urls": sample_urls[:100],
        "interesting_urls": [u for u in sample_urls if interesting_patterns.search(u)][:100],
    }


async def _check_ports(host: str, findings: list, *, display_host: str | None = None) -> list[str]:
    """Check a small set of commonly sensitive ports."""
    sensitive_ports = {
        21: ("FTP", "HIGH"),
        22: ("SSH", "INFO"),
        23: ("Telnet", "CRITICAL"),
        25: ("SMTP", "MEDIUM"),
        3306: ("MySQL", "HIGH"),
        3389: ("RDP", "HIGH"),
        5432: ("PostgreSQL", "HIGH"),
        6379: ("Redis", "HIGH"),
        8080: ("HTTP Alt", "LOW"),
        8443: ("HTTPS Alt", "INFO"),
        27017: ("MongoDB", "HIGH"),
    }

    open_ports: list[str] = []

    async def _probe(port: int):
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=3
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return port
        except Exception:
            return None

    tasks = [_probe(p) for p in sensitive_ports]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    for port, result in zip(sensitive_ports, results):
        if isinstance(result, int):
            label, sev = sensitive_ports[port]
            evidence_host = display_host or host
            open_ports.append(f"{port}/{label}")
            if sev != "INFO":
                findings.append({
                    "severity": sev,
                    "title": f"Exposed service: {label} (port {port})",
                    "description": f"Port {port} ({label}) is open and reachable on {evidence_host}.",
                    "source": "ports",
                    "evidence": f"{evidence_host}:{port} open",
                })

    if open_ports:
        findings.append({
            "severity": "INFO",
            "title": f"Open ports detected: {', '.join(open_ports)}",
            "description": "Port sweep results for common service ports.",
            "source": "ports",
            "evidence": "\n".join(open_ports),
        })
    return open_ports


async def _check_network_context(host: str, target_type: str, discoveries: dict[str, Any], findings: list) -> dict[str, Any]:
    candidate_ip = host if target_type == "ip" else next(iter(discoveries.get("resolved_ips") or []), "")
    if not candidate_ip:
        return {}
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True) as client:
            resp = await client.get(f"https://rdap.org/ip/{candidate_ip}")
    except Exception:
        return {}
    if resp.status_code >= 400:
        return {}
    try:
        data = resp.json()
    except Exception:
        return {}

    cidrs = [
        f"{item.get('v4prefix')}/{item.get('length')}"
        for item in data.get("cidr0_cidrs", [])
        if item.get("v4prefix") and item.get("length") is not None
    ]
    if not cidrs and data.get("startAddress") and data.get("endAddress"):
        cidrs = [f"{data.get('startAddress')} - {data.get('endAddress')}"]
    owner = data.get("name") or data.get("handle")
    if owner or cidrs:
        findings.append({
            "severity": "INFO",
            "title": "Network ownership context discovered",
            "description": f"RDAP metadata was discovered for {candidate_ip}.",
            "source": "rdap",
            "evidence": "\n".join(filter(None, [str(owner or ""), *cidrs[:10]])).strip(),
        })
    return {
        "lookup_ip": candidate_ip,
        "name": data.get("name"),
        "handle": data.get("handle"),
        "cidrs": cidrs[:20],
        "country": data.get("country"),
    }
