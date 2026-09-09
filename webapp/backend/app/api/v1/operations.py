"""Authenticated operational telemetry and capacity endpoints."""

from datetime import datetime, timedelta, timezone

import redis.asyncio as aioredis
import hmac

from fastapi import APIRouter, Depends, Header, HTTPException, status
from fastapi.responses import PlainTextResponse
from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.dependencies import get_db, require_role
from app.models.assessment import Assessment
from app.models.scan import Scan
from app.models.scan_runtime import OrganizationExecutionPolicy, WorkerCapability
from app.models.user import User
from app.services.telemetry import render_prometheus

router = APIRouter(prefix="/operations", tags=["Operations"])
QUEUES = ("scans-web", "scans-api", "scans-artifact", "scans-cloud", "scans-mobile", "scans", "default")


async def _snapshot(user: User, db: AsyncSession) -> dict:
    rows = (
        await db.execute(
            select(Scan.status, func.count(Scan.id))
            .join(Assessment, Assessment.id == Scan.assessment_id)
            .where(Assessment.org_id == user.org_id)
            .group_by(Scan.status)
        )
    ).all()
    stale_cutoff = datetime.now(timezone.utc) - timedelta(minutes=10)
    stale = await db.scalar(
        select(func.count(Scan.id))
        .join(Assessment, Assessment.id == Scan.assessment_id)
        .where(
            Assessment.org_id == user.org_id,
            Scan.status.in_(["queued", "running"]),
            or_(
                Scan.heartbeat_at < stale_cutoff,
                and_(Scan.heartbeat_at.is_(None), Scan.updated_at < stale_cutoff),
            ),
        )
    )
    queue_depths: dict[str, int | None] = {}
    try:
        client = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
        queue_depths = {queue: int(await client.llen(queue)) for queue in QUEUES}
        await client.aclose()
    except Exception:
        queue_depths = {queue: None for queue in QUEUES}
    policy = await db.scalar(
        select(OrganizationExecutionPolicy).where(OrganizationExecutionPolicy.org_id == user.org_id)
    )
    max_active = policy.max_active_scans if policy else settings.DEFAULT_MAX_ACTIVE_SCANS_PER_ORG
    max_queued = policy.max_queued_scans if policy else settings.DEFAULT_MAX_QUEUED_SCANS_PER_ORG
    scan_counts = {status: count for status, count in rows}
    worker_cutoff = datetime.now(timezone.utc) - timedelta(seconds=settings.WORKER_CAPABILITY_TTL_SECONDS)
    workers = (await db.execute(select(WorkerCapability).order_by(WorkerCapability.worker_name))).scalars().all()
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scans": scan_counts,
        "stale_active_scans": int(stale or 0),
        "queue_depths": queue_depths,
        "deployment": {
            "scan_executor": settings.SCAN_EXECUTOR,
            "artifact_storage": settings.ARTIFACT_STORAGE_BACKEND,
            "mobile_dynamic": bool(settings.MOBILE_DYNAMIC_ADAPTER_URL),
            "kubernetes_runtime": bool(settings.KUBERNETES_RUNTIME_ADAPTER_URL),
        },
        "capacity": {
            "max_active_scans": max_active,
            "max_queued_scans": max_queued,
            "active_available": max(0, max_active - int(scan_counts.get("running", 0))),
            "queued_available": max(0, max_queued - int(scan_counts.get("queued", 0))),
            "priority": policy.priority if policy else 5,
        },
        "workers": [{
            "name": worker.worker_name,
            "status": "online" if worker.status == "online" and worker.last_seen_at >= worker_cutoff else "stale",
            "image_identity": worker.image_identity,
            "queues": worker.queues or [],
            "capabilities": worker.capabilities or [],
            "versions": worker.versions or {},
            "last_seen_at": worker.last_seen_at.isoformat(),
        } for worker in workers],
    }


async def _global_snapshot(db: AsyncSession) -> dict:
    rows = (await db.execute(select(Scan.status, func.count(Scan.id)).group_by(Scan.status))).all()
    stale_cutoff = datetime.now(timezone.utc) - timedelta(minutes=settings.STALE_SCAN_MINUTES)
    stale = await db.scalar(
        select(func.count(Scan.id)).where(
            Scan.status.in_(["queued", "running"]),
            or_(Scan.heartbeat_at < stale_cutoff, and_(Scan.heartbeat_at.is_(None), Scan.updated_at < stale_cutoff)),
        )
    )
    queue_depths: dict[str, int | None]
    try:
        client = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
        queue_depths = {queue: int(await client.llen(queue)) for queue in QUEUES}
        await client.aclose()
    except Exception:
        queue_depths = {queue: None for queue in QUEUES}
    return {"scans": dict(rows), "stale_active_scans": int(stale or 0), "queue_depths": queue_depths}


@router.get("/summary")
async def operations_summary(
    current_user: User = Depends(require_role("admin", "manager", "analyst")),
    db: AsyncSession = Depends(get_db),
):
    return await _snapshot(current_user, db)


@router.get("/metrics", response_class=PlainTextResponse)
async def operations_metrics(
    current_user: User = Depends(require_role("admin", "manager")),
    db: AsyncSession = Depends(get_db),
):
    snapshot = await _snapshot(current_user, db)
    extra: dict[str, int] = {"stale_active_scans": snapshot["stale_active_scans"]}
    extra.update({f'scans_{key}': value for key, value in snapshot["scans"].items()})
    extra.update({f'queue_depth_{key}': value for key, value in snapshot["queue_depths"].items() if value is not None})
    return render_prometheus(extra)


@router.get("/internal-metrics", response_class=PlainTextResponse, include_in_schema=False)
async def internal_metrics(
    authorization: str | None = Header(default=None),
    db: AsyncSession = Depends(get_db),
):
    """Prometheus scrape endpoint protected by a dedicated machine token."""
    expected = settings.METRICS_BEARER_TOKEN
    supplied = authorization.removeprefix("Bearer ") if authorization else ""
    if not expected:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Metrics scraping is not configured")
    if not hmac.compare_digest(supplied, expected):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid metrics token")
    snapshot = await _global_snapshot(db)
    extra: dict[str, int] = {"stale_active_scans": snapshot["stale_active_scans"]}
    extra.update({f"scans_{key}": value for key, value in snapshot["scans"].items()})
    extra.update({f"queue_depth_{key}": value for key, value in snapshot["queue_depths"].items() if value is not None})
    return render_prometheus(extra)
