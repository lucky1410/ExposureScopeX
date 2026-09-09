"""Integrations API — CRUD for OrgIntegration records + connection test."""

import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import get_current_user, require_role
from app.models.integration import OrgIntegration, VALID_EVENTS, VALID_PROVIDERS
from app.models.user import User
from app.services.audit import AuditEvent, write_audit
from app.services.encryption import decrypt_dict, encrypt_dict
from app.services.integrations.base import get_service

router = APIRouter(prefix="/integrations", tags=["Integrations"])


# ── Schemas ───────────────────────────────────────────────────────────────────

class IntegrationCreate(BaseModel):
    provider: str
    name: str
    config: dict = {}
    events: list[str] = []
    is_active: bool = True


class IntegrationUpdate(BaseModel):
    name: Optional[str] = None
    config: Optional[dict] = None
    events: Optional[list[str]] = None
    is_active: Optional[bool] = None


# ── Serialiser ────────────────────────────────────────────────────────────────

def _serialize(obj: OrgIntegration) -> dict:
    """Return all columns, replacing ``config`` with ``has_config: bool``."""
    row: dict = {c.name: getattr(obj, c.name) for c in obj.__table__.columns}
    raw_config = row.pop("config", {}) or {}
    row["has_config"] = bool(raw_config)
    return row


# ── Validation helpers ────────────────────────────────────────────────────────

def _validate_provider(provider: str) -> None:
    if provider not in VALID_PROVIDERS:
        raise HTTPException(
            status_code=422,
            detail=f"Unknown provider '{provider}'. Valid: {sorted(VALID_PROVIDERS)}",
        )


def _validate_events(events: list[str]) -> None:
    bad = [e for e in events if e not in VALID_EVENTS]
    if bad:
        raise HTTPException(
            status_code=422,
            detail=f"Unknown event(s): {bad}. Valid: {sorted(VALID_EVENTS)}",
        )


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("")
async def list_integrations(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List all integrations for the current user's organisation.

    The ``config`` field is never returned; ``has_config`` indicates whether
    credentials are stored.
    """
    result = await db.execute(
        select(OrgIntegration)
        .where(OrgIntegration.org_id == current_user.org_id)
        .order_by(OrgIntegration.created_at.desc())
    )
    return [_serialize(i) for i in result.scalars().all()]


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_integration(
    body: IntegrationCreate,
    request: Request,
    current_user: User = Depends(require_role("admin", "manager")),
    db: AsyncSession = Depends(get_db),
):
    """Create a new integration.  ``config`` is encrypted before storage."""
    _validate_provider(body.provider)
    _validate_events(body.events)

    encrypted = encrypt_dict(body.config) if body.config else ""
    now = datetime.now(timezone.utc)

    integration = OrgIntegration(
        id=uuid.uuid4(),
        org_id=current_user.org_id,
        provider=body.provider,
        name=body.name,
        config={"_encrypted": encrypted} if encrypted else {},
        is_active=body.is_active,
        events=body.events,
        created_at=now,
        updated_at=now,
    )
    db.add(integration)
    await db.flush()
    await db.refresh(integration)

    await write_audit(
        db,
        event="integration.create",
        user_id=str(current_user.id),
        org_id=str(current_user.org_id),
        resource_type="org_integration",
        resource_id=str(integration.id),
        details={"provider": body.provider, "name": body.name},
        ip_address=request.client.host if request.client else None,
    )

    return _serialize(integration)


@router.get("/{integration_id}")
async def get_integration(
    integration_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Fetch a single integration by ID (config omitted)."""
    result = await db.execute(
        select(OrgIntegration).where(
            and_(
                OrgIntegration.id == integration_id,
                OrgIntegration.org_id == current_user.org_id,
            )
        )
    )
    integration = result.scalar_one_or_none()
    if not integration:
        raise HTTPException(status_code=404, detail="Integration not found")
    return _serialize(integration)


@router.put("/{integration_id}")
async def update_integration(
    integration_id: uuid.UUID,
    body: IntegrationUpdate,
    request: Request,
    current_user: User = Depends(require_role("admin", "manager")),
    db: AsyncSession = Depends(get_db),
):
    """Update name, config, events, and/or is_active."""
    result = await db.execute(
        select(OrgIntegration).where(
            and_(
                OrgIntegration.id == integration_id,
                OrgIntegration.org_id == current_user.org_id,
            )
        )
    )
    integration = result.scalar_one_or_none()
    if not integration:
        raise HTTPException(status_code=404, detail="Integration not found")

    if body.name is not None:
        integration.name = body.name

    if body.config is not None:
        encrypted = encrypt_dict(body.config) if body.config else ""
        integration.config = {"_encrypted": encrypted} if encrypted else {}

    if body.events is not None:
        _validate_events(body.events)
        integration.events = body.events

    if body.is_active is not None:
        integration.is_active = body.is_active

    integration.updated_at = datetime.now(timezone.utc)
    await db.flush()
    await db.refresh(integration)

    await write_audit(
        db,
        event="integration.update",
        user_id=str(current_user.id),
        org_id=str(current_user.org_id),
        resource_type="org_integration",
        resource_id=str(integration.id),
        details={"provider": integration.provider, "name": integration.name},
        ip_address=request.client.host if request.client else None,
    )

    return _serialize(integration)


@router.delete("/{integration_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_integration(
    integration_id: uuid.UUID,
    request: Request,
    current_user: User = Depends(require_role("admin", "manager")),
    db: AsyncSession = Depends(get_db),
):
    """Delete an integration permanently."""
    result = await db.execute(
        select(OrgIntegration).where(
            and_(
                OrgIntegration.id == integration_id,
                OrgIntegration.org_id == current_user.org_id,
            )
        )
    )
    integration = result.scalar_one_or_none()
    if not integration:
        raise HTTPException(status_code=404, detail="Integration not found")

    await write_audit(
        db,
        event="integration.delete",
        user_id=str(current_user.id),
        org_id=str(current_user.org_id),
        resource_type="org_integration",
        resource_id=str(integration.id),
        details={"provider": integration.provider, "name": integration.name},
        ip_address=request.client.host if request.client else None,
    )

    await db.delete(integration)
    await db.flush()


@router.post("/{integration_id}/test")
async def test_integration(
    integration_id: uuid.UUID,
    current_user: User = Depends(require_role("admin", "manager")),
    db: AsyncSession = Depends(get_db),
):
    """Test-connect to an integration provider.

    Decrypts stored config, instantiates the provider service, and calls
    ``test_connection()``.  Returns ``{"ok": bool, "message": str}``.
    """
    result = await db.execute(
        select(OrgIntegration).where(
            and_(
                OrgIntegration.id == integration_id,
                OrgIntegration.org_id == current_user.org_id,
            )
        )
    )
    integration = result.scalar_one_or_none()
    if not integration:
        raise HTTPException(status_code=404, detail="Integration not found")

    raw_config = integration.config or {}
    if "_encrypted" in raw_config:
        try:
            config = decrypt_dict(raw_config["_encrypted"])
        except Exception as exc:
            raise HTTPException(
                status_code=500,
                detail=f"Failed to decrypt integration config: {exc}",
            )
    else:
        config = raw_config

    try:
        service = get_service(integration.provider, config)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    try:
        test_result = await service.test_connection()
    except Exception as exc:
        test_result = {"ok": False, "message": str(exc)}

    # Record the test attempt
    now = datetime.now(timezone.utc)
    integration.last_used_at = now
    integration.last_status = "ok" if test_result.get("ok") else "error"
    integration.last_error = None if test_result.get("ok") else test_result.get("message", "")[:500]
    integration.updated_at = now
    await db.flush()

    return test_result


# ── Threat Intel special endpoints ────────────────────────────────────────────

@router.post("/nvd-sync")
async def trigger_nvd_sync(
    current_user: User = Depends(require_role("admin", "manager")),
    db: AsyncSession = Depends(get_db),
):
    """Trigger an on-demand NVD CVE feed sync for the current organisation.

    Fetches CVEs published in the last 24 hours and matches them against
    tracked assets.  The result is returned immediately (synchronous for the
    API call; use the Celery task for scheduled daily runs).

    Returns::

        {
            "cves_fetched": int,
            "asset_matches": int,
            "status": "ok" | "error",
            "message": str,
        }
    """
    from app.services.threat_intel.nvd_feed import run_nvd_feed_sync

    result = await run_nvd_feed_sync(
        org_id=str(current_user.org_id),
        days_back=1,
        db=db,
    )
    return result
