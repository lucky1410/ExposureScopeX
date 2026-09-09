"""Settings endpoints: API keys CRUD, users CRUD, scan authorization CRUD."""

import asyncio
import csv
import os
import uuid
from io import StringIO
from urllib.parse import urlsplit
from datetime import datetime, timezone

from cryptography.fernet import Fernet
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.dependencies import get_current_user, get_db, require_role
from app.models.api_key import ApiKey
from app.models.audit_log import AuditLog
from app.models.scan_authorization import ScanAuthorization
from app.models.scan_runtime import OrganizationExecutionPolicy, ScanArtifact
from app.models.scan import Scan
from app.models.assessment import Assessment
from app.models.report import ReportArtifact
from app.models.integration import OrgIntegration
from app.models.user import User
from app.schemas.user import UserCreate, UserResponse, UserUpdate
from app.security import get_password_hash
from app.services.asset_inventory import normalize_target
from app.services.validation import ValidationError as TargetValidationError
from app.services.audit import AuditEvent, write_audit
from app.services.encryption import decrypt_dict, encrypt_dict
from app.services.retention import execute_retention, retention_candidates, retention_preview, verify_confirmation_token

router = APIRouter(prefix="/settings", tags=["Settings"])
RUNTIME_ADAPTERS = {"mobile_dynamic", "kubernetes_runtime"}


def _audit_query(org_id: uuid.UUID, *, action: str | None = None, entity_type: str | None = None,
                 search: str | None = None, success: bool | None = None):
    query = select(AuditLog, User.email).outerjoin(User, User.id == AuditLog.user_id).where(
        AuditLog.new_value["org_id"].astext == str(org_id)
    )
    if action:
        query = query.where(AuditLog.action.ilike(f"%{action[:100]}%"))
    if entity_type:
        query = query.where(AuditLog.entity_type == entity_type[:100])
    if success is not None:
        query = query.where(AuditLog.new_value["success"].astext == ("true" if success else "false"))
    if search:
        term = f"%{search[:200]}%"
        query = query.where(or_(
            AuditLog.action.ilike(term), AuditLog.entity_type.ilike(term),
            AuditLog.ip_address.ilike(term), User.email.ilike(term),
        ))
    return query


def _audit_item(row: AuditLog, actor_email: str | None) -> dict:
    envelope = row.new_value or {}
    return {
        "id": str(row.id), "action": row.action, "entity_type": row.entity_type,
        "entity_id": str(row.entity_id) if row.entity_id else None,
        "actor": actor_email, "user_id": str(row.user_id) if row.user_id else None,
        "ip_address": row.ip_address, "success": bool(envelope.get("success", True)),
        "details": envelope.get("details") if isinstance(envelope.get("details"), dict) else {},
        "created_at": row.created_at.isoformat(),
    }


@router.get("/audit-logs")
async def list_audit_logs(
    action: str | None = None, entity_type: str | None = None, search: str | None = None,
    success: bool | None = None, page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200),
    current_user: User = Depends(require_role("admin", "manager")), db: AsyncSession = Depends(get_db),
):
    query = _audit_query(current_user.org_id, action=action, entity_type=entity_type, search=search, success=success)
    total = await db.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows = (await db.execute(query.order_by(AuditLog.created_at.desc()).offset((page - 1) * page_size).limit(page_size))).all()
    return {"items": [_audit_item(row, email) for row, email in rows], "total": total, "page": page, "page_size": page_size}


@router.get("/audit-logs/export")
async def export_audit_logs(
    action: str | None = None, entity_type: str | None = None, search: str | None = None,
    success: bool | None = None, current_user: User = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    query = _audit_query(current_user.org_id, action=action, entity_type=entity_type, search=search, success=success)
    rows = (await db.execute(query.order_by(AuditLog.created_at.desc()).limit(10000))).all()
    output = StringIO()
    writer = csv.DictWriter(output, fieldnames=["created_at", "action", "entity_type", "entity_id", "actor", "ip_address", "success", "details"])
    writer.writeheader()
    for row, email in rows:
        item = _audit_item(row, email)
        item["details"] = __import__("json").dumps(item["details"], sort_keys=True)
        writer.writerow({key: item.get(key) for key in writer.fieldnames})
    return Response(output.getvalue(), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=audit-log.csv"})


def _validate_adapter_config(provider: str, payload: dict) -> dict:
    if provider not in RUNTIME_ADAPTERS:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Unsupported runtime adapter")
    url = str(payload.get("url") or "").strip().rstrip("/")
    parsed = urlsplit(url)
    if parsed.scheme not in ({"https"} if settings.ENVIRONMENT == "production" else {"http", "https"}) or not parsed.hostname or parsed.username or parsed.password:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Adapter URL is invalid or unsafe")
    allowed_hosts = {item.strip().lower() for item in settings.RUNTIME_ADAPTER_ALLOWED_HOSTS.split(",") if item.strip()}
    if parsed.hostname.lower() not in allowed_hosts:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Adapter host is not in RUNTIME_ADAPTER_ALLOWED_HOSTS")
    api_key = str(payload.get("api_key") or "").strip()
    if not api_key:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Adapter API key is required")
    return {"url": url, "api_key": api_key}


@router.get("/runtime-integrations")
async def runtime_integrations(current_user: User = Depends(require_role("admin", "manager")), db: AsyncSession = Depends(get_db)):
    rows = (await db.execute(select(OrgIntegration).where(OrgIntegration.org_id == current_user.org_id,
        OrgIntegration.provider.in_(RUNTIME_ADAPTERS)))).scalars().all()
    return [{"id": str(row.id), "provider": row.provider, "name": row.name, "is_active": row.is_active,
        "configured": bool((row.config or {}).get("_encrypted")), "last_status": row.last_status,
        "last_error": row.last_error, "last_used_at": row.last_used_at} for row in rows]


@router.put("/runtime-integrations/{provider}")
async def configure_runtime_integration(provider: str, payload: dict, request: Request,
    current_user: User = Depends(require_role("admin")), db: AsyncSession = Depends(get_db)):
    config = _validate_adapter_config(provider, payload)
    row = await db.scalar(select(OrgIntegration).where(OrgIntegration.org_id == current_user.org_id, OrgIntegration.provider == provider))
    if not row:
        row = OrgIntegration(org_id=current_user.org_id, provider=provider, name=str(payload.get("name") or provider.replace("_", " ").title()), events=[])
        db.add(row)
    row.config = {"_encrypted": encrypt_dict(config)}; row.is_active = True; row.last_status = None; row.last_error = None
    await write_audit(db, event="runtime.integration.configure", user_id=str(current_user.id), org_id=str(current_user.org_id),
        resource_type="runtime_integration", resource_id=str(row.id) if row.id else None, details={"provider": provider},
        ip_address=request.client.host if request.client else None)
    await db.flush()
    return {"provider": provider, "configured": True, "is_active": True}


@router.post("/runtime-integrations/{provider}/test")
async def test_runtime_integration(provider: str, current_user: User = Depends(require_role("admin", "manager")), db: AsyncSession = Depends(get_db)):
    row = await db.scalar(select(OrgIntegration).where(OrgIntegration.org_id == current_user.org_id, OrgIntegration.provider == provider, OrgIntegration.is_active.is_(True)))
    if not row or not (row.config or {}).get("_encrypted"):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Runtime adapter is not configured")
    config = decrypt_dict(row.config["_encrypted"])
    result = await _http_adapter_health(config["url"], config["api_key"])
    row.last_status = "ok" if result.get("healthy") else "error"; row.last_error = result.get("message"); row.last_used_at = datetime.now(timezone.utc)
    return result

# Derive a Fernet key from SECRET_KEY for encrypting API keys
import base64
import hashlib

_fernet_key = base64.urlsafe_b64encode(hashlib.sha256(settings.SECRET_KEY.encode()).digest())
_fernet = Fernet(_fernet_key)


@router.get("/execution-policy")
async def get_execution_policy(
    current_user: User = Depends(require_role("admin", "manager")),
    db: AsyncSession = Depends(get_db),
):
    policy = await db.scalar(
        select(OrganizationExecutionPolicy).where(
            OrganizationExecutionPolicy.org_id == current_user.org_id
        )
    )
    return {
        "max_active_scans": policy.max_active_scans if policy else settings.DEFAULT_MAX_ACTIVE_SCANS_PER_ORG,
        "max_queued_scans": policy.max_queued_scans if policy else settings.DEFAULT_MAX_QUEUED_SCANS_PER_ORG,
        "priority": policy.priority if policy else 5,
        "settings": policy.settings if policy else {},
    }


@router.put("/execution-policy")
async def update_execution_policy(
    payload: dict,
    current_user: User = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    try:
        max_active = int(payload.get("max_active_scans", settings.DEFAULT_MAX_ACTIVE_SCANS_PER_ORG))
        max_queued = int(payload.get("max_queued_scans", settings.DEFAULT_MAX_QUEUED_SCANS_PER_ORG))
        priority = int(payload.get("priority", 5))
    except (TypeError, ValueError) as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Execution policy values must be integers") from exc
    if not 1 <= max_active <= 100 or not 1 <= max_queued <= 1000 or not 0 <= priority <= 9:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Policy limits are outside the supported range")
    policy = await db.scalar(
        select(OrganizationExecutionPolicy).where(
            OrganizationExecutionPolicy.org_id == current_user.org_id
        )
    )
    if not policy:
        policy = OrganizationExecutionPolicy(org_id=current_user.org_id)
        db.add(policy)
    policy.max_active_scans = max_active
    policy.max_queued_scans = max_queued
    policy.priority = priority
    policy.settings = payload.get("settings") if isinstance(payload.get("settings"), dict) else {}
    await db.flush()
    return {
        "max_active_scans": policy.max_active_scans,
        "max_queued_scans": policy.max_queued_scans,
        "priority": policy.priority,
        "settings": policy.settings,
    }


@router.get("/storage")
async def storage_status(current_user: User = Depends(require_role("admin", "manager")), db: AsyncSession = Depends(get_db)):
    artifact_bytes = await db.scalar(select(func.coalesce(func.sum(ScanArtifact.size_bytes), 0)).select_from(ScanArtifact)
        .join(Scan, Scan.id == ScanArtifact.scan_id).join(Assessment, Assessment.id == Scan.assessment_id)
        .where(Assessment.org_id == current_user.org_id, ScanArtifact.retained.is_(True))) or 0
    report_bytes = await db.scalar(select(func.coalesce(func.sum(ReportArtifact.file_size), 0)).where(
        ReportArtifact.org_id == current_user.org_id)) or 0
    artifact_count = await db.scalar(select(func.count(ScanArtifact.id)).select_from(ScanArtifact)
        .join(Scan, Scan.id == ScanArtifact.scan_id).join(Assessment, Assessment.id == Scan.assessment_id)
        .where(Assessment.org_id == current_user.org_id, ScanArtifact.retained.is_(True))) or 0
    report_count = await db.scalar(select(func.count(ReportArtifact.id)).where(ReportArtifact.org_id == current_user.org_id)) or 0
    policy = await db.scalar(select(OrganizationExecutionPolicy).where(OrganizationExecutionPolicy.org_id == current_user.org_id))
    policy_settings = policy.settings if policy else {}
    quota_bytes = int(policy_settings.get("storage_quota_bytes") or 50 * 1024 ** 3)
    used_bytes = int(artifact_bytes) + int(report_bytes)
    return {
        "used_bytes": used_bytes, "quota_bytes": quota_bytes,
        "usage_percent": round((used_bytes / quota_bytes) * 100, 2) if quota_bytes else 0,
        "scan_artifacts": {"count": artifact_count, "bytes": int(artifact_bytes)},
        "reports": {"count": report_count, "bytes": int(report_bytes)},
        "retention": {"scan_days": int(policy_settings.get("scan_retention_days") or settings.SCAN_ARTIFACT_RETENTION_DAYS),
            "report_days": int(policy_settings.get("report_retention_days") or settings.REPORT_RETENTION_DAYS)},
        "backend": settings.ARTIFACT_STORAGE_BACKEND,
        "cache_accounting": "Shared scanner caches are managed separately and are not charged to tenant artifact usage.",
    }


@router.put("/storage-policy")
async def update_storage_policy(payload: dict, current_user: User = Depends(require_role("admin")), db: AsyncSession = Depends(get_db)):
    try:
        quota_gb = int(payload.get("quota_gb", 50))
        scan_days = int(payload.get("scan_retention_days", settings.SCAN_ARTIFACT_RETENTION_DAYS))
        report_days = int(payload.get("report_retention_days", settings.REPORT_RETENTION_DAYS))
    except (TypeError, ValueError) as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Storage policy values must be integers") from exc
    if not 1 <= quota_gb <= 10000 or not 1 <= scan_days <= 3650 or not 1 <= report_days <= 3650:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Storage policy is outside supported limits")
    policy = await db.scalar(select(OrganizationExecutionPolicy).where(OrganizationExecutionPolicy.org_id == current_user.org_id))
    if not policy:
        policy = OrganizationExecutionPolicy(org_id=current_user.org_id); db.add(policy)
    policy.settings = {**(policy.settings or {}), "storage_quota_bytes": quota_gb * 1024 ** 3,
        "scan_retention_days": scan_days, "report_retention_days": report_days}
    await write_audit(db, event="storage.policy.update", user_id=str(current_user.id), org_id=str(current_user.org_id),
        resource_type="storage_policy", details={"quota_gb": quota_gb, "scan_days": scan_days, "report_days": report_days})
    await db.flush()
    return {"quota_gb": quota_gb, "scan_retention_days": scan_days, "report_retention_days": report_days}


@router.get("/storage/retention-preview")
async def preview_storage_retention(
    current_user: User = Depends(require_role("admin", "manager")),
    db: AsyncSession = Depends(get_db),
):
    """Preview exactly what the current tenant retention policy would remove."""
    candidates = await retention_candidates(db, current_user.org_id)
    return retention_preview(current_user.org_id, candidates)


@router.post("/storage/retention-cleanup")
async def cleanup_storage_retention(
    payload: dict,
    request: Request,
    current_user: User = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    """Execute a previously previewed cleanup only if its candidate set is unchanged."""
    candidates = await retention_candidates(db, current_user.org_id)
    token = str(payload.get("confirmation_token") or "")
    if not verify_confirmation_token(token, current_user.org_id, candidates):
        raise HTTPException(status.HTTP_409_CONFLICT, "Retention preview expired or storage candidates changed; preview again")
    result = await execute_retention(db, candidates)
    await write_audit(
        db,
        event="storage.retention.cleanup",
        user_id=str(current_user.id),
        org_id=str(current_user.org_id),
        resource_type="storage_policy",
        details={key: value for key, value in result.items() if key != "errors"} | {"error_count": len(result["errors"])},
        ip_address=request.client.host if request.client else None,
        success=not result["errors"],
    )
    await db.flush()
    return result


async def _http_adapter_health(url: str | None, api_key: str | None) -> dict:
    if not url:
        return {"configured": False, "healthy": None, "message": "Not configured"}
    import httpx

    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
    try:
        async with httpx.AsyncClient(timeout=5, follow_redirects=False) as client:
            response = await client.get(url.rstrip("/") + "/health", headers=headers)
        return {"configured": True, "healthy": response.status_code < 500, "status_code": response.status_code}
    except Exception as exc:
        return {"configured": True, "healthy": False, "message": type(exc).__name__}


@router.get("/runtime-status")
async def runtime_status(
    current_user: User = Depends(require_role("admin", "manager")),
    db: AsyncSession = Depends(get_db),
):
    """Return redacted deployment adapter state and bounded readiness probes."""
    configured_rows = (await db.execute(select(OrgIntegration).where(OrgIntegration.org_id == current_user.org_id,
        OrgIntegration.provider.in_(RUNTIME_ADAPTERS), OrgIntegration.is_active.is_(True)))).scalars().all()
    tenant_adapters = {}
    for row in configured_rows:
        try:
            tenant_adapters[row.provider] = decrypt_dict(row.config["_encrypted"])
        except Exception:
            tenant_adapters[row.provider] = {}
    mobile_config = tenant_adapters.get("mobile_dynamic", {})
    kube_config = tenant_adapters.get("kubernetes_runtime", {})
    mobile, kubernetes_runtime = await asyncio.gather(
        _http_adapter_health(mobile_config.get("url") or settings.MOBILE_DYNAMIC_ADAPTER_URL, mobile_config.get("api_key") or settings.MOBILE_DYNAMIC_API_KEY),
        _http_adapter_health(kube_config.get("url") or settings.KUBERNETES_RUNTIME_ADAPTER_URL, kube_config.get("api_key") or settings.KUBERNETES_RUNTIME_API_KEY),
    )
    artifact = {"configured": settings.ARTIFACT_STORAGE_BACKEND == "s3", "healthy": None}
    if artifact["configured"]:
        try:
            from app.services.artifact_storage import _client

            await asyncio.wait_for(
                asyncio.to_thread(_client().head_bucket, Bucket=settings.S3_BUCKET), timeout=6
            )
            artifact["healthy"] = True
        except Exception as exc:
            artifact.update({"healthy": False, "message": type(exc).__name__})
    isolated = {
        "configured": settings.SCAN_EXECUTOR == "kubernetes",
        "healthy": os.path.isfile("/var/run/secrets/kubernetes.io/serviceaccount/token") if settings.SCAN_EXECUTOR == "kubernetes" else None,
    }
    return {
        "scan_executor": {"mode": settings.SCAN_EXECUTOR, **isolated},
        "artifact_storage": {"backend": settings.ARTIFACT_STORAGE_BACKEND, **artifact},
        "mobile_dynamic": mobile,
        "kubernetes_runtime": kubernetes_runtime,
        "cspm": {
            "configured": settings.ENABLE_PROWLER_ADAPTER or settings.ENABLE_SCOUTSUITE_ADAPTER,
            "healthy": None,
            "message": "Capabilities are verified by the worker when a CSPM scan starts",
            "adapters": {"prowler": settings.ENABLE_PROWLER_ADAPTER, "scoutsuite": settings.ENABLE_SCOUTSUITE_ADAPTER},
        },
        "monitoring": {"configured": bool(settings.METRICS_BEARER_TOKEN), "healthy": bool(settings.METRICS_BEARER_TOKEN)},
        "required_variables": {
            "kubernetes_isolation": ["SCAN_EXECUTOR", "SCAN_JOB_IMAGE", "SCAN_JOB_RESULTS_PVC"],
            "s3_artifacts": ["ARTIFACT_STORAGE_BACKEND", "S3_BUCKET", "S3_REGION"],
            "mobile_dynamic": ["MOBILE_DYNAMIC_ADAPTER_URL", "MOBILE_DYNAMIC_API_KEY"],
            "kubernetes_runtime": ["KUBERNETES_RUNTIME_ADAPTER_URL", "KUBERNETES_RUNTIME_API_KEY"],
            "cspm": ["ENABLE_PROWLER_ADAPTER", "ENABLE_SCOUTSUITE_ADAPTER", "PROWLER_BIN", "SCOUTSUITE_BIN"],
        },
    }


# ==================== API Keys ====================


@router.get("/api-keys")
async def list_api_keys(
    current_user: User = Depends(require_role("admin", "manager")),
    db: AsyncSession = Depends(get_db),
):
    """List all API keys for the organization (values masked)."""
    result = await db.execute(
        select(ApiKey).where(ApiKey.org_id == current_user.org_id).order_by(ApiKey.key_name)
    )
    keys = result.scalars().all()
    return [
        {
            "id": str(k.id),
            "name": k.name,
            "key_name": k.key_name,
            "is_active": k.is_active,
            "has_value": bool(k.encrypted_value),
            "created_at": k.created_at.isoformat() if k.created_at else None,
            "updated_at": k.updated_at.isoformat() if k.updated_at else None,
        }
        for k in keys
    ]


@router.post("/api-keys", status_code=status.HTTP_201_CREATED)
async def create_api_key(
    payload: dict,
    current_user: User = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    """Store a new API key (encrypted at rest)."""
    name = payload.get("name", "")
    key_name = payload.get("key_name", "")
    value = payload.get("value", "")

    if not key_name or not value:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="key_name and value are required",
        )

    # Check for duplicate key_name in org
    existing = await db.execute(
        select(ApiKey).where(
            and_(ApiKey.org_id == current_user.org_id, ApiKey.key_name == key_name)
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"API key '{key_name}' already exists",
        )

    encrypted = _fernet.encrypt(value.encode()).decode()
    api_key = ApiKey(
        org_id=current_user.org_id,
        name=name or key_name,
        key_name=key_name,
        encrypted_value=encrypted,
        is_active=True,
        created_by=current_user.id,
    )
    db.add(api_key)
    await db.flush()

    return {"id": str(api_key.id), "key_name": key_name, "detail": "API key stored successfully"}


@router.put("/api-keys/{key_id}")
async def update_api_key(
    key_id: uuid.UUID,
    payload: dict,
    current_user: User = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    """Update an existing API key value."""
    result = await db.execute(
        select(ApiKey).where(
            and_(ApiKey.id == key_id, ApiKey.org_id == current_user.org_id)
        )
    )
    api_key = result.scalar_one_or_none()
    if not api_key:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="API key not found")

    value = payload.get("value")
    if value:
        api_key.encrypted_value = _fernet.encrypt(value.encode()).decode()
    if "name" in payload:
        api_key.name = payload["name"]
    if "is_active" in payload:
        api_key.is_active = payload["is_active"]

    await db.flush()
    return {"detail": "API key updated successfully"}


@router.delete("/api-keys/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_api_key(
    key_id: uuid.UUID,
    current_user: User = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    """Delete an API key."""
    result = await db.execute(
        select(ApiKey).where(
            and_(ApiKey.id == key_id, ApiKey.org_id == current_user.org_id)
        )
    )
    api_key = result.scalar_one_or_none()
    if not api_key:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="API key not found")
    await db.delete(api_key)
    await db.flush()


# ==================== Users ====================


@router.get("/users", response_model=list[UserResponse])
async def list_users(
    current_user: User = Depends(require_role("admin", "manager")),
    db: AsyncSession = Depends(get_db),
):
    """List all users in the organization."""
    result = await db.execute(
        select(User)
        .where(User.org_id == current_user.org_id)
        .order_by(User.created_at.desc())
    )
    return [UserResponse.model_validate(u) for u in result.scalars().all()]


@router.post("/users", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    payload: UserCreate,
    current_user: User = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    """Create a new user in the organization."""
    # Check uniqueness
    existing = await db.execute(select(User).where(User.email == payload.email))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already registered")

    existing = await db.execute(select(User).where(User.username == payload.username))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username already taken")

    user = User(
        org_id=current_user.org_id,
        email=payload.email,
        username=payload.username,
        password_hash=get_password_hash(payload.password),
        role=payload.role,
        is_active=True,
    )
    db.add(user)
    await db.flush()
    await db.refresh(user)
    return UserResponse.model_validate(user)


@router.put("/users/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: uuid.UUID,
    payload: UserUpdate,
    current_user: User = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    """Update a user's profile."""
    result = await db.execute(
        select(User).where(and_(User.id == user_id, User.org_id == current_user.org_id))
    )
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if payload.email is not None:
        user.email = payload.email
    if payload.username is not None:
        user.username = payload.username
    if payload.role is not None:
        user.role = payload.role
    if payload.is_active is not None:
        user.is_active = payload.is_active

    await db.flush()
    await db.refresh(user)
    return UserResponse.model_validate(user)


@router.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: uuid.UUID,
    current_user: User = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    """Deactivate a user (soft delete)."""
    if user_id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete your own account",
        )

    result = await db.execute(
        select(User).where(and_(User.id == user_id, User.org_id == current_user.org_id))
    )
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    user.is_active = False
    await db.flush()


# ==================== Scan Authorization ====================


@router.get("/scan-authorizations")
async def list_scan_authorizations(
    current_user: User = Depends(require_role("admin", "manager")),
    db: AsyncSession = Depends(get_db),
):
    """List all scan authorizations for the organization."""
    result = await db.execute(
        select(ScanAuthorization)
        .where(ScanAuthorization.org_id == current_user.org_id)
        .order_by(ScanAuthorization.created_at.desc())
    )
    auths = result.scalars().all()
    return [
        {
            "id": str(a.id),
            "target": a.target,
            "authorization_type": a.authorization_type,
            "authorized_by": str(a.authorized_by),
            "scope_file": a.scope_file,
            "valid_from": a.valid_from.isoformat() if a.valid_from else None,
            "valid_until": a.valid_until.isoformat() if a.valid_until else None,
            "notes": a.notes,
            "created_at": a.created_at.isoformat() if a.created_at else None,
        }
        for a in auths
    ]


@router.post("/scan-authorizations", status_code=status.HTTP_201_CREATED)
async def create_scan_authorization(
    payload: dict,
    request: Request,
    current_user: User = Depends(require_role("admin", "manager")),
    db: AsyncSession = Depends(get_db),
):
    """Create a new scan authorization record."""
    target = str(payload.get("target", "")).strip()
    if not target:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="target is required",
        )

    authorization_type = payload.get("authorization_type", "full")
    if authorization_type not in {"full", "passive_only", "read_only"}:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Invalid authorization_type")

    try:
        if target.startswith("*."):
            normalize_target(target[2:], "domain")
            target = target.lower().rstrip(".")
        else:
            target = normalize_target(target, "auto").normalized_value
    except TargetValidationError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc

    def parse_datetime(value):
        if not value:
            return None
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed.replace(tzinfo=parsed.tzinfo or timezone.utc)

    try:
        valid_from = parse_datetime(payload.get("valid_from"))
        valid_until = parse_datetime(payload.get("valid_until"))
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Invalid authorization validity date") from exc
    if valid_from and valid_until and valid_until <= valid_from:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "valid_until must be after valid_from")

    auth = ScanAuthorization(
        org_id=current_user.org_id,
        target=target,
        authorized_by=current_user.id,
        authorization_type=authorization_type,
        scope_file=payload.get("scope_file"),
        valid_from=valid_from,
        valid_until=valid_until,
        notes=payload.get("notes"),
    )
    db.add(auth)
    await db.flush()
    await write_audit(
        db,
        event=AuditEvent.SCAN_AUTHORIZATION_CREATE,
        user_id=str(current_user.id),
        org_id=str(current_user.org_id),
        resource_type="scan_authorization",
        resource_id=str(auth.id),
        details={"target": target, "authorization_type": authorization_type, "valid_until": valid_until.isoformat() if valid_until else None},
        ip_address=request.client.host if request.client else None,
    )

    return {"id": str(auth.id), "detail": "Scan authorization created"}


@router.delete("/scan-authorizations/{auth_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scan_authorization(
    auth_id: uuid.UUID,
    request: Request,
    current_user: User = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    """Delete a scan authorization."""
    result = await db.execute(
        select(ScanAuthorization).where(
            and_(
                ScanAuthorization.id == auth_id,
                ScanAuthorization.org_id == current_user.org_id,
            )
        )
    )
    auth = result.scalar_one_or_none()
    if not auth:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Scan authorization not found"
        )
    await write_audit(
        db,
        event=AuditEvent.SCAN_AUTHORIZATION_DELETE,
        user_id=str(current_user.id),
        org_id=str(current_user.org_id),
        resource_type="scan_authorization",
        resource_id=str(auth.id),
        details={"target": auth.target, "authorization_type": auth.authorization_type},
        ip_address=request.client.host if request.client else None,
    )
    await db.delete(auth)
    await db.flush()
