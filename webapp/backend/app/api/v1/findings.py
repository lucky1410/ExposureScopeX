"""Finding endpoints: list, detail, status update, stats."""

import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import get_current_user, get_db, require_permission
from app.models.assessment import Assessment
from app.models.asset import Asset
from app.models.finding import Finding, FindingActivity, FindingIdentity, FindingObservation
from app.models.user import User
from app.schemas.finding import (FindingActivityCreate, FindingActivityResponse, FindingList,
    FindingObservationResponse, FindingResponse, FindingStats, FindingStatusUpdate, FindingWorkflowUpdate)
from app.services.audit import AuditEvent, write_audit

router = APIRouter(prefix="/findings", tags=["Findings"])

SUPPRESSIVE_STATUSES = {
    "false_positive", "suppressed", "approved_exception", "accepted_risk",
    "compensating_control", "not_exploitable",
}


def _finding_response(f: Finding) -> FindingResponse:
    payload = FindingResponse.model_validate(f).model_dump()
    payload.pop("asset_value", None)
    payload.pop("vulnerability_title", None)
    if f.due_at and f.status not in {"remediated", *SUPPRESSIVE_STATUSES}:
        payload["sla_status"] = "overdue" if f.due_at < datetime.now(timezone.utc) else "on_track"
    return FindingResponse(
        **payload,
        asset_value=f.asset.value if f.asset else None,
        vulnerability_title=f.vulnerability.title if f.vulnerability else None,
    )


@router.get("", response_model=FindingList)
async def list_findings(
    assessment_id: uuid.UUID | None = None,
    scan_id: uuid.UUID | None = None,
    asset_id: uuid.UUID | None = None,
    asset_query: str | None = None,
    severity: str | None = None,
    status_filter: str | None = Query(None, alias="status"),
    source: str | None = None,
    search: str | None = None,
    has_url: bool | None = None,
    min_risk_score: float | None = Query(None, ge=0, le=100),
    min_confidence: float | None = Query(None, ge=0, le=100),
    reachability: str | None = None,
    exploitability: str | None = None,
    suppression_active: bool | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List findings for the user's organization with filters."""
    base = select(Finding).join(Assessment).where(Assessment.org_id == current_user.org_id)

    if assessment_id:
        base = base.where(Finding.assessment_id == assessment_id)
    if scan_id:
        base = base.where(Finding.scan_id == scan_id)
    if asset_id:
        base = base.where(Finding.asset_id == asset_id)
    if asset_query:
        base = base.where(Finding.asset.has(Asset.value.ilike(f"%{asset_query}%")))
    if severity:
        base = base.where(Finding.severity == severity.upper())
    if status_filter:
        base = base.where(Finding.status == status_filter)
    if source:
        base = base.where(Finding.source == source)
    if search:
        base = base.where(
            Finding.title.ilike(f"%{search}%") | Finding.description.ilike(f"%{search}%")
        )
    if has_url is True:
        base = base.where(Finding.url.is_not(None))
    elif has_url is False:
        base = base.where(Finding.url.is_(None))
    if min_risk_score is not None:
        base = base.where(Finding.risk_score >= min_risk_score)
    if min_confidence is not None:
        base = base.where(Finding.confidence_score >= min_confidence)
    if reachability:
        base = base.where(Finding.reachability == reachability)
    if exploitability:
        base = base.where(Finding.exploitability == exploitability)
    if suppression_active is True:
        base = base.where(
            Finding.status.in_(SUPPRESSIVE_STATUSES),
            Finding.suppression_expires_at > datetime.now(timezone.utc),
        )
    elif suppression_active is False:
        base = base.where(
            ~Finding.status.in_(SUPPRESSIVE_STATUSES)
            | (Finding.suppression_expires_at <= datetime.now(timezone.utc))
            | Finding.suppression_expires_at.is_(None)
        )

    count_q = select(func.count()).select_from(base.subquery())
    total = (await db.execute(count_q)).scalar() or 0

    # Custom severity ordering
    severity_order = func.array_position(
        ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"], Finding.severity
    )

    offset = (page - 1) * page_size
    result = await db.execute(
        base.order_by(severity_order, Finding.created_at.desc()).offset(offset).limit(page_size)
    )
    findings = result.scalars().all()

    items = [_finding_response(f) for f in findings]

    return FindingList(items=items, total=total, page=page, page_size=page_size)


@router.get("/stats", response_model=FindingStats)
async def get_finding_stats(
    assessment_id: uuid.UUID | None = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get finding statistics: counts by severity and status."""
    base_filter = and_(Assessment.org_id == current_user.org_id)
    if assessment_id:
        base_filter = and_(base_filter, Finding.assessment_id == assessment_id)

    # By severity
    by_severity = {}
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        q = await db.execute(
            select(func.count(Finding.id))
            .join(Assessment)
            .where(and_(base_filter, Finding.severity == sev))
        )
        by_severity[sev] = q.scalar() or 0

    # By status
    by_status = {}
    for st in [
        "new", "confirmed", "false_positive", "remediated", "suppressed",
        "approved_exception", "accepted_risk", "compensating_control", "not_exploitable",
    ]:
        q = await db.execute(
            select(func.count(Finding.id))
            .join(Assessment)
            .where(and_(base_filter, Finding.status == st))
        )
        by_status[st] = q.scalar() or 0

    total = sum(by_severity.values())

    # New in last 24h
    now = datetime.now(timezone.utc)
    q24 = await db.execute(
        select(func.count(Finding.id))
        .join(Assessment)
        .where(and_(base_filter, Finding.created_at >= now - timedelta(hours=24)))
    )
    new_24h = q24.scalar() or 0

    # New in last 7d
    q7d = await db.execute(
        select(func.count(Finding.id))
        .join(Assessment)
        .where(and_(base_filter, Finding.created_at >= now - timedelta(days=7)))
    )
    new_7d = q7d.scalar() or 0

    return FindingStats(
        total=total,
        by_severity=by_severity,
        by_status=by_status,
        new_last_24h=new_24h,
        new_last_7d=new_7d,
    )


@router.get("/{finding_id}", response_model=FindingResponse)
async def get_finding(
    finding_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get a single finding by ID."""
    result = await db.execute(
        select(Finding)
        .join(Assessment)
        .where(and_(Finding.id == finding_id, Assessment.org_id == current_user.org_id))
    )
    f = result.scalar_one_or_none()
    if not f:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")

    return _finding_response(f)


@router.get("/{finding_id}/observations", response_model=list[FindingObservationResponse])
async def get_finding_observations(
    finding_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return the same normalized issue as observed across authorized scans."""
    identity_id = await db.scalar(
        select(Finding.identity_id).join(Assessment).where(
            Finding.id == finding_id, Assessment.org_id == current_user.org_id
        )
    )
    if not identity_id:
        return []
    observations = (await db.execute(
        select(FindingObservation)
        .join(FindingIdentity)
        .where(FindingObservation.identity_id == identity_id, FindingIdentity.org_id == current_user.org_id)
        .order_by(FindingObservation.observed_at.desc())
    )).scalars().all()
    return observations


@router.get("/{finding_id}/activities", response_model=list[FindingActivityResponse])
async def list_finding_activities(finding_id: uuid.UUID, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    exists = await db.scalar(select(Finding.id).join(Assessment).where(Finding.id == finding_id, Assessment.org_id == current_user.org_id))
    if not exists:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not found")
    return (await db.execute(select(FindingActivity).where(FindingActivity.finding_id == finding_id).order_by(FindingActivity.created_at))).scalars().all()


@router.post("/{finding_id}/activities", response_model=FindingActivityResponse, status_code=status.HTTP_201_CREATED)
async def create_finding_activity(finding_id: uuid.UUID, payload: FindingActivityCreate,
    current_user: User = Depends(require_permission("findings:triage")), db: AsyncSession = Depends(get_db)):
    finding = await db.scalar(select(Finding).join(Assessment).where(Finding.id == finding_id, Assessment.org_id == current_user.org_id))
    if not finding:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not found")
    if payload.activity_type == "comment" and not (payload.body or "").strip():
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Comment text is required")
    activity = FindingActivity(finding_id=finding.id, actor_id=current_user.id, activity_type=payload.activity_type,
        body=(payload.body or "").strip() or None, payload=payload.payload)
    if payload.activity_type == "retest_requested":
        finding.verification_status = "requested"
    db.add(activity)
    await write_audit(db, event="finding.activity.create", user_id=str(current_user.id), org_id=str(current_user.org_id),
        resource_type="finding", resource_id=str(finding.id), details={"activity_type": payload.activity_type})
    await db.flush()
    await db.refresh(activity)
    return activity


@router.patch("/{finding_id}/workflow", response_model=FindingResponse)
async def update_finding_workflow(finding_id: uuid.UUID, payload: FindingWorkflowUpdate,
    current_user: User = Depends(require_permission("findings:triage")), db: AsyncSession = Depends(get_db)):
    finding = await db.scalar(select(Finding).join(Assessment).where(Finding.id == finding_id, Assessment.org_id == current_user.org_id))
    if not finding:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not found")
    if payload.assigned_to:
        assignee = await db.scalar(select(User).where(User.id == payload.assigned_to, User.org_id == current_user.org_id, User.is_active.is_(True)))
        if not assignee:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Assignee is not an active organization member")
    changes = payload.model_dump(exclude_unset=True, exclude={"comment"})
    for key, value in changes.items():
        setattr(finding, key, value)
    finding.sla_status = "untracked" if not finding.due_at else ("overdue" if finding.due_at < datetime.now(timezone.utc) else "on_track")
    db.add(FindingActivity(finding_id=finding.id, actor_id=current_user.id, activity_type="workflow_updated",
        body=(payload.comment or "").strip() or None, payload={key: str(value) if value is not None else None for key, value in changes.items()}))
    await write_audit(db, event="finding.workflow.update", user_id=str(current_user.id), org_id=str(current_user.org_id),
        resource_type="finding", resource_id=str(finding.id), details={"fields": sorted(changes)})
    await db.flush()
    await db.refresh(finding)
    return _finding_response(finding)


@router.patch("/{finding_id}/status", response_model=FindingResponse)
async def update_finding_status(
    finding_id: uuid.UUID,
    payload: FindingStatusUpdate,
    current_user: User = Depends(require_permission("findings:triage")),
    db: AsyncSession = Depends(get_db),
):
    """Update the status of a finding (confirm, mark false positive, remediate, suppress)."""
    result = await db.execute(
        select(Finding)
        .join(Assessment)
        .where(and_(Finding.id == finding_id, Assessment.org_id == current_user.org_id))
    )
    f = result.scalar_one_or_none()
    if not f:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")

    now = datetime.now(timezone.utc)
    if payload.status in SUPPRESSIVE_STATUSES:
        if not payload.notes or not payload.notes.strip():
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "A reason is required for this disposition")
        if not payload.scope or not payload.scope.strip():
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "A suppression scope is required")
        if payload.expires_at is None or payload.expires_at <= now:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "A future expiry date is required")
    f.status = payload.status
    f.status_reason = payload.notes.strip() if payload.notes else None
    f.status_scope = payload.scope.strip() if payload.scope else None
    f.status_changed_by = current_user.id
    f.status_changed_at = now
    f.suppression_expires_at = payload.expires_at if payload.status in SUPPRESSIVE_STATUSES else None
    if payload.status == "remediated":
        f.remediated_at = now
    elif payload.status != "remediated":
        f.remediated_at = None
    if f.identity_id:
        identity = await db.get(FindingIdentity, f.identity_id)
        if identity:
            identity.status = "closed" if payload.status in {"remediated", *SUPPRESSIVE_STATUSES} else "open"

    await db.flush()
    await db.refresh(f)

    return _finding_response(f)
