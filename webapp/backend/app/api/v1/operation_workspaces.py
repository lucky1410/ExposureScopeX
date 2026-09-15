"""Operation workspace endpoints for offensive security planning."""

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import get_db, require_role
from app.models.assessment import Assessment
from app.models.operation_workspace import OperationWorkspace
from app.models.scan import Scan
from app.models.user import User
from app.schemas.operation_workspace import OperationTransitionRequest, OperationWorkspaceCreate, OperationWorkspaceResponse, OperationWorkspaceUpdate
from app.services.audit import write_audit
from app.services.operation_control import target_status_for_transition

router = APIRouter(prefix="/operations/workspaces", tags=["Operation Workspaces"])


@router.get("", response_model=list[OperationWorkspaceResponse])
async def list_operation_workspaces(
    current_user: User = Depends(require_role("admin", "manager", "analyst", "viewer")),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(OperationWorkspace)
        .where(OperationWorkspace.org_id == current_user.org_id)
        .order_by(OperationWorkspace.updated_at.desc(), OperationWorkspace.created_at.desc())
    )
    return [OperationWorkspaceResponse.model_validate(item) for item in result.scalars().all()]


@router.post("", response_model=OperationWorkspaceResponse, status_code=status.HTTP_201_CREATED)
async def create_operation_workspace(
    payload: OperationWorkspaceCreate,
    request: Request,
    current_user: User = Depends(require_role("admin", "manager", "analyst")),
    db: AsyncSession = Depends(get_db),
):
    if payload.codename:
        existing = await db.scalar(
            select(OperationWorkspace).where(
                and_(
                    OperationWorkspace.org_id == current_user.org_id,
                    OperationWorkspace.codename == payload.codename,
                )
            )
        )
        if existing:
            raise HTTPException(status.HTTP_409_CONFLICT, "Codename already exists for this organization")

    operation = OperationWorkspace(
        org_id=current_user.org_id,
        created_by=current_user.id,
        name=payload.name,
        codename=payload.codename,
        description=payload.description,
        objective=payload.objective,
        status=payload.status,
        classification=payload.classification,
        operation_type=payload.operation_type,
        planned_start_at=payload.planned_start_at,
        planned_end_at=payload.planned_end_at,
        scope_summary=payload.scope_summary,
        roe_summary=payload.roe_summary,
        tags=payload.tags,
    )
    db.add(operation)
    await db.flush()
    await db.refresh(operation)

    await write_audit(
        db,
        event="operation.workspace.create",
        user_id=str(current_user.id),
        org_id=str(current_user.org_id),
        resource_type="operation_workspace",
        resource_id=str(operation.id),
        details={"name": operation.name, "status": operation.status, "operation_type": operation.operation_type},
        ip_address=request.client.host if request.client else None,
    )

    return OperationWorkspaceResponse.model_validate(operation)


@router.get("/{operation_id}", response_model=OperationWorkspaceResponse)
async def get_operation_workspace(
    operation_id: uuid.UUID,
    current_user: User = Depends(require_role("admin", "manager", "analyst", "viewer")),
    db: AsyncSession = Depends(get_db),
):
    operation = await db.scalar(
        select(OperationWorkspace).where(
            and_(
                OperationWorkspace.id == operation_id,
                OperationWorkspace.org_id == current_user.org_id,
            )
        )
    )
    if operation is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Operation workspace not found")
    return OperationWorkspaceResponse.model_validate(operation)


@router.patch("/{operation_id}", response_model=OperationWorkspaceResponse)
async def update_operation_workspace(
    operation_id: uuid.UUID,
    payload: OperationWorkspaceUpdate,
    request: Request,
    current_user: User = Depends(require_role("admin", "manager", "analyst")),
    db: AsyncSession = Depends(get_db),
):
    operation = await db.scalar(select(OperationWorkspace).where(
        OperationWorkspace.id == operation_id,
        OperationWorkspace.org_id == current_user.org_id,
    ).with_for_update())
    if operation is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Operation workspace not found")
    if operation.status != "planning":
        raise HTTPException(status.HTTP_409_CONFLICT, "Only planning operations can be edited")
    changes = payload.model_dump(exclude_unset=True)
    start = changes.get("planned_start_at", operation.planned_start_at)
    end = changes.get("planned_end_at", operation.planned_end_at)
    if start and end and end <= start:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "planned_end_at must be after planned_start_at")
    if changes.get("codename"):
        duplicate = await db.scalar(select(OperationWorkspace.id).where(
            OperationWorkspace.org_id == current_user.org_id,
            OperationWorkspace.codename == changes["codename"],
            OperationWorkspace.id != operation.id,
        ))
        if duplicate:
            raise HTTPException(status.HTTP_409_CONFLICT, "Codename already exists for this organization")
    for field, value in changes.items():
        setattr(operation, field, value)
    await write_audit(db, event="operation.workspace.update", user_id=str(current_user.id),
        org_id=str(current_user.org_id), resource_type="operation_workspace", resource_id=str(operation.id),
        details={"fields": sorted(changes)}, ip_address=request.client.host if request.client else None)
    await db.flush()
    await db.refresh(operation)
    return OperationWorkspaceResponse.model_validate(operation)


@router.post("/{operation_id}/transition", response_model=OperationWorkspaceResponse)
async def transition_operation_workspace(
    operation_id: uuid.UUID,
    payload: OperationTransitionRequest,
    request: Request,
    current_user: User = Depends(require_role("admin", "manager")),
    db: AsyncSession = Depends(get_db),
):
    operation = await db.scalar(
        select(OperationWorkspace).where(
            OperationWorkspace.id == operation_id,
            OperationWorkspace.org_id == current_user.org_id,
        ).with_for_update()
    )
    if operation is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Operation workspace not found")
    try:
        target_status = target_status_for_transition(operation, payload.action)
    except ValueError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc

    now = datetime.now(timezone.utc)
    previous_status = operation.status
    operation.status = target_status
    if payload.action == "approve":
        operation.approved_by = current_user.id
        operation.approved_at = now
    elif payload.action in {"activate", "resume"}:
        operation.activated_at = operation.activated_at or now
    elif payload.action == "emergency_stop":
        operation.stopped_at = now
        operation.stop_reason = payload.reason
        assessments = (await db.execute(select(Assessment).where(
            Assessment.operation_id == operation.id,
            Assessment.org_id == current_user.org_id,
        ))).scalars().all()
        assessment_ids = [item.id for item in assessments]
        scans = (await db.execute(select(Scan).where(
            Scan.assessment_id.in_(assessment_ids),
            Scan.status.in_(["queued", "running"]),
        ))).scalars().all() if assessment_ids else []
        for scan in scans:
            scan.scan_metadata = {
                **(scan.scan_metadata or {}),
                "cancel_requested": True,
                "cancel_requested_at": now.isoformat(),
                "cancel_reason": payload.reason,
                "operation_emergency_stop": str(operation.id),
            }
            scan.cancel_requested_at = now
            if scan.status == "queued":
                scan.status = "cancelled"
                scan.current_phase = "cancelled"
                scan.completed_at = now
            else:
                scan.current_phase = "cancelling"
        for assessment in assessments:
            if assessment.status == "running":
                assessment.status = "cancelled"

    await write_audit(
        db,
        event=f"operation.workspace.{payload.action}",
        user_id=str(current_user.id),
        org_id=str(current_user.org_id),
        resource_type="operation_workspace",
        resource_id=str(operation.id),
        details={"previous_status": previous_status, "status": target_status, "reason": payload.reason},
        ip_address=request.client.host if request.client else None,
    )
    await db.flush()
    await db.refresh(operation)
    return OperationWorkspaceResponse.model_validate(operation)
