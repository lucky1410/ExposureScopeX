"""Investigation endpoints: CRUD, link findings, evidence, notes, timeline."""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import get_current_user, get_db, require_permission
from app.models.assessment import Assessment
from app.models.finding import Finding
from app.models.investigation import Evidence, Investigation, InvestigationFinding, Note
from app.models.user import User
from app.schemas.investigation import (
    EvidenceCreate,
    EvidenceResponse,
    InvestigationCreate,
    InvestigationResponse,
    InvestigationUpdate,
    NoteCreate,
    NoteResponse,
)

router = APIRouter(prefix="/investigations", tags=["Investigations"])


def _build_response(inv: Investigation) -> InvestigationResponse:
    return InvestigationResponse(
        id=inv.id,
        org_id=inv.org_id,
        created_by=inv.created_by,
        title=inv.title,
        description=inv.description,
        status=inv.status,
        priority=inv.priority,
        assigned_to=inv.assigned_to,
        creator_username=inv.creator.username if inv.creator else None,
        assignee_username=inv.assignee.username if inv.assignee else None,
        finding_count=len(inv.finding_links) if inv.finding_links else 0,
        evidence_count=len(inv.evidence_items) if inv.evidence_items else 0,
        note_count=len(inv.notes) if inv.notes else 0,
        created_at=inv.created_at,
        updated_at=inv.updated_at,
    )


@router.get("", response_model=list[InvestigationResponse])
async def list_investigations(
    status_filter: str | None = Query(None, alias="status"),
    priority: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List investigations for the user's organization."""
    base = select(Investigation).where(Investigation.org_id == current_user.org_id)

    if status_filter:
        base = base.where(Investigation.status == status_filter)
    if priority:
        base = base.where(Investigation.priority == priority)

    offset = (page - 1) * page_size
    result = await db.execute(
        base.order_by(Investigation.created_at.desc()).offset(offset).limit(page_size)
    )
    investigations = result.scalars().all()
    return [_build_response(inv) for inv in investigations]


@router.post("", response_model=InvestigationResponse, status_code=status.HTTP_201_CREATED)
async def create_investigation(
    payload: InvestigationCreate,
    current_user: User = Depends(require_permission("investigations:write")),
    db: AsyncSession = Depends(get_db),
):
    """Create a new investigation."""
    await _validate_assignee(payload.assigned_to, current_user, db)
    inv = Investigation(
        org_id=current_user.org_id,
        created_by=current_user.id,
        title=payload.title,
        description=payload.description,
        priority=payload.priority,
        assigned_to=payload.assigned_to,
        status="open",
    )
    db.add(inv)
    await db.flush()
    await db.refresh(inv)
    return _build_response(inv)


@router.get("/{investigation_id}", response_model=InvestigationResponse)
async def get_investigation(
    investigation_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get a single investigation."""
    inv = await _get_investigation(investigation_id, current_user, db)
    return _build_response(inv)


@router.put("/{investigation_id}", response_model=InvestigationResponse)
async def update_investigation(
    investigation_id: uuid.UUID,
    payload: InvestigationUpdate,
    current_user: User = Depends(require_permission("investigations:write")),
    db: AsyncSession = Depends(get_db),
):
    """Update an investigation."""
    inv = await _get_investigation(investigation_id, current_user, db)
    await _validate_assignee(payload.assigned_to, current_user, db)

    if payload.title is not None:
        inv.title = payload.title
    if payload.description is not None:
        inv.description = payload.description
    if payload.status is not None:
        inv.status = payload.status
    if payload.priority is not None:
        inv.priority = payload.priority
    if payload.assigned_to is not None:
        inv.assigned_to = payload.assigned_to

    await db.flush()
    await db.refresh(inv)
    return _build_response(inv)


@router.delete("/{investigation_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_investigation(
    investigation_id: uuid.UUID,
    current_user: User = Depends(require_permission("investigations:write")),
    db: AsyncSession = Depends(get_db),
):
    """Delete an investigation."""
    inv = await _get_investigation(investigation_id, current_user, db)
    await db.delete(inv)
    await db.flush()


# --- Finding Links ---


@router.post("/{investigation_id}/findings/{finding_id}", status_code=status.HTTP_201_CREATED)
async def link_finding(
    investigation_id: uuid.UUID,
    finding_id: uuid.UUID,
    current_user: User = Depends(require_permission("investigations:write")),
    db: AsyncSession = Depends(get_db),
):
    """Link a finding to an investigation."""
    await _get_investigation(investigation_id, current_user, db)

    # Verify finding exists
    fq = await db.execute(
        select(Finding)
        .join(Assessment, Assessment.id == Finding.assessment_id)
        .where(Finding.id == finding_id, Assessment.org_id == current_user.org_id)
    )
    if not fq.scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")

    # Check for existing link
    existing = await db.execute(
        select(InvestigationFinding).where(
            and_(
                InvestigationFinding.investigation_id == investigation_id,
                InvestigationFinding.finding_id == finding_id,
            )
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="Finding already linked"
        )

    link = InvestigationFinding(
        investigation_id=investigation_id, finding_id=finding_id
    )
    db.add(link)
    await db.flush()
    return {"detail": "Finding linked successfully"}


@router.delete("/{investigation_id}/findings/{finding_id}", status_code=status.HTTP_204_NO_CONTENT)
async def unlink_finding(
    investigation_id: uuid.UUID,
    finding_id: uuid.UUID,
    current_user: User = Depends(require_permission("investigations:write")),
    db: AsyncSession = Depends(get_db),
):
    """Unlink a finding from an investigation."""
    await _get_investigation(investigation_id, current_user, db)
    result = await db.execute(
        select(InvestigationFinding).where(
            and_(
                InvestigationFinding.investigation_id == investigation_id,
                InvestigationFinding.finding_id == finding_id,
            )
        )
    )
    link = result.scalar_one_or_none()
    if not link:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Link not found")
    await db.delete(link)
    await db.flush()


# --- Evidence ---


@router.get("/{investigation_id}/evidence", response_model=list[EvidenceResponse])
async def list_evidence(
    investigation_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List evidence items for an investigation."""
    await _get_investigation(investigation_id, current_user, db)
    result = await db.execute(
        select(Evidence)
        .where(Evidence.investigation_id == investigation_id)
        .order_by(Evidence.created_at.desc())
    )
    return [EvidenceResponse.model_validate(e) for e in result.scalars().all()]


@router.post(
    "/{investigation_id}/evidence",
    response_model=EvidenceResponse,
    status_code=status.HTTP_201_CREATED,
)
async def add_evidence(
    investigation_id: uuid.UUID,
    payload: EvidenceCreate,
    current_user: User = Depends(require_permission("investigations:write")),
    db: AsyncSession = Depends(get_db),
):
    """Add evidence to an investigation."""
    await _get_investigation(investigation_id, current_user, db)
    evidence = Evidence(
        investigation_id=investigation_id,
        type=payload.type,
        title=payload.title,
        content=payload.content,
        file_path=payload.file_path,
        created_by=current_user.id,
    )
    db.add(evidence)
    await db.flush()
    await db.refresh(evidence)
    return EvidenceResponse.model_validate(evidence)


# --- Notes ---


@router.get("/{investigation_id}/notes", response_model=list[NoteResponse])
async def list_notes(
    investigation_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List notes for an investigation."""
    await _get_investigation(investigation_id, current_user, db)
    result = await db.execute(
        select(Note)
        .where(Note.investigation_id == investigation_id)
        .order_by(Note.created_at.desc())
    )
    notes = result.scalars().all()
    return [
        NoteResponse(
            id=n.id,
            investigation_id=n.investigation_id,
            content=n.content,
            created_by=n.created_by,
            creator_username=n.creator.username if n.creator else None,
            created_at=n.created_at,
        )
        for n in notes
    ]


@router.post(
    "/{investigation_id}/notes",
    response_model=NoteResponse,
    status_code=status.HTTP_201_CREATED,
)
async def add_note(
    investigation_id: uuid.UUID,
    payload: NoteCreate,
    current_user: User = Depends(require_permission("investigations:write")),
    db: AsyncSession = Depends(get_db),
):
    """Add a note to an investigation."""
    await _get_investigation(investigation_id, current_user, db)
    note = Note(
        investigation_id=investigation_id,
        content=payload.content,
        created_by=current_user.id,
    )
    db.add(note)
    await db.flush()
    await db.refresh(note)
    return NoteResponse(
        id=note.id,
        investigation_id=note.investigation_id,
        content=note.content,
        created_by=note.created_by,
        creator_username=current_user.username,
        created_at=note.created_at,
    )


# --- Timeline ---


@router.get("/{investigation_id}/timeline")
async def get_investigation_timeline(
    investigation_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get a combined timeline of all events in an investigation."""
    inv = await _get_investigation(investigation_id, current_user, db)

    events = []

    # Investigation created
    events.append({
        "timestamp": inv.created_at.isoformat(),
        "type": "created",
        "description": f"Investigation created: {inv.title}",
    })

    # Evidence
    for e in inv.evidence_items or []:
        events.append({
            "timestamp": e.created_at.isoformat(),
            "type": "evidence_added",
            "description": f"Evidence added: {e.title} ({e.type})",
        })

    # Notes
    for n in inv.notes or []:
        events.append({
            "timestamp": n.created_at.isoformat(),
            "type": "note_added",
            "description": f"Note added by {n.creator.username if n.creator else 'unknown'}",
        })

    events.sort(key=lambda e: e["timestamp"])
    return events


async def _get_investigation(
    investigation_id: uuid.UUID, current_user: User, db: AsyncSession
) -> Investigation:
    """Verify access and return the investigation."""
    result = await db.execute(
        select(Investigation).where(
            and_(
                Investigation.id == investigation_id,
                Investigation.org_id == current_user.org_id,
            )
        )
    )
    inv = result.scalar_one_or_none()
    if not inv:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Investigation not found"
        )
    return inv


async def _validate_assignee(assignee_id: uuid.UUID | None, current_user: User, db: AsyncSession) -> None:
    if assignee_id is None:
        return
    assignee = await db.scalar(
        select(User).where(User.id == assignee_id, User.org_id == current_user.org_id, User.is_active.is_(True))
    )
    if not assignee:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Assignee must be an active user in this organization")
