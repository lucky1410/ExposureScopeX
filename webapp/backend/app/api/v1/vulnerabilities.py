"""Vulnerability endpoints: list, detail, findings."""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import get_current_user, get_db
from app.models.assessment import Assessment
from app.models.finding import Finding
from app.models.user import User
from app.models.vulnerability import Vulnerability
from app.schemas.finding import FindingResponse
from app.schemas.vulnerability import VulnerabilityList, VulnerabilityResponse

router = APIRouter(prefix="/vulnerabilities", tags=["Vulnerabilities"])


@router.get("", response_model=VulnerabilityList)
async def list_vulnerabilities(
    severity: str | None = None,
    search: str | None = None,
    is_kev: bool | None = None,
    exploit_available: bool | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List known vulnerabilities, optionally filtered."""
    base = select(Vulnerability)

    if severity:
        base = base.where(Vulnerability.severity == severity.upper())
    if is_kev is not None:
        base = base.where(Vulnerability.is_kev == is_kev)
    if exploit_available is not None:
        base = base.where(Vulnerability.exploit_available == exploit_available)
    if search:
        base = base.where(
            Vulnerability.title.ilike(f"%{search}%")
            | Vulnerability.cve_id.ilike(f"%{search}%")
            | Vulnerability.description.ilike(f"%{search}%")
        )

    count_q = select(func.count()).select_from(base.subquery())
    total = (await db.execute(count_q)).scalar() or 0

    offset = (page - 1) * page_size
    result = await db.execute(
        base.order_by(Vulnerability.cvss_score.desc().nullslast()).offset(offset).limit(page_size)
    )
    vulns = result.scalars().all()

    return VulnerabilityList(
        items=[VulnerabilityResponse.model_validate(v) for v in vulns],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/{vuln_id}", response_model=VulnerabilityResponse)
async def get_vulnerability(
    vuln_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get a single vulnerability by ID."""
    result = await db.execute(select(Vulnerability).where(Vulnerability.id == vuln_id))
    vuln = result.scalar_one_or_none()
    if not vuln:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Vulnerability not found"
        )
    return VulnerabilityResponse.model_validate(vuln)


@router.get("/{vuln_id}/findings", response_model=list[FindingResponse])
async def get_vulnerability_findings(
    vuln_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get all findings associated with a specific vulnerability."""
    result = await db.execute(
        select(Finding)
        .join(Assessment)
        .where(
            and_(
                Finding.vulnerability_id == vuln_id,
                Assessment.org_id == current_user.org_id,
            )
        )
        .order_by(Finding.created_at.desc())
    )
    findings = result.scalars().all()

    return [
        FindingResponse(
            id=f.id,
            assessment_id=f.assessment_id,
            scan_id=f.scan_id,
            asset_id=f.asset_id,
            vulnerability_id=f.vulnerability_id,
            source=f.source,
            template_id=f.template_id,
            severity=f.severity,
            title=f.title,
            description=f.description,
            url=f.url,
            evidence=f.evidence,
            status=f.status,
            risk_score=f.risk_score,
            first_seen=f.first_seen,
            last_seen=f.last_seen,
            remediated_at=f.remediated_at,
            is_demo=f.is_demo,
            created_at=f.created_at,
            updated_at=f.updated_at,
            asset_value=f.asset.value if f.asset else None,
            vulnerability_title=f.vulnerability.title if f.vulnerability else None,
        )
        for f in findings
    ]
