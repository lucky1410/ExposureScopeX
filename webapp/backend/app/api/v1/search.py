"""Global search endpoint across all entity types."""

from fastapi import APIRouter, Depends
from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import get_current_user, get_db
from app.models.asset import Asset
from app.models.assessment import Assessment
from app.models.finding import Finding
from app.models.user import User
from app.models.vulnerability import Vulnerability
from app.schemas.search import SearchQuery, SearchResponse, SearchResultItem

router = APIRouter(prefix="/search", tags=["Search"])


@router.post("", response_model=SearchResponse)
async def global_search(
    payload: SearchQuery,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Search across assessments, assets, findings, and vulnerabilities."""
    query = payload.query
    limit = payload.limit
    entity_types = payload.entity_types or ["assessment", "asset", "finding", "vulnerability"]
    results: list[SearchResultItem] = []
    per_type_limit = max(limit // len(entity_types), 5)

    # Search assessments
    if "assessment" in entity_types:
        q = await db.execute(
            select(Assessment)
            .where(
                and_(
                    Assessment.org_id == current_user.org_id,
                    or_(
                        Assessment.name.ilike(f"%{query}%"),
                        Assessment.target.ilike(f"%{query}%"),
                        Assessment.description.ilike(f"%{query}%"),
                    ),
                )
            )
            .limit(per_type_limit)
        )
        for a in q.scalars().all():
            results.append(
                SearchResultItem(
                    entity_type="assessment",
                    id=a.id,
                    title=a.name,
                    subtitle=f"{a.target} ({a.status})",
                    metadata={"target_type": a.target_type, "status": a.status},
                )
            )

    # Search assets
    if "asset" in entity_types:
        q = await db.execute(
            select(Asset)
            .join(Assessment)
            .where(
                and_(
                    Assessment.org_id == current_user.org_id,
                    Asset.value.ilike(f"%{query}%"),
                )
            )
            .limit(per_type_limit)
        )
        for a in q.scalars().all():
            results.append(
                SearchResultItem(
                    entity_type="asset",
                    id=a.id,
                    title=a.value,
                    subtitle=f"{a.asset_type} ({'live' if a.is_live else 'inactive'})",
                    metadata={"asset_type": a.asset_type, "is_live": a.is_live},
                )
            )

    # Search findings
    if "finding" in entity_types:
        q = await db.execute(
            select(Finding)
            .join(Assessment)
            .where(
                and_(
                    Assessment.org_id == current_user.org_id,
                    or_(
                        Finding.title.ilike(f"%{query}%"),
                        Finding.description.ilike(f"%{query}%"),
                        Finding.template_id.ilike(f"%{query}%"),
                    ),
                )
            )
            .limit(per_type_limit)
        )
        for f in q.scalars().all():
            results.append(
                SearchResultItem(
                    entity_type="finding",
                    id=f.id,
                    title=f.title,
                    subtitle=f.source,
                    severity=f.severity,
                    metadata={"status": f.status, "severity": f.severity},
                )
            )

    # Search vulnerabilities
    if "vulnerability" in entity_types:
        q = await db.execute(
            select(Vulnerability)
            .where(
                or_(
                    Vulnerability.title.ilike(f"%{query}%"),
                    Vulnerability.cve_id.ilike(f"%{query}%"),
                    Vulnerability.description.ilike(f"%{query}%"),
                )
            )
            .limit(per_type_limit)
        )
        for v in q.scalars().all():
            results.append(
                SearchResultItem(
                    entity_type="vulnerability",
                    id=v.id,
                    title=v.cve_id or v.title,
                    subtitle=v.title if v.cve_id else None,
                    severity=v.severity,
                    metadata={"cvss": float(v.cvss_score) if v.cvss_score else None},
                )
            )

    return SearchResponse(query=query, total=len(results), items=results[:limit])
