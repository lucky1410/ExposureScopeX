"""Asset endpoints: list, detail with ports/dns/tls/technologies/headers/findings/timeline."""

import uuid
from collections import defaultdict

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import get_current_user, get_db, require_permission
from app.models.asm import AsmTarget
from app.models.asset import Asset
from app.models.asset_graph import AssetRelation, AttackPath, ExposureEvent
from app.models.assessment import Assessment
from app.models.dns_record import DnsRecord
from app.models.finding import Finding
from app.models.http_header import HttpHeader
from app.models.port import Port
from app.models.technology import Technology
from app.models.tls_certificate import TlsCertificate
from app.models.user import User
from app.schemas.asset import (
    AssetDetail,
    InventoryAsset,
    InventoryAssetList,
    InventoryRelation,
    AssetList,
    AssetResponse,
    AssetUpdate,
    DnsRecordResponse,
    HttpHeaderResponse,
    PortResponse,
    TechnologyResponse,
    TlsCertificateResponse,
)
from app.schemas.finding import FindingResponse
from app.services.asset_inventory import normalize_target, summarize_asm_target, summarize_asset

router = APIRouter(prefix="/assets", tags=["Assets"])


@router.get("", response_model=AssetList)
async def list_assets(
    assessment_id: uuid.UUID | None = None,
    asset_type: str | None = None,
    is_live: bool | None = None,
    search: str | None = None,
    root_domain: str | None = None,
    owner: str | None = None,
    ownership_status: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List assets for the user's organization, with optional filters."""
    base = select(Asset).join(Assessment).where(Assessment.org_id == current_user.org_id)

    if assessment_id:
        base = base.where(Asset.assessment_id == assessment_id)
    if asset_type:
        base = base.where(Asset.asset_type == asset_type)
    if is_live is not None:
        base = base.where(Asset.is_live == is_live)
    if search:
        base = base.where(Asset.value.ilike(f"%{search}%"))
    if root_domain:
        base = base.where(Asset.root_domain == root_domain.lower().rstrip("."))
    if owner:
        base = base.where(Asset.owner.ilike(f"%{owner}%"))
    if ownership_status:
        base = base.where(Asset.ownership_status == ownership_status)

    count_q = select(func.count()).select_from(base.subquery())
    total = (await db.execute(count_q)).scalar() or 0

    offset = (page - 1) * page_size
    result = await db.execute(base.order_by(Asset.value).offset(offset).limit(page_size))
    assets = result.scalars().all()

    inventory_index, _ = await _build_inventory_index(current_user.org_id, db)

    return AssetList(
        items=[
            AssetResponse.model_validate(
                {
                    **AssetResponse.model_validate(a).model_dump(),
                    "canonical_key": inventory_index.get(str(a.id), {}).get("canonical_key"),
                    "normalized_value": inventory_index.get(str(a.id), {}).get("normalized_value"),
                    "root_domain": inventory_index.get(str(a.id), {}).get("root_domain"),
                    "related_count": inventory_index.get(str(a.id), {}).get("related_count", 0),
                    "asm_related_count": inventory_index.get(str(a.id), {}).get("asm_related_count", 0),
                }
            )
            for a in assets
        ],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/inventory", response_model=InventoryAssetList)
async def get_inventory(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return a normalized asset inventory across assessments and ASM."""
    _, inventory_payload = await _build_inventory_index(current_user.org_id, db)
    return inventory_payload


@router.get("/graph")
async def get_asset_graph(
    assessment_id: uuid.UUID | None = None,
    scan_id: uuid.UUID | None = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return persisted graph nodes, edges, and attack paths for the tenant."""
    asset_query = select(Asset).join(Assessment).where(Assessment.org_id == current_user.org_id)
    relation_query = select(AssetRelation).join(Assessment).where(Assessment.org_id == current_user.org_id)
    path_query = select(AttackPath).join(Assessment).where(Assessment.org_id == current_user.org_id)
    if assessment_id:
        asset_query = asset_query.where(Asset.assessment_id == assessment_id)
        relation_query = relation_query.where(AssetRelation.assessment_id == assessment_id)
        path_query = path_query.where(AttackPath.assessment_id == assessment_id)
    if scan_id:
        relation_query = relation_query.where(AssetRelation.scan_id == scan_id)
        path_query = path_query.where(AttackPath.scan_id == scan_id)
    assets = (await db.execute(asset_query.order_by(Asset.value).limit(5000))).scalars().all()
    relations = (await db.execute(relation_query.order_by(AssetRelation.created_at).limit(10000))).scalars().all()
    paths = (await db.execute(path_query.order_by(AttackPath.risk_score.desc()).limit(500))).scalars().all()
    return {
        "nodes": [{
            "id": str(asset.id),
            "canonical_key": asset.canonical_key,
            "type": asset.asset_type,
            "label": asset.value,
            "is_live": asset.is_live,
            "owner": asset.owner,
            "ownership_status": asset.ownership_status,
        } for asset in assets],
        "edges": [{
            "id": str(relation.id),
            "source": str(relation.source_asset_id),
            "target": str(relation.target_asset_id),
            "relation": relation.relation_type,
            "confidence": relation.confidence,
            "evidence": relation.evidence,
        } for relation in relations],
        "attack_paths": [{
            "id": str(path.id),
            "scan_id": str(path.scan_id),
            "title": path.title,
            "severity": path.severity,
            "risk_score": float(path.risk_score),
            "status": path.status,
            "nodes": path.nodes,
            "edges": path.edges,
            "evidence": path.evidence,
        } for path in paths],
    }


@router.get("/drift")
async def get_asset_drift(
    assessment_id: uuid.UUID | None = None,
    scan_id: uuid.UUID | None = None,
    event_type: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=250),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    query = select(ExposureEvent).where(ExposureEvent.org_id == current_user.org_id)
    if assessment_id:
        query = query.where(ExposureEvent.assessment_id == assessment_id)
    if scan_id:
        query = query.where(ExposureEvent.scan_id == scan_id)
    if event_type:
        query = query.where(ExposureEvent.event_type == event_type)
    total = (await db.execute(select(func.count()).select_from(query.subquery()))).scalar() or 0
    events = (await db.execute(
        query.order_by(ExposureEvent.observed_at.desc()).offset((page - 1) * page_size).limit(page_size)
    )).scalars().all()
    return {
        "items": [{
            "id": str(event.id),
            "assessment_id": str(event.assessment_id),
            "scan_id": str(event.scan_id) if event.scan_id else None,
            "asset_id": str(event.asset_id) if event.asset_id else None,
            "event_type": event.event_type,
            "severity": event.severity,
            "payload": event.payload,
            "observed_at": event.observed_at,
        } for event in events],
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@router.get("/{asset_id}", response_model=AssetDetail)
async def get_asset(
    asset_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get full asset details including ports, DNS, TLS, technologies, and headers."""
    result = await db.execute(
        select(Asset)
        .join(Assessment)
        .where(and_(Asset.id == asset_id, Assessment.org_id == current_user.org_id))
    )
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")

    # Load related data
    ports_r = await db.execute(select(Port).where(Port.asset_id == asset_id))
    dns_r = await db.execute(select(DnsRecord).where(DnsRecord.asset_id == asset_id))
    tech_r = await db.execute(select(Technology).where(Technology.asset_id == asset_id))
    tls_r = await db.execute(select(TlsCertificate).where(TlsCertificate.asset_id == asset_id))
    hdr_r = await db.execute(select(HttpHeader).where(HttpHeader.asset_id == asset_id))

    return AssetDetail(
        id=asset.id,
        assessment_id=asset.assessment_id,
        asset_type=asset.asset_type,
        value=asset.value,
        parent_id=asset.parent_id,
        is_live=asset.is_live,
        first_seen=asset.first_seen,
        last_seen=asset.last_seen,
        metadata_=asset.metadata_,
        canonical_key=asset.canonical_key,
        root_domain=asset.root_domain,
        owner=asset.owner,
        ownership_status=asset.ownership_status,
        is_demo=asset.is_demo,
        created_at=asset.created_at,
        updated_at=asset.updated_at,
        ports=[PortResponse.model_validate(p) for p in ports_r.scalars().all()],
        dns_records=[DnsRecordResponse.model_validate(d) for d in dns_r.scalars().all()],
        technologies=[TechnologyResponse.model_validate(t) for t in tech_r.scalars().all()],
        tls_certificates=[TlsCertificateResponse.model_validate(t) for t in tls_r.scalars().all()],
        http_headers=[HttpHeaderResponse.model_validate(h) for h in hdr_r.scalars().all()],
    )


@router.patch("/{asset_id}", response_model=AssetResponse)
async def update_asset(
    asset_id: uuid.UUID,
    payload: AssetUpdate,
    current_user: User = Depends(require_permission("assets:write")),
    db: AsyncSession = Depends(get_db),
):
    """Update ownership attribution or archive/reactivate an asset."""
    asset = await _verify_asset_access(asset_id, current_user, db)
    changes = payload.model_dump(exclude_unset=True)
    if "owner" in changes:
        asset.owner = changes["owner"].strip() if changes["owner"] else None
    if "ownership_status" in changes:
        asset.ownership_status = changes["ownership_status"]
    if "is_live" in changes:
        asset.is_live = changes["is_live"]
    await db.commit()
    await db.refresh(asset)
    return AssetResponse.model_validate(asset)


@router.get("/{asset_id}/ports", response_model=list[PortResponse])
async def get_asset_ports(
    asset_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get ports for a specific asset."""
    await _verify_asset_access(asset_id, current_user, db)
    result = await db.execute(
        select(Port).where(Port.asset_id == asset_id).order_by(Port.port_number)
    )
    return [PortResponse.model_validate(p) for p in result.scalars().all()]


@router.get("/{asset_id}/dns", response_model=list[DnsRecordResponse])
async def get_asset_dns(
    asset_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get DNS records for a specific asset."""
    await _verify_asset_access(asset_id, current_user, db)
    result = await db.execute(select(DnsRecord).where(DnsRecord.asset_id == asset_id))
    return [DnsRecordResponse.model_validate(d) for d in result.scalars().all()]


@router.get("/{asset_id}/tls", response_model=list[TlsCertificateResponse])
async def get_asset_tls(
    asset_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get TLS certificates for a specific asset."""
    await _verify_asset_access(asset_id, current_user, db)
    result = await db.execute(select(TlsCertificate).where(TlsCertificate.asset_id == asset_id))
    return [TlsCertificateResponse.model_validate(t) for t in result.scalars().all()]


@router.get("/{asset_id}/technologies", response_model=list[TechnologyResponse])
async def get_asset_technologies(
    asset_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get technologies detected on a specific asset."""
    await _verify_asset_access(asset_id, current_user, db)
    result = await db.execute(select(Technology).where(Technology.asset_id == asset_id))
    return [TechnologyResponse.model_validate(t) for t in result.scalars().all()]


@router.get("/{asset_id}/headers", response_model=list[HttpHeaderResponse])
async def get_asset_headers(
    asset_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get HTTP headers for a specific asset."""
    await _verify_asset_access(asset_id, current_user, db)
    result = await db.execute(select(HttpHeader).where(HttpHeader.asset_id == asset_id))
    return [HttpHeaderResponse.model_validate(h) for h in result.scalars().all()]


@router.get("/{asset_id}/findings", response_model=list[FindingResponse])
async def get_asset_findings(
    asset_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get findings for a specific asset."""
    await _verify_asset_access(asset_id, current_user, db)
    result = await db.execute(
        select(Finding).where(Finding.asset_id == asset_id).order_by(Finding.severity)
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
        )
        for f in findings
    ]


@router.get("/{asset_id}/timeline")
async def get_asset_timeline(
    asset_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get a timeline of events for a specific asset."""
    await _verify_asset_access(asset_id, current_user, db)

    events = []

    # Port discoveries
    ports = await db.execute(
        select(Port).where(Port.asset_id == asset_id).order_by(Port.first_seen)
    )
    for p in ports.scalars().all():
        if p.first_seen:
            events.append({
                "timestamp": p.first_seen.isoformat(),
                "type": "port_discovered",
                "description": f"Port {p.port_number}/{p.protocol} ({p.service_name or 'unknown'}) discovered",
            })

    # Findings
    findings = await db.execute(
        select(Finding).where(Finding.asset_id == asset_id).order_by(Finding.first_seen)
    )
    for f in findings.scalars().all():
        if f.first_seen:
            events.append({
                "timestamp": f.first_seen.isoformat(),
                "type": "finding",
                "severity": f.severity,
                "description": f.title,
            })

    # Sort by timestamp
    events.sort(key=lambda e: e["timestamp"])
    return events


async def _build_inventory_index(org_id, db: AsyncSession) -> tuple[dict[str, dict], InventoryAssetList]:
    assessment_assets = (
        await db.execute(select(Asset).join(Assessment).where(Assessment.org_id == org_id))
    ).scalars().all()
    asm_targets = (
        await db.execute(select(AsmTarget).where(AsmTarget.org_id == org_id))
    ).scalars().all()

    groups: dict[str, dict] = {}
    relations: set[tuple[str, str, str]] = set()
    asset_index: dict[str, dict] = {}

    def ensure_group(summary: dict) -> dict:
        group = groups.setdefault(
            summary["canonical_key"],
            {
                "canonical_key": summary["canonical_key"],
                "normalized_value": summary["normalized_value"],
                "primary_type": summary["asset_type"],
                "hostname": summary.get("hostname"),
                "root_domain": summary.get("root_domain"),
                "related_keys": set(),
                "assessment_ids": set(),
                "asm_target_ids": set(),
                "assessment_asset_ids": set(),
                "source_types": set(),
                "values": set(),
                "statuses": defaultdict(int),
                "metadata": {},
                "seed": summary.get("seed"),
            },
        )
        group["values"].add(summary["value"])
        group["source_types"].add(summary["source"])
        if summary.get("seed") and not group.get("seed"):
            group["seed"] = summary.get("seed")
        parent_key = summary.get("parent_key")
        if parent_key:
            group["related_keys"].add(parent_key)
            relations.add((summary["canonical_key"], parent_key, summary.get("relation_label") or "related_to"))
        return group

    for asset in assessment_assets:
        summary = summarize_asset(asset)
        group = ensure_group(summary)
        group["assessment_ids"].add(summary["assessment_id"])
        group["assessment_asset_ids"].add(summary["id"])
        group["statuses"]["live" if summary["is_live"] else "inactive"] += 1
        asset_index[summary["id"]] = {
            "canonical_key": summary["canonical_key"],
            "normalized_value": summary["normalized_value"],
            "root_domain": summary.get("root_domain"),
        }

    for target in asm_targets:
        summary = summarize_asm_target(target)
        group = ensure_group(summary)
        group["asm_target_ids"].add(summary["asm_target_id"])
        group["statuses"][summary.get("scan_status") or "idle"] += 1
        group["metadata"]["last_scan_summary"] = summary["metadata"].get("last_scan_summary", {})
        discoveries = ((summary["metadata"].get("last_scan_summary") or {}).get("discoveries") or {})
        for relation, values in (
            ("discovered_subdomain", discoveries.get("subdomains", [])),
            ("certificate_name", discoveries.get("certificate_sans", [])),
            ("resolved_to", discoveries.get("resolved_ips", [])),
            ("ipv6_address", discoveries.get("ipv6_addresses", [])),
            ("api_endpoint", discoveries.get("api_docs", [])),
            ("historical_url", discoveries.get("archived_urls", [])),
        ):
            for value in values[:50]:
                try:
                    related = normalize_target(value, "auto")
                except Exception:
                    continue
                group["related_keys"].add(related.canonical_key)
                relations.add((summary["canonical_key"], related.canonical_key, relation))

    for group in groups.values():
        related_count = len(group["related_keys"])
        asm_related_count = len(group["asm_target_ids"])
        for asset_id in group["assessment_asset_ids"]:
            asset_index[asset_id]["related_count"] = related_count
            asset_index[asset_id]["asm_related_count"] = asm_related_count

    items = [
        InventoryAsset(
            canonical_key=group["canonical_key"],
            normalized_value=group["normalized_value"],
            primary_type=group["primary_type"],
            hostname=group["hostname"],
            root_domain=group["root_domain"],
            related_keys=sorted(group["related_keys"]),
            assessment_ids=sorted(group["assessment_ids"]),
            asm_target_ids=sorted(group["asm_target_ids"]),
            assessment_asset_ids=sorted(group["assessment_asset_ids"]),
            source_types=sorted(group["source_types"]),
            values=sorted(group["values"]),
            statuses=dict(group["statuses"]),
            metadata={**group["metadata"], "seed": group.get("seed")},
        )
        for group in groups.values()
    ]
    items.sort(key=lambda item: (item.root_domain or item.normalized_value, item.normalized_value))

    payload = InventoryAssetList(
        items=items,
        relations=[
            InventoryRelation(source_key=source, target_key=target, relation=relation)
            for source, target, relation in sorted(relations)
        ],
        total=len(items),
    )
    return asset_index, payload


async def _verify_asset_access(
    asset_id: uuid.UUID, current_user: User, db: AsyncSession
) -> Asset:
    """Verify the current user has access to the given asset."""
    result = await db.execute(
        select(Asset)
        .join(Assessment)
        .where(and_(Asset.id == asset_id, Assessment.org_id == current_user.org_id))
    )
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")
    return asset
