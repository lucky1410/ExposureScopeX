"""Dashboard endpoints: stats, risk-score, trends, recent-findings, and exposure intelligence."""

from datetime import datetime, timedelta, timezone
from decimal import Decimal

from fastapi import APIRouter, Depends
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import get_current_user, get_db
from app.models.asset import Asset
from app.models.assessment import Assessment
from app.models.finding import Finding
from app.models.investigation import Investigation
from app.models.scan import Scan
from app.models.user import User
from app.schemas.dashboard import (
    AssetGraphData,
    AssetGraphEdge,
    AssetGraphNode,
    ChangeFeedEvent,
    DashboardStats,
    ExposureCategory,
    ExposureMethodology,
    ExposureProfile,
    MethodologyCategory,
    NotableSignal,
    RiskScore,
    TrendData,
    TrendDataPoint,
)
from app.schemas.finding import FindingResponse

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


METHODOLOGY_CATEGORIES = [
    {
        "key": "surface",
        "label": "External Surface Breadth",
        "weight": 25,
        "summary": "How much internet-reachable infrastructure, endpoint surface, and archived exposure is attributed to the organization.",
        "evidence_sources": ["assets", "wayback", "subdomains", "ports"],
    },
    {
        "key": "vulnerability",
        "label": "Vulnerability Pressure",
        "weight": 30,
        "summary": "Severity-weighted findings, exploitability signals, and concentration of critical exposures.",
        "evidence_sources": ["findings", "nuclei", "headers", "ssl"],
    },
    {
        "key": "hygiene",
        "label": "Security Hygiene",
        "weight": 20,
        "summary": "Baseline hardening quality inferred from headers, TLS posture, exposed services, and repetitive hygiene failures.",
        "evidence_sources": ["headers", "ssl", "ports", "dns"],
    },
    {
        "key": "coverage",
        "label": "Monitoring Coverage",
        "weight": 15,
        "summary": "How actively the platform is scanning, refreshing, and observing the external footprint.",
        "evidence_sources": ["assessments", "scans", "asm"],
    },
    {
        "key": "drift",
        "label": "Change & Drift",
        "weight": 10,
        "summary": "How quickly new assets, findings, and scan events are appearing relative to the recent baseline.",
        "evidence_sources": ["change_feed", "findings", "assets"],
    },
]


def _score_to_tier(score: int) -> str:
    if score >= 760:
        return "Fortified"
    if score >= 680:
        return "Resilient"
    if score >= 580:
        return "Watchlist"
    return "Exposed"


def _score_to_confidence(observations: int) -> str:
    if observations >= 50:
        return "High confidence"
    if observations >= 15:
        return "Moderate confidence"
    return "Early signal"


def _make_iso(dt: datetime | None) -> str:
    return (dt or datetime.now(timezone.utc)).isoformat()


@router.get("/stats", response_model=DashboardStats)
async def get_stats(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get overall dashboard statistics for the user's organization."""
    org_id = current_user.org_id

    # Total and live assets
    total_assets_q = await db.execute(
        select(func.count(Asset.id)).join(Assessment).where(Assessment.org_id == org_id)
    )
    total_assets = total_assets_q.scalar() or 0

    live_assets_q = await db.execute(
        select(func.count(Asset.id))
        .join(Assessment)
        .where(and_(Assessment.org_id == org_id, Asset.is_live.is_(True)))
    )
    live_assets = live_assets_q.scalar() or 0

    # Findings by severity
    severity_counts = {}
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        q = await db.execute(
            select(func.count(Finding.id))
            .join(Assessment)
            .where(and_(Assessment.org_id == org_id, Finding.severity == sev))
        )
        severity_counts[sev] = q.scalar() or 0

    total_findings = sum(severity_counts.values())

    # Open investigations
    inv_q = await db.execute(
        select(func.count(Investigation.id)).where(
            and_(Investigation.org_id == org_id, Investigation.status != "closed")
        )
    )
    open_investigations = inv_q.scalar() or 0

    # Active assessments
    active_q = await db.execute(
        select(func.count(Assessment.id)).where(
            and_(
                Assessment.org_id == org_id,
                Assessment.status.in_(["created", "running"]),
            )
        )
    )
    active_assessments = active_q.scalar() or 0

    # Risk score from latest completed assessment
    risk_q = await db.execute(
        select(Assessment.risk_score)
        .where(and_(Assessment.org_id == org_id, Assessment.risk_score.isnot(None)))
        .order_by(Assessment.updated_at.desc())
        .limit(1)
    )
    risk_score = risk_q.scalar()

    return DashboardStats(
        total_assets=total_assets,
        live_assets=live_assets,
        total_findings=total_findings,
        critical_findings=severity_counts.get("CRITICAL", 0),
        high_findings=severity_counts.get("HIGH", 0),
        medium_findings=severity_counts.get("MEDIUM", 0),
        low_findings=severity_counts.get("LOW", 0),
        info_findings=severity_counts.get("INFO", 0),
        open_investigations=open_investigations,
        active_assessments=active_assessments,
        risk_score=risk_score,
    )


@router.get("/exposure-profile", response_model=ExposureProfile)
async def get_exposure_profile(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return a benchmark-style exposure profile for the current organization."""
    org_id = current_user.org_id

    total_assets = (
        await db.execute(select(func.count(Asset.id)).join(Assessment).where(Assessment.org_id == org_id))
    ).scalar() or 0
    subdomains = (
        await db.execute(
            select(func.count(Asset.id))
            .join(Assessment)
            .where(and_(Assessment.org_id == org_id, Asset.asset_type == "subdomain"))
        )
    ).scalar() or 0
    urls = (
        await db.execute(
            select(func.count(Asset.id))
            .join(Assessment)
            .where(and_(Assessment.org_id == org_id, Asset.asset_type == "url"))
        )
    ).scalar() or 0
    critical_findings = (
        await db.execute(
            select(func.count(Finding.id))
            .join(Assessment)
            .where(and_(Assessment.org_id == org_id, Finding.severity == "CRITICAL"))
        )
    ).scalar() or 0
    open_findings = (
        await db.execute(
            select(func.count(Finding.id))
            .join(Assessment)
            .where(and_(Assessment.org_id == org_id, Finding.status.in_(["new", "confirmed"])))
        )
    ).scalar() or 0
    active_scans = (
        await db.execute(
            select(func.count(Scan.id))
            .join(Assessment)
            .where(and_(Assessment.org_id == org_id, Scan.status.in_(["queued", "running"])))
        )
    ).scalar() or 0
    last_scan = (
        await db.execute(
            select(func.max(Scan.updated_at)).join(Assessment).where(Assessment.org_id == org_id)
        )
    ).scalar()

    surface_score = min(100, total_assets * 3 + subdomains * 2 + urls)
    vuln_score = min(100, critical_findings * 18 + max(open_findings - critical_findings, 0) * 3)
    hygiene_score = min(100, open_findings * 2 + critical_findings * 8)
    coverage_score = 25 if total_assets == 0 else min(100, 40 + active_scans * 20 + min(total_assets, 20))
    week_ago = datetime.now(timezone.utc) - timedelta(days=7)
    new_findings_7d = (
        await db.execute(
            select(func.count(Finding.id))
            .join(Assessment)
            .where(and_(Assessment.org_id == org_id, Finding.created_at >= week_ago))
        )
    ).scalar() or 0
    new_assets_7d = (
        await db.execute(
            select(func.count(Asset.id))
            .join(Assessment)
            .where(and_(Assessment.org_id == org_id, Asset.created_at >= week_ago))
        )
    ).scalar() or 0
    drift_score = min(100, new_findings_7d * 6 + new_assets_7d * 4)

    category_scores = {
        "surface": surface_score,
        "vulnerability": vuln_score,
        "hygiene": hygiene_score,
        "coverage": coverage_score,
        "drift": drift_score,
    }
    weighted_risk = sum(
        category_scores[c["key"]] * c["weight"] / 100 for c in METHODOLOGY_CATEGORIES
    )
    overall_score = max(300, min(850, int(round(850 - (weighted_risk * 5.5)))))

    if critical_findings > 0:
        notable_signal = f"{critical_findings} critical finding{'s' if critical_findings != 1 else ''} currently shape external risk posture."
    elif new_assets_7d > 0:
        notable_signal = f"{new_assets_7d} new asset{'s' if new_assets_7d != 1 else ''} observed in the last 7 days."
    elif active_scans > 0:
        notable_signal = f"{active_scans} scan{'s' if active_scans != 1 else ''} currently running across the monitored surface."
    else:
        notable_signal = "Baseline exposure is being tracked with no acute critical signal right now."

    categories = [
        ExposureCategory(
            key=category["key"],
            label=category["label"],
            weight=category["weight"],
            score=category_scores[category["key"]],
            summary=category["summary"],
        )
        for category in METHODOLOGY_CATEGORIES
    ]

    return ExposureProfile(
        profile_name=getattr(current_user, "username", None) or current_user.email or "ExposureScopeX Organization",
        org_id=str(org_id),
        external_footprint={
            "assets": total_assets,
            "subdomains": subdomains,
            "urls": urls,
            "open_findings": open_findings,
            "active_scans": active_scans,
        },
        overall_score=overall_score,
        posture_tier=_score_to_tier(overall_score),
        confidence=_score_to_confidence(total_assets + open_findings + active_scans),
        notable_signal=notable_signal,
        last_observed=_make_iso(last_scan),
        categories=categories,
    )


@router.get("/methodology", response_model=ExposureMethodology)
async def get_exposure_methodology():
    """Explain how the exposure benchmark is weighted."""
    return ExposureMethodology(
        title="Exposure Benchmark Methodology",
        description="A weighted benchmark that turns attack-surface breadth, vulnerability pressure, hygiene, monitoring coverage, and recent drift into one defensible operating score.",
        categories=[MethodologyCategory(**category) for category in METHODOLOGY_CATEGORIES],
    )


@router.get("/change-feed", response_model=list[ChangeFeedEvent])
async def get_change_feed(
    limit: int = 20,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return a recent operational feed across assessments, assets, findings, and scans."""
    org_id = current_user.org_id
    events: list[ChangeFeedEvent] = []

    finding_rows = (
        await db.execute(
            select(Finding)
            .join(Assessment)
            .where(Assessment.org_id == org_id)
            .order_by(Finding.created_at.desc())
            .limit(limit)
        )
    ).scalars().all()
    for finding in finding_rows:
        events.append(
            ChangeFeedEvent(
                id=f"finding:{finding.id}",
                event_type="finding",
                title=finding.title,
                detail=f"{finding.severity} finding from {finding.source or 'scanner'}",
                severity=finding.severity,
                timestamp=_make_iso(finding.created_at),
                href="/findings",
            )
        )

    asset_rows = (
        await db.execute(
            select(Asset)
            .join(Assessment)
            .where(Assessment.org_id == org_id)
            .order_by(Asset.created_at.desc())
            .limit(limit)
        )
    ).scalars().all()
    for asset in asset_rows:
        events.append(
            ChangeFeedEvent(
                id=f"asset:{asset.id}",
                event_type="asset",
                title=f"Asset discovered: {asset.value}",
                detail=f"{asset.asset_type} added to monitored surface",
                severity="INFO",
                timestamp=_make_iso(asset.created_at),
                href=f"/assets/{asset.id}",
            )
        )

    assessment_rows = (
        await db.execute(
            select(Assessment)
            .where(Assessment.org_id == org_id)
            .order_by(Assessment.updated_at.desc())
            .limit(limit)
        )
    ).scalars().all()
    for assessment in assessment_rows:
        sev = "MEDIUM" if assessment.status == "failed" else "INFO"
        events.append(
            ChangeFeedEvent(
                id=f"assessment:{assessment.id}",
                event_type="assessment",
                title=f"Assessment {assessment.status}: {assessment.name}",
                detail=f"Target {assessment.target} in {assessment.scan_mode} mode",
                severity=sev,
                timestamp=_make_iso(assessment.updated_at),
                href="/assessments",
            )
        )

    scan_rows = (
        await db.execute(
            select(Scan)
            .join(Assessment)
            .where(Assessment.org_id == org_id)
            .order_by(Scan.updated_at.desc())
            .limit(limit)
        )
    ).scalars().all()
    for scan in scan_rows:
        sev = "HIGH" if scan.status == "failed" else "INFO"
        events.append(
            ChangeFeedEvent(
                id=f"scan:{scan.id}",
                event_type="scan",
                title=f"Scan {scan.status}",
                detail=f"{scan.current_phase or 'execution'} · {scan.progress}% complete",
                severity=sev,
                timestamp=_make_iso(scan.updated_at),
                href="/assessments",
            )
        )

    events.sort(key=lambda event: event.timestamp, reverse=True)
    return events[:limit]


@router.get("/notable-signals", response_model=list[NotableSignal])
async def get_notable_signals(
    limit: int = 6,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return concise, operator-ready signals drawn from recent surface activity."""
    org_id = current_user.org_id
    now = datetime.now(timezone.utc)
    signals: list[NotableSignal] = []

    critical_recent = (
        await db.execute(
            select(Finding)
            .join(Assessment)
            .where(
                and_(
                    Assessment.org_id == org_id,
                    Finding.severity == "CRITICAL",
                )
            )
            .order_by(Finding.created_at.desc())
            .limit(2)
        )
    ).scalars().all()
    for finding in critical_recent:
        signals.append(
            NotableSignal(
                id=f"critical:{finding.id}",
                title=f"Critical exposure: {finding.title}",
                detail=finding.description or "Critical finding requires review.",
                severity="CRITICAL",
                source=finding.source or "finding",
                timestamp=_make_iso(finding.created_at),
            )
        )

    stale_scan = (
        await db.execute(
            select(func.max(Scan.updated_at))
            .join(Assessment)
            .where(Assessment.org_id == org_id)
        )
    ).scalar()
    if stale_scan and stale_scan < now - timedelta(days=7):
        signals.append(
            NotableSignal(
                id="scan-stale",
                title="Monitoring cadence is falling behind",
                detail="No assessment scan has updated in over 7 days.",
                severity="MEDIUM",
                source="coverage",
                timestamp=_make_iso(stale_scan),
            )
        )

    recent_assets = (
        await db.execute(
            select(func.count(Asset.id))
            .join(Assessment)
            .where(and_(Assessment.org_id == org_id, Asset.created_at >= now - timedelta(days=7)))
        )
    ).scalar() or 0
    if recent_assets:
        signals.append(
            NotableSignal(
                id="recent-assets",
                title="Surface expansion detected",
                detail=f"{recent_assets} new asset{'s' if recent_assets != 1 else ''} appeared in the last 7 days.",
                severity="INFO",
                source="asset",
                timestamp=_make_iso(now),
            )
        )

    active_scan_count = (
        await db.execute(
            select(func.count(Scan.id))
            .join(Assessment)
            .where(and_(Assessment.org_id == org_id, Scan.status.in_(["queued", "running"])))
        )
    ).scalar() or 0
    if active_scan_count:
        signals.append(
            NotableSignal(
                id="active-scans",
                title="Live collection in progress",
                detail=f"{active_scan_count} scan{'s' if active_scan_count != 1 else ''} currently updating the exposure profile.",
                severity="INFO",
                source="scan",
                timestamp=_make_iso(now),
            )
        )

    if not signals:
        signals.append(
            NotableSignal(
                id="baseline",
                title="Baseline posture established",
                detail="No urgent signal is standing out; keep monitoring cadence and review methodology weighting.",
                severity="INFO",
                source="platform",
                timestamp=_make_iso(now),
            )
        )

    signals.sort(key=lambda signal: signal.timestamp or "", reverse=True)
    return signals[:limit]


@router.get("/risk-score", response_model=RiskScore)
async def get_risk_score(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Compute overall risk score and category breakdown."""
    org_id = current_user.org_id

    # Weight: CRITICAL=10, HIGH=7, MEDIUM=4, LOW=1, INFO=0
    weights = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1, "INFO": 0}
    category_scores = {}
    total_score = Decimal("0")
    total_weight = 0

    for sev, weight in weights.items():
        q = await db.execute(
            select(func.count(Finding.id))
            .join(Assessment)
            .where(
                and_(
                    Assessment.org_id == org_id,
                    Finding.severity == sev,
                    Finding.status.in_(["new", "confirmed"]),
                )
            )
        )
        count = q.scalar() or 0
        category_scores[sev] = Decimal(str(count * weight))
        total_score += category_scores[sev]
        total_weight += count

    # Normalize to 0-100 scale
    overall = min(total_score, Decimal("100"))

    # Build 30-day trend (simplified)
    trend = []
    now = datetime.now(timezone.utc)
    for i in range(30, -1, -1):
        day = now - timedelta(days=i)
        trend.append({"date": day.strftime("%Y-%m-%d"), "score": float(overall)})

    return RiskScore(
        overall=overall,
        by_category=category_scores,
        trend=trend,
    )


@router.get("/trends", response_model=TrendData)
async def get_trends(
    days: int = 30,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get finding and asset trend data for the given time window."""
    org_id = current_user.org_id
    now = datetime.now(timezone.utc)

    findings_trend = []
    assets_trend = []

    for i in range(days, -1, -1):
        day = now - timedelta(days=i)
        day_start = day.replace(hour=0, minute=0, second=0, microsecond=0)
        day_end = day_start + timedelta(days=1)

        # Findings created on this day
        fq = await db.execute(
            select(func.count(Finding.id))
            .join(Assessment)
            .where(
                and_(
                    Assessment.org_id == org_id,
                    Finding.created_at >= day_start,
                    Finding.created_at < day_end,
                )
            )
        )
        findings_trend.append(
            TrendDataPoint(date=day_start.strftime("%Y-%m-%d"), value=fq.scalar() or 0)
        )

        # Assets discovered on this day
        aq = await db.execute(
            select(func.count(Asset.id))
            .join(Assessment)
            .where(
                and_(
                    Assessment.org_id == org_id,
                    Asset.first_seen >= day_start,
                    Asset.first_seen < day_end,
                )
            )
        )
        assets_trend.append(
            TrendDataPoint(date=day_start.strftime("%Y-%m-%d"), value=aq.scalar() or 0)
        )

    # Severity distribution
    severity_dist = {}
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        q = await db.execute(
            select(func.count(Finding.id))
            .join(Assessment)
            .where(and_(Assessment.org_id == org_id, Finding.severity == sev))
        )
        severity_dist[sev] = q.scalar() or 0

    return TrendData(
        findings_trend=findings_trend,
        assets_trend=assets_trend,
        severity_distribution=severity_dist,
    )


@router.get("/recent-findings", response_model=list[FindingResponse])
async def get_recent_findings(
    limit: int = 10,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get the most recent findings for the user's organization."""
    org_id = current_user.org_id

    result = await db.execute(
        select(Finding)
        .join(Assessment)
        .where(Assessment.org_id == org_id)
        .order_by(Finding.created_at.desc())
        .limit(limit)
    )
    findings = result.scalars().all()

    responses = []
    for f in findings:
        resp = FindingResponse(
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
        responses.append(resp)

    return responses


@router.get("/asset-graph", response_model=AssetGraphData)
async def get_asset_graph(
    assessment_id: str | None = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Build an asset relationship graph for visualization."""
    org_id = current_user.org_id

    query = select(Asset).join(Assessment).where(Assessment.org_id == org_id)
    if assessment_id:
        import uuid

        query = query.where(Asset.assessment_id == uuid.UUID(assessment_id))

    result = await db.execute(query.limit(200))
    assets = result.scalars().all()

    nodes = []
    edges = []
    seen_ids = set()

    for asset in assets:
        node_id = str(asset.id)
        if node_id not in seen_ids:
            nodes.append(
                AssetGraphNode(
                    id=node_id,
                    label=asset.value,
                    type=asset.asset_type,
                    group=asset.asset_type,
                )
            )
            seen_ids.add(node_id)

        if asset.parent_id:
            edges.append(
                AssetGraphEdge(
                    source=str(asset.parent_id),
                    target=node_id,
                    label="parent",
                )
            )

    return AssetGraphData(nodes=nodes, edges=edges)
