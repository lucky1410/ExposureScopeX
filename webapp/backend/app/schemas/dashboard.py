"""Dashboard statistics and visualization schemas."""

from decimal import Decimal
from typing import Any, Optional

from pydantic import BaseModel


class DashboardStats(BaseModel):
    total_assets: int
    live_assets: int
    total_findings: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    info_findings: int
    open_investigations: int
    active_assessments: int
    risk_score: Optional[Decimal] = None
    assets_change_pct: float = 0.0
    findings_change_pct: float = 0.0


class RiskScore(BaseModel):
    overall: Decimal
    by_category: dict[str, Decimal]
    trend: list[dict[str, Any]]  # [{date, score}]


class TrendDataPoint(BaseModel):
    date: str
    value: int
    label: Optional[str] = None


class TrendData(BaseModel):
    findings_trend: list[TrendDataPoint]
    assets_trend: list[TrendDataPoint]
    severity_distribution: dict[str, int]


class ExposureCategory(BaseModel):
    key: str
    label: str
    weight: int
    score: int
    summary: str


class ExposureProfile(BaseModel):
    profile_name: str
    org_id: str
    external_footprint: dict[str, int]
    overall_score: int
    posture_tier: str
    confidence: str
    notable_signal: str
    last_observed: str
    categories: list[ExposureCategory]


class MethodologyCategory(BaseModel):
    key: str
    label: str
    weight: int
    summary: str
    evidence_sources: list[str]


class ExposureMethodology(BaseModel):
    title: str
    description: str
    categories: list[MethodologyCategory]


class ChangeFeedEvent(BaseModel):
    id: str
    event_type: str
    title: str
    detail: str
    severity: str
    timestamp: str
    href: str | None = None


class NotableSignal(BaseModel):
    id: str
    title: str
    detail: str
    severity: str
    source: str
    timestamp: str | None = None


class AssetGraphNode(BaseModel):
    id: str
    label: str
    type: str
    group: Optional[str] = None


class AssetGraphEdge(BaseModel):
    source: str
    target: str
    label: Optional[str] = None


class AssetGraphData(BaseModel):
    nodes: list[AssetGraphNode]
    edges: list[AssetGraphEdge]
