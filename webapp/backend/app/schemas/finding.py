"""Finding schemas."""

import uuid
from datetime import datetime
from decimal import Decimal
from typing import Any, Optional

from pydantic import BaseModel, Field


class FindingResponse(BaseModel):
    id: uuid.UUID
    assessment_id: uuid.UUID
    scan_id: Optional[uuid.UUID] = None
    asset_id: Optional[uuid.UUID] = None
    vulnerability_id: Optional[uuid.UUID] = None
    identity_id: Optional[uuid.UUID] = None
    source: Optional[str] = None
    template_id: Optional[str] = None
    severity: str
    title: str
    description: Optional[str] = None
    url: Optional[str] = None
    evidence: Optional[str] = None
    status: str
    risk_score: Optional[Decimal] = None
    confidence_score: Optional[Decimal] = None
    reachability: Optional[str] = None
    exploitability: Optional[str] = None
    evidence_metadata: dict = Field(default_factory=dict)
    status_reason: Optional[str] = None
    status_scope: Optional[str] = None
    status_changed_by: Optional[uuid.UUID] = None
    status_changed_at: Optional[datetime] = None
    suppression_expires_at: Optional[datetime] = None
    assigned_to: Optional[uuid.UUID] = None
    due_at: Optional[datetime] = None
    sla_status: str = "untracked"
    verification_status: str = "not_requested"
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    remediated_at: Optional[datetime] = None
    is_demo: bool
    created_at: datetime
    updated_at: datetime
    # Joined fields
    asset_value: Optional[str] = None
    vulnerability_title: Optional[str] = None

    model_config = {"from_attributes": True}


class FindingList(BaseModel):
    items: list[FindingResponse]
    total: int
    page: int
    page_size: int


class FindingStatusUpdate(BaseModel):
    status: str = Field(
        ...,
        pattern="^(new|confirmed|false_positive|remediated|suppressed|approved_exception|accepted_risk|compensating_control|not_exploitable)$",
    )
    notes: Optional[str] = None
    scope: Optional[str] = Field(default=None, max_length=100)
    expires_at: Optional[datetime] = None


class FindingStats(BaseModel):
    total: int
    by_severity: dict[str, int]
    by_status: dict[str, int]
    new_last_24h: int
    new_last_7d: int


class FindingObservationResponse(BaseModel):
    id: uuid.UUID
    finding_id: uuid.UUID
    scan_id: uuid.UUID
    assessment_id: uuid.UUID
    observed_at: datetime
    evidence_sha256: Optional[str] = None
    payload: dict[str, Any] = Field(default_factory=dict)

    model_config = {"from_attributes": True}


class FindingWorkflowUpdate(BaseModel):
    assigned_to: Optional[uuid.UUID] = None
    due_at: Optional[datetime] = None
    verification_status: Optional[str] = Field(default=None, pattern="^(not_requested|requested|in_progress|passed|failed|inconclusive)$")
    comment: Optional[str] = Field(default=None, max_length=10000)


class FindingActivityCreate(BaseModel):
    activity_type: str = Field(pattern="^(comment|retest_requested|approval_requested|approval_decision)$")
    body: Optional[str] = Field(default=None, max_length=10000)
    payload: dict[str, Any] = Field(default_factory=dict)


class FindingActivityResponse(BaseModel):
    id: uuid.UUID
    finding_id: uuid.UUID
    actor_id: Optional[uuid.UUID] = None
    activity_type: str
    body: Optional[str] = None
    payload: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime

    model_config = {"from_attributes": True}
