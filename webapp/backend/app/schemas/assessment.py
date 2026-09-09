"""Assessment schemas."""

import uuid
from datetime import datetime
from decimal import Decimal
from typing import Any, Optional

from pydantic import BaseModel, Field


class AssessmentCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    target: str = Field(..., min_length=1, max_length=500)
    target_type: str = Field(default="domain", pattern="^(domain|ip|cidr|url|api|file|asn|repository|image|kubernetes|android|ios|cloud_account|organization|mcp)$")
    scan_mode: str = Field(default="medium", pattern="^(light|medium|aggressive)$")
    phases: Optional[dict[str, Any]] = None
    flags: Optional[dict[str, Any]] = None
    requested_scans: list[str] = Field(default_factory=list)
    requested_utilities: list[str] = Field(default_factory=list)
    nuclei_tags: list[str] = Field(default_factory=list)
    imported_targets: list[dict[str, Any]] = Field(default_factory=list)
    auto_start: bool = Field(
        default=True,
        description="Create the assessment and immediately queue a scan.",
    )


class AssessmentResponse(BaseModel):
    id: uuid.UUID
    org_id: uuid.UUID
    created_by: uuid.UUID
    name: str
    description: Optional[str] = None
    target: str
    target_type: str
    status: str
    scan_mode: str
    phases: Optional[dict[str, Any]] = None
    flags: Optional[dict[str, Any]] = None
    is_demo: bool
    risk_score: Optional[Decimal] = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class AssessmentScanResponse(BaseModel):
    id: uuid.UUID
    assessment_id: uuid.UUID
    celery_task_id: str | None = None
    session_dir: str | None = None
    status: str
    current_phase: str | None = None
    progress: int
    started_at: datetime | None = None
    completed_at: datetime | None = None
    heartbeat_at: datetime | None = None
    cancel_requested_at: datetime | None = None
    attempt: int = 1
    max_attempts: int = 2
    error_message: str | None = None
    raw_log: str | None = None
    scan_metadata: dict[str, Any] | None = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class ScanEventResponse(BaseModel):
    id: uuid.UUID
    event_type: str
    status: str | None = None
    phase: str | None = None
    progress: int | None = None
    message: str | None = None
    payload: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime

    model_config = {"from_attributes": True}


class ScanToolRunResponse(BaseModel):
    id: uuid.UUID
    external_id: str
    tool: str
    tool_version: str | None = None
    status: str
    exit_code: int | None = None
    command: str | None = None
    output_file: str | None = None
    output_excerpt: str | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    duration_ms: int | None = None
    provenance: dict[str, Any] = Field(default_factory=dict)

    model_config = {"from_attributes": True}


class ScanArtifactResponse(BaseModel):
    id: uuid.UUID
    path: str
    artifact_type: str
    mime_type: str | None = None
    size_bytes: int
    sha256: str
    retained: bool
    provenance: dict[str, Any] = Field(default_factory=dict)

    model_config = {"from_attributes": True}


class ScanExecutionResponse(AssessmentScanResponse):
    """Scan execution enriched with its assessment context for operator views."""

    assessment_name: str
    target: str
    target_type: str
    scan_mode: str
    events: list[ScanEventResponse] = Field(default_factory=list)
    tool_runs: list[ScanToolRunResponse] = Field(default_factory=list)
    artifacts: list[ScanArtifactResponse] = Field(default_factory=list)


class ScanExecutionList(BaseModel):
    items: list[ScanExecutionResponse]
    total: int
    page: int
    page_size: int


class ScanProfileResponse(BaseModel):
    mode: str
    label: str
    description: str
    target_type: str
    phases: dict[str, bool]
    flags: dict[str, Any]
    utilities: list[str]
    nuclei_tags: list[str]
    business_logic: str
    pipeline: list[str] = []
    scan_strategy: str = "active"
    readiness: dict[str, str]
    tool_plan: list[dict[str, Any]] = Field(default_factory=list)


class ExecutionPreviewResponse(BaseModel):
    target_type: str
    target_count: int
    scan_mode: str
    phases: dict[str, Any]
    flags: dict[str, Any]
    tool_plan: list[dict[str, Any]]
    execution_manifest: list[dict[str, Any]]
    execution_policy: dict[str, Any]
    authorization: dict[str, Any]
    estimated_seconds: int
    warnings: list[str] = Field(default_factory=list)
    template_plan: dict[str, Any] = Field(default_factory=dict)
    wordlist_plan: dict[str, Any] = Field(default_factory=dict)
    adapter_prerequisites: list[dict[str, Any]] = Field(default_factory=list)
    safety_controls: list[str] = Field(default_factory=list)
    exclusions: list[str] = Field(default_factory=list)
    confidence: str = "high"


class SavedScanProfileCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=2000)
    target_type: str
    scan_mode: str = Field(pattern="^(light|medium|aggressive)$")
    configuration: dict[str, Any] = Field(default_factory=dict)


class SavedScanProfileResponse(SavedScanProfileCreate):
    id: uuid.UUID
    version: int
    is_active: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class ScanScheduleCreate(BaseModel):
    assessment_id: uuid.UUID
    name: str = Field(min_length=1, max_length=255)
    timezone: str = Field(default="UTC", max_length=100)
    interval_minutes: int = Field(default=1440, ge=15, le=525600)
    window_start: str | None = Field(default=None, pattern=r"^([01]\d|2[0-3]):[0-5]\d$")
    window_end: str | None = Field(default=None, pattern=r"^([01]\d|2[0-3]):[0-5]\d$")
    missed_run_policy: str = Field(default="run_once", pattern="^(run_once|skip)$")
    overlap_policy: str = Field(default="skip", pattern="^skip$")
    is_active: bool = True


class ScanScheduleUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    timezone: str | None = Field(default=None, max_length=100)
    interval_minutes: int | None = Field(default=None, ge=15, le=525600)
    window_start: str | None = Field(default=None, pattern=r"^([01]\d|2[0-3]):[0-5]\d$")
    window_end: str | None = Field(default=None, pattern=r"^([01]\d|2[0-3]):[0-5]\d$")
    missed_run_policy: str | None = Field(default=None, pattern="^(run_once|skip)$")
    overlap_policy: str | None = Field(default=None, pattern="^skip$")
    is_active: bool | None = None


class ScanScheduleResponse(BaseModel):
    id: uuid.UUID
    assessment_id: uuid.UUID
    name: str
    timezone: str
    interval_minutes: int
    window_start: str | None
    window_end: str | None
    missed_run_policy: str
    overlap_policy: str
    is_active: bool
    next_run_at: datetime
    last_run_at: datetime | None
    last_status: str | None
    last_scan_id: uuid.UUID | None
    created_at: datetime

    model_config = {"from_attributes": True}


class AssessmentList(BaseModel):
    items: list[AssessmentResponse]
    total: int
    page: int
    page_size: int


class AssessmentImportResponse(BaseModel):
    added: int
    skipped: int
    errors: list[str]
    imported_targets: list[dict[str, Any]] = Field(default_factory=list)
    suggested_name: str | None = None
    suggested_description: str | None = None
