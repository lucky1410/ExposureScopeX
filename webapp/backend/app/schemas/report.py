"""Report generation schemas."""

import uuid
from typing import Optional

from pydantic import BaseModel, Field, field_validator, model_validator


class ReportRequest(BaseModel):
    assessment_id: uuid.UUID
    scan_id: uuid.UUID | None = None
    baseline_scan_id: uuid.UUID | None = None
    format: str = Field(default="html", pattern="^(html|pdf|docx|sarif|markdown|csv|json|evidence)$")
    include_evidence: bool = True
    include_remediation: bool = True
    executive_summary: bool = True
    title: Optional[str] = Field(default=None, max_length=500)
    asset_ids: list[uuid.UUID] = Field(default_factory=list, max_length=500)
    severities: list[str] = Field(default_factory=list, max_length=5)
    statuses: list[str] = Field(default_factory=list, max_length=20)
    owners: list[str] = Field(default_factory=list, max_length=100)
    modules: list[str] = Field(default_factory=list, max_length=100)

    @model_validator(mode="after")
    def require_scan_for_client_deliverables(self):
        if self.format in {"pdf", "docx", "evidence"} and not self.scan_id:
            raise ValueError(f"{self.format.upper()} client deliverables require scan_id")
        if self.baseline_scan_id and not self.scan_id:
            raise ValueError("baseline_scan_id requires scan_id")
        return self

    @field_validator("severities")
    @classmethod
    def validate_severities(cls, values: list[str]) -> list[str]:
        normalized = [value.upper().strip() for value in values]
        if any(value not in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"} for value in normalized):
            raise ValueError("Invalid severity")
        return normalized

    @field_validator("statuses")
    @classmethod
    def validate_statuses(cls, values: list[str]) -> list[str]:
        normalized = [value.lower().strip() for value in values if value.strip()]
        allowed = {
            "new", "open", "confirmed", "in_progress", "remediated", "resolved",
            "accepted", "accepted_risk", "approved_exception", "compensating_control",
            "not_exploitable", "false_positive", "suppressed",
        }
        if any(value not in allowed for value in normalized):
            raise ValueError("Invalid finding status")
        return normalized

    @field_validator("owners", "modules")
    @classmethod
    def validate_scope_strings(cls, values: list[str]) -> list[str]:
        normalized = [value.strip() for value in values if value.strip()]
        if any(len(value) > 255 for value in normalized):
            raise ValueError("Report scope values cannot exceed 255 characters")
        return normalized


class ReportResponse(BaseModel):
    id: str
    assessment_id: uuid.UUID
    format: str
    title: str
    filename: str
    status: str  # generating/ready/failed
    download_url: Optional[str] = None
    generated_at: Optional[str] = None
    created_at: str
    file_size: int
    version: int
    sha256: str
    scope: dict = Field(default_factory=dict)
    error: Optional[str] = None
