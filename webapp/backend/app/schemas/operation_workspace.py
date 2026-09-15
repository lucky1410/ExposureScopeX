"""Schemas for operation workspace planning."""

from datetime import datetime
import uuid

from pydantic import BaseModel, Field, field_validator, model_validator

_STATUS_VALUES = ("planning", "approved", "active", "paused", "completed", "stopped", "archived")
_CLASSIFICATION_VALUES = ("internal", "confidential", "restricted")
_OPERATION_TYPE_VALUES = ("red_team", "adversary_emulation", "purple_team", "tabletop")


class OperationWorkspaceCreate(BaseModel):
    name: str = Field(..., min_length=3, max_length=255)
    codename: str | None = Field(default=None, max_length=80)
    description: str | None = Field(default=None, max_length=4000)
    objective: str = Field(..., min_length=10, max_length=4000)
    status: str = Field(default="planning", pattern="^planning$")
    classification: str = Field(default="internal", pattern="^(internal|confidential|restricted)$")
    operation_type: str = Field(default="red_team", pattern="^(red_team|adversary_emulation|purple_team|tabletop)$")
    planned_start_at: datetime | None = None
    planned_end_at: datetime | None = None
    scope_summary: str | None = Field(default=None, max_length=4000)
    roe_summary: str | None = Field(default=None, max_length=4000)
    tags: list[str] = Field(default_factory=list, max_length=12)

    @field_validator("name", "codename", "description", "objective", "scope_summary", "roe_summary", mode="before")
    @classmethod
    def strip_text(cls, value):
        if isinstance(value, str):
            return value.strip()
        return value

    @field_validator("status")
    @classmethod
    def validate_status(cls, value: str) -> str:
        if value not in _STATUS_VALUES:
            raise ValueError("Unsupported operation status")
        return value

    @field_validator("classification")
    @classmethod
    def validate_classification(cls, value: str) -> str:
        if value not in _CLASSIFICATION_VALUES:
            raise ValueError("Unsupported classification")
        return value

    @field_validator("operation_type")
    @classmethod
    def validate_operation_type(cls, value: str) -> str:
        if value not in _OPERATION_TYPE_VALUES:
            raise ValueError("Unsupported operation type")
        return value

    @field_validator("tags", mode="before")
    @classmethod
    def normalize_tags(cls, value):
        if value is None:
            return []
        if not isinstance(value, list):
            raise ValueError("tags must be a list of strings")
        normalized: list[str] = []
        seen: set[str] = set()
        for tag in value:
            if not isinstance(tag, str):
                raise ValueError("tags must be a list of strings")
            cleaned = tag.strip().lower()
            if not cleaned or cleaned in seen:
                continue
            seen.add(cleaned)
            normalized.append(cleaned[:40])
        return normalized

    @model_validator(mode="after")
    def validate_date_window(self):
        if self.planned_start_at and self.planned_start_at.utcoffset() is None:
            raise ValueError("planned_start_at must include a timezone")
        if self.planned_end_at and self.planned_end_at.utcoffset() is None:
            raise ValueError("planned_end_at must include a timezone")
        if self.planned_start_at and self.planned_end_at and self.planned_end_at < self.planned_start_at:
            raise ValueError("planned_end_at must be after planned_start_at")
        return self


class OperationWorkspaceResponse(BaseModel):
    id: uuid.UUID
    org_id: uuid.UUID
    created_by: uuid.UUID
    name: str
    codename: str | None = None
    description: str | None = None
    objective: str
    status: str
    classification: str
    operation_type: str
    planned_start_at: datetime | None = None
    planned_end_at: datetime | None = None
    scope_summary: str | None = None
    roe_summary: str | None = None
    tags: list[str] = Field(default_factory=list)
    approved_by: uuid.UUID | None = None
    approved_at: datetime | None = None
    activated_at: datetime | None = None
    stopped_at: datetime | None = None
    stop_reason: str | None = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class OperationWorkspaceUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=3, max_length=255)
    codename: str | None = Field(default=None, max_length=80)
    description: str | None = Field(default=None, max_length=4000)
    objective: str | None = Field(default=None, min_length=10, max_length=4000)
    classification: str | None = Field(default=None, pattern="^(internal|confidential|restricted)$")
    operation_type: str | None = Field(default=None, pattern="^(red_team|adversary_emulation|purple_team|tabletop)$")
    planned_start_at: datetime | None = None
    planned_end_at: datetime | None = None
    scope_summary: str | None = Field(default=None, max_length=4000)
    roe_summary: str | None = Field(default=None, max_length=4000)
    tags: list[str] | None = Field(default=None, max_length=12)

    @field_validator("name", "codename", "description", "objective", "scope_summary", "roe_summary", mode="before")
    @classmethod
    def strip_text(cls, value):
        return value.strip() if isinstance(value, str) else value

    @field_validator("tags", mode="before")
    @classmethod
    def normalize_tags(cls, value):
        return OperationWorkspaceCreate.normalize_tags(value) if value is not None else None

    @model_validator(mode="after")
    def validate_timezones(self):
        for field in ("planned_start_at", "planned_end_at"):
            value = getattr(self, field)
            if value and value.utcoffset() is None:
                raise ValueError(f"{field} must include a timezone")
        return self


class OperationTransitionRequest(BaseModel):
    action: str = Field(pattern="^(approve|activate|resume|pause|complete|emergency_stop|archive)$")
    reason: str | None = Field(default=None, max_length=2000)

    @field_validator("reason", mode="before")
    @classmethod
    def strip_reason(cls, value):
        return value.strip() if isinstance(value, str) else value

    @model_validator(mode="after")
    def require_stop_reason(self):
        if self.action == "emergency_stop" and not self.reason:
            raise ValueError("An emergency stop reason is required")
        return self
