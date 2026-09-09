"""Investigation schemas."""

import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class InvestigationCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=500)
    description: Optional[str] = None
    priority: str = Field(default="medium", pattern="^(critical|high|medium|low)$")
    assigned_to: Optional[uuid.UUID] = None


class InvestigationResponse(BaseModel):
    id: uuid.UUID
    org_id: uuid.UUID
    created_by: uuid.UUID
    title: str
    description: Optional[str] = None
    status: str
    priority: str
    assigned_to: Optional[uuid.UUID] = None
    creator_username: Optional[str] = None
    assignee_username: Optional[str] = None
    finding_count: int = 0
    evidence_count: int = 0
    note_count: int = 0
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class InvestigationUpdate(BaseModel):
    title: Optional[str] = Field(None, min_length=1, max_length=500)
    description: Optional[str] = None
    status: Optional[str] = Field(None, pattern="^(open|in_progress|closed)$")
    priority: Optional[str] = Field(None, pattern="^(critical|high|medium|low)$")
    assigned_to: Optional[uuid.UUID] = None


class EvidenceCreate(BaseModel):
    type: str = Field(..., max_length=50)
    title: str = Field(..., max_length=500)
    content: Optional[str] = None
    file_path: Optional[str] = None


class EvidenceResponse(BaseModel):
    id: uuid.UUID
    investigation_id: uuid.UUID
    type: str
    title: str
    content: Optional[str] = None
    file_path: Optional[str] = None
    created_by: uuid.UUID
    created_at: datetime

    model_config = {"from_attributes": True}


class NoteCreate(BaseModel):
    content: str = Field(..., min_length=1)


class NoteResponse(BaseModel):
    id: uuid.UUID
    investigation_id: uuid.UUID
    content: str
    created_by: uuid.UUID
    creator_username: Optional[str] = None
    created_at: datetime

    model_config = {"from_attributes": True}
