"""Global search schemas."""

import uuid
from typing import Any, Optional

from pydantic import BaseModel, Field


class SearchQuery(BaseModel):
    query: str = Field(..., min_length=1, max_length=500)
    entity_types: Optional[list[str]] = None  # assessment/asset/finding/vulnerability
    limit: int = Field(default=20, ge=1, le=100)


class SearchResultItem(BaseModel):
    entity_type: str
    id: uuid.UUID
    title: str
    subtitle: Optional[str] = None
    severity: Optional[str] = None
    metadata: Optional[dict[str, Any]] = None

    model_config = {"from_attributes": True}


class SearchResponse(BaseModel):
    query: str
    total: int
    items: list[SearchResultItem]
