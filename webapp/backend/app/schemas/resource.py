"""Resource schemas."""

import uuid
from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel


class ResourceResponse(BaseModel):
    id: uuid.UUID
    category: str
    subcategory: Optional[str] = None
    name: str
    description: Optional[str] = None
    url: Optional[str] = None
    icon: Optional[str] = None
    tags: Optional[list[Any]] = None
    is_featured: bool
    display_order: Optional[int] = None
    is_favorited: bool = False
    created_at: datetime

    model_config = {"from_attributes": True}


class ResourceList(BaseModel):
    items: list[ResourceResponse]
    total: int
    categories: list[str]
