"""Notification schemas."""

import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class NotificationResponse(BaseModel):
    id: uuid.UUID
    user_id: uuid.UUID
    type: str
    title: str
    message: Optional[str] = None
    severity: Optional[str] = None
    is_read: bool
    entity_type: Optional[str] = None
    entity_id: Optional[uuid.UUID] = None
    created_at: datetime

    model_config = {"from_attributes": True}


class NotificationList(BaseModel):
    items: list[NotificationResponse]
    total: int
    unread_count: int
