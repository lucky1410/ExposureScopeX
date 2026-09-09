"""Notification model for in-app user notifications."""

from sqlalchemy import Boolean, Column, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.database import Base
from app.models.base import TimestampMixin


class Notification(TimestampMixin, Base):
    __tablename__ = "notifications"

    user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    type = Column(String(50), nullable=False)  # scan_complete/finding/alert/system
    title = Column(String(500), nullable=False)
    message = Column(Text, nullable=True)
    severity = Column(String(20), nullable=True)  # critical/high/medium/low/info
    is_read = Column(Boolean, default=False, nullable=False)
    entity_type = Column(String(50), nullable=True)  # assessment/finding/investigation
    entity_id = Column(UUID(as_uuid=True), nullable=True)

    # Relationships
    user = relationship("User", back_populates="notifications")
