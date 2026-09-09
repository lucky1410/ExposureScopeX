"""Resource and UserFavorite models for the security resources library."""

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text, Boolean
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import relationship
from datetime import datetime, timezone

from app.database import Base
from app.models.base import TimestampMixin


class Resource(TimestampMixin, Base):
    __tablename__ = "resources"

    category = Column(String(100), nullable=False, index=True)
    subcategory = Column(String(100), nullable=True)
    name = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)
    url = Column(String(2000), nullable=True)
    icon = Column(String(100), nullable=True)
    tags = Column(JSONB, nullable=True, default=list)
    is_featured = Column(Boolean, default=False, nullable=False)
    display_order = Column(Integer, nullable=True, default=0)

    # Relationships
    favorites = relationship(
        "UserFavorite", back_populates="resource", cascade="all, delete-orphan", lazy="selectin"
    )


class UserFavorite(Base):
    __tablename__ = "user_favorites"

    user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        primary_key=True,
    )
    resource_id = Column(
        UUID(as_uuid=True),
        ForeignKey("resources.id", ondelete="CASCADE"),
        primary_key=True,
    )
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    user = relationship("User", back_populates="favorites")
    resource = relationship("Resource", back_populates="favorites")
