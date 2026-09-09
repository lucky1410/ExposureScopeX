"""HTTP header security analysis model."""

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, String
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import relationship

from app.database import Base
from app.models.base import TimestampMixin


class HttpHeader(TimestampMixin, Base):
    __tablename__ = "http_headers"

    asset_id = Column(
        UUID(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    url = Column(String(2000), nullable=True)
    headers = Column(JSONB, nullable=True, default=dict)
    missing_headers = Column(JSONB, nullable=True, default=list)
    cors_policy = Column(String(500), nullable=True)
    server_header = Column(String(500), nullable=True)
    is_demo = Column(Boolean, default=False, nullable=False)
    checked_at = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    asset = relationship("Asset", back_populates="http_headers")
