"""Scan authorization model for tracking authorization to scan targets."""

from sqlalchemy import Column, DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.database import Base
from app.models.base import TimestampMixin


class ScanAuthorization(TimestampMixin, Base):
    __tablename__ = "scan_authorizations"

    org_id = Column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id"),
        nullable=False,
        index=True,
    )
    target = Column(String(500), nullable=False)
    authorized_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    authorization_type = Column(
        String(20), nullable=False, default="full"
    )  # full/passive_only/read_only
    scope_file = Column(Text, nullable=True)
    valid_from = Column(DateTime(timezone=True), nullable=True)
    valid_until = Column(DateTime(timezone=True), nullable=True)
    notes = Column(Text, nullable=True)

    # Relationships
    organization = relationship("Organization", back_populates="scan_authorizations")
    authorizer = relationship("User", lazy="selectin")
