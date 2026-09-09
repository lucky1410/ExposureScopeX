"""Assessment model representing a security assessment run."""

from sqlalchemy import Boolean, Column, ForeignKey, Numeric, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import relationship

from app.database import Base
from app.models.base import TimestampMixin


class Assessment(TimestampMixin, Base):
    __tablename__ = "assessments"

    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True)
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    target = Column(String(500), nullable=False)
    target_type = Column(
        String(20), nullable=False, default="domain"
    )  # domain/ip/cidr/url/file
    status = Column(
        String(20), nullable=False, default="created"
    )  # created/running/completed/failed/cancelled
    scan_mode = Column(
        String(20), nullable=False, default="medium"
    )  # light/medium/aggressive
    phases = Column(JSONB, nullable=True, default=dict)
    flags = Column(JSONB, nullable=True, default=dict)
    is_demo = Column(Boolean, default=False, nullable=False)
    risk_score = Column(Numeric(5, 2), nullable=True)

    # Relationships
    organization = relationship("Organization", back_populates="assessments")
    created_by_user = relationship("User", back_populates="assessments")
    scans = relationship(
        "Scan", back_populates="assessment", cascade="all, delete-orphan", lazy="selectin"
    )
    assets = relationship(
        "Asset", back_populates="assessment", cascade="all, delete-orphan", lazy="selectin"
    )
    findings = relationship(
        "Finding", back_populates="assessment", cascade="all, delete-orphan", lazy="selectin"
    )
