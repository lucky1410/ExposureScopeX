"""Asset model representing discovered infrastructure assets."""

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import relationship

from app.database import Base
from app.models.base import TimestampMixin


class Asset(TimestampMixin, Base):
    __tablename__ = "assets"

    assessment_id = Column(
        UUID(as_uuid=True),
        ForeignKey("assessments.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    asset_type = Column(
        String(20), nullable=False
    )  # domain/subdomain/ip/url
    value = Column(String(500), nullable=False, index=True)
    canonical_key = Column(String(700), nullable=True, index=True)
    root_domain = Column(String(500), nullable=True, index=True)
    owner = Column(String(255), nullable=True, index=True)
    ownership_status = Column(String(30), nullable=False, default="unattributed", index=True)
    parent_id = Column(UUID(as_uuid=True), ForeignKey("assets.id"), nullable=True)
    is_live = Column(Boolean, default=True, nullable=False)
    first_seen = Column(DateTime(timezone=True), nullable=True)
    last_seen = Column(DateTime(timezone=True), nullable=True)
    metadata_ = Column("metadata", JSONB, nullable=True, default=dict)
    is_demo = Column(Boolean, default=False, nullable=False)

    __table_args__ = (
        UniqueConstraint("assessment_id", "asset_type", "value", name="uq_asset_assessment_type_value"),
    )

    # Relationships
    assessment = relationship("Assessment", back_populates="assets")
    parent = relationship("Asset", remote_side="Asset.id", lazy="selectin")
    dns_records = relationship(
        "DnsRecord", back_populates="asset", cascade="all, delete-orphan", lazy="selectin"
    )
    ports = relationship(
        "Port", back_populates="asset", cascade="all, delete-orphan", lazy="selectin"
    )
    technologies = relationship(
        "Technology", back_populates="asset", cascade="all, delete-orphan", lazy="selectin"
    )
    tls_certificates = relationship(
        "TlsCertificate", back_populates="asset", cascade="all, delete-orphan", lazy="selectin"
    )
    http_headers = relationship(
        "HttpHeader", back_populates="asset", cascade="all, delete-orphan", lazy="selectin"
    )
    findings = relationship("Finding", back_populates="asset", lazy="selectin")
