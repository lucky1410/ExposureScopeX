"""Persistent asset graph, historical snapshots, drift, and attack paths."""

from sqlalchemy import Column, DateTime, ForeignKey, Integer, Numeric, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import relationship

from app.database import Base
from app.models.base import TimestampMixin


class AssetRelation(TimestampMixin, Base):
    __tablename__ = "asset_relations"

    assessment_id = Column(UUID(as_uuid=True), ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False, index=True)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=True, index=True)
    source_asset_id = Column(UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    target_asset_id = Column(UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    relation_type = Column(String(100), nullable=False, index=True)
    confidence = Column(Integer, nullable=False, default=80)
    evidence = Column(JSONB, nullable=False, default=dict)
    first_seen = Column(DateTime(timezone=True), nullable=False)
    last_seen = Column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        UniqueConstraint(
            "scan_id", "source_asset_id", "target_asset_id", "relation_type",
            name="uq_asset_relation_scan_edge",
        ),
    )

    source_asset = relationship("Asset", foreign_keys=[source_asset_id], lazy="selectin")
    target_asset = relationship("Asset", foreign_keys=[target_asset_id], lazy="selectin")


class AssetSnapshot(TimestampMixin, Base):
    __tablename__ = "asset_snapshots"

    asset_id = Column(UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    fingerprint = Column(String(64), nullable=False, index=True)
    state = Column(JSONB, nullable=False, default=dict)
    observed_at = Column(DateTime(timezone=True), nullable=False, index=True)

    __table_args__ = (
        UniqueConstraint("asset_id", "scan_id", name="uq_asset_snapshot_scan"),
    )


class ExposureEvent(TimestampMixin, Base):
    __tablename__ = "exposure_events"

    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    assessment_id = Column(UUID(as_uuid=True), ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False, index=True)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=True, index=True)
    asset_id = Column(UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=True, index=True)
    event_type = Column(String(100), nullable=False, index=True)
    severity = Column(String(20), nullable=False, default="INFO")
    payload = Column(JSONB, nullable=False, default=dict)
    observed_at = Column(DateTime(timezone=True), nullable=False, index=True)


class AttackPath(TimestampMixin, Base):
    __tablename__ = "attack_paths"

    assessment_id = Column(UUID(as_uuid=True), ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False, index=True)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    title = Column(String(500), nullable=False)
    severity = Column(String(20), nullable=False)
    risk_score = Column(Numeric(5, 2), nullable=False)
    status = Column(String(20), nullable=False, default="open")
    nodes = Column(JSONB, nullable=False, default=list)
    edges = Column(JSONB, nullable=False, default=list)
    evidence = Column(Text, nullable=True)
