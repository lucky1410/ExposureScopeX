"""ASM (Attack Surface Management) models."""

from datetime import datetime, timezone
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import relationship

from app.database import Base
from app.models.base import TimestampMixin


class AsmTarget(TimestampMixin, Base):
    __tablename__ = "asm_targets"

    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True)
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    name = Column(String(255), nullable=False)
    # ip / cidr / domain / hostname
    target_type = Column(String(20), nullable=False, default="domain")
    target_value = Column(String(500), nullable=False)
    # manual / csv / aws / gcp / azure
    source_type = Column(String(20), nullable=False, default="manual")
    cloud_region = Column(String(100), nullable=True)
    cloud_account_id = Column(String(200), nullable=True)
    tags = Column(JSONB, nullable=False, default=list)
    # idle / scanning / completed / failed
    scan_status = Column(String(20), nullable=False, default="idle")
    last_scanned = Column(DateTime(timezone=True), nullable=True)
    # aggregated counts from last scan
    last_scan_summary = Column(JSONB, nullable=True)
    notes = Column(Text, nullable=True)


class AsmCloudSource(TimestampMixin, Base):
    __tablename__ = "asm_cloud_sources"

    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True)
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    name = Column(String(255), nullable=False)
    # aws / gcp / azure / onprem
    provider = Column(String(20), nullable=False)
    # non-secret config: region, project_id, subscription_id etc
    config = Column(JSONB, nullable=False, default=dict)
    is_active = Column(Boolean, nullable=False, default=True)
    last_sync = Column(DateTime(timezone=True), nullable=True)
    last_sync_count = Column(String(20), nullable=True)
    status = Column(String(20), nullable=False, default="pending")  # pending/ok/error
    status_message = Column(Text, nullable=True)


class AsmFinding(TimestampMixin, Base):
    """Lightweight finding scoped to an ASM target (no assessment dependency)."""

    __tablename__ = "asm_findings"

    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True)
    target_id = Column(UUID(as_uuid=True), ForeignKey("asm_targets.id", ondelete="CASCADE"), nullable=False, index=True)
    severity = Column(String(20), nullable=False)   # CRITICAL/HIGH/MEDIUM/LOW/INFO
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)
    source = Column(String(100), nullable=True)     # dns / ssl / headers / subdomains / ports
    url = Column(String(2000), nullable=True)
    evidence = Column(Text, nullable=True)
    # new / confirmed / false_positive / remediated
    status = Column(String(20), nullable=False, default="new")
    first_seen = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    last_seen = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

    target = relationship("AsmTarget", lazy="select")
