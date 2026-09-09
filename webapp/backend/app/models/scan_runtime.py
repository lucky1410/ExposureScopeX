"""Durable scan scheduling, event, and tool provenance models."""

from sqlalchemy import BigInteger, Boolean, Column, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import relationship

from app.database import Base
from app.models.base import TimestampMixin


class OrganizationExecutionPolicy(TimestampMixin, Base):
    __tablename__ = "organization_execution_policies"

    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, unique=True, index=True)
    max_active_scans = Column(Integer, nullable=False, default=2)
    max_queued_scans = Column(Integer, nullable=False, default=25)
    priority = Column(Integer, nullable=False, default=5)
    settings = Column(JSONB, nullable=False, default=dict)


class OrganizationScanProfile(TimestampMixin, Base):
    __tablename__ = "organization_scan_profiles"
    __table_args__ = (UniqueConstraint("org_id", "name", "version", name="uq_org_scan_profile_version"),)

    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    name = Column(String(255), nullable=False)
    version = Column(Integer, nullable=False, default=1)
    description = Column(Text, nullable=True)
    target_type = Column(String(30), nullable=False, default="domain")
    scan_mode = Column(String(20), nullable=False, default="medium")
    configuration = Column(JSONB, nullable=False, default=dict)
    is_active = Column(Boolean, nullable=False, default=True, index=True)


class ScanEvent(TimestampMixin, Base):
    __tablename__ = "scan_events"

    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    event_type = Column(String(100), nullable=False, index=True)
    status = Column(String(20), nullable=True)
    phase = Column(String(100), nullable=True)
    progress = Column(Integer, nullable=True)
    message = Column(Text, nullable=True)
    payload = Column(JSONB, nullable=False, default=dict)

    scan = relationship("Scan", back_populates="events")


class ScanToolRun(TimestampMixin, Base):
    __tablename__ = "scan_tool_runs"
    __table_args__ = (
        UniqueConstraint("scan_id", "external_id", name="uq_scan_tool_run_external"),
    )

    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    external_id = Column(String(255), nullable=False)
    tool = Column(String(100), nullable=False, index=True)
    tool_version = Column(String(255), nullable=True)
    status = Column(String(20), nullable=False, index=True)
    exit_code = Column(Integer, nullable=True)
    command = Column(Text, nullable=True)
    output_file = Column(String(1000), nullable=True)
    output_excerpt = Column(Text, nullable=True)
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    duration_ms = Column(Integer, nullable=True)
    provenance = Column(JSONB, nullable=False, default=dict)

    scan = relationship("Scan", back_populates="tool_runs")


class WorkerCapability(TimestampMixin, Base):
    __tablename__ = "worker_capabilities"

    worker_name = Column(String(255), nullable=False, unique=True)
    image_identity = Column(String(500), nullable=False)
    queues = Column(JSONB, nullable=False, default=list)
    capabilities = Column(JSONB, nullable=False, default=list)
    versions = Column(JSONB, nullable=False, default=dict)
    status = Column(String(20), nullable=False, default="online", index=True)
    last_seen_at = Column(DateTime(timezone=True), nullable=False, index=True)


class ScanArtifact(TimestampMixin, Base):
    __tablename__ = "scan_artifacts"
    __table_args__ = (UniqueConstraint("scan_id", "path", name="uq_scan_artifact_path"),)

    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    path = Column(String(1000), nullable=False)
    artifact_type = Column(String(100), nullable=False, index=True)
    mime_type = Column(String(255), nullable=True)
    size_bytes = Column(BigInteger, nullable=False)
    sha256 = Column(String(64), nullable=False, index=True)
    retained = Column(Boolean, nullable=False, default=True)
    provenance = Column(JSONB, nullable=False, default=dict)

    scan = relationship("Scan", back_populates="artifacts")


class ScanSchedule(TimestampMixin, Base):
    __tablename__ = "scan_schedules"

    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    assessment_id = Column(UUID(as_uuid=True), ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False, index=True)
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    name = Column(String(255), nullable=False)
    timezone = Column(String(100), nullable=False, default="UTC")
    interval_minutes = Column(Integer, nullable=False)
    window_start = Column(String(5), nullable=True)
    window_end = Column(String(5), nullable=True)
    missed_run_policy = Column(String(20), nullable=False, default="run_once")
    overlap_policy = Column(String(20), nullable=False, default="skip")
    is_active = Column(Boolean, nullable=False, default=True, index=True)
    next_run_at = Column(DateTime(timezone=True), nullable=False, index=True)
    last_run_at = Column(DateTime(timezone=True), nullable=True)
    last_status = Column(String(30), nullable=True)
    last_scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id", ondelete="SET NULL"), nullable=True)


class ScanScheduleRun(TimestampMixin, Base):
    __tablename__ = "scan_schedule_runs"

    schedule_id = Column(UUID(as_uuid=True), ForeignKey("scan_schedules.id", ondelete="CASCADE"), nullable=False, index=True)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id", ondelete="SET NULL"), nullable=True, index=True)
    planned_at = Column(DateTime(timezone=True), nullable=False)
    status = Column(String(30), nullable=False, index=True)
    message = Column(Text, nullable=True)
