"""Scan model tracking individual scan executions within an assessment."""

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import relationship

from app.database import Base
from app.models.base import TimestampMixin


class Scan(TimestampMixin, Base):
    __tablename__ = "scans"

    assessment_id = Column(
        UUID(as_uuid=True),
        ForeignKey("assessments.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    celery_task_id = Column(String(255), nullable=True, unique=True)
    session_dir = Column(String(500), nullable=True)
    status = Column(
        String(20), nullable=False, default="queued"
    )  # queued/running/completed/partial/failed/cancelled
    current_phase = Column(String(100), nullable=True)
    progress = Column(Integer, nullable=False, default=0)  # 0-100
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    heartbeat_at = Column(DateTime(timezone=True), nullable=True, index=True)
    cancel_requested_at = Column(DateTime(timezone=True), nullable=True)
    attempt = Column(Integer, nullable=False, default=1)
    max_attempts = Column(Integer, nullable=False, default=2)
    error_message = Column(Text, nullable=True)
    raw_log = Column(Text, nullable=True)
    scan_metadata = Column(JSONB, nullable=True, default=dict)
    is_demo = Column(Boolean, default=False, nullable=False)

    # Relationships
    assessment = relationship("Assessment", back_populates="scans")
    findings = relationship("Finding", back_populates="scan", lazy="selectin")
    ports = relationship("Port", back_populates="scan", lazy="selectin")
    events = relationship("ScanEvent", back_populates="scan", cascade="all, delete-orphan", lazy="selectin")
    tool_runs = relationship("ScanToolRun", back_populates="scan", cascade="all, delete-orphan", lazy="selectin")
    artifacts = relationship("ScanArtifact", back_populates="scan", cascade="all, delete-orphan", lazy="selectin")
