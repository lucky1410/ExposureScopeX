"""Immutable generated report artifacts."""

from sqlalchemy import Column, ForeignKey, Integer, LargeBinary, String
from sqlalchemy.dialects.postgresql import JSONB, UUID

from app.database import Base
from app.models.base import TimestampMixin


class ReportArtifact(TimestampMixin, Base):
    __tablename__ = "report_artifacts"

    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    assessment_id = Column(UUID(as_uuid=True), ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False, index=True)
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    title = Column(String(500), nullable=False)
    format = Column(String(20), nullable=False)
    filename = Column(String(500), nullable=False)
    media_type = Column(String(100), nullable=False)
    status = Column(String(20), nullable=False, default="ready")
    version = Column(Integer, nullable=False, default=1)
    file_size = Column(Integer, nullable=False)
    sha256 = Column(String(64), nullable=False, index=True)
    storage_backend = Column(String(20), nullable=False, default="database")
    object_key = Column(String(1000), nullable=True, unique=True)
    content = Column(LargeBinary, nullable=True)
    scope = Column(JSONB, nullable=False, default=dict)
