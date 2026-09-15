"""Operation workspace model for red-team and purple-team planning."""

from sqlalchemy import Column, DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import relationship

from app.database import Base
from app.models.base import TimestampMixin


class OperationWorkspace(TimestampMixin, Base):
    __tablename__ = "operation_workspaces"

    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True)
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    codename = Column(String(80), nullable=True, index=True)
    description = Column(Text, nullable=True)
    objective = Column(Text, nullable=False)
    status = Column(String(20), nullable=False, default="planning")
    classification = Column(String(20), nullable=False, default="internal")
    operation_type = Column(String(30), nullable=False, default="red_team")
    planned_start_at = Column(DateTime(timezone=True), nullable=True)
    planned_end_at = Column(DateTime(timezone=True), nullable=True)
    scope_summary = Column(Text, nullable=True)
    roe_summary = Column(Text, nullable=True)
    tags = Column(JSONB, nullable=False, default=list)
    approved_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    approved_at = Column(DateTime(timezone=True), nullable=True)
    activated_at = Column(DateTime(timezone=True), nullable=True)
    stopped_at = Column(DateTime(timezone=True), nullable=True)
    stop_reason = Column(Text, nullable=True)

    organization = relationship("Organization", back_populates="operation_workspaces")
    owner = relationship("User", back_populates="operation_workspaces", foreign_keys=[created_by])
    assessments = relationship("Assessment", back_populates="operation", lazy="selectin")
