"""Persisted MCP security assessments and their protocol evidence."""

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID

from app.database import Base
from app.models.base import TimestampMixin


class McpSecurityRun(TimestampMixin, Base):
    __tablename__ = "mcp_security_runs"

    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True)
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    name = Column(String(255), nullable=False)
    endpoint = Column(String(2000), nullable=False)
    status = Column(String(20), nullable=False, default="running", index=True)
    overall_severity = Column(String(20), nullable=False, default="INFO")
    risk_score = Column(Integer, nullable=False, default=0)
    summary = Column(JSONB, nullable=False, default=dict)
    inventory = Column(JSONB, nullable=False, default=dict)
    findings = Column(JSONB, nullable=False, default=list)
    exchanges = Column(JSONB, nullable=False, default=list)
    error_message = Column(Text, nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
