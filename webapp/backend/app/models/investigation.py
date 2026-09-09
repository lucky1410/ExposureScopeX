"""Investigation, evidence, and note models for tracking security investigations."""

from sqlalchemy import Column, DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.database import Base
from app.models.base import TimestampMixin


class Investigation(TimestampMixin, Base):
    __tablename__ = "investigations"

    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True)
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)
    status = Column(
        String(20), nullable=False, default="open"
    )  # open/in_progress/closed
    priority = Column(
        String(20), nullable=False, default="medium"
    )  # critical/high/medium/low
    assigned_to = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)

    # Relationships
    organization = relationship("Organization", back_populates="investigations")
    creator = relationship("User", foreign_keys=[created_by], lazy="selectin")
    assignee = relationship("User", foreign_keys=[assigned_to], lazy="selectin")
    finding_links = relationship(
        "InvestigationFinding",
        back_populates="investigation",
        cascade="all, delete-orphan",
        lazy="selectin",
    )
    evidence_items = relationship(
        "Evidence",
        back_populates="investigation",
        cascade="all, delete-orphan",
        lazy="selectin",
    )
    notes = relationship(
        "Note",
        back_populates="investigation",
        cascade="all, delete-orphan",
        lazy="selectin",
    )


class InvestigationFinding(Base):
    __tablename__ = "investigation_findings"

    investigation_id = Column(
        UUID(as_uuid=True),
        ForeignKey("investigations.id", ondelete="CASCADE"),
        primary_key=True,
    )
    finding_id = Column(
        UUID(as_uuid=True),
        ForeignKey("findings.id", ondelete="CASCADE"),
        primary_key=True,
    )

    # Relationships
    investigation = relationship("Investigation", back_populates="finding_links")
    finding = relationship("Finding", back_populates="investigation_links")


class Evidence(TimestampMixin, Base):
    __tablename__ = "evidence"

    investigation_id = Column(
        UUID(as_uuid=True),
        ForeignKey("investigations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    type = Column(String(50), nullable=False)  # screenshot/log/pcap/note/file
    title = Column(String(500), nullable=False)
    content = Column(Text, nullable=True)
    file_path = Column(String(1000), nullable=True)
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)

    # Relationships
    investigation = relationship("Investigation", back_populates="evidence_items")
    creator = relationship("User", lazy="selectin")


class Note(TimestampMixin, Base):
    __tablename__ = "notes"

    investigation_id = Column(
        UUID(as_uuid=True),
        ForeignKey("investigations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    content = Column(Text, nullable=False)
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)

    # Relationships
    investigation = relationship("Investigation", back_populates="notes")
    creator = relationship("User", lazy="selectin")
