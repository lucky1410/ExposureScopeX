"""Finding model linking vulnerabilities to specific assets in an assessment."""

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Numeric, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import relationship

from app.database import Base
from app.models.base import TimestampMixin


class Finding(TimestampMixin, Base):
    __tablename__ = "findings"

    assessment_id = Column(
        UUID(as_uuid=True),
        ForeignKey("assessments.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    scan_id = Column(
        UUID(as_uuid=True),
        ForeignKey("scans.id"),
        nullable=True,
    )
    asset_id = Column(
        UUID(as_uuid=True),
        ForeignKey("assets.id"),
        nullable=True,
    )
    vulnerability_id = Column(
        UUID(as_uuid=True),
        ForeignKey("vulnerabilities.id"),
        nullable=True,
    )
    identity_id = Column(UUID(as_uuid=True), ForeignKey("finding_identities.id", ondelete="SET NULL"), nullable=True, index=True)
    source = Column(String(100), nullable=True)
    template_id = Column(String(200), nullable=True)
    severity = Column(String(20), nullable=False)  # CRITICAL/HIGH/MEDIUM/LOW/INFO
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)
    url = Column(String(2000), nullable=True)
    evidence = Column(Text, nullable=True)
    status = Column(
        String(20), nullable=False, default="new"
    )  # new/confirmed/false_positive/remediated/suppressed
    risk_score = Column(Numeric(5, 2), nullable=True)
    confidence_score = Column(Numeric(5, 2), nullable=True)
    reachability = Column(String(20), nullable=True)
    exploitability = Column(String(20), nullable=True)
    evidence_metadata = Column(JSONB, nullable=False, default=dict)
    status_reason = Column(Text, nullable=True)
    status_scope = Column(String(100), nullable=True)
    status_changed_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    status_changed_at = Column(DateTime(timezone=True), nullable=True)
    suppression_expires_at = Column(DateTime(timezone=True), nullable=True, index=True)
    assigned_to = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    due_at = Column(DateTime(timezone=True), nullable=True, index=True)
    sla_status = Column(String(20), nullable=False, default="untracked", index=True)
    verification_status = Column(String(30), nullable=False, default="not_requested", index=True)
    first_seen = Column(DateTime(timezone=True), nullable=True)
    last_seen = Column(DateTime(timezone=True), nullable=True)
    remediated_at = Column(DateTime(timezone=True), nullable=True)
    is_demo = Column(Boolean, default=False, nullable=False)

    __table_args__ = (
        UniqueConstraint(
            "scan_id", "asset_id", "source", "template_id", "url",
            name="uq_finding_scan_asset_source_template_url",
        ),
    )

    # Relationships
    assessment = relationship("Assessment", back_populates="findings")
    scan = relationship("Scan", back_populates="findings")
    asset = relationship("Asset", back_populates="findings")
    vulnerability = relationship("Vulnerability", lazy="selectin")
    investigation_links = relationship(
        "InvestigationFinding", back_populates="finding", lazy="selectin"
    )
    identity = relationship("FindingIdentity", back_populates="findings")
    observation = relationship("FindingObservation", back_populates="finding", uselist=False)
    activities = relationship("FindingActivity", back_populates="finding", cascade="all, delete-orphan", lazy="selectin")


class FindingIdentity(TimestampMixin, Base):
    __tablename__ = "finding_identities"
    __table_args__ = (UniqueConstraint("org_id", "fingerprint", name="uq_finding_identity_org_fingerprint"),)

    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    fingerprint = Column(String(64), nullable=False, index=True)
    source = Column(String(100), nullable=False)
    template_id = Column(String(200), nullable=True)
    title = Column(String(500), nullable=False)
    severity = Column(String(20), nullable=False)
    status = Column(String(30), nullable=False, default="open", index=True)
    first_seen = Column(DateTime(timezone=True), nullable=False)
    last_seen = Column(DateTime(timezone=True), nullable=False)

    findings = relationship("Finding", back_populates="identity")
    observations = relationship("FindingObservation", back_populates="identity", cascade="all, delete-orphan")


class FindingObservation(TimestampMixin, Base):
    __tablename__ = "finding_observations"
    __table_args__ = (UniqueConstraint("identity_id", "scan_id", name="uq_finding_observation_identity_scan"),)

    identity_id = Column(UUID(as_uuid=True), ForeignKey("finding_identities.id", ondelete="CASCADE"), nullable=False, index=True)
    finding_id = Column(UUID(as_uuid=True), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, unique=True)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    assessment_id = Column(UUID(as_uuid=True), ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False, index=True)
    observed_at = Column(DateTime(timezone=True), nullable=False)
    evidence_sha256 = Column(String(64), nullable=True)
    payload = Column(JSONB, nullable=False, default=dict)

    identity = relationship("FindingIdentity", back_populates="observations")
    finding = relationship("Finding", back_populates="observation")


class FindingActivity(TimestampMixin, Base):
    __tablename__ = "finding_activities"

    finding_id = Column(UUID(as_uuid=True), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True)
    actor_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    activity_type = Column(String(40), nullable=False, index=True)
    body = Column(Text, nullable=True)
    payload = Column(JSONB, nullable=False, default=dict)

    finding = relationship("Finding", back_populates="activities")
