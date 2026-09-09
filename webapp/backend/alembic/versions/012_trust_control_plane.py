"""Add worker capabilities, artifact manifests, and finding observations.

Revision ID: 012_trust_control_plane
Revises: 011_scan_orchestration
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "012_trust_control_plane"
down_revision = "011_scan_orchestration"
branch_labels = None
depends_on = None


def _timestamps():
    return [
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    ]


def upgrade() -> None:
    op.create_table(
        "worker_capabilities",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("worker_name", sa.String(255), nullable=False, unique=True),
        sa.Column("image_identity", sa.String(500), nullable=False),
        sa.Column("queues", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("capabilities", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("versions", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("status", sa.String(20), nullable=False, server_default="online"),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        *_timestamps(),
    )
    op.create_index("ix_worker_capabilities_name", "worker_capabilities", ["worker_name"])
    op.create_index("ix_worker_capabilities_status_seen", "worker_capabilities", ["status", "last_seen_at"])

    op.create_table(
        "scan_artifacts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("path", sa.String(1000), nullable=False),
        sa.Column("artifact_type", sa.String(100), nullable=False),
        sa.Column("mime_type", sa.String(255), nullable=True),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("retained", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("provenance", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        *_timestamps(),
        sa.UniqueConstraint("scan_id", "path", name="uq_scan_artifact_path"),
    )
    op.create_index("ix_scan_artifacts_scan", "scan_artifacts", ["scan_id"])
    op.create_index("ix_scan_artifacts_sha256", "scan_artifacts", ["sha256"])

    op.create_table(
        "finding_identities",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("source", sa.String(100), nullable=False),
        sa.Column("template_id", sa.String(200), nullable=True),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("status", sa.String(30), nullable=False, server_default="open"),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        *_timestamps(),
        sa.UniqueConstraint("org_id", "fingerprint", name="uq_finding_identity_org_fingerprint"),
    )
    op.create_index("ix_finding_identities_org_status", "finding_identities", ["org_id", "status"])
    op.create_index("ix_finding_identities_fingerprint", "finding_identities", ["fingerprint"])

    op.add_column("findings", sa.Column("identity_id", postgresql.UUID(as_uuid=True), nullable=True))
    op.create_foreign_key("fk_findings_identity", "findings", "finding_identities", ["identity_id"], ["id"], ondelete="SET NULL")
    op.create_index("ix_findings_identity_id", "findings", ["identity_id"])

    op.create_table(
        "finding_observations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("identity_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("finding_identities.id", ondelete="CASCADE"), nullable=False),
        sa.Column("finding_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, unique=True),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("assessment_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("evidence_sha256", sa.String(64), nullable=True),
        sa.Column("payload", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        *_timestamps(),
        sa.UniqueConstraint("identity_id", "scan_id", name="uq_finding_observation_identity_scan"),
    )
    op.create_index("ix_finding_observations_identity", "finding_observations", ["identity_id", "observed_at"])
    op.create_index("ix_finding_observations_scan", "finding_observations", ["scan_id"])


def downgrade() -> None:
    op.drop_table("finding_observations")
    op.drop_index("ix_findings_identity_id", table_name="findings")
    op.drop_constraint("fk_findings_identity", "findings", type_="foreignkey")
    op.drop_column("findings", "identity_id")
    op.drop_table("finding_identities")
    op.drop_table("scan_artifacts")
    op.drop_table("worker_capabilities")
