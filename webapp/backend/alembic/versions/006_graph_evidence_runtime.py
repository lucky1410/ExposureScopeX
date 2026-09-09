"""Add graph, evidence, drift, and durable scan runtime fields.

Revision ID: 006_graph_evidence_runtime
Revises: 005_mcp_security_runs
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "006_graph_evidence_runtime"
down_revision = "005_mcp_security_runs"
branch_labels = None
depends_on = None


def _timestamps() -> list[sa.Column]:
    return [
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    ]


def upgrade() -> None:
    op.add_column("scans", sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("scans", sa.Column("cancel_requested_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("scans", sa.Column("attempt", sa.Integer(), nullable=False, server_default="1"))
    op.add_column("scans", sa.Column("max_attempts", sa.Integer(), nullable=False, server_default="2"))
    op.create_index("ix_scans_heartbeat_at", "scans", ["heartbeat_at"])

    op.add_column("assets", sa.Column("canonical_key", sa.String(700), nullable=True))
    op.add_column("assets", sa.Column("root_domain", sa.String(500), nullable=True))
    op.add_column("assets", sa.Column("owner", sa.String(255), nullable=True))
    op.add_column("assets", sa.Column("ownership_status", sa.String(30), nullable=False, server_default="unattributed"))
    op.create_index("ix_assets_canonical_key", "assets", ["canonical_key"])
    op.create_index("ix_assets_root_domain", "assets", ["root_domain"])
    op.create_index("ix_assets_owner", "assets", ["owner"])
    op.create_index("ix_assets_ownership_status", "assets", ["ownership_status"])

    op.add_column("findings", sa.Column("confidence_score", sa.Numeric(5, 2), nullable=True))
    op.add_column("findings", sa.Column("reachability", sa.String(20), nullable=True))
    op.add_column("findings", sa.Column("exploitability", sa.String(20), nullable=True))
    op.add_column("findings", sa.Column("evidence_metadata", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")))
    op.add_column("findings", sa.Column("status_reason", sa.Text(), nullable=True))
    op.add_column("findings", sa.Column("status_scope", sa.String(100), nullable=True))
    op.add_column("findings", sa.Column("status_changed_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=True))
    op.add_column("findings", sa.Column("status_changed_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("findings", sa.Column("suppression_expires_at", sa.DateTime(timezone=True), nullable=True))
    op.create_index("ix_findings_suppression_expires_at", "findings", ["suppression_expires_at"])

    op.create_table(
        "asset_relations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("assessment_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=True),
        sa.Column("source_asset_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("target_asset_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("relation_type", sa.String(100), nullable=False),
        sa.Column("confidence", sa.Integer(), nullable=False, server_default="80"),
        sa.Column("evidence", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        *_timestamps(),
        sa.UniqueConstraint("scan_id", "source_asset_id", "target_asset_id", "relation_type", name="uq_asset_relation_scan_edge"),
    )
    for column in ("assessment_id", "scan_id", "source_asset_id", "target_asset_id", "relation_type"):
        op.create_index(f"ix_asset_relations_{column}", "asset_relations", [column])

    op.create_table(
        "asset_snapshots",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("state", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        *_timestamps(),
        sa.UniqueConstraint("asset_id", "scan_id", name="uq_asset_snapshot_scan"),
    )
    for column in ("asset_id", "scan_id", "fingerprint", "observed_at"):
        op.create_index(f"ix_asset_snapshots_{column}", "asset_snapshots", [column])

    op.create_table(
        "exposure_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("assessment_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=True),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=True),
        sa.Column("event_type", sa.String(100), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False, server_default="INFO"),
        sa.Column("payload", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        *_timestamps(),
    )
    for column in ("org_id", "assessment_id", "scan_id", "asset_id", "event_type", "observed_at"):
        op.create_index(f"ix_exposure_events_{column}", "exposure_events", [column])

    op.create_table(
        "attack_paths",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("assessment_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("risk_score", sa.Numeric(5, 2), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="open"),
        sa.Column("nodes", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("edges", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("evidence", sa.Text(), nullable=True),
        *_timestamps(),
    )
    op.create_index("ix_attack_paths_assessment_id", "attack_paths", ["assessment_id"])
    op.create_index("ix_attack_paths_scan_id", "attack_paths", ["scan_id"])


def downgrade() -> None:
    op.drop_table("attack_paths")
    op.drop_table("exposure_events")
    op.drop_table("asset_snapshots")
    op.drop_table("asset_relations")
    op.drop_index("ix_findings_suppression_expires_at", table_name="findings")
    for column in ("suppression_expires_at", "status_changed_at", "status_changed_by", "status_scope", "status_reason", "evidence_metadata", "exploitability", "reachability", "confidence_score"):
        op.drop_column("findings", column)
    for index in ("ix_assets_ownership_status", "ix_assets_owner", "ix_assets_root_domain", "ix_assets_canonical_key"):
        op.drop_index(index, table_name="assets")
    for column in ("ownership_status", "owner", "root_domain", "canonical_key"):
        op.drop_column("assets", column)
    op.drop_index("ix_scans_heartbeat_at", table_name="scans")
    for column in ("max_attempts", "attempt", "cancel_requested_at", "heartbeat_at"):
        op.drop_column("scans", column)
