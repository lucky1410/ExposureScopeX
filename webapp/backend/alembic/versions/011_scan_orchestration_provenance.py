"""Add execution policy, scan events, and tool provenance.

Revision ID: 011_scan_orchestration
Revises: 010_artifact_object_storage
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "011_scan_orchestration"
down_revision = "010_artifact_object_storage"
branch_labels = None
depends_on = None


def _timestamps() -> list[sa.Column]:
    return [
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    ]


def upgrade() -> None:
    op.add_column("report_artifacts", sa.Column("scope", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")))
    op.create_table(
        "organization_execution_policies",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("max_active_scans", sa.Integer(), nullable=False, server_default="2"),
        sa.Column("max_queued_scans", sa.Integer(), nullable=False, server_default="25"),
        sa.Column("priority", sa.Integer(), nullable=False, server_default="5"),
        sa.Column("settings", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        *_timestamps(),
        sa.UniqueConstraint("org_id", name="uq_org_execution_policy_org"),
    )
    op.create_index("ix_org_execution_policy_org", "organization_execution_policies", ["org_id"])

    op.create_table(
        "scan_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("event_type", sa.String(100), nullable=False),
        sa.Column("status", sa.String(20), nullable=True),
        sa.Column("phase", sa.String(100), nullable=True),
        sa.Column("progress", sa.Integer(), nullable=True),
        sa.Column("message", sa.Text(), nullable=True),
        sa.Column("payload", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        *_timestamps(),
    )
    op.create_index("ix_scan_events_scan_created", "scan_events", ["scan_id", "created_at"])
    op.create_index("ix_scan_events_event_type", "scan_events", ["event_type"])

    op.create_table(
        "scan_tool_runs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("external_id", sa.String(255), nullable=False),
        sa.Column("tool", sa.String(100), nullable=False),
        sa.Column("tool_version", sa.String(255), nullable=True),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("exit_code", sa.Integer(), nullable=True),
        sa.Column("command", sa.Text(), nullable=True),
        sa.Column("output_file", sa.String(1000), nullable=True),
        sa.Column("output_excerpt", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column("provenance", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        *_timestamps(),
        sa.UniqueConstraint("scan_id", "external_id", name="uq_scan_tool_run_external"),
    )
    op.create_index("ix_scan_tool_runs_scan_created", "scan_tool_runs", ["scan_id", "created_at"])
    op.create_index("ix_scan_tool_runs_tool", "scan_tool_runs", ["tool"])
    op.create_index("ix_scan_tool_runs_status", "scan_tool_runs", ["status"])


def downgrade() -> None:
    op.drop_table("scan_tool_runs")
    op.drop_table("scan_events")
    op.drop_table("organization_execution_policies")
    op.drop_column("report_artifacts", "scope")
