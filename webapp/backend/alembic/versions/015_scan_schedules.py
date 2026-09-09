"""Add recurring assessment schedules and run history."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "015_scan_schedules"
down_revision = "014_saved_scan_profiles"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table("scan_schedules",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("assessment_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("name", sa.String(255), nullable=False), sa.Column("timezone", sa.String(100), nullable=False, server_default="UTC"),
        sa.Column("interval_minutes", sa.Integer(), nullable=False), sa.Column("window_start", sa.String(5)), sa.Column("window_end", sa.String(5)),
        sa.Column("missed_run_policy", sa.String(20), nullable=False, server_default="run_once"),
        sa.Column("overlap_policy", sa.String(20), nullable=False, server_default="skip"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=False), sa.Column("last_run_at", sa.DateTime(timezone=True)),
        sa.Column("last_status", sa.String(30)), sa.Column("last_scan_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("scans.id", ondelete="SET NULL")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()))
    op.create_index("ix_scan_schedules_due", "scan_schedules", ["is_active", "next_run_at"])
    op.create_index("ix_scan_schedules_org", "scan_schedules", ["org_id"])
    op.create_index("ix_scan_schedules_assessment", "scan_schedules", ["assessment_id"])
    op.create_table("scan_schedule_runs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("schedule_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("scan_schedules.id", ondelete="CASCADE"), nullable=False),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("scans.id", ondelete="SET NULL")),
        sa.Column("planned_at", sa.DateTime(timezone=True), nullable=False), sa.Column("status", sa.String(30), nullable=False), sa.Column("message", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()))
    op.create_index("ix_scan_schedule_runs_schedule", "scan_schedule_runs", ["schedule_id", "created_at"])


def downgrade() -> None:
    op.drop_table("scan_schedule_runs")
    op.drop_table("scan_schedules")
