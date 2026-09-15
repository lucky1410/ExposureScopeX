"""Add controlled operation lifecycle and assessment linkage."""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "018_operation_control"
down_revision = "017_operation_workspaces"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("operation_workspaces", sa.Column("approved_by", postgresql.UUID(as_uuid=True), nullable=True))
    op.add_column("operation_workspaces", sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("operation_workspaces", sa.Column("activated_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("operation_workspaces", sa.Column("stopped_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("operation_workspaces", sa.Column("stop_reason", sa.Text(), nullable=True))
    op.create_foreign_key("fk_operation_workspaces_approved_by", "operation_workspaces", "users", ["approved_by"], ["id"], ondelete="SET NULL")
    # Earlier releases allowed callers to create operations directly in an
    # execution state. Force those records through the new approval gate.
    op.execute("""
        UPDATE operation_workspaces
        SET status = 'planning'
        WHERE status IN ('approved', 'active', 'paused')
    """)
    op.add_column("assessments", sa.Column("operation_id", postgresql.UUID(as_uuid=True), nullable=True))
    op.create_foreign_key("fk_assessments_operation_id", "assessments", "operation_workspaces", ["operation_id"], ["id"], ondelete="SET NULL")
    op.create_index("ix_assessments_operation_id", "assessments", ["operation_id"])


def downgrade() -> None:
    op.drop_index("ix_assessments_operation_id", table_name="assessments")
    op.drop_constraint("fk_assessments_operation_id", "assessments", type_="foreignkey")
    op.drop_column("assessments", "operation_id")
    op.drop_constraint("fk_operation_workspaces_approved_by", "operation_workspaces", type_="foreignkey")
    op.drop_column("operation_workspaces", "stop_reason")
    op.drop_column("operation_workspaces", "stopped_at")
    op.drop_column("operation_workspaces", "activated_at")
    op.drop_column("operation_workspaces", "approved_at")
    op.drop_column("operation_workspaces", "approved_by")
