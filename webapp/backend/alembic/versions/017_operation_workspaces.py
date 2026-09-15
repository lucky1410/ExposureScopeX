"""Add operation workspaces for red-team and purple-team planning."""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "017_operation_workspaces"
down_revision = "016_audit_retention"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "operation_workspaces",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("codename", sa.String(length=80), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("objective", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="planning"),
        sa.Column("classification", sa.String(length=20), nullable=False, server_default="internal"),
        sa.Column("operation_type", sa.String(length=30), nullable=False, server_default="red_team"),
        sa.Column("planned_start_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("planned_end_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("scope_summary", sa.Text(), nullable=True),
        sa.Column("roe_summary", sa.Text(), nullable=True),
        sa.Column("tags", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default="[]"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_operation_workspaces_org_id", "operation_workspaces", ["org_id"])
    op.create_index("ix_operation_workspaces_created_by", "operation_workspaces", ["created_by"])
    op.create_index("ix_operation_workspaces_codename", "operation_workspaces", ["codename"])
    op.create_index("ix_operation_workspaces_id", "operation_workspaces", ["id"])


def downgrade() -> None:
    op.drop_index("ix_operation_workspaces_id", table_name="operation_workspaces")
    op.drop_index("ix_operation_workspaces_codename", table_name="operation_workspaces")
    op.drop_index("ix_operation_workspaces_created_by", table_name="operation_workspaces")
    op.drop_index("ix_operation_workspaces_org_id", table_name="operation_workspaces")
    op.drop_table("operation_workspaces")
