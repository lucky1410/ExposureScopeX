"""Add tenant-scoped MCP security assessment history.

Revision ID: 005_mcp_security_runs
Revises: 004_scan_result_isolation
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "005_mcp_security_runs"
down_revision = "004_scan_result_isolation"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "mcp_security_runs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("endpoint", sa.String(2000), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="running"),
        sa.Column("overall_severity", sa.String(20), nullable=False, server_default="INFO"),
        sa.Column("risk_score", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("summary", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("inventory", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("findings", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("exchanges", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_mcp_security_runs_org_id", "mcp_security_runs", ["org_id"])
    op.create_index("ix_mcp_security_runs_status", "mcp_security_runs", ["status"])


def downgrade() -> None:
    op.drop_index("ix_mcp_security_runs_status", table_name="mcp_security_runs")
    op.drop_index("ix_mcp_security_runs_org_id", table_name="mcp_security_runs")
    op.drop_table("mcp_security_runs")
