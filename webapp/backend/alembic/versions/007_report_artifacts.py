"""Persist immutable generated report artifacts.

Revision ID: 007_report_artifacts
Revises: 006_graph_evidence_runtime
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "007_report_artifacts"
down_revision = "006_graph_evidence_runtime"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "report_artifacts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("assessment_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("format", sa.String(20), nullable=False),
        sa.Column("filename", sa.String(500), nullable=False),
        sa.Column("media_type", sa.String(100), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="ready"),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("file_size", sa.Integer(), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("content", sa.LargeBinary(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    for column in ("org_id", "assessment_id", "sha256"):
        op.create_index(f"ix_report_artifacts_{column}", "report_artifacts", [column])
    op.create_index(
        "ix_report_artifacts_assessment_format_version",
        "report_artifacts",
        ["assessment_id", "format", "version"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_table("report_artifacts")
