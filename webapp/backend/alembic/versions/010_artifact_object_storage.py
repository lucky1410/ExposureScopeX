"""Add pluggable object storage metadata to report artifacts.

Revision ID: 010_artifact_object_storage
Revises: 009_disable_legacy_default_admin
"""

from alembic import op
import sqlalchemy as sa

revision = "010_artifact_object_storage"
down_revision = "009_disable_legacy_default_admin"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("report_artifacts", sa.Column("storage_backend", sa.String(20), nullable=False, server_default="database"))
    op.add_column("report_artifacts", sa.Column("object_key", sa.String(1000), nullable=True))
    op.alter_column("report_artifacts", "content", existing_type=sa.LargeBinary(), nullable=True)
    op.create_index("ix_report_artifacts_object_key", "report_artifacts", ["object_key"], unique=True)


def downgrade() -> None:
    op.execute("UPDATE report_artifacts SET content = ''::bytea WHERE content IS NULL")
    op.alter_column("report_artifacts", "content", existing_type=sa.LargeBinary(), nullable=False)
    op.drop_index("ix_report_artifacts_object_key", table_name="report_artifacts")
    op.drop_column("report_artifacts", "object_key")
    op.drop_column("report_artifacts", "storage_backend")
