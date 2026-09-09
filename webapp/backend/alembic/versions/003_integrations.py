"""Create org_integrations table.

Revision ID: 003_integrations
Revises: 002_asm_tables
Create Date: 2026-08-17 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "003_integrations"
down_revision = "002_asm_tables"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "org_integrations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "org_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id"),
            nullable=False,
        ),
        sa.Column("provider", sa.String(50), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column(
            "config",
            postgresql.JSONB,
            nullable=False,
            server_default="{}",
        ),
        sa.Column(
            "is_active",
            sa.Boolean,
            nullable=False,
            server_default=sa.text("true"),
        ),
        sa.Column(
            "events",
            postgresql.JSONB,
            nullable=False,
            server_default="[]",
        ),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_status", sa.String(20), nullable=True),
        sa.Column("last_error", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )

    # Index: look up all integrations for an org (most common query)
    op.create_index(
        "ix_org_integrations_org_id",
        "org_integrations",
        ["org_id"],
    )

    # Index: look up integrations for an org filtered by provider
    op.create_index(
        "ix_org_integrations_org_id_provider",
        "org_integrations",
        ["org_id", "provider"],
    )

    # Index: look up only active integrations for an org (used by dispatcher)
    op.create_index(
        "ix_org_integrations_org_id_is_active",
        "org_integrations",
        ["org_id", "is_active"],
    )


def downgrade() -> None:
    op.drop_index("ix_org_integrations_org_id_is_active", table_name="org_integrations")
    op.drop_index("ix_org_integrations_org_id_provider", table_name="org_integrations")
    op.drop_index("ix_org_integrations_org_id", table_name="org_integrations")
    op.drop_table("org_integrations")
