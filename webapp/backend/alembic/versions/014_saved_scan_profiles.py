"""Add versioned organization scan profiles."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "014_saved_scan_profiles"
down_revision = "013_finding_lifecycle"
branch_labels = None
depends_on = None

def upgrade() -> None:
    op.create_table("organization_scan_profiles",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("name", sa.String(255), nullable=False), sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("description", sa.Text()), sa.Column("target_type", sa.String(30), nullable=False),
        sa.Column("scan_mode", sa.String(20), nullable=False),
        sa.Column("configuration", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("org_id", "name", "version", name="uq_org_scan_profile_version"))
    op.create_index("ix_org_scan_profiles_org_active", "organization_scan_profiles", ["org_id", "is_active"])

def downgrade() -> None:
    op.drop_table("organization_scan_profiles")
