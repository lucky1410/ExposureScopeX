"""Add collaborative finding lifecycle fields and activity timeline."""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "013_finding_lifecycle"
down_revision = "012_trust_control_plane"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("findings", sa.Column("assigned_to", postgresql.UUID(as_uuid=True), nullable=True))
    op.add_column("findings", sa.Column("due_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("findings", sa.Column("sla_status", sa.String(20), nullable=False, server_default="untracked"))
    op.add_column("findings", sa.Column("verification_status", sa.String(30), nullable=False, server_default="not_requested"))
    op.create_foreign_key("fk_findings_assigned_to", "findings", "users", ["assigned_to"], ["id"], ondelete="SET NULL")
    for column in ("assigned_to", "due_at", "sla_status", "verification_status"):
        op.create_index(f"ix_findings_{column}", "findings", [column])
    op.create_table(
        "finding_activities",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("finding_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("findings.id", ondelete="CASCADE"), nullable=False),
        sa.Column("actor_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("activity_type", sa.String(40), nullable=False),
        sa.Column("body", sa.Text(), nullable=True),
        sa.Column("payload", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_finding_activities_finding", "finding_activities", ["finding_id", "created_at"])
    op.create_index("ix_finding_activities_actor", "finding_activities", ["actor_id"])
    op.create_index("ix_finding_activities_type", "finding_activities", ["activity_type"])


def downgrade() -> None:
    op.drop_table("finding_activities")
    for column in ("verification_status", "sla_status", "due_at", "assigned_to"):
        op.drop_index(f"ix_findings_{column}", table_name="findings")
    op.drop_constraint("fk_findings_assigned_to", "findings", type_="foreignkey")
    for column in ("verification_status", "sla_status", "due_at", "assigned_to"):
        op.drop_column("findings", column)
