"""Enforce append-only audit records and retain authentication device context."""

from alembic import op
import sqlalchemy as sa

revision = "016_audit_retention"
down_revision = "015_scan_schedules"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("auth_sessions", sa.Column("ip_address", sa.String(45), nullable=True))
    op.add_column("auth_sessions", sa.Column("user_agent", sa.Text(), nullable=True))
    op.add_column("auth_sessions", sa.Column("device_name", sa.String(255), nullable=True))
    op.execute(
        """
        CREATE OR REPLACE FUNCTION reject_audit_log_mutation()
        RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'audit_logs is append-only';
        END;
        $$ LANGUAGE plpgsql
        """
    )
    op.execute(
        """
        CREATE TRIGGER audit_logs_append_only_update
            BEFORE UPDATE ON audit_logs FOR EACH ROW
            EXECUTE FUNCTION reject_audit_log_mutation()
        """
    )
    op.execute(
        """
        CREATE TRIGGER audit_logs_append_only_delete
            BEFORE DELETE ON audit_logs FOR EACH ROW
            EXECUTE FUNCTION reject_audit_log_mutation()
        """
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS audit_logs_append_only_delete ON audit_logs")
    op.execute("DROP TRIGGER IF EXISTS audit_logs_append_only_update ON audit_logs")
    op.execute("DROP FUNCTION IF EXISTS reject_audit_log_mutation")
    op.drop_column("auth_sessions", "device_name")
    op.drop_column("auth_sessions", "user_agent")
    op.drop_column("auth_sessions", "ip_address")
