"""Disable the published legacy demo administrator.

Revision ID: 009_disable_legacy_default_admin
Revises: 008_auth_sessions
"""

from alembic import op

revision = "009_disable_legacy_default_admin"
down_revision = "008_auth_sessions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "UPDATE users SET is_active = false "
        "WHERE lower(email) = 'admin@exposurescopex.local' AND username = 'admin'"
    )


def downgrade() -> None:
    # Re-enabling an account with a formerly published password is unsafe.
    pass
