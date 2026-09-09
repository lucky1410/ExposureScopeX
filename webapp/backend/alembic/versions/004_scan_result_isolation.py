"""Scope findings and ports uniqueness to one scan execution.

Revision ID: 004_scan_result_isolation
Revises: 003_integrations
"""

from alembic import op

revision = "004_scan_result_isolation"
down_revision = "003_integrations"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_constraint(
        "uq_finding_assessment_asset_source_template_url",
        "findings",
        type_="unique",
    )
    op.create_unique_constraint(
        "uq_finding_scan_asset_source_template_url",
        "findings",
        ["scan_id", "asset_id", "source", "template_id", "url"],
    )
    op.drop_constraint("uq_port_asset_port_proto", "ports", type_="unique")
    op.create_unique_constraint(
        "uq_port_scan_asset_port_proto",
        "ports",
        ["scan_id", "asset_id", "port_number", "protocol"],
    )


def downgrade() -> None:
    op.drop_constraint("uq_port_scan_asset_port_proto", "ports", type_="unique")
    op.create_unique_constraint(
        "uq_port_asset_port_proto",
        "ports",
        ["asset_id", "port_number", "protocol"],
    )
    op.drop_constraint(
        "uq_finding_scan_asset_source_template_url",
        "findings",
        type_="unique",
    )
    op.create_unique_constraint(
        "uq_finding_assessment_asset_source_template_url",
        "findings",
        ["assessment_id", "asset_id", "source", "template_id", "url"],
    )
