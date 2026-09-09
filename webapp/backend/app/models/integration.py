"""OrgIntegration model — notification/SIEM/ticketing provider configurations."""

from datetime import datetime, timezone
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID

from app.database import Base
from app.models.base import TimestampMixin

# Valid provider identifiers
VALID_PROVIDERS = {
    "slack",
    "teams",
    "pagerduty",
    "splunk",
    "elastic",
    "jira",
    "github_sarif",
    "greynoise",
    "aws",
    "gcp",
    "azure",
    "servicenow",
    "gitlab_sarif",
    "mobile_dynamic",
    "kubernetes_runtime",
}

# Normalized ASM/CTEM events that can be delivered to a SOC.
EXPOSURE_EVENTS = {
    "asset.new", "asset.removed", "asset.changed", "service.new", "certificate.new",
    "api.new", "api.shadowed", "cloud.exposure", "identity.changed", "secret.discovered",
    "cve.exploitable", "kev.exposed", "attackpath.created", "attackpath.expanded",
    "mcp.server.new", "mcp.tool.changed", "mcp.authorization.changed", "agent.new", "ai.endpoint.new",
}

# Valid event names that can be subscribed to
VALID_EVENTS = {
    "scan.completed",
    "scan.failed",
    "finding.critical",
    "finding.high",
    "assessment.completed",
    "asm.scan.completed",
} | EXPOSURE_EVENTS


class OrgIntegration(TimestampMixin, Base):
    """Per-organisation integration configuration.

    The ``config`` column stores provider credentials encrypted at rest via
    Fernet as ``{"_encrypted": "<ciphertext>"}``.  Never return the raw
    ciphertext to API callers; expose ``has_config: bool`` instead.
    """

    __tablename__ = "org_integrations"

    org_id = Column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id"),
        nullable=False,
        index=True,
    )
    # Provider slug — one of VALID_PROVIDERS
    provider = Column(String(50), nullable=False)
    # Human-readable display name chosen by the user
    name = Column(String(255), nullable=False)
    # Encrypted credentials: {"_encrypted": "<ciphertext>"}
    config = Column(JSONB, nullable=False, default=dict)
    is_active = Column(Boolean, nullable=False, default=True)
    # List of event name strings that trigger delivery for this integration
    events = Column(JSONB, nullable=False, default=list)
    last_used_at = Column(DateTime(timezone=True), nullable=True)
    # "ok" or "error"
    last_status = Column(String(20), nullable=True)
    last_error = Column(Text, nullable=True)
