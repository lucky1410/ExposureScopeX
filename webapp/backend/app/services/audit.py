"""Audit logging service.

The current database schema stores audit information in the legacy
``audit_logs`` shape from the initial migration, so this writer maps the
newer event-style API into those persisted columns.
"""

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger("exposurescopex.audit")

# Audit event types (keep in sync with BACKLOG / frontend filter lists)
class AuditEvent:
    # Auth
    LOGIN_SUCCESS = "auth.login.success"
    LOGIN_FAILURE = "auth.login.failure"
    LOGOUT = "auth.logout"
    TOKEN_REFRESH = "auth.token.refresh"
    PASSWORD_CHANGE = "auth.password.change"
    # Users
    USER_CREATE = "user.create"
    USER_UPDATE = "user.update"
    USER_DELETE = "user.delete"
    # Assessments
    ASSESSMENT_CREATE = "assessment.create"
    ASSESSMENT_DELETE = "assessment.delete"
    ASSESSMENT_SCAN_START = "assessment.scan.start"
    SCAN_AUTHORIZATION_CREATE = "scan.authorization.create"
    SCAN_AUTHORIZATION_DELETE = "scan.authorization.delete"
    # ASM
    ASM_TARGET_CREATE = "asm.target.create"
    ASM_TARGET_DELETE = "asm.target.delete"
    ASM_SCAN_START = "asm.scan.start"
    ASM_CLOUD_SOURCE_CREATE = "asm.cloud_source.create"
    ASM_CLOUD_SOURCE_DELETE = "asm.cloud_source.delete"
    # Findings
    FINDING_STATUS_UPDATE = "finding.status.update"
    FINDING_WORKFLOW_UPDATE = "finding.workflow.update"
    FINDING_ACTIVITY_CREATE = "finding.activity.create"
    # API Keys
    API_KEY_CREATE = "api_key.create"
    API_KEY_DELETE = "api_key.delete"
    # Reports
    REPORT_GENERATE = "report.generate"
    REPORT_EXPORT = "report.export"


async def write_audit(
    db: AsyncSession,
    *,
    event: str,
    user_id: Optional[str] = None,
    org_id: Optional[str] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    details: Optional[dict[str, Any]] = None,
    ip_address: Optional[str] = None,
    success: bool = True,
) -> None:
    """Insert one audit log row. Errors are caught and logged, never raised."""
    try:
        now = datetime.now(timezone.utc)
        await db.execute(
            text(
                """
                INSERT INTO audit_logs
                    (id, user_id, action, entity_type, entity_id,
                     old_value, new_value, ip_address, user_agent, created_at, updated_at)
                VALUES
                    (:id, :user_id, :action, :entity_type, :entity_id,
                     CAST(:old_value AS jsonb), CAST(:new_value AS jsonb),
                     :ip_address, :user_agent, :created_at, :updated_at)
                """
            ),
            {
                "id": str(uuid.uuid4()),
                "user_id": user_id,
                "action": event,
                "entity_type": resource_type,
                "entity_id": resource_id,
                "old_value": None,
                "new_value": __import__("json").dumps(
                    {
                        "org_id": org_id,
                        "details": details or {},
                        "success": success,
                    }
                ),
                "ip_address": ip_address,
                "user_agent": None,
                "created_at": now,
                "updated_at": now,
            },
        )
    except Exception as exc:
        logger.warning("Audit write failed: %s", exc)
