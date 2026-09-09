"""Import all models so that SQLAlchemy and Alembic can discover them."""

from app.models.base import TimestampMixin
from app.models.user import Organization, User
from app.models.assessment import Assessment
from app.models.scan import Scan
from app.models.asset import Asset
from app.models.asset_graph import AssetRelation, AssetSnapshot, AttackPath, ExposureEvent
from app.models.dns_record import DnsRecord
from app.models.port import Port
from app.models.technology import Technology
from app.models.tls_certificate import TlsCertificate
from app.models.http_header import HttpHeader
from app.models.vulnerability import Vulnerability
from app.models.finding import Finding, FindingActivity, FindingIdentity, FindingObservation
from app.models.investigation import Investigation, InvestigationFinding, Evidence, Note
from app.models.notification import Notification
from app.models.api_key import ApiKey
from app.models.scan_authorization import ScanAuthorization
from app.models.audit_log import AuditLog
from app.models.resource import Resource, UserFavorite
from app.models.asm import AsmTarget, AsmCloudSource, AsmFinding
from app.models.integration import OrgIntegration
from app.models.mcp_security import McpSecurityRun
from app.models.report import ReportArtifact
from app.models.auth_session import AuthSession
from app.models.scan_runtime import OrganizationExecutionPolicy, OrganizationScanProfile, ScanArtifact, ScanEvent, ScanSchedule, ScanScheduleRun, ScanToolRun, WorkerCapability

__all__ = [
    "TimestampMixin",
    "Organization",
    "User",
    "Assessment",
    "Scan",
    "Asset",
    "AssetRelation",
    "AssetSnapshot",
    "AttackPath",
    "ExposureEvent",
    "DnsRecord",
    "Port",
    "Technology",
    "TlsCertificate",
    "HttpHeader",
    "Vulnerability",
    "Finding",
    "FindingActivity",
    "FindingIdentity",
    "FindingObservation",
    "Investigation",
    "InvestigationFinding",
    "Evidence",
    "Note",
    "Notification",
    "ApiKey",
    "ScanAuthorization",
    "AuditLog",
    "Resource",
    "UserFavorite",
    "AsmTarget",
    "AsmCloudSource",
    "AsmFinding",
    "OrgIntegration",
    "McpSecurityRun",
    "ReportArtifact",
    "AuthSession",
    "OrganizationExecutionPolicy",
    "OrganizationScanProfile",
    "ScanSchedule",
    "ScanScheduleRun",
    "ScanEvent",
    "ScanToolRun",
    "ScanArtifact",
    "WorkerCapability",
]
