from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field, field_validator, model_validator
from urllib.parse import urlsplit

from .scope_files import normalize_scope, scope_token_is_valid


class ScopeFileValidationRequest(BaseModel):
    filename: str = Field(min_length=5, max_length=255)
    content: str = Field(min_length=2, max_length=512 * 1024)


class AssessmentScope(BaseModel):
    target: str
    authorization_id: str = Field(min_length=1, max_length=160)
    authorization_expires_at: datetime
    allowed_paths: list[str] = Field(min_length=1, max_length=500)
    excluded_paths: list[str] = Field(default_factory=list, max_length=500)
    allowed_ports: list[int] = Field(min_length=1, max_length=200)
    credential_reference: str | None = Field(default=None, max_length=512)
    source_format: Literal["csv", "json"]
    source_sha256: str = Field(min_length=64, max_length=64)
    validation_token: str = Field(min_length=64, max_length=64)

    @model_validator(mode="after")
    def normalized_declaration(self):
        normalize_scope(self.model_dump(mode="json"), self.source_format, self.source_sha256)
        if not scope_token_is_valid(self.model_dump(mode="json")):
            raise ValueError("scope file must be validated by the scope-file endpoint before use")
        return self


class AssessmentCreate(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    target: str = Field(min_length=1, max_length=2048)
    mode: Literal["light", "medium", "aggressive"]
    service_tier: Literal["external_baseline", "authorized_deep"] = "external_baseline"
    authorization_confirmed: bool
    authentication: "WebAuthentication | None" = None
    scope: AssessmentScope | None = None

    @field_validator("target")
    @classmethod
    def valid_target(cls, value: str) -> str:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("target must be an absolute HTTP or HTTPS URL")
        if parsed.username or parsed.password:
            raise ValueError("credentials must not be embedded in the target URL")
        return value.rstrip("/")

    @model_validator(mode="after")
    def authentication_stays_in_scope(self):
        if self.authentication:
            target = urlsplit(self.target)
            login = urlsplit(self.authentication.login_url)
            target_origin = (target.scheme, (target.hostname or "").lower(), target.port or (443 if target.scheme == "https" else 80))
            login_origin = (login.scheme, (login.hostname or "").lower(), login.port or (443 if login.scheme == "https" else 80))
            if target_origin != login_origin:
                raise ValueError("authentication login_url must use the assessment target origin")
        if self.scope and self.scope.target != self.target:
            raise ValueError("scope target must exactly match the assessment target")
        if self.service_tier == "authorized_deep" and self.scope is None:
            raise ValueError("authorized deep assessments require a validated scope file")
        if self.service_tier == "authorized_deep" and self.mode == "light":
            raise ValueError("authorized deep assessments require the medium or aggressive profile")
        return self


class PassiveInventoryRequest(BaseModel):
    """A public-record lookup target. This request never authorizes active assessment work."""

    target: str = Field(min_length=1, max_length=2048)

    @field_validator("target")
    @classmethod
    def valid_target(cls, value: str) -> str:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("target must be an absolute HTTP or HTTPS URL")
        if parsed.username or parsed.password:
            raise ValueError("credentials must not be embedded in the target URL")
        return value.rstrip("/")


class SubdomainAssessmentCreate(BaseModel):
    hostnames: list[str] = Field(min_length=1, max_length=25)
    authorization_confirmed: bool


class AssetDiscoveryRequest(BaseModel):
    """Bound passive discovery to a reviewable number of candidate assets."""

    limit: int = Field(default=100, ge=1, le=250)


class AssessmentAssetReview(BaseModel):
    ownership_status: Literal["approved", "excluded"]
    authorization_confirmed: bool = False
    note: str | None = Field(default=None, max_length=1000)


class AssetAssessmentStart(BaseModel):
    authorization_confirmed: bool


class ExposureAssetReview(BaseModel):
    ownership_status: Literal["verified", "excluded"]
    verification_method: Literal["written_authorization", "dns_attestation", "cloud_connector"]
    note: str | None = Field(default=None, max_length=1000)


class ExposureMonitorCreate(BaseModel):
    assessment_id: UUID
    cadence_hours: int = Field(default=168, ge=24, le=720)


class ExposureMonitorUpdate(BaseModel):
    status: Literal["active", "paused"]


class ExposureFindingLifecycleUpdate(BaseModel):
    lifecycle_status: Literal["open", "accepted_risk", "dismissed", "needs_revalidation"]
    note: str = Field(min_length=3, max_length=1000)


class ValidationCorpusCreate(BaseModel):
    name: str = Field(min_length=2, max_length=160)
    version: str = Field(min_length=1, max_length=100)
    classification: Literal["synthetic", "public", "internal", "restricted"]
    source_reference: str = Field(min_length=1, max_length=512)
    source_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    cases: list["ValidationCorpusCase"] = Field(min_length=1, max_length=10_000)


class ValidationCorpusCase(BaseModel):
    case_key: str = Field(min_length=1, max_length=180)
    expected_outcome: Literal["finding_expected", "no_finding_expected"]
    family: str = Field(min_length=1, max_length=100)
    severity: Literal["critical", "high", "medium", "low", "info"] | None = None
    metadata: dict = Field(default_factory=dict)


class IntegrationCreate(BaseModel):
    name: str = Field(min_length=2, max_length=160)
    integration_type: Literal["webhook", "siem", "cloud_inventory", "dns_attestation"]
    endpoint_url: str | None = Field(default=None, max_length=2048)
    signing_secret: str | None = Field(default=None, max_length=1024)
    event_types: list[Literal["asset.discovered", "asset.changed", "finding.opened", "finding.resolved", "scan.completed", "monitor.blocked"]] = Field(default_factory=list, max_length=20)
    configuration: dict = Field(default_factory=dict)

    @model_validator(mode="after")
    def endpoint_matches_type(self):
        if self.integration_type in {"webhook", "siem"} and not self.endpoint_url:
            raise ValueError("webhook and SIEM integrations require an endpoint URL")
        if self.endpoint_url:
            parsed = urlsplit(self.endpoint_url)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                raise ValueError("endpoint_url must be an absolute HTTP or HTTPS URL")
            if parsed.username or parsed.password or parsed.query or parsed.fragment:
                raise ValueError("endpoint_url cannot contain credentials, a query string, or a fragment")
        if _configuration_contains_secret(self.configuration):
            raise ValueError("connector configuration cannot contain credentials; use the encrypted signing_secret field")
        return self


def _configuration_contains_secret(value: object) -> bool:
    """Reject credential-shaped configuration so it cannot bypass encrypted storage."""
    sensitive_fragments = ("secret", "token", "password", "credential", "private_key", "access_key", "api_key")
    if isinstance(value, dict):
        return any(
            any(fragment in str(key).lower() for fragment in sensitive_fragments)
            or _configuration_contains_secret(nested)
            for key, nested in value.items()
        )
    if isinstance(value, list):
        return any(_configuration_contains_secret(item) for item in value)
    return False


ValidationCorpusCreate.model_rebuild()


class WebAuthentication(BaseModel):
    login_url: str = Field(max_length=2048)
    username: str = Field(min_length=1, max_length=320)
    password: str = Field(min_length=1, max_length=1024)
    username_selector: str = Field(default='input[name="username"]', min_length=1, max_length=500)
    password_selector: str = Field(default='input[type="password"]', min_length=1, max_length=500)
    submit_selector: str = Field(default='button[type="submit"], input[type="submit"]', min_length=1, max_length=500)

    @field_validator("login_url")
    @classmethod
    def valid_login_url(cls, value: str) -> str:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("login_url must be an absolute HTTP or HTTPS URL")
        if parsed.username or parsed.password:
            raise ValueError("credentials must not be embedded in login_url")
        return value


AssessmentCreate.model_rebuild()


class Assessment(BaseModel):
    id: UUID
    name: str
    target: str
    mode: str
    service_tier: str = "external_baseline"
    authorization_confirmed: bool
    status: str
    created_at: datetime


class ScanStarted(BaseModel):
    id: UUID
    assessment_id: UUID
    status: str
    plan_version: str


class ScanDetail(BaseModel):
    id: UUID
    assessment_id: UUID
    status: str
    plan_version: str
    plan: dict
    started_at: datetime | None
    finished_at: datetime | None
    failure_reason: str | None
    stages: list[dict]
    findings: list[dict]
    coverage: list[dict]
    report: dict | None
