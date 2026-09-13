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
        return self


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
