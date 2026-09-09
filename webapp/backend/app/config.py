"""Application configuration loaded from environment variables."""

import re
from typing import Optional
from urllib.parse import urlparse

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings loaded from environment variables or .env file."""

    # --- Core ---
    APP_NAME: str = "ExposureScopeX"
    APP_VERSION: str = "2.2.0"
    DEBUG: bool = False
    ENVIRONMENT: str = "development"

    # --- Database ---
    DATABASE_URL: str = "postgresql+asyncpg://exposurescopex:exposurescopex@db:5432/exposurescopex"
    DATABASE_NULL_POOL: bool = False

    # --- Redis ---
    REDIS_URL: str = "redis://redis:6379/0"
    REDIS_PASSWORD: str = "development-only-change-me"

    # --- Security ---
    SECRET_KEY: str = "change-me-in-production-use-openssl-rand-hex-32"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    SESSION_COOKIE_SECURE: bool = False
    SESSION_COOKIE_SAMESITE: str = "strict"
    ALLOW_PUBLIC_REGISTRATION: bool = False
    STALE_SCAN_MINUTES: int = 10
    SCAN_ARTIFACT_RETENTION_DAYS: int = 30
    REPORT_RETENTION_DAYS: int = 90
    DEFAULT_MAX_ACTIVE_SCANS_PER_ORG: int = 2
    DEFAULT_MAX_QUEUED_SCANS_PER_ORG: int = 25
    ENFORCE_WORKER_CAPABILITIES: bool = True
    WORKER_CAPABILITY_TTL_SECONDS: int = 120

    # --- Execution isolation ---
    SCAN_EXECUTOR: str = "process"
    SCANNER_IMAGE_IDENTITY: str = "exposurescopex-worker:local"
    SCAN_JOB_IMAGE: str = "exposurescopex-worker:latest"
    SCAN_JOB_NAMESPACE: str = "exposurescopex"
    SCAN_JOB_SERVICE_ACCOUNT: str = "exposurescopex-scanner"
    SCAN_JOB_SECRET_NAME: str = "exposurescopex-runtime"
    SCAN_JOB_CONFIG_MAP: Optional[str] = None
    SCAN_JOB_RESULTS_PVC: str = "exposurescopex-results"
    SCAN_JOB_ACTIVE_DEADLINE_SECONDS: int = 86400
    SCAN_JOB_ALLOW_NET_RAW: bool = False

    # --- Artifact storage ---
    ARTIFACT_STORAGE_BACKEND: str = "database"
    S3_ENDPOINT_URL: Optional[str] = None
    S3_REGION: str = "us-east-1"
    S3_BUCKET: str = "exposurescopex-artifacts"
    S3_ACCESS_KEY_ID: Optional[str] = None
    S3_SECRET_ACCESS_KEY: Optional[str] = None
    S3_PREFIX: str = "exposurescopex"
    S3_SERVER_SIDE_ENCRYPTION: str = "AES256"

    # --- Monitoring and runtime adapters ---
    METRICS_BEARER_TOKEN: Optional[str] = None
    MOBILE_DYNAMIC_ADAPTER_URL: Optional[str] = None
    MOBILE_DYNAMIC_API_KEY: Optional[str] = None
    KUBERNETES_RUNTIME_ADAPTER_URL: Optional[str] = None
    KUBERNETES_RUNTIME_API_KEY: Optional[str] = None
    RUNTIME_ADAPTER_ALLOWED_HOSTS: str = "host.docker.internal,mobile-lab,kubernetes-runtime"

    # --- CORS ---
    BACKEND_CORS_ORIGINS: list[str] = [
        "http://localhost:3001",
        "http://localhost:8081",
        "http://127.0.0.1:3001",
        "http://127.0.0.1:8081",
    ]

    @field_validator("BACKEND_CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: str | list[str]) -> list[str]:
        if isinstance(v, str) and not v.startswith("["):
            return [origin.strip() for origin in v.split(",")]
        if isinstance(v, list):
            return v
        raise ValueError("BACKEND_CORS_ORIGINS must be a comma-separated string or JSON list")

    @field_validator("SESSION_COOKIE_SAMESITE")
    @classmethod
    def validate_samesite(cls, value: str) -> str:
        normalized = value.lower()
        if normalized not in {"strict", "lax", "none"}:
            raise ValueError("SESSION_COOKIE_SAMESITE must be strict, lax, or none")
        return normalized

    @model_validator(mode="after")
    def validate_production_security(self):
        if self.ENVIRONMENT.lower() != "production":
            return self
        if self.SECRET_KEY == "change-me-in-production-use-openssl-rand-hex-32" or len(self.SECRET_KEY) < 32:
            raise ValueError("Production requires a unique SECRET_KEY of at least 32 characters")
        if not self.SESSION_COOKIE_SECURE:
            raise ValueError("Production requires SESSION_COOKIE_SECURE=true")
        if self.DEBUG:
            raise ValueError("Production cannot run with DEBUG=true")
        if self.REDIS_PASSWORD == "development-only-change-me" or not urlparse(self.REDIS_URL).password:
            raise ValueError("Production requires an authenticated Redis URL and unique REDIS_PASSWORD")
        if self.SEED_DEMO_DATA or self.IMPORT_REAL_DATA:
            raise ValueError("Demo seeding and filesystem import must be disabled in production")
        if self.SESSION_COOKIE_SAMESITE == "none" and not self.SESSION_COOKIE_SECURE:
            raise ValueError("SameSite=None cookies require SESSION_COOKIE_SECURE=true")
        if any(origin == "*" or not origin.startswith("https://") for origin in self.BACKEND_CORS_ORIGINS):
            raise ValueError("Production CORS origins must be explicit HTTPS origins")
        if self.SCAN_EXECUTOR not in {"process", "kubernetes"}:
            raise ValueError("SCAN_EXECUTOR must be process or kubernetes")
        if self.ARTIFACT_STORAGE_BACKEND not in {"database", "s3"}:
            raise ValueError("ARTIFACT_STORAGE_BACKEND must be database or s3")
        if self.ARTIFACT_STORAGE_BACKEND == "s3" and not self.S3_BUCKET:
            raise ValueError("S3 artifact storage requires a bucket")
        if bool(self.S3_ACCESS_KEY_ID) != bool(self.S3_SECRET_ACCESS_KEY):
            raise ValueError("S3 access key ID and secret must be configured together")
        if (
            not self.METRICS_BEARER_TOKEN
            or len(self.METRICS_BEARER_TOKEN) < 32
            or self.METRICS_BEARER_TOKEN == "development-metrics-token-change-me-123456"
        ):
            raise ValueError("Production requires METRICS_BEARER_TOKEN with at least 32 characters")
        adapter_urls = [self.MOBILE_DYNAMIC_ADAPTER_URL, self.KUBERNETES_RUNTIME_ADAPTER_URL]
        if any(url and not url.startswith("https://") for url in adapter_urls):
            raise ValueError("Production runtime adapter URLs must use HTTPS")
        return self

    @field_validator("SCAN_EXECUTOR")
    @classmethod
    def validate_scan_executor(cls, value: str) -> str:
        normalized = value.lower()
        if normalized not in {"process", "kubernetes"}:
            raise ValueError("SCAN_EXECUTOR must be process or kubernetes")
        return normalized

    @field_validator("ARTIFACT_STORAGE_BACKEND")
    @classmethod
    def validate_artifact_backend(cls, value: str) -> str:
        normalized = value.lower()
        if normalized not in {"database", "s3"}:
            raise ValueError("ARTIFACT_STORAGE_BACKEND must be database or s3")
        return normalized

    @field_validator("METRICS_BEARER_TOKEN")
    @classmethod
    def validate_metrics_token(cls, value: str | None) -> str | None:
        if value and not re.fullmatch(r"[A-Za-z0-9._~-]{32,256}", value):
            raise ValueError("METRICS_BEARER_TOKEN must be 32-256 URL-safe characters")
        return value

    # --- Demo Seeding ---
    SEED_DEMO_DATA: bool = False
    IMPORT_REAL_DATA: bool = False
    BOOTSTRAP_ADMIN_PASSWORD: Optional[str] = None

    # --- AI Agent ---
    AGENT_MODEL: str = "claude-opus-4-6"

    # --- External API Keys (all optional) ---
    ANTHROPIC_API_KEY: Optional[str] = None
    SHODAN_API_KEY: Optional[str] = None
    VIRUSTOTAL_API_KEY: Optional[str] = None
    CENSYS_API_ID: Optional[str] = None
    CENSYS_API_SECRET: Optional[str] = None
    HIBP_API_KEY: Optional[str] = None
    GITHUB_TOKEN: Optional[str] = None

    # --- Optional scanner adapters ---
    PROWLER_BIN: str = "prowler"
    SCOUTSUITE_BIN: str = "scout"
    ENABLE_PROWLER_ADAPTER: bool = True
    ENABLE_SCOUTSUITE_ADAPTER: bool = False
    SYFT_BIN: str = "syft"
    GRYPE_BIN: str = "grype"
    ENABLE_SYFT_ADAPTER: bool = True
    ENABLE_GRYPE_ADAPTER: bool = True

    # --- Notification Integrations (all optional) ---
    SLACK_WEBHOOK_URL: Optional[str] = None
    TEAMS_WEBHOOK_URL: Optional[str] = None
    SPLUNK_HEC_URL: Optional[str] = None
    SPLUNK_HEC_TOKEN: Optional[str] = None
    SYSLOG_HOST: Optional[str] = None
    SYSLOG_PORT: Optional[int] = None

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": True,
    }


settings = Settings()
