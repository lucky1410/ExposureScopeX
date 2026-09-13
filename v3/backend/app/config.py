from functools import lru_cache
from typing import Literal

from pydantic import SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    deployment_mode: Literal["development", "production"] = "development"
    database_url: str = "postgresql://exposurescopex:change-me-before-production@localhost:5432/exposurescopex"
    artifact_root: str = "/data/artifacts"
    runner_poll_seconds: float = 2.0
    request_timeout_seconds: float = 15.0
    session_ttl_hours: int = 12
    secure_cookies: bool = False
    cors_origins: str = "http://localhost:3001,http://127.0.0.1:3001"
    credential_encryption_key: str = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
    scope_validation_key: str = "change-this-scope-validation-key-before-production"
    nuclei_templates_dir: str = "/opt/nuclei-templates"
    benchmark_root: str = "/app/benchmarks"
    report_organization: str = "ExposureScopeX Security"
    report_contact: str = "Security Assessment Team"
    report_contact_email: str = "security@esx.local"
    ai_evaluator_provider: str = "disabled"
    ai_evaluator_model: str = ""
    ai_evaluator_base_url: str = "https://api.openai.com/v1"
    ai_evaluator_api_key: SecretStr = SecretStr("")
    ai_evaluator_timeout_seconds: float = 90.0
    ai_evaluator_allow_internal_data: bool = False
    ai_evaluator_require_independent_approval: bool = False
    ai_evaluator_adapter_timeout_seconds: float = 20.0
    ai_evaluator_adapter_max_cases: int = 100
    ai_evaluator_adapter_max_case_bytes: int = 16_384
    ai_evaluator_adapter_max_request_bytes: int = 524_288
    ai_evaluator_adapter_max_response_bytes: int = 524_288
    ai_evaluator_adapter_allowed_hosts: str = ""
    ai_evaluator_adapter_private_networks: str = ""
    ai_evaluator_client_max_package_age_hours: int = 24
    ai_evaluator_github_oidc_audience: str = "exposurescopex-evaluator"
    ai_evaluator_github_oidc_jwks_url: str = "https://token.actions.githubusercontent.com/.well-known/jwks"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    @model_validator(mode="after")
    def reject_insecure_production_defaults(self) -> "Settings":
        if self.deployment_mode != "production":
            return self
        if not self.secure_cookies:
            raise ValueError("SECURE_COOKIES=true is required in production mode")
        if self.credential_encryption_key == "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=":
            raise ValueError("CREDENTIAL_ENCRYPTION_KEY must not use the development default in production mode")
        if self.scope_validation_key == "change-this-scope-validation-key-before-production":
            raise ValueError("SCOPE_VALIDATION_KEY must not use the development default in production mode")
        if not self.ai_evaluator_require_independent_approval:
            raise ValueError("AI_EVALUATOR_REQUIRE_INDEPENDENT_APPROVAL=true is required in production mode")
        if not self.allowed_cors_origins or any("localhost" in value for value in self.allowed_cors_origins):
            raise ValueError("CORS_ORIGINS must contain only approved production web origins")
        return self

    @property
    def allowed_cors_origins(self) -> list[str]:
        return [value.strip() for value in self.cors_origins.split(",") if value.strip()]


@lru_cache
def settings() -> Settings:
    return Settings()
