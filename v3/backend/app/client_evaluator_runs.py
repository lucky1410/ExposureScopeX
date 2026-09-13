"""Contracts for evaluations executed on a customer's laptop or CI worker.

The control plane receives labels, confidence values, provenance and hashes only.
Prompts, model responses, source code and unredacted traces stay in the client
environment that executed the test.
"""

from __future__ import annotations

import base64
import binascii
from collections.abc import Callable, Mapping
from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
import time
from typing import Any, Literal
from urllib.error import URLError
from urllib.request import urlopen
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa
from pydantic import BaseModel, ConfigDict, Field, model_validator

from .config import settings
from .evaluation import (
    AgentTraceEnvelope,
    ClaimGrade,
    ClientRunnerProvenance,
    CostEfficiencyGrade,
    EvaluationDimension,
    EvaluationRequest,
    JudgeAgreementGrade,
    RagGrade,
    ReproducibilityGrade,
    RobustnessGrade,
    SecurityGrade,
    TrajectoryGrade,
)
from .serialization import json_safe


CLIENT_RUNNER_SCHEMA_VERSION = "esx-client-evaluation-result-1.1"
LEGACY_CLIENT_RUNNER_SCHEMA_VERSION = "esx-client-evaluation-result-1.0"
CLIENT_RUNNER_VERSION = "0.1.0"
GITHUB_ACTIONS_ISSUER = "https://token.actions.githubusercontent.com"
_SAFE_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,159}$")


class ClientRunError(RuntimeError):
    def __init__(self, code: str, message: str, *, status_code: int = 422):
        super().__init__(message)
        self.code = code
        self.status_code = status_code


class ClientRunModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


def canonical_json(value: object) -> bytes:
    return json.dumps(
        json_safe(value), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def sha256(value: object) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _base64(value: str, *, label: str) -> bytes:
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, ValueError, binascii.Error) as exc:
        raise ClientRunError("invalid_base64", f"{label} must be base64 encoded") from exc


def decode_public_key(value: str) -> bytes:
    key = _base64(value, label="Ed25519 public key")
    if len(key) != 32:
        raise ClientRunError("invalid_public_key", "Ed25519 public keys must be 32 bytes")
    return key


def public_key_fingerprint(value: str) -> str:
    return hashlib.sha256(decode_public_key(value)).hexdigest()


class ClientRunnerExecution(ClientRunModel):
    adapter_type: Literal["command_json_v1", "command_json_v2"]
    case_count: int = Field(ge=1, le=10_000)
    duration_ms: int = Field(ge=0, le=3_600_000)
    request_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    response_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")


class ClientRunnerSource(ClientRunModel):
    origin: Literal["local", "github_actions", "other_ci"]
    repository: str | None = Field(default=None, max_length=256)
    commit_sha: str | None = Field(default=None, max_length=128)
    workflow_ref: str | None = Field(default=None, max_length=512)
    external_run_id: str | None = Field(default=None, max_length=160)


class ClientRunnerEvaluationInput(ClientRunModel):
    """The score input deliberately excludes case inputs and model outputs."""

    name: str = Field(min_length=1, max_length=160)
    agent_id: str = Field(min_length=1, max_length=100)
    subject_version: str = Field(min_length=1, max_length=100)
    subject_type: Literal["model", "rag", "agent", "multi_agent_system"] = "agent"
    project_key: str = Field(default="default", pattern=r"^[a-z][a-z0-9-]{1,62}$")
    dataset_version: str = Field(min_length=1, max_length=100)
    expected_labels: list[str] = Field(min_length=1, max_length=10_000)
    predicted_labels: list[str] = Field(min_length=1, max_length=10_000)
    confidences: list[float] = Field(min_length=1, max_length=10_000)
    policy_id: str = "esx-ai-evaluator-release-1.0"
    required_dimensions: list[EvaluationDimension] = Field(
        default_factory=lambda: ["classification", "confidence"], min_length=2, max_length=10
    )
    trace_envelope: AgentTraceEnvelope | None = None
    claims: list[ClaimGrade] = Field(default_factory=list, max_length=10_000)
    security: SecurityGrade | None = None
    trajectory: TrajectoryGrade | None = None
    rag: RagGrade | None = None
    robustness: RobustnessGrade | None = None
    judge_agreement: JudgeAgreementGrade | None = None
    reproducibility: ReproducibilityGrade | None = None
    cost_efficiency: CostEfficiencyGrade | None = None

    @model_validator(mode="after")
    def aligned_results(self) -> "ClientRunnerEvaluationInput":
        if len(self.expected_labels) != len(self.predicted_labels) or len(self.expected_labels) != len(self.confidences):
            raise ValueError("expected_labels, predicted_labels and confidences must have equal lengths")
        if any(value < 0 or value > 1 for value in self.confidences):
            raise ValueError("confidences must be between 0 and 1")
        _safe_client_references(self.expected_labels, "expected_labels")
        _safe_client_references(self.predicted_labels, "predicted_labels")
        required = set(self.required_dimensions)
        if len(required) != len(self.required_dimensions):
            raise ValueError("required_dimensions values must be unique")
        if not {"classification", "confidence"}.issubset(required):
            raise ValueError("classification and confidence are mandatory evaluation dimensions")
        supplied = _client_supplied_dimensions(self)
        undeclared = sorted(supplied - required)
        if undeclared:
            raise ValueError(
                "client-runner measurements must be declared as required dimensions: "
                + ", ".join(undeclared)
            )
        missing = sorted((required - {"classification", "confidence"}) - supplied)
        if missing:
            raise ValueError(
                "client-runner package is missing declared measurements: " + ", ".join(missing)
            )
        _validate_client_measurement_references(self)
        return self


class ClientRunnerSignature(ClientRunModel):
    identity_id: UUID
    algorithm: Literal["ed25519"] = "ed25519"
    value: str = Field(min_length=80, max_length=512)


class EvaluatorClientIdentityCreate(ClientRunModel):
    project_key: str = Field(pattern=r"^[a-z][a-z0-9-]{1,62}$")
    name: str = Field(min_length=2, max_length=160)
    public_key: str = Field(min_length=40, max_length=128)

    @model_validator(mode="after")
    def valid_public_key(self) -> "EvaluatorClientIdentityCreate":
        try:
            decode_public_key(self.public_key)
        except ClientRunError as exc:
            raise ValueError(str(exc)) from exc
        return self


class EvaluatorGitHubIntegrationCreate(ClientRunModel):
    project_key: str = Field(pattern=r"^[a-z][a-z0-9-]{1,62}$")
    name: str = Field(min_length=2, max_length=160)
    repository: str = Field(pattern=r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
    workflow_ref: str = Field(min_length=20, max_length=512)

    @model_validator(mode="after")
    def trusted_workflow_path(self) -> "EvaluatorGitHubIntegrationCreate":
        expected_prefix = f"{self.repository}/.github/workflows/".lower()
        if not self.workflow_ref.lower().startswith(expected_prefix) or "@refs/" not in self.workflow_ref:
            raise ValueError("workflow_ref must pin a workflow in the registered repository, for example owner/repo/.github/workflows/evaluate.yml@refs/heads/main")
        return self


class ClientRunnerPackage(ClientRunModel):
    schema_version: Literal[
        LEGACY_CLIENT_RUNNER_SCHEMA_VERSION,
        CLIENT_RUNNER_SCHEMA_VERSION,
    ] = CLIENT_RUNNER_SCHEMA_VERSION
    package_id: UUID
    issued_at: datetime
    runner_version: str = Field(min_length=1, max_length=100)
    execution: ClientRunnerExecution
    source: ClientRunnerSource
    evaluation: ClientRunnerEvaluationInput
    signature: ClientRunnerSignature | None = None

    @model_validator(mode="after")
    def validate_package_age(self) -> "ClientRunnerPackage":
        issued_at = self.issued_at
        if issued_at.tzinfo is None:
            raise ValueError("issued_at must include a timezone")
        now = datetime.now(timezone.utc)
        if issued_at > now + timedelta(minutes=5):
            raise ValueError("issued_at cannot be more than five minutes in the future")
        maximum_age = timedelta(hours=settings().ai_evaluator_client_max_package_age_hours)
        if now - issued_at > maximum_age:
            raise ValueError("evaluation package has exceeded the configured submission age")
        if self.execution.case_count != len(self.evaluation.expected_labels):
            raise ValueError("execution case_count must equal the number of labelled results")
        if self.schema_version == LEGACY_CLIENT_RUNNER_SCHEMA_VERSION:
            if self.execution.adapter_type != "command_json_v1" or set(
                self.evaluation.required_dimensions
            ) != {"classification", "confidence"}:
                raise ValueError(
                    "client-runner result 1.0 supports classification and confidence only"
                )
        return self

    def unsigned_payload(self) -> dict[str, Any]:
        payload = self.model_dump(mode="json", exclude={"signature"}, exclude_unset=True)
        # The client runner signs the RFC 3339 text it emits. Avoid serializer
        # differences such as `Z` versus `+00:00` changing a valid signature.
        payload["issued_at"] = self.issued_at.isoformat()
        return payload

    def package_sha256(self) -> str:
        return sha256(self.unsigned_payload())

    def execution_sha256(self) -> str:
        return sha256(self.execution.model_dump(mode="json"))

    def source_attestation_sha256(self) -> str:
        return sha256(self.source.model_dump(mode="json"))


def verify_ed25519_package(package: ClientRunnerPackage, public_key: str) -> None:
    if package.signature is None:
        raise ClientRunError("signature_required", "A local or CI client-runner package must be signed")
    if package.signature.algorithm != "ed25519":
        raise ClientRunError("signature_algorithm", "Only Ed25519 client-runner signatures are supported")
    signature = _base64(package.signature.value, label="package signature")
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(decode_public_key(public_key)).verify(
            signature, canonical_json(package.unsigned_payload())
        )
    except InvalidSignature as exc:
        raise ClientRunError("signature_invalid", "Client-runner package signature verification failed", status_code=401) from exc


def package_evaluation_request(
    package: ClientRunnerPackage,
    *,
    identity_type: Literal["ed25519", "github_actions_oidc"],
    identity_id: UUID,
    identity_name: str,
    identity_fingerprint: str,
) -> EvaluationRequest:
    provenance = ClientRunnerProvenance(
        identity_type=identity_type,
        identity_id=identity_id,
        identity_name=identity_name,
        identity_fingerprint=identity_fingerprint,
        package_id=package.package_id,
        package_sha256=package.package_sha256(),
        runner_version=package.runner_version,
        execution_sha256=package.execution_sha256(),
        source_attestation_sha256=package.source_attestation_sha256(),
        external_run_id=package.source.external_run_id,
    )
    return EvaluationRequest.model_validate(
        {
            **package.evaluation.model_dump(mode="json"),
            "integration_mode": "client_runner",
            "client_provenance": provenance.model_dump(mode="json"),
        }
    )


def _client_supplied_dimensions(payload: ClientRunnerEvaluationInput) -> set[EvaluationDimension]:
    supplied: set[EvaluationDimension] = set()
    if payload.claims:
        supplied.add("groundedness")
    for dimension, value in (
        ("security", payload.security),
        ("trajectory", payload.trajectory),
        ("rag", payload.rag),
        ("robustness", payload.robustness),
        ("judge_agreement", payload.judge_agreement),
        ("reproducibility", payload.reproducibility),
        ("cost_efficiency", payload.cost_efficiency),
    ):
        if value is not None:
            supplied.add(dimension)  # type: ignore[arg-type]
    return supplied


def _safe_client_reference(value: str, field: str) -> None:
    if not _SAFE_REFERENCE.fullmatch(value):
        raise ValueError(
            f"{field} must be an opaque reference (letters, digits, . _ : / or -; maximum 160 characters)"
        )


def _safe_client_references(values: list[str], field: str) -> None:
    for index, value in enumerate(values):
        _safe_client_reference(value, f"{field}[{index}]")


def _validate_client_measurement_references(payload: ClientRunnerEvaluationInput) -> None:
    """Reject raw artefact content even when the ingestion endpoint is called directly."""
    for claim in payload.claims:
        _safe_client_reference(claim.claim_id, "claims.claim_id")
        _safe_client_references(claim.evidence_ids, "claims.evidence_ids")
    if payload.security is not None:
        for case in payload.security.cases:
            _safe_client_reference(case.case_id, "security.cases.case_id")
            _safe_client_references(case.evidence_ids, "security.cases.evidence_ids")
    if payload.trajectory is not None:
        _safe_client_references(payload.trajectory.required_milestones, "trajectory.required_milestones")
        _safe_client_references(payload.trajectory.observed_milestones, "trajectory.observed_milestones")
        _safe_client_references(payload.trajectory.policy_violations, "trajectory.policy_violations")
        _safe_client_references(payload.trajectory.scope_violations, "trajectory.scope_violations")
        _safe_client_references(payload.trajectory.tool_misuse_events, "trajectory.tool_misuse_events")
    if payload.rag is not None:
        _safe_client_references(payload.rag.relevant_document_ids, "rag.relevant_document_ids")
        _safe_client_references(payload.rag.retrieved_document_ids, "rag.retrieved_document_ids")
        _safe_client_references(payload.rag.cited_document_ids, "rag.cited_document_ids")
        for claim in payload.rag.answer_claims:
            _safe_client_reference(claim.claim_id, "rag.answer_claims.claim_id")
            _safe_client_references(claim.evidence_ids, "rag.answer_claims.evidence_ids")
    if payload.robustness is not None:
        for case in payload.robustness.perturbations:
            _safe_client_reference(case.case_id, "robustness.perturbations.case_id")
    if payload.judge_agreement is not None:
        for decision in payload.judge_agreement.decisions:
            _safe_client_reference(decision.case_id, "judge_agreement.decisions.case_id")
            _safe_client_reference(decision.judge_id, "judge_agreement.decisions.judge_id")
    if payload.reproducibility is not None:
        for decision in payload.reproducibility.decisions:
            _safe_client_reference(decision.case_id, "reproducibility.decisions.case_id")
            _safe_client_reference(decision.run_id, "reproducibility.decisions.run_id")
    if payload.cost_efficiency is not None:
        for observation in payload.cost_efficiency.observations:
            _safe_client_reference(observation.case_id, "cost_efficiency.observations.case_id")
    if payload.trace_envelope is not None:
        trace = payload.trace_envelope
        _safe_client_reference(trace.trace_id, "trace_envelope.trace_id")
        _safe_client_reference(trace.schema_version, "trace_envelope.schema_version")
        _safe_client_reference(trace.producer, "trace_envelope.producer")
        _safe_client_references(trace.agent_ids, "trace_envelope.agent_ids")
        for event in trace.events:
            _safe_client_reference(event.event_id, "trace_envelope.events.event_id")
            _safe_client_reference(event.agent_id, "trace_envelope.events.agent_id")
            if event.tool_name is not None:
                _safe_client_reference(event.tool_name, "trace_envelope.events.tool_name")
            if event.scope_reference is not None:
                _safe_client_reference(event.scope_reference, "trace_envelope.events.scope_reference")
            _safe_client_references(event.evidence_ids, "trace_envelope.events.evidence_ids")


def _b64url_decode(value: str) -> bytes:
    padding_length = (-len(value)) % 4
    try:
        return base64.urlsafe_b64decode((value + "=" * padding_length).encode("ascii"))
    except (UnicodeEncodeError, ValueError) as exc:
        raise ClientRunError("github_oidc_invalid", "GitHub OIDC token is not valid base64url", status_code=401) from exc


def _parse_github_jwt(token: str) -> tuple[dict[str, Any], dict[str, Any], bytes, bytes]:
    parts = token.split(".")
    if len(parts) != 3 or any(not part for part in parts):
        raise ClientRunError("github_oidc_invalid", "GitHub OIDC token must be a signed JWT", status_code=401)
    try:
        header = json.loads(_b64url_decode(parts[0]))
        claims = json.loads(_b64url_decode(parts[1]))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ClientRunError("github_oidc_invalid", "GitHub OIDC token has invalid JSON", status_code=401) from exc
    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise ClientRunError("github_oidc_invalid", "GitHub OIDC token payload is invalid", status_code=401)
    return header, claims, f"{parts[0]}.{parts[1]}".encode("ascii"), _b64url_decode(parts[2])


_jwks_cache: tuple[float, dict[str, Any]] | None = None


def _github_jwks(fetcher: Callable[[str], bytes] | None = None) -> dict[str, Any]:
    global _jwks_cache
    now = time.monotonic()
    if fetcher is None and _jwks_cache is not None and now - _jwks_cache[0] < 300:
        return _jwks_cache[1]
    url = settings().ai_evaluator_github_oidc_jwks_url
    try:
        raw = fetcher(url) if fetcher is not None else urlopen(url, timeout=5).read(1_000_000)
        decoded = json.loads(raw.decode("utf-8"))
    except (URLError, OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ClientRunError("github_oidc_keys_unavailable", "GitHub OIDC signing keys are unavailable", status_code=503) from exc
    if not isinstance(decoded, dict) or not isinstance(decoded.get("keys"), list):
        raise ClientRunError("github_oidc_keys_invalid", "GitHub OIDC signing keys are invalid", status_code=503)
    if fetcher is None:
        _jwks_cache = (now, decoded)
    return decoded


def verify_github_actions_oidc(
    token: str,
    *,
    fetcher: Callable[[str], bytes] | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Verify the short-lived GitHub Actions JWT using GitHub's public JWKS."""
    header, claims, signing_input, signature = _parse_github_jwt(token)
    if header.get("alg") != "RS256" or not isinstance(header.get("kid"), str):
        raise ClientRunError("github_oidc_algorithm", "GitHub OIDC token must use an RS256 signing key", status_code=401)
    key = next((item for item in _github_jwks(fetcher).get("keys", []) if item.get("kid") == header["kid"]), None)
    if not isinstance(key, dict) or key.get("kty") != "RSA":
        raise ClientRunError("github_oidc_key", "GitHub OIDC signing key was not found", status_code=401)
    try:
        modulus = int.from_bytes(_b64url_decode(str(key["n"])), "big")
        exponent = int.from_bytes(_b64url_decode(str(key["e"])), "big")
        public_key = rsa.RSAPublicNumbers(exponent, modulus).public_key()
        public_key.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())
    except (KeyError, ValueError, InvalidSignature) as exc:
        raise ClientRunError("github_oidc_signature", "GitHub OIDC signature verification failed", status_code=401) from exc
    checked_at = now or datetime.now(timezone.utc)
    expected_audience = settings().ai_evaluator_github_oidc_audience
    audience = claims.get("aud")
    audiences = audience if isinstance(audience, list) else [audience]
    if claims.get("iss") != GITHUB_ACTIONS_ISSUER or expected_audience not in audiences:
        raise ClientRunError("github_oidc_claims", "GitHub OIDC issuer or audience is not trusted", status_code=401)
    try:
        expires = datetime.fromtimestamp(int(claims["exp"]), tz=timezone.utc)
        issued = datetime.fromtimestamp(int(claims["iat"]), tz=timezone.utc)
    except (KeyError, TypeError, ValueError, OverflowError) as exc:
        raise ClientRunError("github_oidc_claims", "GitHub OIDC token is missing valid time claims", status_code=401) from exc
    if expires <= checked_at or issued > checked_at + timedelta(minutes=5):
        raise ClientRunError("github_oidc_expired", "GitHub OIDC token is expired or not yet valid", status_code=401)
    return claims


def github_integration_claims_match(claims: Mapping[str, object], integration: Mapping[str, object]) -> None:
    repository = str(claims.get("repository") or "").lower()
    workflow_ref = str(claims.get("workflow_ref") or "")
    subject = str(claims.get("sub") or "")
    expected_repository = str(integration["repository"]).lower()
    expected_workflow = str(integration["workflow_ref"])
    if repository != expected_repository or workflow_ref != expected_workflow:
        raise ClientRunError("github_oidc_untrusted_workflow", "GitHub repository or workflow is not approved for this evaluator project", status_code=403)
    if not subject.lower().startswith(f"repo:{expected_repository}:"):
        raise ClientRunError("github_oidc_subject", "GitHub OIDC subject is not bound to the approved repository", status_code=403)


def github_identity_fingerprint(claims: Mapping[str, object], integration: Mapping[str, object]) -> str:
    return sha256(
        {
            "issuer": claims.get("iss"),
            "repository": integration["repository"],
            "workflow_ref": integration["workflow_ref"],
            "subject": claims.get("sub"),
        }
    )
