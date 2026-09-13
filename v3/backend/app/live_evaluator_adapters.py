from __future__ import annotations

import hashlib
import ipaddress
import json
import socket
import time
from dataclasses import dataclass
from typing import Any, Callable, Literal
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, SecretStr, model_validator

from .config import settings
from .evaluation import EvaluationRequest, EvaluationSubjectType


LIVE_ADAPTER_SCHEMA_VERSION = "esx-live-evaluation-request-1.0"
LIVE_ADAPTER_RESPONSE_SCHEMA_VERSION = "esx-live-evaluation-response-1.0"
LIVE_ADAPTER_TYPE = "http_json_v1"
LIVE_ADAPTER_NETWORK_POLICY_VERSION = "esx-egress-allowlist-1.0"
AdapterStatus = Literal["draft", "approved", "disabled"]


class AdapterModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class EvaluatorLiveAdapterCreate(AdapterModel):
    project_key: str = Field(pattern=r"^[a-z][a-z0-9-]{1,62}$")
    name: str = Field(min_length=2, max_length=160)
    endpoint_url: str = Field(min_length=12, max_length=512)
    api_token: SecretStr = Field(min_length=16, max_length=4096)

    @model_validator(mode="after")
    def has_safe_endpoint(self) -> "EvaluatorLiveAdapterCreate":
        validate_adapter_endpoint_url(self.endpoint_url)
        return self


class LiveAdapterCase(AdapterModel):
    case_id: str = Field(min_length=1, max_length=160)
    input: dict[str, Any]
    expected_label: str = Field(min_length=1, max_length=160)

    @model_validator(mode="after")
    def bounded_input(self) -> "LiveAdapterCase":
        encoded = json.dumps(self.input, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        if len(encoded) > settings().ai_evaluator_adapter_max_case_bytes:
            raise ValueError("live adapter case input exceeds the configured size limit")
        return self


class LiveAdapterEvaluationRequest(AdapterModel):
    name: str = Field(min_length=1, max_length=160)
    adapter_id: UUID
    subject_id: str = Field(min_length=1, max_length=100)
    subject_version: str = Field(min_length=1, max_length=100)
    subject_type: EvaluationSubjectType = "agent"
    project_key: str = Field(default="default", pattern=r"^[a-z][a-z0-9-]{1,62}$")
    dataset_version: str = Field(min_length=1, max_length=100)
    required_dimensions: list[Literal["classification", "confidence"]] = Field(
        default_factory=lambda: ["classification", "confidence"], min_length=2, max_length=2
    )
    cases: list[LiveAdapterCase] = Field(min_length=1)

    @model_validator(mode="after")
    def valid_live_request(self) -> "LiveAdapterEvaluationRequest":
        if len(self.cases) > settings().ai_evaluator_adapter_max_cases:
            raise ValueError("live adapter request exceeds the configured case limit")
        request_bytes = len(json.dumps(
            [{"case_id": item.case_id, "input": item.input} for item in self.cases],
            separators=(",", ":"), ensure_ascii=True,
        ).encode("utf-8"))
        if request_bytes > settings().ai_evaluator_adapter_max_request_bytes:
            raise ValueError("live adapter request exceeds the configured batch size limit")
        case_ids = [item.case_id for item in self.cases]
        if len(case_ids) != len(set(case_ids)):
            raise ValueError("live adapter case_id values must be unique")
        if set(self.required_dimensions) != {"classification", "confidence"}:
            raise ValueError("http_json_v1 supports only classification and confidence release dimensions")
        return self


class LiveAdapterResult(AdapterModel):
    case_id: str = Field(min_length=1, max_length=160)
    predicted_label: str = Field(min_length=1, max_length=160)
    confidence: float = Field(ge=0, le=1)


class LiveAdapterResponse(AdapterModel):
    schema_version: Literal["esx-live-evaluation-response-1.0"]
    results: list[LiveAdapterResult] = Field(min_length=1)


@dataclass(frozen=True)
class AdapterInvocation:
    response: LiveAdapterResponse
    request_sha256: str
    response_sha256: str
    duration_ms: int
    request_id: str


class AdapterInvocationError(RuntimeError):
    def __init__(self, code: str, detail: str, *, retryable: bool = False):
        self.code = code
        self.detail = detail
        self.retryable = retryable
        super().__init__(detail)


def validate_adapter_endpoint_url(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme not in {"https", "http"} or not parsed.hostname:
        raise ValueError("adapter endpoint_url must be an absolute HTTP(S) URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("adapter endpoint_url cannot contain credentials, query parameters, or fragments")
    if parsed.scheme != "https" and settings().deployment_mode == "production":
        raise ValueError("adapter endpoint_url must use HTTPS in production")
    if settings().deployment_mode == "production" and parsed.hostname.lower() not in _allowed_hosts():
        raise ValueError("adapter endpoint host is not present in the deployment egress allowlist")
    if parsed.scheme != "https" and not _is_local_development_host(parsed.hostname):
        raise ValueError("HTTP adapter endpoints are permitted only for local development hosts")
    path = parsed.path or "/"
    if not path.startswith("/") or "//" in path or "/../" in f"/{path.strip('/')}/":
        raise ValueError("adapter endpoint_url has an unsafe path")
    return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


def endpoint_sha256(endpoint_url: str) -> str:
    return hashlib.sha256(validate_adapter_endpoint_url(endpoint_url).encode("utf-8")).hexdigest()


def _is_local_development_host(hostname: str) -> bool:
    return hostname.lower() == "localhost" or hostname.startswith("127.") or hostname == "::1"


def _allowed_hosts() -> set[str]:
    return {
        item.strip().lower()
        for item in settings().ai_evaluator_adapter_allowed_hosts.split(",")
        if item.strip()
    }


def _allowed_private_networks() -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    networks = []
    for item in settings().ai_evaluator_adapter_private_networks.split(","):
        if item.strip():
            networks.append(ipaddress.ip_network(item.strip(), strict=False))
    return networks


def assert_adapter_network_allowed(endpoint_url: str) -> None:
    """Resolve and validate the exact configured destination before every invocation."""
    parsed = urlsplit(validate_adapter_endpoint_url(endpoint_url))
    hostname = parsed.hostname
    assert hostname is not None
    allowed_hosts = _allowed_hosts()
    if settings().deployment_mode == "production" and hostname.lower() not in allowed_hosts:
        raise AdapterInvocationError(
            "egress_host_not_allowlisted",
            "adapter host is not present in the deployment egress allowlist",
        )
    try:
        resolved = socket.getaddrinfo(hostname, parsed.port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM)
    except OSError as exc:
        raise AdapterInvocationError("adapter_dns_unavailable", "adapter host could not be resolved", retryable=True) from exc
    private_networks = _allowed_private_networks()
    for item in resolved:
        address = ipaddress.ip_address(item[4][0])
        if address.is_global:
            continue
        if settings().deployment_mode != "production" and _is_local_development_host(hostname):
            continue
        if any(address in network for network in private_networks):
            continue
        raise AdapterInvocationError(
            "adapter_destination_blocked",
            "adapter destination resolves to a blocked network address",
        )


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *_: object, **__: object):
        raise AdapterInvocationError("adapter_redirect_blocked", "adapter endpoint returned a redirect")


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _post_live_adapter(endpoint_url: str, api_token: str, payload: dict) -> tuple[int, bytes]:
    request = Request(
        endpoint_url,
        data=json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "ExposureScopeX-AI-Evaluator/1.3",
        },
        method="POST",
    )
    try:
        response = build_opener(_NoRedirect()).open(request, timeout=settings().ai_evaluator_adapter_timeout_seconds)
        with response:
            return response.status, response.read(settings().ai_evaluator_adapter_max_response_bytes + 1)
    except HTTPError as exc:
        body = exc.read(settings().ai_evaluator_adapter_max_response_bytes + 1)
        return exc.code, body
    except AdapterInvocationError:
        raise
    except (URLError, TimeoutError, OSError) as exc:
        raise AdapterInvocationError("adapter_unavailable", "adapter endpoint could not be reached", retryable=True) from exc


def invoke_live_adapter(
    endpoint_url: str,
    api_token: str,
    cases: list[LiveAdapterCase],
    *,
    transport: Callable[[str, str, dict], tuple[int, bytes]] = _post_live_adapter,
) -> AdapterInvocation:
    assert_adapter_network_allowed(endpoint_url)
    request_id = str(uuid4())
    body = {
        "schema_version": LIVE_ADAPTER_SCHEMA_VERSION,
        "request_id": request_id,
        "cases": [
            {"case_id": item.case_id, "input": item.input}
            for item in cases
        ],
    }
    request_digest = _canonical_sha256(body)
    started = time.monotonic()
    status_code, response_bytes = transport(endpoint_url, api_token, body)
    duration_ms = round((time.monotonic() - started) * 1_000)
    if len(response_bytes) > settings().ai_evaluator_adapter_max_response_bytes:
        raise AdapterInvocationError("adapter_response_too_large", "adapter response exceeded the configured size limit")
    if status_code < 200 or status_code >= 300:
        raise AdapterInvocationError("adapter_http_error", f"adapter endpoint returned HTTP {status_code}", retryable=status_code >= 500)
    try:
        decoded = json.loads(response_bytes.decode("utf-8"))
        response = LiveAdapterResponse.model_validate(decoded)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise AdapterInvocationError("adapter_invalid_response", "adapter response did not match http_json_v1 contract") from exc
    expected_ids = {item.case_id for item in cases}
    actual_ids = [item.case_id for item in response.results]
    if set(actual_ids) != expected_ids or len(actual_ids) != len(set(actual_ids)):
        raise AdapterInvocationError("adapter_case_mismatch", "adapter response must contain exactly one result for every submitted case")
    return AdapterInvocation(
        response=response,
        request_sha256=request_digest,
        response_sha256=_canonical_sha256(decoded),
        duration_ms=duration_ms,
        request_id=request_id,
    )


def adapter_evaluation_payload(
    request: LiveAdapterEvaluationRequest,
    invocation: AdapterInvocation,
    *,
    adapter_name: str,
    adapter_url_sha256: str,
) -> EvaluationRequest:
    results = {item.case_id: item for item in invocation.response.results}
    return EvaluationRequest.model_validate(
        {
            "name": request.name,
            "agent_id": request.subject_id,
            "subject_version": request.subject_version,
            "subject_type": request.subject_type,
            "integration_mode": "live_adapter",
            "project_key": request.project_key,
            "dataset_version": request.dataset_version,
            "expected_labels": [item.expected_label for item in request.cases],
            "predicted_labels": [results[item.case_id].predicted_label for item in request.cases],
            "confidences": [results[item.case_id].confidence for item in request.cases],
            "required_dimensions": request.required_dimensions,
            "adapter_provenance": {
                "adapter_id": request.adapter_id,
                "adapter_name": adapter_name,
                "adapter_type": LIVE_ADAPTER_TYPE,
                "endpoint_sha256": adapter_url_sha256,
                "request_sha256": invocation.request_sha256,
                "response_sha256": invocation.response_sha256,
                "request_id": invocation.request_id,
                "case_count": len(request.cases),
                "duration_ms": invocation.duration_ms,
                "network_policy_version": LIVE_ADAPTER_NETWORK_POLICY_VERSION,
            },
        }
    )
