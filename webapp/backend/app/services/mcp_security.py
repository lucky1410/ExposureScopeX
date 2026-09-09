"""Non-destructive MCP protocol inventory and security analysis."""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import os
import re
import socket
import time
import unicodedata
import uuid
from dataclasses import dataclass, field
from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx

LEGACY_PROTOCOL_VERSION = "2025-11-25"
MODERN_PROTOCOL_VERSION = "2026-07-28"
MAX_EVIDENCE_LENGTH = 100_000
SEVERITY_SCORE = {"CRITICAL": 95, "HIGH": 75, "MEDIUM": 50, "LOW": 25, "INFO": 5}
POISONING_PATTERNS = re.compile(
    r"ignore (?:all |the )?(?:previous|prior|system)|system prompt|do not (?:tell|reveal)|"
    r"secretly|exfiltrat|override (?:instructions|policy)|disable (?:security|safety)",
    re.IGNORECASE,
)
DANGEROUS_PATTERNS = re.compile(
    r"(?:^|[_\-])(exec|shell|command|terminal|delete|remove|drop|write|upload|send|email|"
    r"publish|deploy|admin|sudo|eval)(?:$|[_\-])",
    re.IGNORECASE,
)
READ_PATTERNS = re.compile(r"(?:^|[_\-])(read|get|list|search|fetch|download|query)(?:$|[_\-])", re.I)
EGRESS_PATTERNS = re.compile(r"(?:^|[_\-])(send|email|upload|post|publish|webhook|request)(?:$|[_\-])", re.I)
EXEC_PATTERNS = re.compile(r"(?:^|[_\-])(exec|shell|command|terminal|run|eval)(?:$|[_\-])", re.I)
PATH_LIKE_PATTERNS = re.compile(r"(?:path|file|dir|directory|repo|repository|branch|cwd|root)", re.I)
NETWORK_TARGET_PATTERNS = re.compile(r"(?:url|uri|endpoint|host|domain|address|target|callback|webhook)", re.I)

_MCP_TEST_IDS = """
MCP-PROTO-001 MCP-PROTO-002 MCP-PROTO-003 MCP-PROTO-004 MCP-PROTO-005 MCP-PROTO-006
MCP-AUTH-001 MCP-AUTH-002 MCP-AUTH-003 MCP-AUTH-004 MCP-AUTH-005 MCP-AUTH-006
MCP-STATE-001 MCP-STATE-002 MCP-STATE-003 MCP-STATE-004 MCP-STATE-005
MCP-MRTR-001 MCP-MRTR-002 MCP-MRTR-003 MCP-MRTR-004 MCP-MRTR-005
MCP-TASK-001 MCP-TASK-002 MCP-TASK-003 MCP-TASK-004
MCP-CACHE-001 MCP-CACHE-002 MCP-CACHE-003 MCP-CACHE-004
MCP-AI-001 MCP-AI-002 MCP-AI-003 MCP-AI-004 MCP-AI-005 MCP-AI-006 MCP-AI-007
MCP-SINK-001 MCP-SINK-002 MCP-SINK-003 MCP-SINK-004 MCP-SINK-005
MCP-SSRF-001 MCP-SSRF-002 MCP-SSRF-003 MCP-SSRF-004
MCP-OAUTH-001 MCP-OAUTH-002 MCP-OAUTH-003 MCP-OAUTH-004
MCP-DATA-001 MCP-DATA-002 MCP-DATA-003
MCP-CHAIN-001 MCP-CHAIN-002 MCP-CHAIN-003
MCP-APP-001 MCP-APP-002 MCP-APP-003
MCP-LOCAL-001 MCP-LOCAL-002 MCP-LOCAL-003 MCP-LOCAL-004
MCP-DOS-001 MCP-DOS-002 MCP-DOS-003
MCP-TELEM-001 MCP-TELEM-002
MCP-SUPPLY-001 MCP-SUPPLY-002 MCP-SUPPLY-003
MCP-DRIFT-001 MCP-DRIFT-002
"""
MCP_TEST_CATALOG = tuple(_MCP_TEST_IDS.split())

_MCP_TEST_TITLES = """
MCP-PROTO-001|Protocol/version downgrade
MCP-PROTO-002|Header/body method desynchronization
MCP-PROTO-003|Duplicate HTTP security headers
MCP-PROTO-004|Duplicate JSON fields / parser differential
MCP-PROTO-005|Unicode normalization / confusable identifiers
MCP-PROTO-006|Encoding and path canonicalization differential
MCP-AUTH-001|Missing authentication
MCP-AUTH-002|Token audience/resource mismatch
MCP-AUTH-003|Issuer validation failure
MCP-AUTH-004|Scope/privilege mismatch
MCP-AUTH-005|Hidden-tool direct invocation / allowlist bypass
MCP-AUTH-006|Cross-principal operation isolation
MCP-STATE-001|Cross-instance state leakage
MCP-STATE-002|Shared transport/context contamination
MCP-STATE-003|Request-state replay
MCP-STATE-004|Authorization change between rounds
MCP-STATE-005|Race conditions on identity/state transitions
MCP-MRTR-001|Request-state principal binding
MCP-MRTR-002|Tool/resource substitution between MRTR rounds
MCP-MRTR-003|Input-response substitution / type confusion
MCP-MRTR-004|Infinite/recursive MRTR loop
MCP-MRTR-005|Oversized requestState / input amplification
MCP-TASK-001|Task IDOR / ownership bypass
MCP-TASK-002|Task enumeration
MCP-TASK-003|Task cancel/update race
MCP-TASK-004|Task result after authorization loss
MCP-CACHE-001|Cross-principal cache leakage
MCP-CACHE-002|Cache poisoning across authorization state
MCP-CACHE-003|Stale-privilege reuse
MCP-CACHE-004|Pagination cursor cross-user reuse
MCP-AI-001|Tool-description poisoning
MCP-AI-002|Resource/result indirect prompt injection
MCP-AI-003|Split-instruction cross-channel attack
MCP-AI-004|Server-instructions trust-boundary abuse
MCP-AI-005|Tool shadowing / name collision
MCP-AI-006|Rug-pull / tool-definition drift
MCP-AI-007|Annotation/metadata deception
MCP-SINK-001|Command/argument injection
MCP-SINK-002|Leading-dash option injection
MCP-SINK-003|Path traversal and filesystem escape
MCP-SINK-004|SQL/query injection
MCP-SINK-005|Template / expression injection
MCP-SSRF-001|Basic SSRF / internal target reachability
MCP-SSRF-002|Private-address normalization bypass
MCP-SSRF-003|Redirect-based SSRF
MCP-SSRF-004|DNS rebinding / validation-to-connect race
MCP-OAUTH-001|Protected-resource metadata SSRF
MCP-OAUTH-002|Authorization-server issuer mix-up
MCP-OAUTH-003|Resource/client binding failure
MCP-OAUTH-004|PKCE/state/redirect validation failure
MCP-DATA-001|Sensitive resource exposure
MCP-DATA-002|Resource-template traversal / parameter injection
MCP-DATA-003|Prompt metadata abuse
MCP-CHAIN-001|Read to egress/execution capability chain
MCP-CHAIN-002|Cross-server capability chaining
MCP-CHAIN-003|Confused deputy through privileged MCP server
MCP-APP-001|postMessage origin/source validation
MCP-APP-002|CSP / external resource trust
MCP-APP-003|UI capability escalation / approval mismatch
MCP-LOCAL-001|MCP configuration command injection
MCP-LOCAL-002|PATH hijacking / executable resolution
MCP-LOCAL-003|Environment/credential inheritance
MCP-LOCAL-004|stdio protocol contamination
MCP-DOS-001|Request/body/schema amplification
MCP-DOS-002|SSE/stream buffering exhaustion
MCP-DOS-003|Task/MRTR flooding
MCP-TELEM-001|Sensitive data in logs
MCP-TELEM-002|Trace-context spoofing / tenant confusion
MCP-SUPPLY-001|Dependency/version vulnerability correlation
MCP-SUPPLY-002|Publisher/server identity spoofing
MCP-SUPPLY-003|OCI/package/config metadata execution
MCP-DRIFT-001|Capability drift
MCP-DRIFT-002|Endpoint/OAuth policy drift
"""
MCP_TEST_TITLES = dict(line.split("|", 1) for line in _MCP_TEST_TITLES.splitlines() if line)


@dataclass(slots=True)
class McpExecutionProfile:
    """Optional inputs that unlock identity, task, canary, and deep tests."""

    secondary_bearer_token: str | None = None
    audience_mismatch_token: str | None = None
    issuer_mismatch_token: str | None = None
    approved_tool_name: str | None = None
    approved_tool_arguments: dict[str, Any] = field(default_factory=dict)
    approved_resource_uri: str | None = None
    approved_prompt_name: str | None = None
    test_task_id: str | None = None
    canary_url: str | None = None
    cross_server_endpoint: str | None = None
    cross_server_bearer_token: str | None = None
    local_config_text: str | None = None
    max_concurrency: int = 4
    enable_deep_tests: bool = False
    allow_mutation_tests: bool = False

    def public_summary(self) -> dict[str, Any]:
        return {
            "secondary_identity": bool(self.secondary_bearer_token),
            "audience_token": bool(self.audience_mismatch_token),
            "issuer_token": bool(self.issuer_mismatch_token),
            "approved_tool": bool(self.approved_tool_name),
            "approved_tool_name": self.approved_tool_name,
            "approved_tool_arguments": self.approved_tool_arguments,
            "approved_resource": bool(self.approved_resource_uri),
            "approved_resource_uri": self.approved_resource_uri,
            "approved_prompt": bool(self.approved_prompt_name),
            "approved_prompt_name": self.approved_prompt_name,
            "test_task": bool(self.test_task_id),
            "test_task_id": self.test_task_id,
            "oob_canary": bool(self.canary_url),
            "canary_url": self.canary_url,
            "cross_server": bool(self.cross_server_endpoint),
            "cross_server_endpoint": self.cross_server_endpoint,
            "local_config": bool(self.local_config_text),
            "local_config_text": self.local_config_text,
            "max_concurrency": self.max_concurrency,
            "deep_tests": self.enable_deep_tests,
            "mutation_tests": self.allow_mutation_tests,
        }

    def secrets(self) -> list[str]:
        return [
            value
            for value in (
                self.secondary_bearer_token,
                self.audience_mismatch_token,
                self.issuer_mismatch_token,
                self.cross_server_bearer_token,
            )
            if value
        ]

EXCHANGE_TEST_IDS = {
    "server/discover": "MCP-PROTO-001",
    "protocol-version-downgrade": "MCP-PROTO-001",
    "header-method-mismatch": "MCP-PROTO-002",
    "duplicate-json-fields": "MCP-PROTO-004",
    "unicode-confusable-tool": "MCP-PROTO-005",
    "encoded-resource-traversal": "MCP-PROTO-006",
    "unauthenticated-initialize": "MCP-AUTH-001",
    "unauthenticated-tools-list": "MCP-AUTH-001",
    "session-replay-with-invalid-bearer": "MCP-STATE-003",
    "unknown-task-get": "MCP-TASK-002",
    "unknown-task-cancel": "MCP-TASK-003",
    "unknown-task-update": "MCP-TASK-003",
    "oauth-protected-resource": "MCP-OAUTH-001",
    "oauth-protected-resource-path": "MCP-OAUTH-001",
    "unknown-resource-read": "MCP-DATA-001",
    "unknown-prompt-get": "MCP-DATA-003",
    "untrusted-origin": "MCP-APP-001",
    "cors-preflight": "MCP-APP-001",
    "cross-site-text-plain": "MCP-APP-003",
    "bounded-amplification": "MCP-DOS-001",
    "trace-context-spoof": "MCP-TELEM-002",
    "duplicate-security-headers": "MCP-PROTO-003",
    "audience-mismatch-token": "MCP-AUTH-002",
    "issuer-mismatch-token": "MCP-AUTH-003",
    "secondary-tools-list": "MCP-AUTH-004",
    "hidden-tool-direct-call": "MCP-AUTH-005",
    "cross-principal-session": "MCP-AUTH-006",
    "state-race": "MCP-STATE-005",
    "cursor-cross-principal": "MCP-CACHE-004",
    "task-primary-get": "MCP-TASK-001",
    "task-secondary-get": "MCP-TASK-001",
    "task-invalid-token-get": "MCP-TASK-004",
    "task-race-update": "MCP-TASK-003",
    "task-race-cancel": "MCP-TASK-003",
    "stream-buffering": "MCP-DOS-002",
    "task-flood-bounded": "MCP-DOS-003",
    "mrtr-principal-binding": "MCP-MRTR-001",
    "mrtr-tool-substitution": "MCP-MRTR-002",
    "mrtr-type-confusion": "MCP-MRTR-003",
    "mrtr-replay": "MCP-MRTR-004",
    "mrtr-oversized-state": "MCP-MRTR-005",
    "sink-command-canary": "MCP-SINK-001",
    "sink-option-canary": "MCP-SINK-002",
    "sink-path-canary": "MCP-SINK-003",
    "sink-query-canary": "MCP-SINK-004",
    "sink-template-canary": "MCP-SINK-005",
    "ssrf-canary": "MCP-SSRF-001",
    "ssrf-private-normalization": "MCP-SSRF-002",
    "ssrf-redirect-canary": "MCP-SSRF-003",
    "ssrf-rebinding-canary": "MCP-SSRF-004",
}


class McpAuditError(ValueError):
    """Raised for an invalid or unreachable MCP audit target."""


class McpAuditCancelled(Exception):
    """Raised when a cooperative MCP run cancellation is requested."""

    def __init__(self, message: str, exchanges: list[dict[str, Any]] | None = None):
        super().__init__(message)
        self.exchanges = exchanges or []


def _finding(
    severity: str,
    title: str,
    category: str,
    evidence: str,
    remediation: str,
    exchange_id: str | None = None,
    test_id: str | None = None,
) -> dict[str, Any]:
    return {
        "id": str(uuid.uuid4()),
        "severity": severity,
        "title": title,
        "category": category,
        "evidence": evidence[:4000],
        "remediation": remediation,
        "exchange_id": exchange_id,
        "test_id": test_id,
    }


def _coverage_findings(coverage: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings = []
    for item in coverage:
        if item["status"] != "failed":
            continue
        test_id = item["test_id"]
        family = test_id.split("-", 2)[1]
        severity = "CRITICAL" if family in {"SINK", "SSRF", "CHAIN"} else "HIGH"
        findings.append(_finding(
            severity,
            f"{test_id}: {item['title']}",
            f"MCP {family}",
            item.get("reason") or "Canonical MCP security test failed.",
            "Inspect the linked exchange, enforce the tested trust boundary, and retain this test as a regression control.",
            item.get("checks", [None])[0] if item.get("checks") else None,
            test_id,
        ))
    return findings


def _safe_headers(headers: httpx.Headers | dict[str, str]) -> dict[str, str]:
    allowed = {
        "accept", "allow", "access-control-allow-origin", "access-control-allow-credentials",
        "access-control-allow-methods", "access-control-allow-headers", "access-control-max-age",
        "content-type", "mcp-session-id", "mcp-protocol-version", "server", "www-authenticate",
        "x-content-type-options", "x-frame-options", "content-security-policy", "location",
        "vary", "cache-control", "etag",
    }
    return {key.lower(): value for key, value in headers.items() if key.lower() in allowed}


def _safe_header_values(headers: httpx.Headers) -> dict[str, list[str]]:
    """Preserve duplicate security headers for parser-differential review."""
    tracked = {
        "access-control-allow-origin", "cache-control", "content-security-policy",
        "location", "mcp-session-id", "mcp-protocol-version", "vary", "www-authenticate",
        "x-content-type-options", "x-frame-options",
    }
    return {name: headers.get_list(name) for name in tracked if headers.get_list(name)}


def _decode_body(response: httpx.Response) -> Any:
    text = response.text[:MAX_EVIDENCE_LENGTH]
    content_type = response.headers.get("content-type", "")
    if "text/event-stream" in content_type or text.lstrip().startswith("event:"):
        payloads = []
        for line in text.splitlines():
            if line.startswith("data:"):
                try:
                    payloads.append(json.loads(line[5:].strip()))
                except json.JSONDecodeError:
                    continue
        return payloads[-1] if payloads else {"raw": text}
    try:
        return json.loads(text)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return {"raw": text}


def _safe_request_body(body: Any) -> Any:
    if body is None:
        return None
    encoded = body if isinstance(body, str) else json.dumps(body, default=str)
    if len(encoded) <= 8000:
        return body
    return {
        "truncated": True,
        "length": len(encoded),
        "sha256": hashlib.sha256(encoded.encode("utf-8")).hexdigest(),
        "preview": encoded[:1000],
    }


SENSITIVE_KEY_PATTERN = re.compile(
    r"authorization|password|passwd|secret|token|api.?key|credential|cookie|session",
    re.IGNORECASE,
)


def _redact_sensitive(value: Any, secrets: list[str] | None = None) -> Any:
    """Redact credentials recursively, including values echoed by a target."""
    secret_values = [item for item in (secrets or []) if len(item) >= 4]
    if isinstance(value, dict):
        return {
            key: "[REDACTED]"
            if SENSITIVE_KEY_PATTERN.search(str(key)) and isinstance(item, (str, bytes))
            else _redact_sensitive(item, secret_values)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_sensitive(item, secret_values) for item in value]
    if isinstance(value, tuple):
        return tuple(_redact_sensitive(item, secret_values) for item in value)
    if isinstance(value, str):
        redacted = value
        for secret in secret_values:
            redacted = redacted.replace(secret, "[REDACTED]")
        redacted = re.sub(
            r"(?i)(bearer\s+)[A-Za-z0-9._~+\-/]+=*",
            r"\1[REDACTED]",
            redacted,
        )
        return redacted
    return value


def _result_payload(body: Any) -> dict[str, Any]:
    if isinstance(body, dict):
        return body.get("result") if isinstance(body.get("result"), dict) else body
    return {}


def _request_rejected(body: Any) -> bool:
    if not isinstance(body, dict):
        return False
    if isinstance(body.get("error"), dict):
        return True
    result = body.get("result")
    return isinstance(result, dict) and result.get("isError") is True


def _error_code(body: Any) -> int | None:
    if not isinstance(body, dict):
        return None
    error = body.get("error")
    if not isinstance(error, dict):
        return None
    try:
        return int(error.get("code"))
    except (TypeError, ValueError):
        return None


def _client_meta() -> dict[str, Any]:
    return {
        "io.modelcontextprotocol/protocolVersion": MODERN_PROTOCOL_VERSION,
        "io.modelcontextprotocol/clientInfo": {"name": "ExposureScopeX MCP Security", "version": "2.3"},
        "io.modelcontextprotocol/clientCapabilities": {
            "extensions": {"io.modelcontextprotocol/tasks": {}},
        },
    }


def _modern_body(request_id: int | str, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = {"jsonrpc": "2.0", "id": request_id, "method": method}
    payload["params"] = {"_meta": _client_meta(), **(params or {})}
    return payload


def _extract_schema_refs(value: Any, refs: list[str]) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if key == "$ref" and isinstance(item, str):
                refs.append(item)
            else:
                _extract_schema_refs(item, refs)
    elif isinstance(value, list):
        for item in value:
            _extract_schema_refs(item, refs)


def _server_info_from_discover(result: dict[str, Any]) -> dict[str, Any]:
    meta = result.get("_meta")
    if isinstance(meta, dict):
        info = meta.get("io.modelcontextprotocol/serverInfo")
        if isinstance(info, dict):
            return info
    info = result.get("serverInfo")
    return info if isinstance(info, dict) else {}


async def validate_endpoint(endpoint: str, allow_private: bool) -> str:
    parsed = urlsplit(endpoint.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise McpAuditError("Endpoint must be an absolute HTTP or HTTPS URL")
    if parsed.username or parsed.password or parsed.fragment:
        raise McpAuditError("Endpoint credentials and fragments are not allowed")
    localhost_target = parsed.hostname in {"localhost", "127.0.0.1", "::1"}
    localhost_alias = os.getenv("MCP_LOCALHOST_ALIAS", "").strip()
    if localhost_target and not allow_private:
        raise McpAuditError("Local endpoints require explicit Private endpoint approval")
    if localhost_target and localhost_alias:
        alias_netloc = localhost_alias
        if parsed.port:
            alias_netloc = f"{alias_netloc}:{parsed.port}"
        parsed = parsed._replace(netloc=alias_netloc)
    try:
        addresses = await asyncio.to_thread(
            socket.getaddrinfo, parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80)
        )
    except socket.gaierror as exc:
        raise McpAuditError(f"Endpoint DNS resolution failed: {exc}") from exc
    resolved = {item[4][0].split("%", 1)[0] for item in addresses}
    restricted = []
    for value in resolved:
        address = ipaddress.ip_address(value)
        if not address.is_global:
            restricted.append(value)
    if restricted and not allow_private:
        raise McpAuditError("Private, loopback, or non-global endpoints require explicit private-target approval")
    netloc = parsed.hostname
    if parsed.port:
        netloc = f"{netloc}:{parsed.port}"
    return urlunsplit((parsed.scheme, netloc, parsed.path or "/mcp", parsed.query, ""))


class McpProbe:
    def __init__(
        self,
        endpoint: str,
        bearer_token: str | None,
        *,
        secrets: list[str] | None = None,
        should_cancel: Callable[[], bool] | None = None,
        on_exchange: Callable[[str, int], None] | None = None,
        prior_exchanges: list[dict[str, Any]] | None = None,
    ):
        self.endpoint = endpoint
        self.session_id: str | None = None
        self.exchanges: list[dict[str, Any]] = []
        self.secrets = [value for value in [bearer_token, *(secrets or [])] if value]
        self.should_cancel = should_cancel
        self.on_exchange = on_exchange
        self.prior_exchanges = prior_exchanges
        self.headers = {
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
            "MCP-Protocol-Version": LEGACY_PROTOCOL_VERSION,
            "User-Agent": "ExposureScopeX-MCP-Audit/2.3",
        }
        if bearer_token:
            self.headers["Authorization"] = f"Bearer {bearer_token}"

    async def exchange(
        self,
        client: httpx.AsyncClient,
        name: str,
        method: str = "POST",
        body: Any = None,
        *,
        headers: dict[str, str] | None = None,
        url: str | None = None,
        omit_authorization: bool = False,
        omit_session: bool = False,
        protocol_version: str | None = None,
        mcp_method: str | None = None,
        mcp_name: str | None = None,
    ) -> tuple[httpx.Response | None, Any]:
        if self.should_cancel and self.should_cancel():
            raise McpAuditCancelled(
                "MCP assessment cancelled",
                [*(self.prior_exchanges or []), *self.exchanges],
            )
        exchange_id = str(uuid.uuid4())
        request_headers = {**self.headers, **(headers or {})}
        if omit_authorization:
            request_headers.pop("Authorization", None)
        if protocol_version:
            request_headers["MCP-Protocol-Version"] = protocol_version
        if mcp_method:
            request_headers["Mcp-Method"] = mcp_method
        else:
            request_headers.pop("Mcp-Method", None)
        if mcp_name:
            request_headers["Mcp-Name"] = mcp_name
        else:
            request_headers.pop("Mcp-Name", None)
        if self.session_id and not omit_session:
            request_headers["Mcp-Session-Id"] = self.session_id
        elif omit_session:
            request_headers.pop("Mcp-Session-Id", None)
        started = time.monotonic()
        response: httpx.Response | None = None
        error: str | None = None
        decoded: Any = None
        try:
            kwargs: dict[str, Any] = {"headers": request_headers}
            if body is not None:
                kwargs["content"] = body if isinstance(body, str) else json.dumps(body)
            response = await client.request(method, url or self.endpoint, **kwargs)
            self.session_id = response.headers.get("mcp-session-id") or self.session_id
            decoded = _decode_body(response)
        except httpx.HTTPError as exc:
            error = f"{type(exc).__name__}: {exc}"
        duration_ms = round((time.monotonic() - started) * 1000)
        self.exchanges.append({
            "id": exchange_id,
            "name": name,
            "request": {
                "method": method,
                "url": url or self.endpoint,
                "headers": {key: "[REDACTED]" if key.lower() == "authorization" else value for key, value in request_headers.items()},
                "body": _safe_request_body(_redact_sensitive(body, self.secrets)),
            },
            "response": {
                "status": response.status_code if response else None,
                "headers": _safe_headers(response.headers) if response else {},
                "header_values": _safe_header_values(response.headers) if response else {},
                "body": _redact_sensitive(decoded, self.secrets),
                "error": error,
            },
            "duration_ms": duration_ms,
        })
        if self.on_exchange:
            self.on_exchange(name, len(self.exchanges))
        return response, decoded


def analyze_inventory(endpoint: str, inventory: dict[str, Any], exchanges: list[dict]) -> list[dict]:
    findings: list[dict] = []
    parsed = urlsplit(endpoint)
    by_name = {item["name"]: item for item in exchanges}
    negotiation = inventory.get("negotiation") if isinstance(inventory.get("negotiation"), dict) else {}
    selected_protocol = str(negotiation.get("selected_protocol") or inventory.get("protocol_version") or "")

    if parsed.scheme != "https" and parsed.hostname not in {"localhost", "127.0.0.1", "::1", "host.docker.internal"}:
        findings.append(_finding("HIGH", "MCP transport is not encrypted", "Transport", endpoint,
            "Serve remote MCP endpoints exclusively over HTTPS with a valid certificate."))

    discover = by_name.get("server/discover")
    if discover and discover["response"].get("status") in {301, 302, 307, 308}:
        findings.append(_finding("MEDIUM", "MCP endpoint redirects protocol traffic", "Transport",
            pretty_evidence(discover["response"].get("headers")),
            "Avoid redirecting MCP RPC traffic; terminate TLS and route requests directly at the MCP endpoint.", discover["id"]))
    discover_result = _result_payload(discover["response"].get("body")) if discover else {}
    if discover and discover["response"].get("status") in {200, 201} and not discover_result:
        findings.append(_finding("MEDIUM", "server/discover returned an unusable success response", "Protocol",
            pretty_evidence(discover["response"].get("body")),
            "Return a valid JSON-RPC result or a method-not-found error so clients can safely negotiate protocol eras.", discover["id"]))

    initialize = by_name.get("initialize")
    if initialize:
        headers = initialize["response"].get("headers", {})
        init_status = initialize["response"].get("status")
        init_body = initialize["response"].get("body")
        if init_status and init_status >= 400 and init_status not in {401, 403}:
            findings.append(_finding("MEDIUM", "MCP initialization failed", "Protocol",
                f"Initialize returned HTTP {init_status}.",
                "Return a valid JSON-RPC initialize response and a supported protocol version.", initialize["id"]))
        if isinstance(init_body, dict) and init_body.get("error"):
            findings.append(_finding("MEDIUM", "MCP initialize returned a JSON-RPC error", "Protocol",
                json.dumps(init_body.get("error"), default=str),
                "Review protocol-version negotiation and return standards-compliant JSON-RPC errors.", initialize["id"]))
        if initialize["response"].get("status") in {200, 201} and not inventory.get("authenticated"):
            findings.append(_finding("MEDIUM", "MCP capabilities are available without authentication", "Authorization",
                "The unauthenticated initialize request succeeded.",
                "Require OAuth 2.1 for non-public capabilities and enforce least-privilege scopes.", initialize["id"]))
        if headers.get("access-control-allow-origin") == "*" and headers.get("access-control-allow-credentials", "").lower() == "true":
            findings.append(_finding("HIGH", "Unsafe credentialed wildcard CORS policy", "Origin Security",
                "Access-Control-Allow-Origin: * with credentials enabled.",
                "Allow only trusted origins and never combine wildcard origins with credentials.", initialize["id"]))

    origin = by_name.get("untrusted-origin")
    if origin and origin["response"].get("status") in {200, 201}:
        acao = origin["response"].get("headers", {}).get("access-control-allow-origin")
        if acao in {"*", "https://attacker.invalid"}:
            findings.append(_finding("HIGH", "Untrusted browser origin accepted", "Origin Security",
                f"The server answered an attacker origin with Access-Control-Allow-Origin: {acao}.",
                "Validate Origin on HTTP transports and allow only explicitly trusted MCP clients.", origin["id"]))

    unauthenticated = by_name.get("unauthenticated-initialize")
    if unauthenticated and unauthenticated["response"].get("status") in {200, 201, 202}:
        findings.append(_finding("HIGH", "Bearer authentication can be bypassed", "Authorization",
            "A fresh initialize request without the supplied bearer token succeeded.",
            "Require authentication before creating sessions or returning any MCP capabilities.", unauthenticated["id"]))
    elif unauthenticated and unauthenticated["response"].get("status") == 401:
        auth_header = unauthenticated["response"].get("headers", {}).get("www-authenticate", "")
        if "resource_metadata=" not in auth_header and not inventory.get("oauth_metadata_published"):
            findings.append(_finding("MEDIUM", "401 response omits MCP authorization discovery hints", "Authorization",
                auth_header or "WWW-Authenticate header missing",
                "Return Bearer challenge metadata or publish RFC 9728 protected-resource metadata so clients can discover the correct authorization server.", unauthenticated["id"]))

    unauthenticated_tools = by_name.get("unauthenticated-tools-list")
    if unauthenticated_tools and unauthenticated_tools["response"].get("status") in {200, 201, 202} and not _request_rejected(unauthenticated_tools["response"].get("body")):
        findings.append(_finding("HIGH", "Bearer authentication can be bypassed for capability enumeration", "Authorization",
            "A fresh tools/list request without the supplied bearer token succeeded.",
            "Require authorization for tool inventory if the endpoint is not intentionally public, and bind any cached result to the caller context.", unauthenticated_tools["id"]))

    preflight = by_name.get("cors-preflight")
    if preflight and preflight["response"].get("status") in {200, 204}:
        preflight_headers = preflight["response"].get("headers", {})
        if preflight_headers.get("access-control-allow-origin") in {"*", "https://attacker.invalid"}:
            findings.append(_finding("HIGH", "MCP CORS preflight trusts an untrusted origin", "Origin Security",
                json.dumps(preflight_headers), "Restrict CORS to explicitly trusted MCP web clients.", preflight["id"]))

    text_plain = by_name.get("cross-site-text-plain")
    if text_plain and text_plain["response"].get("status") in {200, 201, 202} and not _request_rejected(text_plain["response"].get("body")):
        findings.append(_finding("HIGH", "Simple cross-site POST reached the MCP handler", "Origin Security",
            "A cross-site text/plain POST received a non-error response.",
            "Reject non-JSON content types on MCP POSTs and validate Origin/Host before dispatch.", text_plain["id"]))

    malformed = by_name.get("malformed-json")
    if malformed:
        malformed_status = malformed["response"].get("status")
        if malformed_status and malformed_status >= 500:
            findings.append(_finding("MEDIUM", "Malformed JSON causes a server error", "Error Handling",
                f"Malformed JSON returned HTTP {malformed_status}.",
                "Reject invalid JSON with a bounded 4xx JSON-RPC error without exposing internals.", malformed["id"]))
        elif malformed_status and malformed_status < 300:
            findings.append(_finding("MEDIUM", "Malformed JSON was accepted", "Input Validation",
                f"The invalid request returned HTTP {malformed_status}.",
                "Strictly parse JSON-RPC envelopes and reject malformed input before dispatch.", malformed["id"]))

    unsupported = by_name.get("unsupported-method")
    unsupported_body = unsupported["response"].get("body") if unsupported else None
    if unsupported and not (isinstance(unsupported_body, dict) and isinstance(unsupported_body.get("error"), dict)):
        findings.append(_finding("MEDIUM", "Unknown JSON-RPC methods are not rejected correctly", "Protocol",
            pretty_evidence(unsupported_body), "Return JSON-RPC method-not-found error -32601.", unsupported["id"]))

    invalid_version = by_name.get("invalid-jsonrpc-version")
    invalid_body = invalid_version["response"].get("body") if invalid_version else None
    if invalid_version and not (isinstance(invalid_body, dict) and isinstance(invalid_body.get("error"), dict)):
        findings.append(_finding("MEDIUM", "Invalid JSON-RPC version was not rejected", "Protocol",
            pretty_evidence(invalid_body), "Validate the JSON-RPC envelope and reject versions other than 2.0.", invalid_version["id"]))

    method_mismatch = by_name.get("header-method-mismatch")
    method_mismatch_body = method_mismatch["response"].get("body") if method_mismatch else None
    if method_mismatch and method_mismatch["response"].get("status", 0) < 400 and not _request_rejected(method_mismatch_body):
        findings.append(_finding("HIGH", "Header/body routing mismatch was accepted", "Protocol",
            pretty_evidence(method_mismatch_body),
            "Reject requests when `Mcp-Method` and the JSON-RPC `method` disagree to prevent gateway/application confusion.", method_mismatch["id"]))

    for probe_name, title, remediation in (
        ("unknown-tool-call", "Unknown tool names are accepted", "Reject unregistered tool names before dispatch."),
        ("unknown-resource-read", "Unknown resource URIs are accepted", "Validate and allowlist resource URIs before reading."),
        ("unknown-prompt-get", "Unknown prompt names are accepted", "Reject prompt names that are not registered for this authorization context."),
        ("unknown-task-get", "Unknown task IDs are accepted", "Reject unknown task identifiers and scope all task access to the initiating principal."),
        ("unknown-task-cancel", "Unknown task cancellations are accepted", "Reject unknown task IDs and verify ownership before accepting cancellation."),
        ("unknown-task-update", "Unknown task updates are accepted", "Reject updates for unknown tasks or unsatisfied input requests."),
    ):
        probe_exchange = by_name.get(probe_name)
        probe_body = probe_exchange["response"].get("body") if probe_exchange else None
        if probe_exchange and probe_exchange["response"].get("status", 0) < 400 and not _request_rejected(probe_body):
            findings.append(_finding("HIGH", title, "Dispatch Validation", pretty_evidence(probe_body), remediation,
                probe_exchange["id"]))

    tasks_list = by_name.get("tasks/list")
    tasks_result = _result_payload(tasks_list["response"].get("body")) if tasks_list else {}
    listed_tasks = tasks_result.get("tasks") if isinstance(tasks_result.get("tasks"), list) else []
    if listed_tasks:
        severity = "HIGH" if not inventory.get("authenticated") else "MEDIUM"
        findings.append(_finding(severity, "Task inventory is enumerable", "Task Isolation",
            pretty_evidence(listed_tasks[:5]),
            "Ensure task enumeration is disabled or scoped to the authenticated principal and tenant.", tasks_list["id"]))

    if by_name.get("session-replay-with-invalid-bearer") and by_name["session-replay-with-invalid-bearer"]["response"].get("status") in {200, 201, 202}:
        findings.append(_finding("MEDIUM", "Session traffic succeeded with an invalid bearer token", "Session Binding",
            "A session-bound request completed even when the bearer token was replaced with an invalid value.",
            "Bind session-bound requests to the authenticated principal or use the stateless 2026 protocol for horizontally scaled deployments.", by_name["session-replay-with-invalid-bearer"]["id"]))

    tools = inventory.get("tools", [])
    names: dict[str, int] = {}
    read_tools: list[str] = []
    egress_tools: list[str] = []
    exec_tools: list[str] = []
    for tool in tools:
        name = str(tool.get("name") or "unnamed")
        description = str(tool.get("description") or "")
        names[name] = names.get(name, 0) + 1
        combined = f"{name} {description}"
        if POISONING_PATTERNS.search(combined):
            findings.append(_finding("CRITICAL", f"Potential tool-description poisoning: {name}", "Tool Poisoning",
                description or name, "Remove embedded behavioral instructions from metadata and pin reviewed tool definitions."))
        if DANGEROUS_PATTERNS.search(name):
            annotations = tool.get("annotations") or {}
            severity = "HIGH" if annotations.get("readOnlyHint") is not True else "MEDIUM"
            findings.append(_finding(severity, f"High-impact MCP capability exposed: {name}", "Excessive Capability",
                description or name, "Require explicit approval, least-privilege scopes, sandboxing, and audit logging for this tool."))
            if not any(key in annotations for key in ("readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint")):
                findings.append(_finding("LOW", f"High-impact tool lacks safety annotations: {name}", "Tool Metadata",
                    description or name, "Add tool annotations so clients can surface better approval and containment UX for risky actions."))
        schema = tool.get("inputSchema") or {}
        refs: list[str] = []
        _extract_schema_refs(schema, refs)
        external_refs = [ref for ref in refs if ref.startswith(("http://", "https://", "file://"))]
        if external_refs:
            findings.append(_finding("MEDIUM", f"External schema references exposed by {name}", "Tool Schema",
                ", ".join(external_refs[:6]),
                "Avoid remote or filesystem `$ref` targets in tool schemas; inline or vend reviewed schemas instead."))
        properties = schema.get("properties") if isinstance(schema, dict) else None
        if isinstance(properties, dict):
            unconstrained = [key for key, value in properties.items() if isinstance(value, dict) and value.get("type") == "string" and not any(limit in value for limit in ("enum", "pattern", "maxLength", "format"))]
            if unconstrained:
                findings.append(_finding("LOW", f"Unbounded string inputs on {name}", "Input Validation",
                    ", ".join(unconstrained), "Constrain strings with formats, patterns, enums, and maximum lengths; validate again in handlers."))
            sensitive = [key for key in properties if re.search(r"password|passwd|secret|token|api.?key|credential|command|shell", key, re.I)]
            if sensitive:
                findings.append(_finding("MEDIUM", f"Sensitive or high-impact inputs accepted by {name}", "Tool Schema",
                    ", ".join(sensitive), "Use secret references instead of raw credentials and require approval for command-like inputs."))
            path_like = [key for key in unconstrained if PATH_LIKE_PATTERNS.search(key)]
            if path_like:
                findings.append(_finding("MEDIUM", f"Path-like inputs are weakly constrained on {name}", "Path Safety",
                    ", ".join(path_like),
                    "Constrain path and repository parameters, canonicalize them server-side, and enforce an allowlisted root."))
            network_targets = [key for key in unconstrained if NETWORK_TARGET_PATTERNS.search(key)]
            if network_targets and (READ_PATTERNS.search(name) or EGRESS_PATTERNS.search(name) or "http" in description.lower()):
                findings.append(_finding("MEDIUM", f"Potential SSRF-style inputs exposed by {name}", "Network Boundary",
                    ", ".join(network_targets),
                    "Validate destination schemes, hosts, and ports; block link-local, loopback, and metadata-address targets."))
        if isinstance(schema, dict) and schema.get("additionalProperties") is True:
            findings.append(_finding("LOW", f"Arbitrary additional inputs accepted by {name}", "Tool Schema",
                "inputSchema.additionalProperties is true", "Reject unknown properties and validate against a closed schema."))
        if READ_PATTERNS.search(name): read_tools.append(name)
        if EGRESS_PATTERNS.search(name): egress_tools.append(name)
        if EXEC_PATTERNS.search(name): exec_tools.append(name)

    duplicates = sorted(name for name, count in names.items() if count > 1)
    if duplicates:
        findings.append(_finding("HIGH", "Duplicate MCP tool names can enable shadowing", "Tool Integrity",
            ", ".join(duplicates), "Reject duplicate names and pin a hash of approved tool definitions to detect drift."))
    if read_tools and (egress_tools or exec_tools):
        findings.append(_finding("CRITICAL", "Capability chain can read data and exfiltrate or execute", "Capability Chain",
            f"Read: {', '.join(read_tools[:8])}; Egress/execute: {', '.join((egress_tools + exec_tools)[:8])}",
            "Separate capabilities by trust zone, require per-step approval, restrict egress, and enforce data-flow policy."))

    for resource in inventory.get("resources", []):
        uri = str(resource.get("uri") or "")
        if uri.startswith("file://") or re.search(r"(?:\.\./|/etc/|/proc/|[A-Za-z]:\\)", uri):
            findings.append(_finding("HIGH", "Sensitive filesystem resource exposed", "Resource Boundary", uri,
                "Expose allowlisted virtual resources rather than arbitrary host filesystem paths."))

    metadata_items = [
        ("resource", item) for item in inventory.get("resources", [])
    ] + [
        ("resource template", item) for item in inventory.get("resource_templates", [])
    ] + [
        ("prompt", item) for item in inventory.get("prompts", [])
    ]
    if inventory.get("instructions"):
        metadata_items.append(("server instruction", {"description": inventory["instructions"]}))
    for item_type, item in metadata_items:
        content = " ".join(str(item.get(key) or "") for key in ("name", "title", "description", "uri", "uriTemplate"))
        if POISONING_PATTERNS.search(content):
            findings.append(_finding("CRITICAL", f"Potential {item_type} metadata poisoning", "Metadata Poisoning",
                content, "Remove behavioral instructions from server metadata and require review before agent exposure."))

    if selected_protocol == MODERN_PROTOCOL_VERSION:
        for surface, cache in (inventory.get("cache_hints") or {}).items():
            if not isinstance(cache, dict):
                continue
            if cache.get("ttlMs") is None or cache.get("cacheScope") is None:
                findings.append(_finding("LOW", f"Modern cache hints are missing on {surface}", "Caching",
                    pretty_evidence(cache),
                    "Return `ttlMs` and `cacheScope` for cacheable list/discovery responses in 2026-era deployments."))
            elif inventory.get("authenticated") and cache.get("cacheScope") == "public":
                findings.append(_finding("HIGH", f"Authenticated {surface} response is publicly cacheable", "Caching",
                    pretty_evidence(cache),
                    "Do not mark authenticated or user-specific results as `cacheScope: public`; scope them privately or disable caching."))

    oauth = by_name.get("oauth-protected-resource")
    oauth_path = by_name.get("oauth-protected-resource-path")
    if oauth and oauth["response"].get("status") == 404 and (
        not oauth_path or oauth_path["response"].get("status") == 404
    ) and inventory.get("authenticated"):
        findings.append(_finding("MEDIUM", "OAuth protected-resource metadata is missing", "Authorization",
            "The RFC 9728 discovery endpoint returned 404.",
            "Publish protected-resource metadata and bind access tokens to the MCP server audience.", oauth["id"]))
    return findings


def pretty_evidence(value: Any) -> str:
    return json.dumps(value, default=str) if not isinstance(value, str) else value


def build_protocol_checks(exchanges: list[dict[str, Any]]) -> list[dict[str, Any]]:
    checks = []
    for exchange in exchanges:
        name = exchange["name"]
        response = exchange["response"]
        status_code = response.get("status")
        body = response.get("body")
        error = body.get("error") if isinstance(body, dict) else None
        status = "passed"
        detail = f"HTTP {status_code}" if status_code else response.get("error") or "No response"
        if not status_code:
            status = "failed"
        elif name == "server/discover":
            result = _result_payload(body)
            if isinstance(error, dict) and error.get("code") == -32601:
                status = "informational"
                detail = "Legacy server; discover not supported"
            elif status_code >= 400 or not result:
                status = "failed"
                detail = "Discover did not return a usable capability result"
            else:
                status = "passed"
                detail = "Modern capability discovery succeeded"
        elif name == "unauthenticated-initialize":
            status = "passed" if status_code in {401, 403} else "failed"
            detail = "Authentication enforced" if status == "passed" else "Request succeeded without bearer token"
        elif name == "unauthenticated-tools-list":
            status = "passed" if status_code in {401, 403} or _request_rejected(body) else "failed"
            detail = "Authentication enforced" if status == "passed" else "tools/list succeeded without bearer token"
        elif name == "session-replay-with-invalid-bearer":
            status = "review" if status_code in {200, 201, 202} else "passed"
            detail = "Session accepted invalid bearer token; verify principal binding" if status == "review" else "Invalid bearer token was rejected"
        elif name in {"malformed-json", "invalid-jsonrpc-version"}:
            status = "passed" if status_code < 500 and (status_code >= 400 or error) else "failed"
            detail = "Invalid envelope rejected safely" if status == "passed" else f"Unsafe handling (HTTP {status_code})"
        elif name == "unsupported-method":
            status = "passed" if isinstance(error, dict) and error.get("code") == -32601 else "failed"
            detail = "Method-not-found returned" if status == "passed" else "Expected JSON-RPC -32601"
        elif name == "header-method-mismatch":
            status = "passed" if status_code >= 400 or _request_rejected(body) else "failed"
            detail = "Header/body mismatch rejected safely" if status == "passed" else "Gateway/app accepted mismatched routing metadata"
        elif name in {"protocol-version-downgrade", "duplicate-json-fields", "unicode-confusable-tool", "encoded-resource-traversal"}:
            status = "passed" if status_code >= 400 or _request_rejected(body) else "review"
            detail = "Differential probe was rejected" if status == "passed" else "Probe was accepted; compare gateway and server interpretation"
        elif name == "cross-site-text-plain":
            status = "passed" if status_code >= 400 or _request_rejected(body) else "failed"
            detail = "Cross-site text/plain request was blocked" if status == "passed" else "Simple cross-site POST reached the handler"
        elif name in {"unknown-tool-call", "unknown-resource-read", "unknown-prompt-get"}:
            status = "passed" if status_code >= 400 or _request_rejected(body) else "failed"
            detail = "Unknown identifier rejected safely" if status == "passed" else "Unknown identifier was accepted"
        elif name in {"unknown-task-get", "unknown-task-cancel", "unknown-task-update"}:
            status = "passed" if status_code >= 400 or _request_rejected(body) else "failed"
            detail = "Unknown task identifier rejected safely" if status == "passed" else "Unknown task identifier was accepted"
        elif name == "tasks/list":
            tasks = _result_payload(body).get("tasks", []) if isinstance(_result_payload(body), dict) else []
            if status_code >= 400 or isinstance(error, dict):
                status = "informational"
                detail = error.get("message", detail) if isinstance(error, dict) else detail
            elif isinstance(tasks, list) and tasks:
                status = "review"
                detail = f"{len(tasks)} task(s) were enumerable; verify ownership scoping"
            else:
                status = "passed"
                detail = "No tasks were enumerable"
        elif name in {"oauth-protected-resource", "oauth-protected-resource-path"}:
            status = "passed" if status_code < 300 else "informational"
            detail = "Metadata published" if status == "passed" else f"Discovery returned HTTP {status_code}"
        elif name in {"untrusted-origin", "cors-preflight"}:
            acao = response.get("headers", {}).get("access-control-allow-origin")
            status = "failed" if acao in {"*", "https://attacker.invalid"} else "passed"
            detail = f"Access-Control-Allow-Origin: {acao}" if acao else f"No permissive CORS header (HTTP {status_code})"
        elif name == "bounded-amplification":
            response_size = len(json.dumps(body, default=str)) if body is not None else 0
            status = "review" if response_size > 262144 or status_code >= 500 else "passed"
            detail = f"Bounded 64 KiB request produced approximately {response_size} response bytes"
        elif name == "trace-context-spoof":
            status = "failed" if status_code >= 500 else "passed"
            detail = "Malformed trace context did not destabilize the endpoint" if status == "passed" else "Malformed trace context caused a server error"
        elif status_code >= 500:
            status = "failed"
        elif status_code >= 400 or error:
            status = "informational"
            detail = error.get("message", detail) if isinstance(error, dict) else detail
        checks.append({
            "id": exchange["id"], "name": name, "status": status, "detail": detail,
            "http_status": status_code, "duration_ms": exchange["duration_ms"],
            "test_id": EXCHANGE_TEST_IDS.get(name),
        })
    return checks


def _test_result(
    test_id: str,
    status: str,
    mode: str,
    reason: str,
    *,
    checks: list[str] | None = None,
    evidence: Any = None,
) -> dict[str, Any]:
    return {
        "test_id": test_id,
        "title": MCP_TEST_TITLES[test_id],
        "status": status,
        "mode": mode,
        "checks": checks or [],
        "reason": reason,
        "evidence": _redact_sensitive(evidence),
    }


STATIC_ANALYSIS_TESTS = {
    "MCP-PROTO-003",
    "MCP-AI-001", "MCP-AI-002", "MCP-AI-003", "MCP-AI-004", "MCP-AI-005", "MCP-AI-006", "MCP-AI-007",
    "MCP-SINK-001", "MCP-SINK-002", "MCP-SINK-003", "MCP-SINK-004", "MCP-SINK-005",
    "MCP-SSRF-001", "MCP-SSRF-002",
    "MCP-OAUTH-002", "MCP-OAUTH-003", "MCP-OAUTH-004",
    "MCP-DATA-001", "MCP-DATA-002", "MCP-DATA-003",
    "MCP-CHAIN-001", "MCP-CHAIN-003",
    "MCP-APP-002",
    "MCP-TELEM-001",
    "MCP-SUPPLY-001", "MCP-SUPPLY-002", "MCP-SUPPLY-003",
    "MCP-DRIFT-001", "MCP-DRIFT-002",
    "MCP-CACHE-002",
}

TEST_PREREQUISITES = {
    "MCP-AUTH-002": "Provide an access token issued for a different audience/resource.",
    "MCP-AUTH-003": "Provide an access token issued by an untrusted test issuer.",
    "MCP-AUTH-004": "Provide a lower-privilege secondary principal token.",
    "MCP-AUTH-005": "Provide an approved hidden or privileged tool name and enable deep tests.",
    "MCP-AUTH-006": "Provide a secondary principal token.",
    "MCP-STATE-001": "Provide a secondary principal token to test instance/session isolation.",
    "MCP-STATE-002": "Provide a secondary principal token to test transport-context isolation.",
    "MCP-STATE-004": "Provide a secondary principal and an MRTR-capable disposable tool.",
    "MCP-STATE-005": "Provide a secondary principal for bounded identity-transition concurrency.",
    "MCP-MRTR-001": "Provide an approved disposable tool that returns requestState and a secondary principal.",
    "MCP-MRTR-002": "Provide an approved disposable tool that returns requestState.",
    "MCP-MRTR-003": "Provide an approved disposable tool that returns requestState.",
    "MCP-MRTR-004": "Provide an approved disposable tool that returns requestState.",
    "MCP-MRTR-005": "Provide an approved disposable tool that returns requestState.",
    "MCP-TASK-001": "Provide a disposable task ID and a secondary principal token.",
    "MCP-TASK-004": "Provide a disposable task ID.",
    "MCP-CACHE-001": "Provide a secondary principal token.",
    "MCP-CACHE-003": "Provide a secondary principal token.",
    "MCP-CACHE-004": "Provide a secondary principal token and a paginated list response.",
    "MCP-SSRF-003": "Provide an approved canary URL and disposable URL-capable tool.",
    "MCP-SSRF-004": "Provide an approved rebinding canary URL and disposable URL-capable tool.",
    "MCP-CHAIN-002": "Provide a second authorized MCP endpoint for capability-chain comparison.",
    "MCP-LOCAL-001": "Provide the local MCP configuration text for offline analysis.",
    "MCP-LOCAL-002": "Provide the local MCP configuration text for offline analysis.",
    "MCP-LOCAL-003": "Provide the local MCP configuration text for offline analysis.",
    "MCP-LOCAL-004": "Provide the local MCP configuration text for offline analysis.",
    "MCP-DOS-002": "Enable protocol tests on an endpoint that supports streaming responses.",
    "MCP-DOS-003": "Enable protocol tests on an endpoint that supports Tasks or MRTR.",
}


def _static_test_results(
    inventory: dict[str, Any],
    exchanges: list[dict[str, Any]],
    previous_inventory: dict[str, Any] | None,
) -> dict[str, dict[str, Any]]:
    """Evaluate passive tests against normalized inventory and redacted evidence."""
    results = {
        test_id: _test_result(
            test_id,
            "review",
            "static_inventory_analysis",
            "The test surface was inventoried; confirm the heuristic result against the target's implementation and policy.",
        )
        for test_id in STATIC_ANALYSIS_TESTS
    }

    tools = [item for item in inventory.get("tools", []) if isinstance(item, dict)]
    resources = [item for item in inventory.get("resources", []) if isinstance(item, dict)]
    templates = [item for item in inventory.get("resource_templates", []) if isinstance(item, dict)]
    prompts = [item for item in inventory.get("prompts", []) if isinstance(item, dict)]
    instructions = str(inventory.get("instructions") or "")
    metadata_items = [*tools, *resources, *templates, *prompts]

    poisoned_items = [
        str(item.get("name") or item.get("uri") or item.get("uriTemplate") or "unnamed")
        for item in metadata_items
        if POISONING_PATTERNS.search(json.dumps(item, default=str))
    ]
    results["MCP-AI-001"] = _test_result(
        "MCP-AI-001", "failed" if poisoned_items else "executed", "metadata_poisoning_analysis",
        "Instruction-poisoning indicators were found in advertised metadata." if poisoned_items else "No known instruction-poisoning indicators were found in advertised metadata.",
        evidence=poisoned_items,
    )
    results["MCP-AI-004"] = _test_result(
        "MCP-AI-004", "failed" if POISONING_PATTERNS.search(instructions) else "executed", "server_instruction_analysis",
        "Server instructions contain trust-boundary override indicators." if POISONING_PATTERNS.search(instructions) else "Server instructions contain no known trust-boundary override indicators.",
        evidence=instructions[:2000],
    )

    normalized_names: dict[str, list[str]] = {}
    for tool in tools:
        name = str(tool.get("name") or "")
        canonical = unicodedata.normalize("NFKC", name).casefold()
        normalized_names.setdefault(canonical, []).append(name)
    collisions = [names for names in normalized_names.values() if len(names) > 1]
    results["MCP-AI-005"] = _test_result(
        "MCP-AI-005", "failed" if collisions else "executed", "normalized_name_analysis",
        "Tool names collide after Unicode normalization and case folding." if collisions else "Advertised tool names remain unique after Unicode normalization and case folding.",
        evidence=collisions,
    )

    deceptive_annotations = []
    for tool in tools:
        annotations = tool.get("annotations") if isinstance(tool.get("annotations"), dict) else {}
        name = str(tool.get("name") or "")
        if DANGEROUS_PATTERNS.search(name) and annotations.get("readOnlyHint") is True:
            deceptive_annotations.append({"tool": name, "annotation": "readOnlyHint=true"})
        if annotations.get("destructiveHint") is False and re.search(r"delete|remove|drop|write|deploy", name, re.I):
            deceptive_annotations.append({"tool": name, "annotation": "destructiveHint=false"})
    results["MCP-AI-007"] = _test_result(
        "MCP-AI-007", "failed" if deceptive_annotations else "executed", "annotation_consistency_analysis",
        "Tool annotations conflict with capability names." if deceptive_annotations else "No obvious annotation/name contradictions were found.",
        evidence=deceptive_annotations,
    )

    runtime_content_available = bool(inventory.get("approved_resource_analysis") or inventory.get("approved_prompt_analysis"))
    results["MCP-AI-002"] = _test_result(
        "MCP-AI-002", "executed" if runtime_content_available else "blocked", "runtime_content_analysis",
        "Approved runtime resource/prompt content was analyzed." if runtime_content_available else "Provide an approved resource URI or prompt name and enable deep tests to inspect returned content.",
    )
    suspicious_channels = sum(bool(POISONING_PATTERNS.search(json.dumps(items, default=str))) for items in (tools, resources, prompts))
    results["MCP-AI-003"] = _test_result(
        "MCP-AI-003", "review" if suspicious_channels > 1 else "executed", "cross_channel_metadata_analysis",
        "Multiple metadata channels contain instruction-like content and require composition review." if suspicious_channels > 1 else "No split instruction pattern was detected across advertised metadata channels.",
        evidence={"suspicious_channels": suspicious_channels},
    )

    sink_patterns = {
        "MCP-SINK-001": re.compile(r"cmd|command|argument|script", re.I),
        "MCP-SINK-002": re.compile(r"arg|option|flag", re.I),
        "MCP-SINK-003": PATH_LIKE_PATTERNS,
        "MCP-SINK-004": re.compile(r"query|sql|filter|where", re.I),
        "MCP-SINK-005": re.compile(r"template|expression|format", re.I),
    }
    for test_id, pattern in sink_patterns.items():
        candidates = []
        for tool in tools:
            schema = tool.get("inputSchema") if isinstance(tool.get("inputSchema"), dict) else {}
            properties = schema.get("properties") if isinstance(schema.get("properties"), dict) else {}
            matching = [name for name in properties if pattern.search(str(name))]
            if matching:
                candidates.append({"tool": tool.get("name"), "parameters": matching})
        results[test_id] = _test_result(
            test_id, "review" if candidates else "not_applicable", "schema_sink_analysis",
            "Potential sink parameters require an approved disposable-tool canary test." if candidates else "No matching sink parameter was advertised.",
            evidence=candidates,
        )

    network_inputs = []
    for tool in tools:
        schema = tool.get("inputSchema") if isinstance(tool.get("inputSchema"), dict) else {}
        properties = schema.get("properties") if isinstance(schema.get("properties"), dict) else {}
        matching = [name for name in properties if NETWORK_TARGET_PATTERNS.search(str(name))]
        if matching:
            network_inputs.append({"tool": tool.get("name"), "parameters": matching})
    for test_id in ("MCP-SSRF-001", "MCP-SSRF-002"):
        results[test_id] = _test_result(
            test_id, "review" if network_inputs else "not_applicable", "network_input_schema_analysis",
            "URL/host inputs require an approved OOB or private-address canary test." if network_inputs else "No URL or host input was advertised.",
            evidence=network_inputs,
        )

    sensitive_resources = [
        str(item.get("uri") or "") for item in resources
        if re.search(r"(?i)(?:^file:|/etc/|\.ssh|credential|secret|token|password|keychain)", str(item.get("uri") or ""))
    ]
    results["MCP-DATA-001"] = _test_result(
        "MCP-DATA-001", "failed" if sensitive_resources else "executed", "resource_inventory_analysis",
        "Sensitive resource locations are advertised." if sensitive_resources else "No obviously sensitive resource location was advertised.",
        evidence=sensitive_resources,
    )
    risky_templates = [
        str(item.get("uriTemplate") or "") for item in templates
        if re.search(r"(?i)(path|file|\.\.|\{[^}]*(?:path|file)[^}]*\})", str(item.get("uriTemplate") or ""))
    ]
    results["MCP-DATA-002"] = _test_result(
        "MCP-DATA-002", "review" if risky_templates else "executed", "resource_template_analysis",
        "Path-capable resource templates require traversal/canonicalization review." if risky_templates else "No obviously path-capable resource template was advertised.",
        evidence=risky_templates,
    )
    poisoned_prompts = [str(item.get("name") or "unnamed") for item in prompts if POISONING_PATTERNS.search(json.dumps(item, default=str))]
    results["MCP-DATA-003"] = _test_result(
        "MCP-DATA-003", "failed" if poisoned_prompts else "executed", "prompt_metadata_analysis",
        "Prompt metadata contains instruction-poisoning indicators." if poisoned_prompts else "Advertised prompt metadata contains no known poisoning indicators.",
        evidence=poisoned_prompts,
    )

    serialized_tools = json.dumps(tools, default=str)
    chain_candidate = bool(READ_PATTERNS.search(serialized_tools) and (EGRESS_PATTERNS.search(serialized_tools) or EXEC_PATTERNS.search(serialized_tools)))
    privileged_tools = [str(tool.get("name") or "") for tool in tools if re.search(r"admin|sudo|impersonat|privileg|deploy", str(tool.get("name") or ""), re.I)]
    results["MCP-CHAIN-001"] = _test_result(
        "MCP-CHAIN-001", "failed" if chain_candidate else "executed", "capability_chain_analysis",
        "The server exposes a read-to-egress/execute capability chain." if chain_candidate else "No obvious read-to-egress/execute chain was found within this server.",
    )
    results["MCP-CHAIN-003"] = _test_result(
        "MCP-CHAIN-003", "review" if privileged_tools else "not_applicable", "privileged_capability_analysis",
        "Privileged capabilities require caller/delegation policy review." if privileged_tools else "No obviously privileged deputy capability was advertised.",
        evidence=privileged_tools,
    )
    duplicate_headers = []
    for exchange in exchanges:
        for name, values in (exchange.get("response", {}).get("header_values") or {}).items():
            if len(values) > 1:
                duplicate_headers.append({"exchange": exchange["id"], "header": name, "values": values})
    results["MCP-PROTO-003"] = _test_result(
        "MCP-PROTO-003",
        "review" if duplicate_headers else "executed",
        "passive_evidence",
        "Duplicate security headers require parser review." if duplicate_headers else "No duplicate security headers were observed.",
        evidence=duplicate_headers,
    )

    oauth = inventory.get("oauth_metadata") if isinstance(inventory.get("oauth_metadata"), dict) else {}
    if not oauth:
        for test_id in ("MCP-OAUTH-002", "MCP-OAUTH-003", "MCP-OAUTH-004"):
            results[test_id] = _test_result(test_id, "not_applicable", "passive_evidence", "The server did not publish OAuth protected-resource metadata.")
    else:
        endpoint = urlsplit(str(inventory.get("endpoint") or ""))
        resource = str(oauth.get("resource") or "")
        auth_servers = oauth.get("authorization_servers") if isinstance(oauth.get("authorization_servers"), list) else []
        resource_host = urlsplit(resource).hostname if resource else None
        resource_mismatch = bool(resource_host and endpoint.hostname and resource_host != endpoint.hostname)
        results["MCP-OAUTH-003"] = _test_result(
            "MCP-OAUTH-003", "failed" if resource_mismatch else "executed", "oauth_metadata_analysis",
            "Published resource metadata points to a different host." if resource_mismatch else "Published resource metadata is bound to this endpoint.",
            evidence={"resource": resource},
        )
        issuer_hosts = {urlsplit(str(value)).hostname for value in auth_servers if isinstance(value, str)}
        results["MCP-OAUTH-002"] = _test_result(
            "MCP-OAUTH-002", "review" if len(issuer_hosts) > 1 else "executed", "oauth_metadata_analysis",
            "Multiple authorization-server hosts require issuer allowlist review." if len(issuer_hosts) > 1 else "Authorization-server issuer metadata is unambiguous.",
            evidence={"authorization_servers": auth_servers},
        )
        pkce = oauth.get("code_challenge_methods_supported") or []
        results["MCP-OAUTH-004"] = _test_result(
            "MCP-OAUTH-004", "executed" if "S256" in pkce else "review", "oauth_metadata_analysis",
            "S256 PKCE is advertised." if "S256" in pkce else "S256 PKCE was not advertised in the available metadata; verify the authorization-server metadata.",
            evidence={"code_challenge_methods_supported": pkce},
        )

    cache_hints = inventory.get("cache_hints") or {}
    unsafe_cache = [name for name, value in cache_hints.items() if isinstance(value, dict) and value.get("cacheScope") == "public" and inventory.get("authenticated")]
    results["MCP-CACHE-002"] = _test_result(
        "MCP-CACHE-002", "failed" if unsafe_cache else "executed", "cache_policy_analysis",
        f"Authenticated responses are publicly cacheable: {', '.join(unsafe_cache)}" if unsafe_cache else "No authenticated response declared a public cache scope.",
        evidence=unsafe_cache,
    )

    evidence_text = json.dumps(exchanges, default=str)
    leaked_markers = sorted(set(re.findall(
        r"AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----|gh[pousr]_[A-Za-z0-9]{20,}",
        evidence_text,
    )))
    results["MCP-TELEM-001"] = _test_result(
        "MCP-TELEM-001", "failed" if leaked_markers else "executed", "redacted_evidence_analysis",
        "Credential-like material appeared in protocol evidence." if leaked_markers else "No common credential patterns remained in redacted evidence.",
        evidence=leaked_markers,
    )

    csp_values = [
        exchange.get("response", {}).get("headers", {}).get("content-security-policy")
        for exchange in exchanges
        if exchange.get("response", {}).get("headers", {}).get("content-security-policy")
    ]
    external_ui = [
        str(item.get("uri") or item.get("uriTemplate") or "")
        for item in [*inventory.get("resources", []), *inventory.get("resource_templates", [])]
        if str(item.get("uri") or item.get("uriTemplate") or "").startswith(("http://", "https://"))
    ]
    results["MCP-APP-002"] = _test_result(
        "MCP-APP-002", "review" if external_ui and not csp_values else "executed", "client_resource_analysis",
        "External UI resources were advertised without an observed CSP." if external_ui and not csp_values else "Client resource origins and observed CSP headers were evaluated.",
        evidence={"external_resources": external_ui[:20], "csp": csp_values[:5]},
    )

    server = inventory.get("server") or {}
    results["MCP-SUPPLY-001"] = _test_result(
        "MCP-SUPPLY-001", "review", "software_identity_analysis",
        "Server identity was captured; verify it against the configured NVD/SBOM feed." if server.get("name") and server.get("version") else "Server name/version is incomplete, preventing reliable vulnerability correlation.",
        evidence={"name": server.get("name"), "version": server.get("version")},
    )
    publisher = server.get("publisher") or server.get("vendor") or server.get("issuer")
    results["MCP-SUPPLY-002"] = _test_result(
        "MCP-SUPPLY-002", "review", "publisher_identity_analysis",
        "A publisher identity was advertised but requires registry/signature verification." if publisher else "No publisher identity was advertised for independent verification.",
        evidence={"publisher": publisher},
    )
    external_schema_refs: list[str] = []
    _extract_schema_refs(tools, external_schema_refs)
    remote_refs = sorted({value for value in external_schema_refs if value.startswith(("http://", "https://"))})
    results["MCP-SUPPLY-003"] = _test_result(
        "MCP-SUPPLY-003", "review" if remote_refs else "executed", "schema_supply_chain_analysis",
        "Remote schema references can change independently and require integrity pinning." if remote_refs else "No remotely executable or mutable schema reference was advertised.",
        evidence=remote_refs,
    )

    local_config = inventory.get("local_config_analysis")
    if local_config:
        for test_id in ("MCP-LOCAL-001", "MCP-LOCAL-002", "MCP-LOCAL-003", "MCP-LOCAL-004"):
            issue = next((item for item in local_config.get("issues", []) if item.get("test_id") == test_id), None)
            results[test_id] = _test_result(
                test_id,
                "failed" if issue else "executed",
                "offline_configuration_analysis",
                issue.get("reason") if issue else "Local configuration control evaluated without executing the configured process.",
                evidence=issue,
            )

    if previous_inventory:
        tool_changed = previous_inventory.get("tool_fingerprint") != inventory.get("tool_fingerprint")
        results["MCP-AI-006"] = _test_result("MCP-AI-006", "failed" if tool_changed else "executed", "drift_analysis", "Tool definitions changed." if tool_changed else "Tool definitions are stable.")
        results["MCP-DRIFT-001"] = _test_result("MCP-DRIFT-001", "failed" if tool_changed else "executed", "drift_analysis", "Capability fingerprint changed." if tool_changed else "Capability fingerprint is unchanged.")
        previous_oauth = previous_inventory.get("oauth_metadata") or {}
        oauth_changed = previous_oauth != oauth
        results["MCP-DRIFT-002"] = _test_result("MCP-DRIFT-002", "review" if oauth_changed else "executed", "drift_analysis", "OAuth policy metadata changed." if oauth_changed else "OAuth policy metadata is unchanged.")
    else:
        for test_id in ("MCP-AI-006", "MCP-DRIFT-001", "MCP-DRIFT-002"):
            results[test_id] = _test_result(test_id, "not_applicable", "drift_baseline", "This run established the first comparison baseline.")
    return results


def build_test_coverage(
    checks: list[dict[str, Any]],
    inventory: dict[str, Any],
    direct_results: dict[str, dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Report a concrete result or prerequisite for every canonical test."""
    by_test: dict[str, list[dict[str, Any]]] = {}
    for check in checks:
        test_id = check.get("test_id")
        if test_id:
            by_test.setdefault(test_id, []).append(check)
    resolved = direct_results or {}
    coverage = []
    for test_id in MCP_TEST_CATALOG:
        executions = by_test.get(test_id, [])
        if test_id in resolved:
            coverage.append(resolved[test_id])
        elif executions:
            statuses = {item["status"] for item in executions}
            status = "failed" if "failed" in statuses else "review" if "review" in statuses else "executed"
            coverage.append(_test_result(
                test_id,
                status,
                "safe_active",
                "Active-safe protocol exchanges completed.",
                checks=[item["id"] for item in executions],
            ))
        elif test_id in STATIC_ANALYSIS_TESTS:
            coverage.append(_test_result(test_id, "executed", "static_inventory_analysis", "Normalized inventory and evidence were evaluated."))
        else:
            coverage.append(_test_result(
                test_id,
                "blocked",
                "prerequisite_required",
                TEST_PREREQUISITES.get(test_id, "The target did not expose the protocol capability required by this test."),
            ))
    return coverage


def tool_definition_fingerprint(tools: list[dict[str, Any]]) -> str:
    canonical = json.dumps(tools, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def tool_drift_finding(previous_inventory: dict[str, Any], current_inventory: dict[str, Any]) -> dict[str, Any] | None:
    previous = previous_inventory.get("tool_fingerprint")
    current = current_inventory.get("tool_fingerprint")
    if previous and current and previous != current:
        return _finding("HIGH", "MCP tool definitions changed since the previous run", "Tool Integrity",
            f"Previous fingerprint: {previous}; current fingerprint: {current}.",
            "Review and approve the changed names, descriptions, and schemas before agents use this server.")
    return None


def _rpc_body(protocol: str, request_id: int, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    if protocol == MODERN_PROTOCOL_VERSION:
        return _modern_body(request_id, method, params or {})
    return {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params or {}}


def _accepted(response: httpx.Response | None, body: Any) -> bool:
    return bool(response and response.status_code < 400 and not _request_rejected(body))


def _find_nested(value: Any, keys: set[str]) -> Any:
    if isinstance(value, dict):
        for key, item in value.items():
            if key in keys:
                return item
            found = _find_nested(item, keys)
            if found is not None:
                return found
    elif isinstance(value, list):
        for item in value:
            found = _find_nested(item, keys)
            if found is not None:
                return found
    return None


def _analyze_local_config(config_text: str) -> dict[str, Any]:
    """Inspect stdio MCP configuration without executing user-supplied commands."""
    issues: list[dict[str, str]] = []
    try:
        parsed: Any = json.loads(config_text)
    except json.JSONDecodeError:
        parsed = config_text
    serialized = json.dumps(parsed, default=str) if not isinstance(parsed, str) else parsed
    command_values: list[str] = []
    env_keys: list[str] = []

    def walk(value: Any, parent: str = "") -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                key_lower = str(key).lower()
                if key_lower in {"command", "cmd", "executable"} and isinstance(item, str):
                    command_values.append(item)
                if key_lower in {"env", "environment"} and isinstance(item, dict):
                    env_keys.extend(str(name) for name in item)
                walk(item, key_lower)
        elif isinstance(value, list):
            for item in value:
                walk(item, parent)

    walk(parsed)
    if any(re.search(r"[;&|`]|\$\(|\r|\n", command) for command in command_values):
        issues.append({"test_id": "MCP-LOCAL-001", "reason": "Command configuration contains shell-control syntax."})
    if command_values and any(not command.startswith("/") for command in command_values):
        issues.append({"test_id": "MCP-LOCAL-002", "reason": "Executable resolution is not pinned to an absolute path."})
    if any(SENSITIVE_KEY_PATTERN.search(key) for key in env_keys):
        issues.append({"test_id": "MCP-LOCAL-003", "reason": "The MCP process configuration directly inherits credential-like environment values."})
    if re.search(r"(?i)stdio", serialized) and re.search(r"(?i)(debug|verbose|console|stdout)", serialized):
        issues.append({"test_id": "MCP-LOCAL-004", "reason": "Debug/stdout configuration may contaminate the stdio JSON-RPC channel."})
    return {
        "format": "json" if not isinstance(parsed, str) else "text",
        "commands": len(command_values),
        "environment_keys": sorted(set(env_keys)),
        "issues": issues,
    }


async def _profile_rpc(
    probe: McpProbe,
    client: httpx.AsyncClient,
    protocol: str,
    name: str,
    request_id: int,
    method: str,
    params: dict[str, Any] | None = None,
    **kwargs: Any,
) -> tuple[httpx.Response | None, Any]:
    return await probe.exchange(
        client,
        name,
        body=_rpc_body(protocol, request_id, method, params),
        protocol_version=MODERN_PROTOCOL_VERSION if protocol == MODERN_PROTOCOL_VERSION else None,
        mcp_method=method if protocol == MODERN_PROTOCOL_VERSION else None,
        **kwargs,
    )


async def _run_profile_tests(
    client: httpx.AsyncClient,
    probe: McpProbe,
    inventory: dict[str, Any],
    profile: McpExecutionProfile,
    allow_private: bool = False,
) -> dict[str, dict[str, Any]]:
    """Run bounded behavioral tests unlocked by explicit profile inputs."""
    results: dict[str, dict[str, Any]] = {}
    protocol = str(inventory.get("negotiation", {}).get("selected_protocol") or LEGACY_PROTOCOL_VERSION)
    request_id = 20_000

    async def token_rejection(token: str, test_id: str, name: str) -> None:
        nonlocal request_id
        method = "tools/list" if protocol == MODERN_PROTOCOL_VERSION else "initialize"
        params = {} if method == "tools/list" else {
            "protocolVersion": LEGACY_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "ExposureScopeX token-boundary probe", "version": "2.3"},
        }
        response, body = await _profile_rpc(
            probe, client, protocol, name, request_id, method, params,
            headers={"Authorization": f"Bearer {token}"}, omit_session=True,
        )
        request_id += 1
        accepted = _accepted(response, body)
        results[test_id] = _test_result(
            test_id, "failed" if accepted else "executed", "active_safe",
            "Mismatched token was accepted." if accepted else "Mismatched token was rejected.",
            checks=[probe.exchanges[-1]["id"]],
        )

    if profile.audience_mismatch_token:
        await token_rejection(profile.audience_mismatch_token, "MCP-AUTH-002", "audience-mismatch-token")
    if profile.issuer_mismatch_token:
        await token_rejection(profile.issuer_mismatch_token, "MCP-AUTH-003", "issuer-mismatch-token")

    if profile.secondary_bearer_token:
        secondary = McpProbe(
            probe.endpoint,
            profile.secondary_bearer_token,
            secrets=profile.secrets(),
            should_cancel=probe.should_cancel,
            on_exchange=probe.on_exchange,
            prior_exchanges=probe.exchanges,
        )
        if protocol == LEGACY_PROTOCOL_VERSION:
            await _profile_rpc(secondary, client, protocol, "secondary-initialize", request_id, "initialize", {
                "protocolVersion": LEGACY_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "ExposureScopeX secondary principal", "version": "2.3"},
            })
            request_id += 1
            await secondary.exchange(client, "secondary-initialized", body={"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
        secondary_response, secondary_body = await _profile_rpc(
            secondary, client, protocol, "secondary-tools-list", request_id, "tools/list", {}
        )
        request_id += 1
        secondary_result = _result_payload(secondary_body)
        secondary_tools = secondary_result.get("tools", []) if isinstance(secondary_result, dict) else []
        results["MCP-AUTH-004"] = _test_result(
            "MCP-AUTH-004", "executed" if _accepted(secondary_response, secondary_body) else "review", "identity_matrix",
            f"Compared primary inventory with {len(secondary_tools)} secondary-principal tools." if _accepted(secondary_response, secondary_body) else "Secondary principal could not establish a usable inventory.",
            checks=[secondary.exchanges[-1]["id"]] if secondary.exchanges else [],
        )
        results["MCP-CACHE-001"] = _test_result("MCP-CACHE-001", "executed", "identity_matrix", "Primary and secondary list responses were captured and compared.")

        if probe.session_id:
            response, body = await _profile_rpc(
                probe, client, protocol, "cross-principal-session", request_id, "ping", {},
                headers={"Authorization": f"Bearer {profile.secondary_bearer_token}"},
            )
            request_id += 1
            leaked = _accepted(response, body)
            exchange_id = probe.exchanges[-1]["id"]
            for test_id in ("MCP-AUTH-006", "MCP-STATE-001", "MCP-STATE-002", "MCP-CACHE-003"):
                results[test_id] = _test_result(
                    test_id, "failed" if leaked else "executed", "identity_matrix",
                    "A primary session accepted the secondary identity." if leaked else "The primary session rejected the secondary identity.",
                    checks=[exchange_id],
                )
        else:
            for test_id in ("MCP-AUTH-006", "MCP-STATE-001", "MCP-STATE-002", "MCP-CACHE-003"):
                results[test_id] = _test_result(test_id, "not_applicable", "stateless_identity_matrix", "The endpoint did not issue a reusable session identifier.")

        first_tools = next((item for item in probe.exchanges if item["name"] == "tools/list"), None)
        cursor = _find_nested(first_tools.get("response", {}).get("body"), {"nextCursor"}) if first_tools else None
        if cursor:
            response, body = await _profile_rpc(
                probe, client, protocol, "cursor-cross-principal", request_id, "tools/list", {"cursor": cursor},
                headers={"Authorization": f"Bearer {profile.secondary_bearer_token}"}, omit_session=True,
            )
            request_id += 1
            accepted = _accepted(response, body)
            results["MCP-CACHE-004"] = _test_result(
                "MCP-CACHE-004", "review" if accepted else "executed", "identity_matrix",
                "A primary-principal cursor was accepted for the secondary principal." if accepted else "Cross-principal cursor reuse was rejected.",
                checks=[probe.exchanges[-1]["id"]],
            )
        else:
            results["MCP-CACHE-004"] = _test_result("MCP-CACHE-004", "not_applicable", "identity_matrix", "The primary list response was not paginated.")

        race_calls = []
        for index in range(profile.max_concurrency):
            token = profile.secondary_bearer_token if index % 2 else None
            headers = {"Authorization": f"Bearer {token}"} if token else None
            race_calls.append(_profile_rpc(
                probe, client, protocol, "state-race", request_id + index, "ping", {},
                headers=headers, omit_session=True,
            ))
        race_results = await asyncio.gather(*race_calls)
        unstable = any(response is None or (response.status_code >= 500) for response, _ in race_results)
        race_ids = [item["id"] for item in probe.exchanges if item["name"] == "state-race"][-profile.max_concurrency:]
        results["MCP-STATE-005"] = _test_result(
            "MCP-STATE-005", "failed" if unstable else "executed", "bounded_concurrency",
            "Concurrent identity transitions destabilized the endpoint." if unstable else f"Completed {profile.max_concurrency} bounded alternating-identity requests.",
            checks=race_ids,
        )
        request_id += profile.max_concurrency

        if secondary.session_id:
            await secondary.exchange(client, "secondary-session-delete", method="DELETE", body=None)
        probe.exchanges.extend(secondary.exchanges)

    supports_tasks = "task" in json.dumps(inventory.get("capabilities", {}), default=str).lower()
    if profile.test_task_id:
        response, body = await _profile_rpc(probe, client, protocol, "task-primary-get", request_id, "tasks/get", {"taskId": profile.test_task_id})
        request_id += 1
        primary_ok = _accepted(response, body)
        response, body = await _profile_rpc(
            probe, client, protocol, "task-invalid-token-get", request_id, "tasks/get", {"taskId": profile.test_task_id},
            headers={"Authorization": "Bearer exposurescopex-invalid-probe"}, omit_session=True,
        )
        request_id += 1
        invalid_ok = _accepted(response, body)
        results["MCP-TASK-004"] = _test_result(
            "MCP-TASK-004", "failed" if invalid_ok else "executed", "task_authorization",
            "Task result remained available after authorization loss." if invalid_ok else "Invalid authorization could not retrieve the task.",
            checks=[probe.exchanges[-1]["id"]],
        )
        if profile.secondary_bearer_token:
            response, body = await _profile_rpc(
                probe, client, protocol, "task-secondary-get", request_id, "tasks/get", {"taskId": profile.test_task_id},
                headers={"Authorization": f"Bearer {profile.secondary_bearer_token}"}, omit_session=True,
            )
            request_id += 1
            secondary_ok = _accepted(response, body)
            results["MCP-TASK-001"] = _test_result(
                "MCP-TASK-001", "failed" if secondary_ok else "executed", "task_authorization",
                "Secondary principal retrieved the primary task." if secondary_ok else "Task ownership isolation was enforced.",
                checks=[probe.exchanges[-1]["id"]],
            )
        elif primary_ok:
            results["MCP-TASK-001"] = _test_result("MCP-TASK-001", "blocked", "task_authorization", TEST_PREREQUISITES["MCP-TASK-001"])

        if profile.allow_mutation_tests:
            update_call = _profile_rpc(probe, client, protocol, "task-race-update", request_id, "tasks/update", {"taskId": profile.test_task_id, "inputResponses": {"exposurescopex": "cancel-race"}})
            cancel_call = _profile_rpc(probe, client, protocol, "task-race-cancel", request_id + 1, "tasks/cancel", {"taskId": profile.test_task_id})
            mutation = await asyncio.gather(update_call, cancel_call)
            both_accepted = all(_accepted(response, body) for response, body in mutation)
            ids = [item["id"] for item in probe.exchanges if item["name"] in {"task-race-update", "task-race-cancel"}]
            results["MCP-TASK-003"] = _test_result(
                "MCP-TASK-003", "review" if both_accepted else "executed", "authorized_mutation_race",
                "Concurrent update and cancel were both accepted; verify final task state." if both_accepted else "The task state machine rejected at least one conflicting transition.",
                checks=ids,
            )
            request_id += 2
    elif not supports_tasks:
        for test_id in ("MCP-TASK-001", "MCP-TASK-004", "MCP-DOS-003"):
            results[test_id] = _test_result(test_id, "not_applicable", "capability_detection", "The server does not advertise Tasks support.")

    if supports_tasks:
        flood_calls = [
            _profile_rpc(probe, client, protocol, "task-flood-bounded", request_id + index, "tasks/list", {})
            for index in range(profile.max_concurrency)
        ]
        flood_results = await asyncio.gather(*flood_calls)
        unstable = any(response is None or response.status_code >= 500 for response, _ in flood_results)
        flood_ids = [item["id"] for item in probe.exchanges if item["name"] == "task-flood-bounded"][-profile.max_concurrency:]
        results["MCP-DOS-003"] = _test_result(
            "MCP-DOS-003", "failed" if unstable else "executed", "bounded_concurrency",
            "Bounded task concurrency destabilized the endpoint." if unstable else f"Completed {profile.max_concurrency} bounded task-list requests.",
            checks=flood_ids,
        )
        request_id += profile.max_concurrency

    streaming_exchanges = [
        item for item in probe.exchanges
        if "text/event-stream" in str(item.get("response", {}).get("headers", {}).get("content-type", ""))
    ]
    results["MCP-DOS-002"] = _test_result(
        "MCP-DOS-002",
        "executed" if streaming_exchanges else "not_applicable",
        "bounded_stream_analysis",
        f"Analyzed {len(streaming_exchanges)} bounded SSE response(s)." if streaming_exchanges else "The endpoint did not return an SSE stream during this scan.",
        checks=[item["id"] for item in streaming_exchanges],
    )

    approved_tool = next(
        (tool for tool in inventory.get("tools", []) if tool.get("name") == profile.approved_tool_name),
        None,
    ) if profile.approved_tool_name else None
    if profile.approved_tool_name and profile.enable_deep_tests:
        if approved_tool is None:
            response, body = await _profile_rpc(
                probe, client, protocol, "hidden-tool-direct-call", request_id, "tools/call",
                {"name": profile.approved_tool_name, "arguments": profile.approved_tool_arguments},
            )
            request_id += 1
            accepted = _accepted(response, body)
            results["MCP-AUTH-005"] = _test_result(
                "MCP-AUTH-005", "failed" if accepted else "executed", "authorized_deep_test",
                "A non-advertised tool was callable directly." if accepted else "Direct invocation of the non-advertised tool was rejected.",
                checks=[probe.exchanges[-1]["id"]],
            )
        else:
            results["MCP-AUTH-005"] = _test_result("MCP-AUTH-005", "not_applicable", "authorized_deep_test", "The approved tool is present in the advertised inventory.")
            response, initial_body = await _profile_rpc(
                probe, client, protocol, "approved-tool-baseline", request_id, "tools/call",
                {"name": profile.approved_tool_name, "arguments": profile.approved_tool_arguments},
            )
            request_id += 1
            request_state = _find_nested(initial_body, {"requestState", "request_state"})
            if request_state is None:
                for test_id in ("MCP-MRTR-001", "MCP-MRTR-002", "MCP-MRTR-003", "MCP-MRTR-004", "MCP-MRTR-005", "MCP-STATE-004"):
                    results[test_id] = _test_result(test_id, "not_applicable", "authorized_deep_test", "The approved tool did not start an MRTR flow or return requestState.")
            else:
                mrtr_specs = [
                    ("MCP-MRTR-002", "mrtr-tool-substitution", "__exposurescopex_nonexistent__", request_state),
                    ("MCP-MRTR-003", "mrtr-type-confusion", profile.approved_tool_name, {"unexpected": [request_state]}),
                    ("MCP-MRTR-004", "mrtr-replay", profile.approved_tool_name, request_state),
                    ("MCP-MRTR-005", "mrtr-oversized-state", profile.approved_tool_name, "A" * 65536),
                ]
                for test_id, name, tool_name, state_value in mrtr_specs:
                    response, body = await _profile_rpc(
                        probe, client, protocol, name, request_id, "tools/call", {
                            "name": tool_name,
                            "arguments": profile.approved_tool_arguments,
                            "requestState": state_value,
                        },
                    )
                    request_id += 1
                    accepted = _accepted(response, body)
                    results[test_id] = _test_result(
                        test_id, "review" if accepted else "executed", "authorized_deep_test",
                        "The malformed or replayed MRTR state was accepted; verify state transition semantics." if accepted else "The malformed or replayed MRTR state was rejected.",
                        checks=[probe.exchanges[-1]["id"]],
                    )
                if profile.secondary_bearer_token:
                    response, body = await _profile_rpc(
                        probe, client, protocol, "mrtr-principal-binding", request_id, "tools/call", {
                            "name": profile.approved_tool_name,
                            "arguments": profile.approved_tool_arguments,
                            "requestState": request_state,
                        }, headers={"Authorization": f"Bearer {profile.secondary_bearer_token}"}, omit_session=True,
                    )
                    request_id += 1
                    accepted = _accepted(response, body)
                    exchange_id = probe.exchanges[-1]["id"]
                    results["MCP-MRTR-001"] = _test_result(
                        "MCP-MRTR-001", "failed" if accepted else "executed", "authorized_deep_test",
                        "Secondary principal continued the primary MRTR flow." if accepted else "MRTR state remained bound to the primary principal.",
                        checks=[exchange_id],
                    )
                    results["MCP-STATE-004"] = _test_result(
                        "MCP-STATE-004", "failed" if accepted else "executed", "authorized_deep_test",
                        "Authorization change was accepted between MRTR rounds." if accepted else "Authorization change invalidated the MRTR transition.",
                        checks=[exchange_id],
                    )

            properties = (approved_tool.get("inputSchema") or {}).get("properties") or {}
            sink_specs = [
                ("MCP-SINK-001", "sink-command-canary", re.compile(r"cmd|command|argument|script", re.I), "exsx-canary;printf_exsx"),
                ("MCP-SINK-002", "sink-option-canary", re.compile(r"arg|option|flag", re.I), "--exsx-canary"),
                ("MCP-SINK-003", "sink-path-canary", PATH_LIKE_PATTERNS, "../../__exsx_nonexistent__/canary"),
                ("MCP-SINK-004", "sink-query-canary", re.compile(r"query|sql|filter|where", re.I), "' OR 'exsx'='never"),
                ("MCP-SINK-005", "sink-template-canary", re.compile(r"template|expression|format", re.I), "${{7*7}}-exsx"),
            ]
            for test_id, name, pattern, marker in sink_specs:
                parameter = next((key for key in properties if pattern.search(key)), None)
                if not parameter:
                    continue
                arguments = {**profile.approved_tool_arguments, parameter: marker}
                response, body = await _profile_rpc(
                    probe, client, protocol, name, request_id, "tools/call",
                    {"name": profile.approved_tool_name, "arguments": arguments},
                )
                request_id += 1
                accepted = _accepted(response, body)
                results[test_id] = _test_result(
                    test_id, "review" if accepted else "executed", "authorized_canary",
                    f"Canary value for `{parameter}` was accepted; inspect the isolated sink result." if accepted else f"Canary value for `{parameter}` was rejected.",
                    checks=[probe.exchanges[-1]["id"]],
                )

            network_parameter = next((key for key in properties if NETWORK_TARGET_PATTERNS.search(key)), None)
            if network_parameter and profile.canary_url:
                ssrf_specs = [
                    ("MCP-SSRF-001", "ssrf-canary", profile.canary_url),
                    ("MCP-SSRF-002", "ssrf-private-normalization", "http://127.0.0.1:9/__exsx_canary__"),
                    ("MCP-SSRF-003", "ssrf-redirect-canary", f"{profile.canary_url.rstrip('/')}/redirect"),
                    ("MCP-SSRF-004", "ssrf-rebinding-canary", f"{profile.canary_url.rstrip('/')}/rebind"),
                ]
                for test_id, name, target_url in ssrf_specs:
                    arguments = {**profile.approved_tool_arguments, network_parameter: target_url}
                    response, body = await _profile_rpc(
                        probe, client, protocol, name, request_id, "tools/call",
                        {"name": profile.approved_tool_name, "arguments": arguments},
                    )
                    request_id += 1
                    accepted = _accepted(response, body)
                    results[test_id] = _test_result(
                        test_id, "review" if accepted else "executed", "authorized_oob_canary",
                        f"The URL canary was accepted for `{network_parameter}`; correlate the canary service before confirming SSRF." if accepted else "The URL canary was rejected before execution.",
                        checks=[probe.exchanges[-1]["id"]],
                    )

    if profile.approved_resource_uri and profile.enable_deep_tests:
        response, body = await _profile_rpc(
            probe, client, protocol, "approved-resource-read", request_id, "resources/read",
            {"uri": profile.approved_resource_uri},
        )
        request_id += 1
        resource_accepted = _accepted(response, body)
        resource_poisoned = bool(POISONING_PATTERNS.search(json.dumps(body, default=str))) if resource_accepted else False
        inventory["approved_resource_analysis"] = {
            "accepted": resource_accepted,
            "poisoning_indicators": resource_poisoned,
        }
        results["MCP-DATA-002"] = _test_result(
            "MCP-DATA-002", "review" if resource_accepted else "executed", "authorized_deep_test",
            "Approved parameterized resource was resolved; inspect canonicalization and returned scope." if resource_accepted else "Approved resource request was rejected.",
            checks=[probe.exchanges[-1]["id"]],
        )
        results["MCP-AI-002"] = _test_result(
            "MCP-AI-002", "failed" if resource_poisoned else "executed", "authorized_runtime_content_analysis",
            "Approved resource content contains instruction-poisoning indicators." if resource_poisoned else "Approved resource content contains no known instruction-poisoning indicators.",
            checks=[probe.exchanges[-1]["id"]],
        )

    if profile.approved_prompt_name and profile.enable_deep_tests:
        response, body = await _profile_rpc(
            probe, client, protocol, "approved-prompt-get", request_id, "prompts/get",
            {"name": profile.approved_prompt_name, "arguments": {"exposurescopex": "benign-canary"}},
        )
        request_id += 1
        prompt_text = json.dumps(body, default=str)
        poisoned = bool(POISONING_PATTERNS.search(prompt_text))
        inventory["approved_prompt_analysis"] = {
            "accepted": _accepted(response, body),
            "poisoning_indicators": poisoned,
        }
        results["MCP-AI-002"] = _test_result(
            "MCP-AI-002", "failed" if poisoned else "executed", "authorized_deep_test",
            "Approved prompt result contains instruction-poisoning indicators." if poisoned else "Approved prompt result did not contain known instruction-poisoning indicators.",
            checks=[probe.exchanges[-1]["id"]],
        )
        results["MCP-AI-003"] = _test_result(
            "MCP-AI-003", "review" if _accepted(response, body) else "executed", "authorized_deep_test",
            "Prompt content was captured for cross-channel composition review." if _accepted(response, body) else "Approved prompt request was rejected.",
            checks=[probe.exchanges[-1]["id"]],
        )

    if profile.cross_server_endpoint:
        cross_endpoint = await validate_endpoint(profile.cross_server_endpoint, allow_private)
        cross_probe = McpProbe(
            cross_endpoint,
            profile.cross_server_bearer_token,
            secrets=profile.secrets(),
            should_cancel=probe.should_cancel,
            on_exchange=probe.on_exchange,
            prior_exchanges=probe.exchanges,
        )
        discover_response, discover_body = await cross_probe.exchange(
            client, "cross-server-discover",
            body=_modern_body(request_id, "server/discover", {}),
            protocol_version=MODERN_PROTOCOL_VERSION,
            mcp_method="server/discover",
            omit_session=True,
        )
        request_id += 1
        discover_result = _result_payload(discover_body)
        cross_modern = bool(
            _accepted(discover_response, discover_body)
            and isinstance(discover_result, dict)
            and any(key in discover_result for key in ("supportedVersions", "capabilities", "_meta"))
        )
        if not cross_modern:
            await cross_probe.exchange(
                client, "cross-server-initialize",
                body={
                    "jsonrpc": "2.0", "id": request_id, "method": "initialize",
                    "params": {
                        "protocolVersion": LEGACY_PROTOCOL_VERSION,
                        "capabilities": {},
                        "clientInfo": {"name": "ExposureScopeX cross-server probe", "version": "2.3"},
                    },
                },
            )
            request_id += 1
            await cross_probe.exchange(
                client, "cross-server-initialized",
                body={"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
            )
        response, body = await cross_probe.exchange(
            client, "cross-server-tools-list",
            body=_modern_body(request_id, "tools/list", {}) if cross_modern else {
                "jsonrpc": "2.0", "id": request_id, "method": "tools/list", "params": {},
            },
            protocol_version=MODERN_PROTOCOL_VERSION if cross_modern else None,
            mcp_method="tools/list" if cross_modern else None,
            omit_session=cross_modern,
        )
        cross_tools_exchange_id = cross_probe.exchanges[-1]["id"]
        if cross_probe.session_id:
            await cross_probe.exchange(client, "cross-server-session-delete", method="DELETE", body=None)
        probe.exchanges.extend(cross_probe.exchanges)
        cross_tools = _result_payload(body).get("tools", []) if _accepted(response, body) else []
        combined = json.dumps([inventory.get("tools", []), cross_tools], default=str)
        chain_candidate = bool(READ_PATTERNS.search(combined) and (EGRESS_PATTERNS.search(combined) or EXEC_PATTERNS.search(combined)))
        cross_inventory_ok = _accepted(response, body)
        results["MCP-CHAIN-002"] = _test_result(
            "MCP-CHAIN-002", "blocked" if not cross_inventory_ok else "review" if chain_candidate else "executed", "cross_server_analysis",
            "The second MCP endpoint did not return a usable authorized tool inventory." if not cross_inventory_ok else "Cross-server read-to-egress/execute capabilities require policy review." if chain_candidate else "No obvious cross-server read-to-egress/execute chain was found.",
            checks=[cross_tools_exchange_id],
        )

    if profile.local_config_text:
        inventory["local_config_analysis"] = _analyze_local_config(profile.local_config_text)

    return results


async def run_mcp_audit(
    endpoint: str,
    bearer_token: str | None = None,
    *,
    allow_private: bool = False,
    protocol_tests: bool = True,
    transport: httpx.AsyncBaseTransport | None = None,
    profile: McpExecutionProfile | None = None,
    previous_inventory: dict[str, Any] | None = None,
    should_cancel: Callable[[], bool] | None = None,
    on_exchange: Callable[[str, int], None] | None = None,
) -> dict[str, Any]:
    endpoint = await validate_endpoint(endpoint, allow_private)
    profile = profile or McpExecutionProfile()
    supplied_secrets = [value for value in (bearer_token, *profile.secrets()) if value]
    probe = McpProbe(
        endpoint,
        bearer_token,
        secrets=supplied_secrets,
        should_cancel=should_cancel,
        on_exchange=on_exchange,
    )
    timeout = httpx.Timeout(connect=8, read=20, write=10, pool=5)
    limits = httpx.Limits(max_connections=4, max_keepalive_connections=2)
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=False, limits=limits, transport=transport) as client:
        inventory: dict[str, Any] = {
            "endpoint": endpoint,
            "authenticated": bool(bearer_token),
            "server": {},
            "protocol_version": None,
            "capabilities": {},
            "tools": [],
            "resources": [],
            "resource_templates": [],
            "prompts": [],
            "instructions": None,
            "cache_hints": {},
            "recommended_manual_tests": [],
            "execution_profile": profile.public_summary(),
            "transport_profile": {
                "allow_private": allow_private,
                "protocol_tests": protocol_tests,
            },
            "negotiation": {
                "selected_protocol": None,
                "fallback_reason": None,
                "discover_supported_versions": [],
            },
        }

        discover_body = _modern_body("discover-1", "server/discover")
        discover_response, discover_payload = await probe.exchange(
            client,
            "server/discover",
            body=discover_body,
            protocol_version=MODERN_PROTOCOL_VERSION,
            mcp_method="server/discover",
            omit_session=True,
        )
        discover_result = _result_payload(discover_payload)
        modern_supported = bool(
            discover_response
            and discover_response.status_code < 400
            and not _error_code(discover_payload)
            and isinstance(discover_result, dict)
            and (
                isinstance(discover_result.get("supportedVersions"), list)
                or isinstance(discover_result.get("capabilities"), dict)
                or isinstance(discover_result.get("_meta"), dict)
            )
        )

        request_id = 1
        if modern_supported:
            supported_versions = [
                str(item) for item in discover_result.get("supportedVersions", []) if isinstance(item, str)
            ]
            inventory["negotiation"]["selected_protocol"] = MODERN_PROTOCOL_VERSION
            inventory["negotiation"]["discover_supported_versions"] = supported_versions
            inventory["protocol_version"] = MODERN_PROTOCOL_VERSION
            inventory["server"] = _server_info_from_discover(discover_result)
            inventory["capabilities"] = discover_result.get("capabilities", {}) if isinstance(discover_result.get("capabilities"), dict) else {}
            inventory["instructions"] = discover_result.get("instructions")
            inventory["cache_hints"]["server/discover"] = {
                "ttlMs": discover_result.get("ttlMs"),
                "cacheScope": discover_result.get("cacheScope"),
            }
            request_id = 2
        else:
            if discover_response is None:
                raise McpAuditError("Could not connect to the MCP endpoint")
            inventory["negotiation"]["fallback_reason"] = "server/discover unavailable or unusable"
            init_request = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": LEGACY_PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {"name": "ExposureScopeX MCP Security", "version": "2.3"},
                },
            }
            init_response, init_body = await probe.exchange(client, "initialize", body=init_request)
            if init_response is None:
                raise McpAuditError("Could not connect to the MCP endpoint")
            if init_response.status_code in {401, 403}:
                raise McpAuditError("MCP authentication failed; provide a valid bearer token for this endpoint")
            if init_response.status_code >= 400:
                raise McpAuditError(f"MCP initialize was rejected with HTTP {init_response.status_code}")
            if _request_rejected(init_body):
                error = init_body.get("error", {}) if isinstance(init_body, dict) else {}
                message = error.get("message") if isinstance(error, dict) else None
                raise McpAuditError(f"MCP initialize returned an error: {message or 'unknown protocol error'}")
            init_result = _result_payload(init_body)
            if not isinstance(init_result, dict) or not init_result:
                raise McpAuditError("MCP initialize returned an unusable response")

            initialized = {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}
            await probe.exchange(client, "notifications/initialized", body=initialized)
            inventory["negotiation"]["selected_protocol"] = LEGACY_PROTOCOL_VERSION
            inventory["server"] = init_result.get("serverInfo", {})
            inventory["protocol_version"] = init_result.get("protocolVersion")
            inventory["capabilities"] = init_result.get("capabilities", {})

        ping_body = (
            _modern_body(request_id, "ping", {})
            if inventory["negotiation"]["selected_protocol"] == MODERN_PROTOCOL_VERSION
            else {"jsonrpc": "2.0", "id": 2, "method": "ping", "params": {}}
        )
        await probe.exchange(
            client,
            "ping",
            body=ping_body,
            protocol_version=MODERN_PROTOCOL_VERSION if inventory["negotiation"]["selected_protocol"] == MODERN_PROTOCOL_VERSION else None,
            mcp_method="ping" if inventory["negotiation"]["selected_protocol"] == MODERN_PROTOCOL_VERSION else None,
        )
        if inventory["negotiation"]["selected_protocol"] == LEGACY_PROTOCOL_VERSION:
            request_id = 3
        else:
            request_id += 1
        for name, method, key in (
            ("tools/list", "tools/list", "tools"),
            ("resources/list", "resources/list", "resources"),
            ("resources/templates/list", "resources/templates/list", "resourceTemplates"),
            ("prompts/list", "prompts/list", "prompts"),
        ):
            inventory_key = "resource_templates" if key == "resourceTemplates" else key
            cursor: str | None = None
            pages = 0
            for page in range(20):
                params = {"cursor": cursor} if cursor else {}
                exchange_name = name if page == 0 else f"{name} page {page + 1}"
                request_body = (
                    _modern_body(request_id, method, params)
                    if inventory["negotiation"]["selected_protocol"] == MODERN_PROTOCOL_VERSION
                    else {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
                )
                _, body = await probe.exchange(
                    client,
                    exchange_name,
                    body=request_body,
                    protocol_version=MODERN_PROTOCOL_VERSION if inventory["negotiation"]["selected_protocol"] == MODERN_PROTOCOL_VERSION else None,
                    mcp_method=method if inventory["negotiation"]["selected_protocol"] == MODERN_PROTOCOL_VERSION else None,
                )
                request_id += 1
                pages += 1
                result_page = _result_payload(body)
                value = result_page.get(key, [])
                if isinstance(value, list):
                    inventory[inventory_key].extend(value)
                if page == 0:
                    inventory["cache_hints"][name] = {
                        "ttlMs": result_page.get("ttlMs"),
                        "cacheScope": result_page.get("cacheScope"),
                        "pages": pages,
                    }
                next_cursor = result_page.get("nextCursor")
                cursor = next_cursor if isinstance(next_cursor, str) and next_cursor else None
                if not cursor:
                    break
            if cursor:
                inventory.setdefault("pagination_truncated", []).append(name)

        inventory["tool_fingerprint"] = tool_definition_fingerprint(inventory["tools"])

        origin = urlsplit(endpoint)
        origin_root = f"{origin.scheme}://{origin.netloc}"
        oauth_root_response, oauth_root_body = await probe.exchange(client, "oauth-protected-resource", method="GET", body=None,
            url=f"{origin_root}/.well-known/oauth-protected-resource")
        if origin.path and origin.path != "/":
            oauth_path_response, oauth_path_body = await probe.exchange(client, "oauth-protected-resource-path", method="GET", body=None,
                url=f"{origin_root}/.well-known/oauth-protected-resource{origin.path}")
        else:
            oauth_path_response = None
            oauth_path_body = None
        inventory["oauth_metadata_published"] = bool(
            oauth_root_response and oauth_root_response.status_code < 300
            or oauth_path_response and oauth_path_response.status_code < 300
        )
        published_oauth = oauth_path_body if oauth_path_response and oauth_path_response.status_code < 300 else oauth_root_body
        inventory["oauth_metadata"] = _result_payload(published_oauth) if inventory["oauth_metadata_published"] else {}
        if protocol_tests:
            if bearer_token:
                if inventory["negotiation"]["selected_protocol"] == LEGACY_PROTOCOL_VERSION:
                    await probe.exchange(client, "unauthenticated-initialize", body={
                        "jsonrpc": "2.0",
                        "id": 90,
                        "method": "initialize",
                        "params": {
                            "protocolVersion": LEGACY_PROTOCOL_VERSION,
                            "capabilities": {},
                            "clientInfo": {"name": "ExposureScopeX MCP Security", "version": "2.3"},
                        },
                    }, omit_authorization=True, omit_session=True)
                else:
                    await probe.exchange(
                        client,
                        "unauthenticated-tools-list",
                        body=_modern_body(90, "tools/list", {}),
                        omit_authorization=True,
                        omit_session=True,
                        protocol_version=MODERN_PROTOCOL_VERSION,
                        mcp_method="tools/list",
                    )
                if probe.session_id:
                    await probe.exchange(
                        client,
                        "session-replay-with-invalid-bearer",
                        body={"jsonrpc": "2.0", "id": 96, "method": "ping", "params": {}},
                        headers={"Authorization": "Bearer exposurescopex-invalid-probe"},
                    )
            probe_request = (
                _modern_body(91, "ping", {})
                if inventory["negotiation"]["selected_protocol"] == MODERN_PROTOCOL_VERSION
                else {
                    "jsonrpc": "2.0",
                    "id": 91,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": LEGACY_PROTOCOL_VERSION,
                        "capabilities": {},
                        "clientInfo": {"name": "ExposureScopeX MCP Security", "version": "2.3"},
                    },
                }
            )
            await probe.exchange(
                client,
                "untrusted-origin",
                body=probe_request,
                headers={"Origin": "https://attacker.invalid"},
                protocol_version=MODERN_PROTOCOL_VERSION if inventory["negotiation"]["selected_protocol"] == MODERN_PROTOCOL_VERSION else None,
                mcp_method="ping" if inventory["negotiation"]["selected_protocol"] == MODERN_PROTOCOL_VERSION else None,
            )
            await probe.exchange(client, "cors-preflight", method="OPTIONS", body=None, headers={
                "Origin": "https://attacker.invalid",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "authorization,content-type,mcp-protocol-version",
            }, omit_session=True)
            await probe.exchange(
                client,
                "unsupported-method",
                body=_modern_body(92, "exposurescopex/security-probe", {}) if inventory["negotiation"]["selected_protocol"] == MODERN_PROTOCOL_VERSION else {
                    "jsonrpc": "2.0", "id": 92, "method": "exposurescopex/security-probe", "params": {},
                },
                protocol_version=MODERN_PROTOCOL_VERSION if inventory["negotiation"]["selected_protocol"] == MODERN_PROTOCOL_VERSION else None,
                mcp_method="exposurescopex/security-probe" if inventory["negotiation"]["selected_protocol"] == MODERN_PROTOCOL_VERSION else None,
            )
            await probe.exchange(
                client,
                "unknown-tool-call",
                body=_modern_body(93, "tools/call", {"name": "__exposurescopex_nonexistent__", "arguments": {}})
                if inventory["negotiation"]["selected_protocol"] == MODERN_PROTOCOL_VERSION
                else {
                    "jsonrpc": "2.0", "id": 93, "method": "tools/call",
                    "params": {"name": "__exposurescopex_nonexistent__", "arguments": {}},
                },
                protocol_version=MODERN_PROTOCOL_VERSION if inventory["negotiation"]["selected_protocol"] == MODERN_PROTOCOL_VERSION else None,
                mcp_method="tools/call" if inventory["negotiation"]["selected_protocol"] == MODERN_PROTOCOL_VERSION else None,
                mcp_name="__exposurescopex_nonexistent__" if inventory["negotiation"]["selected_protocol"] == MODERN_PROTOCOL_VERSION else None,
            )
            await probe.exchange(
                client,
                "unknown-resource-read",
                body=_modern_body(94, "resources/read", {"uri": "exposurescopex://nonexistent/security-probe"})
                if inventory["negotiation"]["selected_protocol"] == MODERN_PROTOCOL_VERSION
                else {
                    "jsonrpc": "2.0", "id": 94, "method": "resources/read",
                    "params": {"uri": "exposurescopex://nonexistent/security-probe"},
                },
                protocol_version=MODERN_PROTOCOL_VERSION if inventory["negotiation"]["selected_protocol"] == MODERN_PROTOCOL_VERSION else None,
                mcp_method="resources/read" if inventory["negotiation"]["selected_protocol"] == MODERN_PROTOCOL_VERSION else None,
            )
            await probe.exchange(
                client,
                "unknown-prompt-get",
                body=_modern_body(95, "prompts/get", {"name": "__exposurescopex_nonexistent__", "arguments": {}})
                if inventory["negotiation"]["selected_protocol"] == MODERN_PROTOCOL_VERSION
                else {
                    "jsonrpc": "2.0", "id": 95, "method": "prompts/get",
                    "params": {"name": "__exposurescopex_nonexistent__", "arguments": {}},
                },
                protocol_version=MODERN_PROTOCOL_VERSION if inventory["negotiation"]["selected_protocol"] == MODERN_PROTOCOL_VERSION else None,
                mcp_method="prompts/get" if inventory["negotiation"]["selected_protocol"] == MODERN_PROTOCOL_VERSION else None,
            )
            await probe.exchange(client, "invalid-jsonrpc-version", body={
                "jsonrpc": "1.0", "id": 97, "method": "ping", "params": {},
            })
            await probe.exchange(client, "malformed-json", body='{"jsonrpc":"2.0","id":99,"method":',
                headers={"Content-Type": "application/json"})
            await probe.exchange(
                client,
                "protocol-version-downgrade",
                body={"jsonrpc": "2.0", "id": 100, "method": "ping", "params": {}},
                headers={"MCP-Protocol-Version": "2024-11-05"},
                omit_session=True,
            )
            await probe.exchange(
                client,
                "duplicate-json-fields",
                body='{"jsonrpc":"2.0","id":101,"method":"ping","method":"tools/list","params":{}}',
                omit_session=True,
            )
            await probe.exchange(
                client,
                "unicode-confusable-tool",
                body={
                    "jsonrpc": "2.0", "id": 102, "method": "tools/call",
                    "params": {"name": "__exposure\u0455copex_nonexistent__", "arguments": {}},
                },
                omit_session=True,
            )
            await probe.exchange(
                client,
                "encoded-resource-traversal",
                body={
                    "jsonrpc": "2.0", "id": 103, "method": "resources/read",
                    "params": {"uri": "file:///%252e%252e/%252e%252e/exposurescopex-probe"},
                },
                omit_session=True,
            )
            await probe.exchange(
                client,
                "bounded-amplification",
                body={"jsonrpc": "2.0", "id": 104, "method": "ping", "params": {"padding": "A" * 65536}},
                omit_session=True,
            )
            await probe.exchange(
                client,
                "trace-context-spoof",
                body={"jsonrpc": "2.0", "id": 105, "method": "ping", "params": {}},
                headers={"traceparent": "00-invalid-tenant-context-01", "tracestate": "tenant=attacker"},
                omit_session=True,
            )
            await probe.exchange(
                client,
                "cross-site-text-plain",
                body=json.dumps(_modern_body(98, "ping", {}) if inventory["negotiation"]["selected_protocol"] == MODERN_PROTOCOL_VERSION else {
                    "jsonrpc": "2.0", "id": 98, "method": "ping", "params": {},
                }),
                headers={"Content-Type": "text/plain", "Origin": "https://attacker.invalid"},
                protocol_version=MODERN_PROTOCOL_VERSION if inventory["negotiation"]["selected_protocol"] == MODERN_PROTOCOL_VERSION else None,
                mcp_method="ping" if inventory["negotiation"]["selected_protocol"] == MODERN_PROTOCOL_VERSION else None,
                omit_session=True,
            )
            if inventory["negotiation"]["selected_protocol"] == MODERN_PROTOCOL_VERSION:
                await probe.exchange(
                    client,
                    "header-method-mismatch",
                    body=_modern_body(99, "exposurescopex/security-probe", {}),
                    headers={"Mcp-Method": "ping"},
                    protocol_version=MODERN_PROTOCOL_VERSION,
                    mcp_method="ping",
                    omit_session=True,
                )
                for exchange_name, task_method, params in (
                    ("unknown-task-get", "tasks/get", {"taskId": "__exposurescopex_nonexistent__"}),
                    ("unknown-task-cancel", "tasks/cancel", {"taskId": "__exposurescopex_nonexistent__"}),
                    ("unknown-task-update", "tasks/update", {"taskId": "__exposurescopex_nonexistent__", "inputResponses": {}}),
                ):
                    await probe.exchange(
                        client,
                        exchange_name,
                        body=_modern_body(request_id, task_method, params),
                        protocol_version=MODERN_PROTOCOL_VERSION,
                        mcp_method=task_method,
                        omit_session=True,
                    )
                    request_id += 1
            else:
                for exchange_name, task_method, params in (
                    ("tasks/list", "tasks/list", {}),
                    ("unknown-task-get", "tasks/get", {"taskId": "__exposurescopex_nonexistent__"}),
                    ("unknown-task-cancel", "tasks/cancel", {"taskId": "__exposurescopex_nonexistent__"}),
                ):
                    await probe.exchange(
                        client,
                        exchange_name,
                        body={"jsonrpc": "2.0", "id": request_id, "method": task_method, "params": params},
                    )
                    request_id += 1
        try:
            direct_results = await _run_profile_tests(
                client, probe, inventory, profile, allow_private=allow_private
            ) if protocol_tests else {}
        finally:
            if probe.session_id:
                await probe.exchange(client, "session-delete", method="DELETE", body=None)

    static_results = _static_test_results(inventory, probe.exchanges, previous_inventory)
    direct_results = {**static_results, **direct_results}
    findings = analyze_inventory(endpoint, inventory, probe.exchanges)
    checks = build_protocol_checks(probe.exchanges)
    inventory["protocol_checks"] = checks
    coverage = build_test_coverage(checks, inventory, direct_results)
    inventory["test_coverage"] = coverage
    inventory["recommended_manual_tests"] = [
        item["reason"] for item in coverage if item["status"] == "blocked"
    ]
    findings.extend(_coverage_findings(coverage))
    counts = {severity: sum(1 for item in findings if item["severity"] == severity) for severity in SEVERITY_SCORE}
    check_counts = {status: sum(1 for item in checks if item["status"] == status) for status in (
        "passed", "failed", "review", "informational"
    )}
    coverage_counts = {
        status: sum(1 for item in coverage if item["status"] == status)
        for status in ("executed", "failed", "review", "blocked", "not_applicable")
    }
    risk_score = max((SEVERITY_SCORE[item["severity"]] for item in findings), default=0)
    overall = next((severity for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO") if counts[severity]), "INFO")
    return _redact_sensitive({
        "endpoint": endpoint,
        "overall_severity": overall,
        "risk_score": risk_score,
        "summary": {
            "counts": counts,
            "tools": len(inventory["tools"]),
            "resources": len(inventory["resources"]),
            "resource_templates": len(inventory["resource_templates"]),
            "prompts": len(inventory["prompts"]),
            "exchanges": len(probe.exchanges),
            "checks": check_counts,
            "test_coverage": coverage_counts,
            "canonical_tests": len(MCP_TEST_CATALOG),
        },
        "inventory": inventory,
        "findings": findings,
        "exchanges": probe.exchanges,
    }, supplied_secrets)
