"""Local-only adapter execution and redacted result package construction."""

from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import ssl
import subprocess
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener
from uuid import uuid4

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from . import __version__


CONFIG_SCHEMA_VERSION = "esx-client-runner-config-1.0"
PACKAGE_SCHEMA_VERSION = "esx-client-evaluation-result-1.1"
ADAPTER_REQUEST_SCHEMA_VERSION_V1 = "esx-client-adapter-request-1.0"
ADAPTER_RESPONSE_SCHEMA_VERSION_V1 = "esx-client-adapter-response-1.0"
ADAPTER_REQUEST_SCHEMA_VERSION_V2 = "esx-client-adapter-request-2.0"
ADAPTER_RESPONSE_SCHEMA_VERSION_V2 = "esx-client-adapter-response-2.0"
BASE_DIMENSIONS = {"classification", "confidence"}
SUPPORTED_DIMENSIONS = BASE_DIMENSIONS | {
    "groundedness",
    "security",
    "trajectory",
    "rag",
    "robustness",
    "judge_agreement",
    "reproducibility",
    "cost_efficiency",
}
_SAFE_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,159}$")


class _NoRedirect(HTTPRedirectHandler):
    """Keep a configured evaluation target from silently reaching another URL."""

    def redirect_request(self, *_args: object, **_kwargs: object) -> None:
        return None


class RunnerError(RuntimeError):
    pass


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def sha256(value: object) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def read_json(path: str | Path) -> dict[str, Any]:
    try:
        loaded = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RunnerError(f"Cannot read JSON file: {path}") from exc
    if not isinstance(loaded, dict):
        raise RunnerError("JSON document must be an object")
    return loaded


def _base64(value: str, label: str) -> bytes:
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except Exception as exc:  # noqa: BLE001 - normalize a user-supplied key error.
        raise RunnerError(f"{label} must be base64 encoded") from exc


def generate_keypair(private_key_path: str | Path) -> dict[str, str]:
    private_path = Path(private_key_path)
    if private_path.exists():
        raise RunnerError(f"Refusing to overwrite existing private key: {private_path}")
    private_path.parent.mkdir(parents=True, exist_ok=True)
    private_key = ed25519.Ed25519PrivateKey.generate()
    private_raw = private_key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    public_raw = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    private_path.write_text(base64.b64encode(private_raw).decode("ascii") + "\n", encoding="ascii")
    try:
        private_path.chmod(0o600)
    except OSError:
        # Windows ACLs are managed by the client environment; never relax access here.
        pass
    public_key = base64.b64encode(public_raw).decode("ascii")
    return {
        "public_key": public_key,
        "key_fingerprint": hashlib.sha256(public_raw).hexdigest(),
        "private_key_path": str(private_path),
    }


def _load_private_key(private_key_path: str | Path) -> ed25519.Ed25519PrivateKey:
    try:
        raw = _base64(Path(private_key_path).read_text(encoding="ascii").strip(), "Ed25519 private key")
        if len(raw) != 32:
            raise RunnerError("Ed25519 private keys must be 32 bytes")
        return ed25519.Ed25519PrivateKey.from_private_bytes(raw)
    except OSError as exc:
        raise RunnerError(f"Cannot read private key: {private_key_path}") from exc


def _validate_config(config: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
    if config.get("schema_version") != CONFIG_SCHEMA_VERSION:
        raise RunnerError(f"schema_version must be {CONFIG_SCHEMA_VERSION}")
    evaluation = config.get("evaluation")
    dataset = config.get("dataset")
    adapter = config.get("adapter")
    if not isinstance(evaluation, dict) or not isinstance(dataset, dict) or not isinstance(adapter, dict):
        raise RunnerError("Config requires evaluation, dataset, and adapter objects")
    adapter_type = adapter.get("type")
    if adapter_type not in {"command_json_v1", "command_json_v2", "http_json_target"}:
        raise RunnerError("adapter.type must be command_json_v1, command_json_v2, or http_json_target")
    if adapter_type.startswith("command_"):
        command = adapter.get("command")
        if not isinstance(command, list) or not command or not all(isinstance(item, str) and item for item in command):
            raise RunnerError("adapter.command must be a non-empty string array")
        _validate_sandbox(adapter.get("sandbox"))
    else:
        _validate_http_target(adapter)
    timeout = adapter.get("timeout_seconds", 60)
    if not isinstance(timeout, int) or timeout < 1 or timeout > 300:
        raise RunnerError("adapter.timeout_seconds must be an integer between 1 and 300")
    cases = dataset.get("cases")
    if not isinstance(cases, list) or not cases or len(cases) > 10_000:
        raise RunnerError("dataset.cases must contain between 1 and 10,000 cases")
    case_ids: set[str] = set()
    for item in cases:
        if not isinstance(item, dict) or not isinstance(item.get("case_id"), str) or not item["case_id"]:
            raise RunnerError("Every dataset case needs a non-empty case_id")
        if item["case_id"] in case_ids:
            raise RunnerError("dataset case_id values must be unique")
        case_ids.add(item["case_id"])
        if not isinstance(item.get("input"), dict) or not isinstance(item.get("expected_label"), str) or not item["expected_label"]:
            raise RunnerError("Every dataset case needs object input and expected_label")
        _safe_reference(item["expected_label"], "dataset expected_label")
    if evaluation.get("dataset_version") != dataset.get("version"):
        raise RunnerError("evaluation.dataset_version must match dataset.version")
    for field in ("name", "agent_id", "subject_version", "project_key", "dataset_version"):
        if not isinstance(evaluation.get(field), str) or not evaluation[field]:
            raise RunnerError(f"evaluation.{field} is required")
    required_dimensions = evaluation.get("required_dimensions", ["classification", "confidence"])
    if not isinstance(required_dimensions, list) or not required_dimensions or not all(
        isinstance(value, str) for value in required_dimensions
    ):
        raise RunnerError("evaluation.required_dimensions must be a non-empty string array")
    dimensions = set(required_dimensions)
    if len(dimensions) != len(required_dimensions) or not BASE_DIMENSIONS.issubset(dimensions):
        raise RunnerError("evaluation.required_dimensions must include unique classification and confidence values")
    unsupported = sorted(dimensions - SUPPORTED_DIMENSIONS)
    if unsupported:
        raise RunnerError("Unsupported evaluation dimensions: " + ", ".join(unsupported))
    if adapter["type"] in {"command_json_v1", "http_json_target"} and dimensions != BASE_DIMENSIONS:
        raise RunnerError("This connector supports classification and confidence only; use command_json_v2 for redacted advanced measurements")
    return evaluation, cases, adapter


def _validate_http_target(adapter: dict[str, Any]) -> None:
    url = adapter.get("url")
    parsed = urlparse(url) if isinstance(url, str) else None
    if not parsed or parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise RunnerError("http_json_target.url must be an http or https URL")
    if parsed.username or parsed.password or parsed.fragment or parsed.query:
        raise RunnerError("http_json_target.url must not contain credentials, a query string, or a fragment; use headers_from_env for secrets")
    loopback = _is_loopback_host(parsed.hostname)
    environment = adapter.get("target_environment")
    if loopback:
        if environment != "local":
            raise RunnerError("Loopback HTTP targets must declare target_environment as local")
    elif parsed.scheme != "https":
        raise RunnerError("Non-local HTTP targets must use HTTPS")
    elif adapter.get("allow_remote") is not True or environment != "staging":
        raise RunnerError("A non-local target requires allow_remote=true and target_environment=staging; production targets are not supported")
    _validate_tls_config(adapter.get("tls"), required=not loopback)
    _validate_target_attestation(adapter, required=not loopback)
    if adapter.get("request_mode", "message") not in {"message", "input"}:
        raise RunnerError("http_json_target.request_mode must be message or input")
    for name in ("response_label_path", "response_confidence_path"):
        value = adapter.get(name)
        if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*", value):
            raise RunnerError(f"http_json_target.{name} must be a dotted JSON object path")
    headers = adapter.get("headers_from_env", {})
    if not isinstance(headers, dict) or not all(
        isinstance(header, str) and header and isinstance(env_name, str) and re.fullmatch(r"[A-Z_][A-Z0-9_]*", env_name)
        for header, env_name in headers.items()
    ):
        raise RunnerError("http_json_target.headers_from_env must map header names to uppercase environment-variable names")
    max_cases = adapter.get("max_cases", 500)
    if not isinstance(max_cases, int) or max_cases < 1 or max_cases > 10_000:
        raise RunnerError("http_json_target.max_cases must be an integer between 1 and 10,000")
    delay_ms = adapter.get("minimum_delay_ms", 100)
    if not isinstance(delay_ms, int) or delay_ms < 0 or delay_ms > 60_000:
        raise RunnerError("http_json_target.minimum_delay_ms must be an integer between 0 and 60,000")


def _is_loopback_host(hostname: str) -> bool:
    if hostname.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def _validate_sandbox(value: object) -> None:
    if value is None:
        return
    if not isinstance(value, dict):
        raise RunnerError("adapter.sandbox must be an object")
    allowed = {"mode", "image", "memory_mb", "cpu_limit", "pids_limit"}
    if unknown := sorted(set(value) - allowed):
        raise RunnerError("adapter.sandbox has unsupported fields: " + ", ".join(unknown))
    if value.get("mode") != "container":
        raise RunnerError("adapter.sandbox.mode must be container")
    image = value.get("image")
    if not isinstance(image, str) or not re.fullmatch(r"[^@\s]+@sha256:[a-f0-9]{64}", image):
        raise RunnerError("adapter.sandbox.image must be a digest-pinned container image")
    memory_mb = value.get("memory_mb", 512)
    if not isinstance(memory_mb, int) or memory_mb < 64 or memory_mb > 4096:
        raise RunnerError("adapter.sandbox.memory_mb must be an integer between 64 and 4096")
    cpu_limit = value.get("cpu_limit", 1.0)
    if not isinstance(cpu_limit, (int, float)) or isinstance(cpu_limit, bool) or cpu_limit <= 0 or cpu_limit > 4:
        raise RunnerError("adapter.sandbox.cpu_limit must be a number above 0 and at most 4")
    pids_limit = value.get("pids_limit", 64)
    if not isinstance(pids_limit, int) or pids_limit < 16 or pids_limit > 512:
        raise RunnerError("adapter.sandbox.pids_limit must be an integer between 16 and 512")


def _adapter_command(adapter: dict[str, Any]) -> list[str]:
    sandbox = adapter.get("sandbox")
    if not isinstance(sandbox, dict):
        return adapter["command"]
    return [
        "docker", "run", "--rm", "--network", "none", "--read-only",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--pids-limit", str(sandbox.get("pids_limit", 64)),
        "--memory", f"{sandbox.get('memory_mb', 512)}m",
        "--cpus", str(sandbox.get("cpu_limit", 1.0)),
        "--user", "65532:65532", "-i", sandbox["image"], *adapter["command"],
    ]


def _validate_tls_config(value: object, *, required: bool) -> None:
    if value is None:
        if required:
            raise RunnerError("Approved staging targets require a mutual-TLS configuration")
        return
    if not isinstance(value, dict):
        raise RunnerError("http_json_target.tls must be an object")
    allowed = {"client_certificate_path", "client_private_key_path", "private_key_password_env", "ca_certificate_path"}
    if unknown := sorted(set(value) - allowed):
        raise RunnerError("http_json_target.tls has unsupported fields: " + ", ".join(unknown))
    for field in ("client_certificate_path", "client_private_key_path"):
        path = value.get(field)
        if not isinstance(path, str) or not path or not Path(path).is_file():
            raise RunnerError(f"http_json_target.tls.{field} must name an existing local file")
    password_env = value.get("private_key_password_env")
    if password_env is not None and (not isinstance(password_env, str) or not re.fullmatch(r"[A-Z_][A-Z0-9_]*", password_env)):
        raise RunnerError("http_json_target.tls.private_key_password_env must be an uppercase environment-variable name")
    ca_path = value.get("ca_certificate_path")
    if ca_path is not None and (not isinstance(ca_path, str) or not ca_path or not Path(ca_path).is_file()):
        raise RunnerError("http_json_target.tls.ca_certificate_path must name an existing local file")


def _validate_target_attestation(adapter: dict[str, Any], *, required: bool) -> None:
    value = adapter.get("target_attestation")
    if value is None:
        if required:
            raise RunnerError("Approved staging targets require a signed target_attestation")
        return
    if not isinstance(value, dict):
        raise RunnerError("http_json_target.target_attestation must be an object")
    allowed = {"url", "public_key", "required_capabilities"}
    if unknown := sorted(set(value) - allowed):
        raise RunnerError("http_json_target.target_attestation has unsupported fields: " + ", ".join(unknown))
    target = urlparse(adapter["url"])
    attestation_url = value.get("url")
    parsed = urlparse(attestation_url) if isinstance(attestation_url, str) else None
    if not parsed or parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise RunnerError("target_attestation.url must be an HTTPS URL without credentials, query string, or fragment")
    if (parsed.hostname, parsed.port or 443) != (target.hostname, target.port or 443):
        raise RunnerError("target_attestation.url must use the same host and port as the configured staging target")
    public_key = value.get("public_key")
    if not isinstance(public_key, str) or len(_base64(public_key, "target attestation public key")) != 32:
        raise RunnerError("target_attestation.public_key must be a base64 Ed25519 public key")
    capabilities = value.get("required_capabilities")
    allowed_capabilities = {"test_tenant", "synthetic_data", "production_actions_disabled", "least_privilege_identity"}
    if not isinstance(capabilities, list) or set(capabilities) != allowed_capabilities or not all(isinstance(item, str) for item in capabilities):
        raise RunnerError("target_attestation.required_capabilities must require test_tenant, synthetic_data, production_actions_disabled, and least_privilege_identity")


def _verify_target_attestation(adapter: dict[str, Any], opener: Any) -> str | None:
    definition = adapter.get("target_attestation")
    if not isinstance(definition, dict):
        return None
    nonce = str(uuid4())
    request = Request(definition["url"], headers={"Accept": "application/json", "X-ESX-Evaluation-Nonce": nonce}, method="GET")
    try:
        with opener.open(request, timeout=adapter.get("timeout_seconds", 60)) as response:
            raw = response.read(65_537)
    except HTTPError as exc:
        raise RunnerError(f"Staging target attestation returned status {exc.code}") from exc
    except (URLError, TimeoutError, OSError) as exc:
        raise RunnerError("Staging target attestation could not be reached") from exc
    if len(raw) > 65_536:
        raise RunnerError("Staging target attestation exceeded 64 KB")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RunnerError("Staging target attestation did not return JSON") from exc
    if not isinstance(payload, dict):
        raise RunnerError("Staging target attestation must be a JSON object")
    signature = payload.pop("signature", None)
    expected = {
        "schema_version": "esx-test-target-attestation-1.0",
        "nonce": nonce,
        "target_environment": "staging",
    }
    if any(payload.get(key) != value for key, value in expected.items()):
        raise RunnerError("Staging target attestation did not match this evaluation request")
    if not isinstance(payload.get("test_tenant_id"), str):
        raise RunnerError("Staging target attestation must include an opaque test_tenant_id")
    _safe_reference(payload["test_tenant_id"], "target attestation test_tenant_id")
    capabilities = payload.get("capabilities")
    if not isinstance(capabilities, list) or not all(isinstance(item, str) for item in capabilities):
        raise RunnerError("Staging target attestation must include capabilities")
    required = set(definition["required_capabilities"])
    if not required.issubset(capabilities):
        raise RunnerError("Staging target attestation does not confirm every required safety capability")
    if not isinstance(signature, dict) or signature.get("algorithm") != "ed25519" or not isinstance(signature.get("value"), str):
        raise RunnerError("Staging target attestation must contain an Ed25519 signature")
    try:
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(_base64(definition["public_key"], "target attestation public key"))
        public_key.verify(_base64(signature["value"], "target attestation signature"), canonical_json(payload))
    except (ValueError, InvalidSignature, RunnerError) as exc:
        raise RunnerError("Staging target attestation signature is invalid") from exc
    return sha256(payload)


def _http_opener(adapter: dict[str, Any]):
    tls = adapter.get("tls")
    if not isinstance(tls, dict):
        return build_opener(_NoRedirect())
    context = ssl.create_default_context(cafile=tls.get("ca_certificate_path"))
    password_env = tls.get("private_key_password_env")
    password = None
    if password_env:
        import os
        password = os.environ.get(password_env)
        if not password:
            raise RunnerError(f"The mutual-TLS key requires environment variable {password_env}")
    try:
        context.load_cert_chain(tls["client_certificate_path"], tls["client_private_key_path"], password=password)
    except (OSError, ssl.SSLError) as exc:
        raise RunnerError("Could not load the mutual-TLS certificate or private key") from exc
    return build_opener(_NoRedirect(), HTTPSHandler(context=context))


def _invoke_command_adapter(
    adapter: dict[str, Any],
    cases: list[dict[str, Any]],
    evaluation: dict[str, Any],
) -> tuple[dict[str, Any], int, str, str]:
    is_v2 = adapter["type"] == "command_json_v2"
    request = {
        "schema_version": (
            ADAPTER_REQUEST_SCHEMA_VERSION_V2 if is_v2 else ADAPTER_REQUEST_SCHEMA_VERSION_V1
        ),
        "request_id": str(uuid4()),
        "cases": [{"case_id": item["case_id"], "input": item["input"]} for item in cases],
    }
    if is_v2:
        request["evaluation"] = {
            "subject_type": evaluation.get("subject_type", "agent"),
            "required_dimensions": evaluation.get("required_dimensions", ["classification", "confidence"]),
        }
    request_bytes = canonical_json(request)
    started = time.monotonic()
    try:
        completed = subprocess.run(
            _adapter_command(adapter),
            input=request_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=adapter.get("timeout_seconds", 60),
            shell=False,
        )
    except FileNotFoundError as exc:
        executable = "Docker" if isinstance(adapter.get("sandbox"), dict) else adapter["command"][0]
        raise RunnerError(f"Local adapter executable was not found: {executable}") from exc
    except subprocess.TimeoutExpired as exc:
        raise RunnerError("Local adapter exceeded its configured timeout") from exc
    duration_ms = round((time.monotonic() - started) * 1000)
    if completed.returncode != 0:
        raise RunnerError(f"Local adapter exited with status {completed.returncode}; its stderr remains local")
    max_response_bytes = adapter.get("max_response_bytes", 1_048_576)
    if not isinstance(max_response_bytes, int) or max_response_bytes < 1 or max_response_bytes > 10_485_760:
        raise RunnerError("adapter.max_response_bytes must be between 1 and 10,485,760")
    if len(completed.stdout) > max_response_bytes:
        raise RunnerError("Local adapter response exceeded max_response_bytes")
    try:
        response = json.loads(completed.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RunnerError("Local adapter response is not valid JSON") from exc
    expected_schema = ADAPTER_RESPONSE_SCHEMA_VERSION_V2 if is_v2 else ADAPTER_RESPONSE_SCHEMA_VERSION_V1
    if not isinstance(response, dict) or response.get("schema_version") != expected_schema:
        raise RunnerError(f"Local adapter response schema_version must be {expected_schema}")
    return response, duration_ms, sha256(request), hashlib.sha256(completed.stdout).hexdigest()


def _read_json_path(value: object, path: str) -> object:
    current = value
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            raise RunnerError(f"HTTP target response is missing the configured field: {path}")
        current = current[part]
    return current


def _invoke_http_json_target(
    adapter: dict[str, Any], cases: list[dict[str, Any]], evaluation: dict[str, Any]
) -> tuple[dict[str, Any], int, str, str]:
    """Call a customer-owned JSON endpoint once per case without retaining responses."""
    if len(cases) > adapter.get("max_cases", 500):
        raise RunnerError("HTTP target case count exceeds its configured safety limit")
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": f"ExposureScopeX-Eval-Runner/{__version__}",
        "X-ESX-Evaluation-Mode": "local-pre-release",
        "X-ESX-Evaluation-Run": str(uuid4()),
    }
    for header, env_name in adapter.get("headers_from_env", {}).items():
        import os
        secret = os.environ.get(env_name)
        if not secret:
            raise RunnerError(f"The HTTP target requires environment variable {env_name}")
        headers[header] = secret
    results = []
    response_hash = hashlib.sha256()
    request_summary = []
    started = time.monotonic()
    opener = _http_opener(adapter)
    attestation_sha256 = _verify_target_attestation(adapter, opener)
    for index, case in enumerate(cases):
        input_data = case["input"]
        if adapter.get("request_mode", "message") == "message":
            message = input_data.get("message") if isinstance(input_data, dict) else None
            if not isinstance(message, str):
                raise RunnerError("http_json_target request_mode=message requires every case input.message to be a string")
            body: dict[str, Any] = {"message": message}
        else:
            body = {"input": input_data}
        request_summary.append({"case_id": case["case_id"], "body_sha256": sha256(body)})
        try:
            request = Request(adapter["url"], data=canonical_json(body), headers=headers, method="POST")
            with opener.open(request, timeout=adapter.get("timeout_seconds", 60)) as raw_response:
                response_bytes = raw_response.read(1_048_577)
        except HTTPError as exc:
            raise RunnerError(f"HTTP target returned status {exc.code}; its body remains local") from exc
        except (URLError, TimeoutError, OSError) as exc:
            raise RunnerError("HTTP target could not be reached") from exc
        if len(response_bytes) > 1_048_576:
            raise RunnerError("HTTP target response exceeded 1 MB")
        response_hash.update(response_bytes)
        try:
            payload = json.loads(response_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RunnerError("HTTP target did not return a JSON object") from exc
        label = _read_json_path(payload, adapter["response_label_path"])
        confidence = _read_json_path(payload, adapter["response_confidence_path"])
        results.append({"case_id": case["case_id"], "predicted_label": label, "confidence": confidence})
        if index < len(cases) - 1 and adapter.get("minimum_delay_ms", 100):
            time.sleep(adapter.get("minimum_delay_ms", 100) / 1000)
    response = {"schema_version": ADAPTER_RESPONSE_SCHEMA_VERSION_V2, "results": results, "measurements": {}}
    duration_ms = round((time.monotonic() - started) * 1000)
    if attestation_sha256:
        request_summary.insert(0, {"target_attestation_sha256": attestation_sha256})
    return response, duration_ms, sha256(request_summary), response_hash.hexdigest()


def _normalise_results(cases: list[dict[str, Any]], response: dict[str, Any]) -> tuple[list[str], list[float]]:
    results = response.get("results")
    if not isinstance(results, list) or len(results) != len(cases):
        raise RunnerError("Local adapter must return exactly one result for every submitted case")
    by_case: dict[str, dict[str, Any]] = {}
    for item in results:
        if not isinstance(item, dict) or not isinstance(item.get("case_id"), str):
            raise RunnerError("Every adapter result needs case_id, predicted_label, and confidence")
        if item["case_id"] in by_case:
            raise RunnerError("Local adapter returned duplicate case_id values")
        if not isinstance(item.get("predicted_label"), str) or not item["predicted_label"]:
            raise RunnerError("Every adapter result needs a non-empty predicted_label")
        _safe_reference(item["predicted_label"], "adapter predicted_label")
        confidence = item.get("confidence")
        if not isinstance(confidence, (int, float)) or isinstance(confidence, bool) or confidence < 0 or confidence > 1:
            raise RunnerError("Every adapter result confidence must be a number between 0 and 1")
        by_case[item["case_id"]] = item
    expected_ids = {item["case_id"] for item in cases}
    if set(by_case) != expected_ids:
        raise RunnerError("Local adapter result case_id values do not match the submitted dataset")
    return [by_case[item["case_id"]]["predicted_label"] for item in cases], [float(by_case[item["case_id"]]["confidence"]) for item in cases]


def _strict_object(value: object, field: str, *, required: set[str], allowed: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RunnerError(f"{field} must be an object")
    unknown = sorted(set(value) - allowed)
    missing = sorted(required - set(value))
    if unknown:
        raise RunnerError(f"{field} has unsupported fields: " + ", ".join(unknown))
    if missing:
        raise RunnerError(f"{field} is missing fields: " + ", ".join(missing))
    return value


def _safe_reference(value: object, field: str) -> str:
    if not isinstance(value, str) or not _SAFE_REFERENCE.fullmatch(value):
        raise RunnerError(
            f"{field} must be an opaque reference using letters, digits, . _ : / or - (maximum 160 characters)"
        )
    return value


def _safe_references(value: object, field: str, *, minimum: int = 0) -> list[str]:
    if not isinstance(value, list) or len(value) < minimum or len(value) > 10_000:
        raise RunnerError(f"{field} must contain between {minimum} and 10,000 opaque references")
    result = [_safe_reference(item, f"{field}[{index}]") for index, item in enumerate(value)]
    if len(set(result)) != len(result):
        raise RunnerError(f"{field} values must be unique")
    return result


def _boolean(value: object, field: str) -> bool:
    if not isinstance(value, bool):
        raise RunnerError(f"{field} must be true or false")
    return value


def _score(value: object, field: str) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool) or value < 0 or value > 1:
        raise RunnerError(f"{field} must be a number between 0 and 1")
    return float(value)


def _non_negative_integer(value: object, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise RunnerError(f"{field} must be a non-negative integer")
    return value


def _non_negative_number(value: object, field: str) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool) or value < 0:
        raise RunnerError(f"{field} must be a non-negative number")
    return float(value)


def _safe_label(value: object, field: str, *, optional: bool = False) -> str | None:
    if value is None and optional:
        return None
    if not isinstance(value, str) or not value or len(value) > 160 or "\n" in value or "\r" in value:
        raise RunnerError(f"{field} must be a one-line label no longer than 160 characters")
    return value


def _normalise_claim(value: object, field: str) -> dict[str, Any]:
    item = _strict_object(
        value,
        field,
        required={"claim_id", "evidence_ids", "entailment_score", "citations_valid"},
        allowed={"claim_id", "evidence_ids", "entailment_score", "citations_valid", "evidence_integrity_valid"},
    )
    integrity = item.get("evidence_integrity_valid")
    if integrity is not None:
        integrity = _boolean(integrity, f"{field}.evidence_integrity_valid")
    return {
        "claim_id": _safe_reference(item["claim_id"], f"{field}.claim_id"),
        "evidence_ids": _safe_references(item["evidence_ids"], f"{field}.evidence_ids"),
        "entailment_score": _score(item["entailment_score"], f"{field}.entailment_score"),
        "citations_valid": _boolean(item["citations_valid"], f"{field}.citations_valid"),
        "evidence_integrity_valid": integrity,
    }


def _normalise_claims(value: object, field: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value or len(value) > 10_000:
        raise RunnerError(f"{field} must contain between 1 and 10,000 claim verdicts")
    claims = [_normalise_claim(item, f"{field}[{index}]") for index, item in enumerate(value)]
    if len({item["claim_id"] for item in claims}) != len(claims):
        raise RunnerError(f"{field} claim_id values must be unique")
    return claims


def _normalise_security(value: object) -> dict[str, Any]:
    container = _strict_object(value, "measurements.security", required={"cases"}, allowed={"cases"})
    cases = container["cases"]
    if not isinstance(cases, list) or not cases or len(cases) > 10_000:
        raise RunnerError("measurements.security.cases must contain between 1 and 10,000 cases")
    output = []
    for index, raw_case in enumerate(cases):
        field = f"measurements.security.cases[{index}]"
        case = _strict_object(
            raw_case,
            field,
            required={"case_id", "expected_attack_success", "observed_attack_success", "expected_detection", "observed_detection"},
            allowed={"case_id", "expected_attack_success", "observed_attack_success", "expected_detection", "observed_detection", "evidence_ids", "evidence_integrity_valid"},
        )
        integrity = case.get("evidence_integrity_valid")
        if integrity is not None:
            integrity = _boolean(integrity, f"{field}.evidence_integrity_valid")
        output.append({
            "case_id": _safe_reference(case["case_id"], f"{field}.case_id"),
            "expected_attack_success": _boolean(case["expected_attack_success"], f"{field}.expected_attack_success"),
            "observed_attack_success": _boolean(case["observed_attack_success"], f"{field}.observed_attack_success"),
            "expected_detection": _boolean(case["expected_detection"], f"{field}.expected_detection"),
            "observed_detection": _boolean(case["observed_detection"], f"{field}.observed_detection"),
            "evidence_ids": _safe_references(case.get("evidence_ids", []), f"{field}.evidence_ids"),
            "evidence_integrity_valid": integrity,
        })
    if len({item["case_id"] for item in output}) != len(output):
        raise RunnerError("measurements.security.cases case_id values must be unique")
    return {"cases": output}


def _normalise_trajectory(value: object) -> dict[str, Any]:
    item = _strict_object(
        value,
        "measurements.trajectory",
        required={"required_milestones", "observed_milestones", "action_count"},
        allowed={"required_milestones", "observed_milestones", "action_count", "redundant_actions", "policy_violations", "scope_violations", "tool_misuse_events"},
    )
    action_count = _non_negative_integer(item["action_count"], "measurements.trajectory.action_count")
    redundant = _non_negative_integer(item.get("redundant_actions", 0), "measurements.trajectory.redundant_actions")
    if redundant > action_count:
        raise RunnerError("measurements.trajectory.redundant_actions cannot exceed action_count")
    return {
        "required_milestones": _safe_references(item["required_milestones"], "measurements.trajectory.required_milestones", minimum=1),
        "observed_milestones": _safe_references(item["observed_milestones"], "measurements.trajectory.observed_milestones"),
        "action_count": action_count,
        "redundant_actions": redundant,
        "policy_violations": _safe_references(item.get("policy_violations", []), "measurements.trajectory.policy_violations"),
        "scope_violations": _safe_references(item.get("scope_violations", []), "measurements.trajectory.scope_violations"),
        "tool_misuse_events": _safe_references(item.get("tool_misuse_events", []), "measurements.trajectory.tool_misuse_events"),
    }


def _normalise_rag(value: object) -> dict[str, Any]:
    item = _strict_object(
        value,
        "measurements.rag",
        required={"relevant_document_ids", "retrieved_document_ids", "cited_document_ids", "answer_claims"},
        allowed={"relevant_document_ids", "retrieved_document_ids", "cited_document_ids", "answer_claims", "k"},
    )
    k = item.get("k")
    if k is not None and (not isinstance(k, int) or isinstance(k, bool) or k < 1):
        raise RunnerError("measurements.rag.k must be a positive integer when supplied")
    return {
        "relevant_document_ids": _safe_references(item["relevant_document_ids"], "measurements.rag.relevant_document_ids", minimum=1),
        "retrieved_document_ids": _safe_references(item["retrieved_document_ids"], "measurements.rag.retrieved_document_ids"),
        "cited_document_ids": _safe_references(item["cited_document_ids"], "measurements.rag.cited_document_ids"),
        "answer_claims": _normalise_claims(item["answer_claims"], "measurements.rag.answer_claims"),
        "k": k,
    }


def _normalise_robustness(value: object) -> dict[str, Any]:
    item = _strict_object(
        value,
        "measurements.robustness",
        required={"baseline_correct", "baseline_confidence", "perturbations"},
        allowed={"baseline_correct", "baseline_confidence", "baseline_label", "perturbations"},
    )
    cases = item["perturbations"]
    if not isinstance(cases, list) or not cases or len(cases) > 10_000:
        raise RunnerError("measurements.robustness.perturbations must contain between 1 and 10,000 cases")
    output = []
    for index, raw_case in enumerate(cases):
        field = f"measurements.robustness.perturbations[{index}]"
        case = _strict_object(
            raw_case,
            field,
            required={"case_id", "correct", "confidence"},
            allowed={"case_id", "correct", "confidence", "predicted_label", "variation_type"},
        )
        variation = case.get("variation_type", "perturbation")
        if variation not in {"paraphrase", "perturbation", "repeat"}:
            raise RunnerError(f"{field}.variation_type must be paraphrase, perturbation, or repeat")
        output.append({
            "case_id": _safe_reference(case["case_id"], f"{field}.case_id"),
            "correct": _boolean(case["correct"], f"{field}.correct"),
            "confidence": _score(case["confidence"], f"{field}.confidence"),
            "predicted_label": _safe_label(case.get("predicted_label"), f"{field}.predicted_label", optional=True),
            "variation_type": variation,
        })
    if len({case["case_id"] for case in output}) != len(output):
        raise RunnerError("measurements.robustness.perturbations case_id values must be unique")
    return {
        "baseline_correct": _boolean(item["baseline_correct"], "measurements.robustness.baseline_correct"),
        "baseline_confidence": _score(item["baseline_confidence"], "measurements.robustness.baseline_confidence"),
        "baseline_label": _safe_label(item.get("baseline_label"), "measurements.robustness.baseline_label", optional=True),
        "perturbations": output,
    }


def _normalise_cost_efficiency(value: object) -> dict[str, Any]:
    item = _strict_object(
        value,
        "measurements.cost_efficiency",
        required={"cost_source", "observations"},
        allowed={"cost_source", "observations"},
    )
    if item["cost_source"] not in {"provider_reported", "metered"}:
        raise RunnerError("measurements.cost_efficiency.cost_source must be provider_reported or metered")
    observations = item["observations"]
    if not isinstance(observations, list) or not observations or len(observations) > 10_000:
        raise RunnerError("measurements.cost_efficiency.observations must contain between 1 and 10,000 observations")
    output = []
    for index, raw_observation in enumerate(observations):
        field = f"measurements.cost_efficiency.observations[{index}]"
        observation = _strict_object(
            raw_observation,
            field,
            required={"case_id", "input_tokens", "output_tokens", "request_count", "cost_usd", "latency_ms"},
            allowed={"case_id", "input_tokens", "output_tokens", "request_count", "retry_count", "tool_call_count", "cache_hit", "fallback_used", "cost_usd", "latency_ms", "timed_out"},
        )
        output.append({
            "case_id": _safe_reference(observation["case_id"], f"{field}.case_id"),
            "input_tokens": _non_negative_integer(observation["input_tokens"], f"{field}.input_tokens"),
            "output_tokens": _non_negative_integer(observation["output_tokens"], f"{field}.output_tokens"),
            "request_count": _non_negative_integer(observation["request_count"], f"{field}.request_count"),
            "retry_count": _non_negative_integer(observation.get("retry_count", 0), f"{field}.retry_count"),
            "tool_call_count": _non_negative_integer(observation.get("tool_call_count", 0), f"{field}.tool_call_count"),
            "cache_hit": _boolean(observation.get("cache_hit", False), f"{field}.cache_hit"),
            "fallback_used": _boolean(observation.get("fallback_used", False), f"{field}.fallback_used"),
            "cost_usd": _non_negative_number(observation["cost_usd"], f"{field}.cost_usd"),
            "latency_ms": _non_negative_integer(observation["latency_ms"], f"{field}.latency_ms"),
            "timed_out": _boolean(observation.get("timed_out", False), f"{field}.timed_out"),
        })
    if any(observation["request_count"] < 1 for observation in output):
        raise RunnerError("measurements.cost_efficiency.observations request_count must be at least 1")
    if len({observation["case_id"] for observation in output}) != len(output):
        raise RunnerError("measurements.cost_efficiency.observations case_id values must be unique")
    return {"cost_source": item["cost_source"], "observations": output}


def _normalise_decisions(value: object, *, field: str, actor_field: str, with_confidence: bool) -> dict[str, Any]:
    container = _strict_object(value, field, required={"decisions"}, allowed={"decisions"})
    decisions = container["decisions"]
    if not isinstance(decisions, list) or not decisions or len(decisions) > 10_000:
        raise RunnerError(f"{field}.decisions must contain between 1 and 10,000 decisions")
    output = []
    for index, raw_decision in enumerate(decisions):
        item_field = f"{field}.decisions[{index}]"
        required = {"case_id", actor_field, "verdict"}
        if with_confidence:
            required.add("confidence")
        item = _strict_object(raw_decision, item_field, required=required, allowed=required)
        verdict = item["verdict"]
        if verdict not in {"pass", "fail", "inconclusive"}:
            raise RunnerError(f"{item_field}.verdict must be pass, fail, or inconclusive")
        normalised = {
            "case_id": _safe_reference(item["case_id"], f"{item_field}.case_id"),
            actor_field: _safe_reference(item[actor_field], f"{item_field}.{actor_field}"),
            "verdict": verdict,
        }
        if with_confidence:
            normalised["confidence"] = _score(item["confidence"], f"{item_field}.confidence")
        output.append(normalised)
    if len({f"{item['case_id']}\x00{item[actor_field]}" for item in output}) != len(output):
        raise RunnerError(f"{field}.decisions case and {actor_field} pairs must be unique")
    return {"decisions": output}


def _normalise_trace(value: object) -> dict[str, Any]:
    item = _strict_object(
        value,
        "measurements.trace_envelope",
        required={"trace_id", "schema_version", "producer", "agent_ids", "redaction_status"},
        allowed={"trace_id", "schema_version", "producer", "agent_ids", "redaction_status", "events", "event_count", "content_sha256"},
    )
    redaction_status = item["redaction_status"]
    if redaction_status not in {"redacted", "metadata_only"}:
        raise RunnerError("measurements.trace_envelope.redaction_status must be redacted or metadata_only")
    base = {
        "trace_id": _safe_reference(item["trace_id"], "measurements.trace_envelope.trace_id"),
        "schema_version": _safe_reference(item["schema_version"], "measurements.trace_envelope.schema_version"),
        "producer": _safe_reference(item["producer"], "measurements.trace_envelope.producer"),
        "agent_ids": _safe_references(item["agent_ids"], "measurements.trace_envelope.agent_ids", minimum=1),
        "redaction_status": redaction_status,
    }
    events = item.get("events", [])
    if not isinstance(events, list) or len(events) > 10_000:
        raise RunnerError("measurements.trace_envelope.events must be an array with at most 10,000 entries")
    normalised_events = []
    for index, raw_event in enumerate(events):
        field = f"measurements.trace_envelope.events[{index}]"
        event = _strict_object(
            raw_event,
            field,
            required={"event_id", "sequence", "agent_id", "event_type", "outcome"},
            allowed={"event_id", "sequence", "agent_id", "event_type", "outcome", "tool_name", "scope_reference", "evidence_ids"},
        )
        if event["event_type"] not in {"handoff", "model_request", "model_response", "tool_call", "tool_result", "policy_decision", "final_response", "error"}:
            raise RunnerError(f"{field}.event_type is not supported")
        if event["outcome"] not in {"succeeded", "failed", "blocked", "skipped"}:
            raise RunnerError(f"{field}.outcome is not supported")
        normalised_events.append({
            "event_id": _safe_reference(event["event_id"], f"{field}.event_id"),
            "sequence": _non_negative_integer(event["sequence"], f"{field}.sequence"),
            "agent_id": _safe_reference(event["agent_id"], f"{field}.agent_id"),
            "event_type": event["event_type"],
            "outcome": event["outcome"],
            "tool_name": _safe_reference(event["tool_name"], f"{field}.tool_name") if event.get("tool_name") is not None else None,
            "scope_reference": _safe_reference(event["scope_reference"], f"{field}.scope_reference") if event.get("scope_reference") is not None else None,
            "evidence_ids": _safe_references(event.get("evidence_ids", []), f"{field}.evidence_ids"),
        })
    if len({event["event_id"] for event in normalised_events}) != len(normalised_events):
        raise RunnerError("measurements.trace_envelope.events event_id values must be unique")
    if len({event["sequence"] for event in normalised_events}) != len(normalised_events):
        raise RunnerError("measurements.trace_envelope.events sequence values must be unique")
    declared_agents = set(base["agent_ids"])
    if unknown_agents := sorted({event["agent_id"] for event in normalised_events} - declared_agents):
        raise RunnerError("trace events reference undeclared agents: " + ", ".join(unknown_agents))
    if redaction_status == "redacted":
        if not normalised_events:
            raise RunnerError("redacted trace envelopes require redacted metadata events")
        return {**base, "event_count": len(normalised_events), "content_sha256": sha256(normalised_events), "events": normalised_events}
    if normalised_events:
        raise RunnerError("metadata-only trace envelopes cannot contain events")
    content_hash = item.get("content_sha256")
    if not isinstance(content_hash, str) or not re.fullmatch(r"[a-f0-9]{64}", content_hash):
        raise RunnerError("metadata-only trace envelopes require content_sha256")
    return {
        **base,
        "event_count": _non_negative_integer(item.get("event_count", 0), "measurements.trace_envelope.event_count"),
        "content_sha256": content_hash,
        "events": [],
    }


def _normalise_measurements(
    response: dict[str, Any],
    *,
    adapter_type: str,
    required_dimensions: list[str],
) -> dict[str, Any]:
    if adapter_type in {"command_json_v1", "http_json_target"}:
        return {}
    raw = response.get("measurements", {})
    if not isinstance(raw, dict):
        raise RunnerError("command_json_v2 responses must include a measurements object")
    normalisers = {
        "groundedness": lambda value: _normalise_claims(value, "measurements.claims"),
        "security": _normalise_security,
        "trajectory": _normalise_trajectory,
        "rag": _normalise_rag,
        "robustness": _normalise_robustness,
        "judge_agreement": lambda value: _normalise_decisions(value, field="measurements.judge_agreement", actor_field="judge_id", with_confidence=True),
        "reproducibility": lambda value: _normalise_decisions(value, field="measurements.reproducibility", actor_field="run_id", with_confidence=False),
        "cost_efficiency": _normalise_cost_efficiency,
        "trace_envelope": _normalise_trace,
    }
    allowed = {"claims", "security", "trajectory", "rag", "robustness", "judge_agreement", "reproducibility", "cost_efficiency", "trace_envelope"}
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise RunnerError("measurements has unsupported fields: " + ", ".join(unknown))
    field_by_dimension = {
        "groundedness": "claims",
        **{
            dimension: dimension
            for dimension in normalisers
            if dimension not in {"trace_envelope", "groundedness"}
        },
    }
    output: dict[str, Any] = {}
    for dimension in set(required_dimensions) - BASE_DIMENSIONS:
        field = field_by_dimension[dimension]
        if field not in raw:
            raise RunnerError(f"command_json_v2 response is missing measurements.{field} for required {dimension}")
        output[field] = normalisers[dimension](raw[field])
    for dimension, field in field_by_dimension.items():
        if field in raw and dimension not in required_dimensions:
            raise RunnerError(f"measurements.{field} requires {dimension} in evaluation.required_dimensions")
    if "trace_envelope" in raw:
        output["trace_envelope"] = _normalise_trace(raw["trace_envelope"])
    return output


def _github_source(token: str) -> dict[str, Any]:
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload.encode("ascii")))
    except (IndexError, UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        raise RunnerError("Cannot read GitHub OIDC token claims for package provenance") from exc
    required = ("repository", "sha", "workflow_ref", "run_id")
    if any(not isinstance(claims.get(item), (str, int)) or not str(claims[item]) for item in required):
        raise RunnerError("GitHub OIDC token does not expose the required provenance claims")
    return {
        "origin": "github_actions",
        "repository": str(claims["repository"]),
        "commit_sha": str(claims["sha"]),
        "workflow_ref": str(claims["workflow_ref"]),
        "external_run_id": str(claims["run_id"]),
    }


def build_package(config: dict[str, Any], *, github_oidc_token: str | None = None) -> dict[str, Any]:
    evaluation, cases, adapter = _validate_config(config)
    if adapter["type"] == "http_json_target":
        response, duration_ms, request_sha, response_sha = _invoke_http_json_target(adapter, cases, evaluation)
    else:
        response, duration_ms, request_sha, response_sha = _invoke_command_adapter(adapter, cases, evaluation)
    predicted_labels, confidences = _normalise_results(cases, response)
    measurements = _normalise_measurements(
        response,
        adapter_type=adapter["type"],
        required_dimensions=evaluation.get("required_dimensions", ["classification", "confidence"]),
    )
    source_config = config.get("source", {})
    if not isinstance(source_config, dict):
        raise RunnerError("source must be an object when supplied")
    source = _github_source(github_oidc_token) if github_oidc_token else {
        "origin": source_config.get("origin", "local"),
        "repository": source_config.get("repository"),
        "commit_sha": source_config.get("commit_sha"),
        "workflow_ref": source_config.get("workflow_ref"),
        "external_run_id": source_config.get("external_run_id"),
    }
    if source["origin"] not in {"local", "other_ci", "github_actions"}:
        raise RunnerError("source.origin must be local, other_ci, or github_actions")
    package = {
        "schema_version": PACKAGE_SCHEMA_VERSION,
        "package_id": str(uuid4()),
        "issued_at": datetime.now(timezone.utc).isoformat(),
        "runner_version": __version__,
        "execution": {
            "adapter_type": adapter["type"],
            "sandbox_mode": adapter.get("sandbox", {}).get("mode", "none") if isinstance(adapter.get("sandbox"), dict) else "none",
            "case_count": len(cases),
            "duration_ms": duration_ms,
            "request_sha256": request_sha,
            "response_sha256": response_sha,
        },
        "source": source,
        "evaluation": {
            "name": evaluation["name"],
            "agent_id": evaluation["agent_id"],
            "subject_version": evaluation["subject_version"],
            "subject_type": evaluation.get("subject_type", "agent"),
            "project_key": evaluation["project_key"],
            "dataset_version": evaluation["dataset_version"],
            "policy_id": evaluation.get("policy_id", "esx-ai-evaluator-release-1.0"),
            "required_dimensions": evaluation.get("required_dimensions", ["classification", "confidence"]),
            "expected_labels": [item["expected_label"] for item in cases],
            "predicted_labels": predicted_labels,
            "confidences": confidences,
            **measurements,
        },
    }
    # Raw case inputs, adapter stdout/stderr, and any local secrets are never added.
    return package


def sign_package(package: dict[str, Any], *, identity_id: str, private_key_path: str | Path) -> dict[str, Any]:
    unsigned = {key: value for key, value in package.items() if key != "signature"}
    signature = _load_private_key(private_key_path).sign(canonical_json(unsigned))
    return {
        **unsigned,
        "signature": {
            "identity_id": identity_id,
            "algorithm": "ed25519",
            "value": base64.b64encode(signature).decode("ascii"),
        },
    }
