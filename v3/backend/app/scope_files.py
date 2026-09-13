from __future__ import annotations

import csv
import hmac
import hashlib
import io
import json
from datetime import datetime, timezone
from urllib.parse import urlsplit

from .config import settings


def normalize_target(value: str) -> str:
    parsed = urlsplit(value.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("target must be an absolute HTTP or HTTPS URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("target must not include credentials, a query, or a fragment")
    return parsed.geturl().rstrip("/")


def _paths(value: object, field: str) -> list[str]:
    if value in (None, ""):
        return []
    values = value.split(";") if isinstance(value, str) else value
    if not isinstance(values, list) or any(not isinstance(item, str) for item in values):
        raise ValueError(f"{field} must be an array of paths")
    normalized = []
    for item in values:
        path = item.strip()
        if not path.startswith("/") or "//" in path or "/../" in f"/{path.lstrip('/')}/":
            raise ValueError(f"{field} contains an invalid path: {item}")
        normalized.append(path.rstrip("/") or "/")
    return sorted(set(normalized))


def _ports(value: object) -> list[int]:
    if value in (None, ""):
        return []
    values = value.split(";") if isinstance(value, str) else value
    if not isinstance(values, list):
        raise ValueError("allowed_ports must be an array of port numbers")
    ports = []
    for item in values:
        try:
            port = int(item)
        except (TypeError, ValueError) as exc:
            raise ValueError("allowed_ports contains a non-numeric port") from exc
        if not 1 <= port <= 65535:
            raise ValueError("allowed_ports must be between 1 and 65535")
        ports.append(port)
    return sorted(set(ports))


def normalize_scope(raw: dict, source_format: str, source_sha256: str | None = None) -> dict:
    target = normalize_target(str(raw.get("target") or raw.get("asset") or ""))
    authorization_id = str(raw.get("authorization_id") or "").strip()
    if not authorization_id:
        raise ValueError("authorization_id is required in a scope file")
    expiry_value = str(raw.get("authorization_expires_at") or "").strip()
    try:
        expires_at = datetime.fromisoformat(expiry_value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("authorization_expires_at must be an ISO-8601 timestamp") from exc
    if expires_at.tzinfo is None or expires_at <= datetime.now(timezone.utc):
        raise ValueError("authorization_expires_at must be a future UTC timestamp")
    parsed = urlsplit(target)
    target_port = parsed.port or (443 if parsed.scheme == "https" else 80)
    ports = _ports(raw.get("allowed_ports")) or [target_port]
    if target_port not in ports:
        raise ValueError("allowed_ports must include the target URL port")
    allowed_paths = _paths(raw.get("allowed_paths"), "allowed_paths") or ["/"]
    excluded_paths = _paths(raw.get("excluded_paths"), "excluded_paths")
    credential_reference = raw.get("credential_reference")
    if credential_reference is not None:
        credential_reference = str(credential_reference).strip()
        if not credential_reference or any(character.isspace() for character in credential_reference):
            raise ValueError("credential_reference must be an opaque vault or secret-manager reference")
    normalized = {
        "target": target,
        "authorization_id": authorization_id[:160],
        "authorization_expires_at": expires_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        "allowed_paths": allowed_paths,
        "excluded_paths": excluded_paths,
        "allowed_ports": ports,
        "credential_reference": credential_reference or None,
        "source_format": source_format,
        "source_sha256": source_sha256,
    }
    return normalized


def parse_scope_file(content: str, filename: str) -> dict:
    suffix = filename.lower().rsplit(".", 1)[-1] if "." in filename else ""
    digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
    if suffix == "json":
        try:
            raw = json.loads(content)
        except json.JSONDecodeError as exc:
            raise ValueError("scope JSON is invalid") from exc
        if isinstance(raw, list):
            if len(raw) != 1:
                raise ValueError("one assessment requires exactly one scope asset")
            raw = raw[0]
        if not isinstance(raw, dict):
            raise ValueError("scope JSON must be an object or a one-item array")
        return sign_scope(normalize_scope(raw, "json", digest))
    if suffix == "csv":
        rows = list(csv.DictReader(io.StringIO(content)))
        if len(rows) != 1:
            raise ValueError("scope CSV requires exactly one data row per assessment")
        return sign_scope(normalize_scope(rows[0], "csv", digest))
    raise ValueError("scope files must use .json or .csv")


def _scope_bytes(scope: dict) -> bytes:
    signed = {key: value for key, value in scope.items() if key != "validation_token"}
    return json.dumps(signed, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_scope(scope: dict) -> dict:
    signed = dict(scope)
    signed["validation_token"] = hmac.new(
        settings().scope_validation_key.encode("utf-8"), _scope_bytes(signed), hashlib.sha256
    ).hexdigest()
    return signed


def scope_token_is_valid(scope: dict) -> bool:
    token = str(scope.get("validation_token") or "")
    expected = sign_scope({key: value for key, value in scope.items() if key != "validation_token"})["validation_token"]
    return hmac.compare_digest(token, expected)


def path_is_in_scope(url: str, scope: dict | None) -> bool:
    if not scope:
        return True
    parsed, target = urlsplit(url), urlsplit(scope["target"])
    if (parsed.scheme, parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80)) != (target.scheme, target.hostname, target.port or (443 if target.scheme == "https" else 80)):
        return False
    path = parsed.path or "/"
    if any(path == excluded or path.startswith(excluded.rstrip("/") + "/") for excluded in scope.get("excluded_paths", [])):
        return False
    return any(path == allowed or path.startswith(allowed.rstrip("/") + "/") for allowed in scope.get("allowed_paths", ["/"]))


def scope_dispatch_error(scope: dict | None, target: str) -> str | None:
    if not scope:
        return None
    try:
        expires_at = datetime.fromisoformat(scope["authorization_expires_at"].replace("Z", "+00:00"))
    except (KeyError, ValueError):
        return "Stored scope authorization is malformed"
    if expires_at <= datetime.now(timezone.utc):
        return "Scope authorization has expired"
    if normalize_target(target) != scope["target"] or not path_is_in_scope(target, scope):
        return "Assessment target is outside the stored scope declaration"
    return None
