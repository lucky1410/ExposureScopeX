from __future__ import annotations

import re


_SENSITIVE_KEYS = {
    "authorization",
    "cookie",
    "set-cookie",
    "password",
    "passwd",
    "secret",
    "api-key",
    "apikey",
    "access-token",
    "refresh-token",
}


def _normalized_key(value: object) -> str:
    return re.sub(r"[_\s]+", "-", str(value).strip().lower())


def redact_text(value: str) -> str:
    value = re.sub(r"(?im)^(authorization\s*:\s*)(.+)$", r"\1[REDACTED]", value)
    value = re.sub(r"(?im)^(cookie\s*:\s*)(.+)$", r"\1[REDACTED]", value)
    value = re.sub(r"(?im)^(set-cookie\s*:\s*)(.+)$", r"\1[REDACTED]", value)
    value = re.sub(r"(?i)(password|passwd|secret|api[_-]?key)(\s*[=:]\s*)[^\s,;\"']+", r"\1\2[REDACTED]", value)
    return value


def redact_object(value):
    if isinstance(value, dict):
        return {
            key: "[REDACTED]" if _normalized_key(key) in _SENSITIVE_KEYS else redact_object(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_object(item) for item in value]
    return redact_text(value) if isinstance(value, str) else value
