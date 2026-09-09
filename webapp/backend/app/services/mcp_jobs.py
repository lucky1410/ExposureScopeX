"""Encrypted transient payloads and cancellation flags for MCP scan jobs."""

import base64
import hashlib
import json
from typing import Any

import redis
from cryptography.fernet import Fernet, InvalidToken

from app.config import settings


def _fernet() -> Fernet:
    digest = hashlib.sha256(f"exposurescopex:mcp:{settings.SECRET_KEY}".encode()).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def encrypt_mcp_payload(payload: dict[str, Any]) -> str:
    """Encrypt credentials before the job payload reaches Redis/Celery."""
    return _fernet().encrypt(json.dumps(payload, separators=(",", ":")).encode()).decode()


def decrypt_mcp_payload(ciphertext: str) -> dict[str, Any]:
    try:
        value = json.loads(_fernet().decrypt(ciphertext.encode(), ttl=21600).decode())
    except (InvalidToken, json.JSONDecodeError) as exc:
        raise ValueError("MCP job credentials expired or could not be decrypted") from exc
    if not isinstance(value, dict):
        raise ValueError("MCP job payload is invalid")
    return value


def request_mcp_cancel(run_id: str) -> None:
    client = redis.from_url(settings.REDIS_URL)
    client.setex(f"mcp:cancel:{run_id}", 3600, "1")


def mcp_cancel_requested(run_id: str) -> bool:
    client = redis.from_url(settings.REDIS_URL)
    return bool(client.get(f"mcp:cancel:{run_id}"))


def clear_mcp_cancel(run_id: str) -> None:
    client = redis.from_url(settings.REDIS_URL)
    client.delete(f"mcp:cancel:{run_id}")
