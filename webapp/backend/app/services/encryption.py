"""Fernet symmetric encryption for secrets at rest.

All cloud source credentials are encrypted before DB write and
decrypted on read. The key is derived from SECRET_KEY in settings.
"""

import base64
import hashlib
import json
from typing import Any

from cryptography.fernet import Fernet

from app.config import settings


def _get_fernet() -> Fernet:
    """Derive a stable 32-byte Fernet key from the application SECRET_KEY."""
    raw = hashlib.sha256(settings.SECRET_KEY.encode()).digest()
    key = base64.urlsafe_b64encode(raw)
    return Fernet(key)


def encrypt_dict(data: dict[str, Any]) -> str:
    """Encrypt a dict to a base64 ciphertext string."""
    f = _get_fernet()
    plaintext = json.dumps(data).encode()
    return f.encrypt(plaintext).decode()


def decrypt_dict(ciphertext: str) -> dict[str, Any]:
    """Decrypt a ciphertext string back to a dict."""
    f = _get_fernet()
    plaintext = f.decrypt(ciphertext.encode())
    return json.loads(plaintext)


def mask_secrets(data: dict[str, Any]) -> dict[str, Any]:
    """Return a copy with secret-looking keys replaced by '••••••••'."""
    secret_keys = {"secret", "key", "password", "token", "credential", "private"}
    return {
        k: "••••••••" if any(s in k.lower() for s in secret_keys) else v
        for k, v in data.items()
    }
