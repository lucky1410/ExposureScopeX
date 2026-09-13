from cryptography.fernet import Fernet, InvalidToken

from .config import settings


def _cipher() -> Fernet:
    return Fernet(settings().credential_encryption_key.encode("ascii"))


def encrypt_secret(value: str) -> bytes:
    return _cipher().encrypt(value.encode("utf-8"))


def decrypt_secret(value: bytes) -> str:
    try:
        return _cipher().decrypt(value).decode("utf-8")
    except InvalidToken as exc:
        raise RuntimeError("Stored assessment credentials cannot be decrypted") from exc
