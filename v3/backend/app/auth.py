import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import Cookie, HTTPException, Response, status

from .config import settings
from .db import pool
from .security import Credentials, OwnerSetup, password_digest, verify_password

SESSION_COOKIE = "esx_session"


def public_user(row) -> dict:
    return {
        "id": row["id"],
        "email": row["email"],
        "display_name": row["display_name"],
        "role": row["role"],
    }


async def create_session(response: Response, user_id) -> None:
    token = secrets.token_urlsafe(48)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    expires = datetime.now(timezone.utc) + timedelta(hours=settings().session_ttl_hours)
    await pool().execute(
        "INSERT INTO sessions (user_id, token_hash, expires_at) VALUES ($1, $2, $3)",
        user_id,
        token_hash,
        expires,
    )
    response.set_cookie(
        SESSION_COOKIE,
        token,
        httponly=True,
        secure=settings().secure_cookies,
        samesite="lax",
        max_age=settings().session_ttl_hours * 3600,
        path="/",
    )


async def current_user(esx_session: str | None = Cookie(default=None)) -> dict:
    if not esx_session:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    token_hash = hashlib.sha256(esx_session.encode()).hexdigest()
    row = await pool().fetchrow(
        """
        SELECT u.* FROM sessions s
        JOIN users u ON u.id = s.user_id
        WHERE s.token_hash = $1 AND s.expires_at > now() AND u.active = true
        """,
        token_hash,
    )
    if row is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expired")
    await pool().execute(
        "UPDATE sessions SET last_seen_at = now() WHERE token_hash = $1", token_hash
    )
    return public_user(row)
