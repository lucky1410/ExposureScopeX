"""Authentication endpoints: register, login, refresh, me."""

import hashlib
import hmac
import re
import secrets
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.dependencies import get_current_user, get_db
from app.models.user import Organization, User
from app.models.auth_session import AuthSession
from app.schemas.auth import LoginRequest, RefreshRequest, RegisterRequest, TokenResponse
from app.schemas.user import UserResponse
from app.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    get_password_hash,
    verify_password,
)
from app.services.audit import AuditEvent, write_audit

router = APIRouter(prefix="/auth", tags=["Authentication"])


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _set_session_cookies(response: Response, access_token: str, refresh_token: str, csrf_token: str) -> None:
    common = {
        "secure": settings.SESSION_COOKIE_SECURE,
        "samesite": settings.SESSION_COOKIE_SAMESITE,
    }
    response.set_cookie(
        "access_token",
        access_token,
        httponly=True,
        path="/",
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        **common,
    )
    response.set_cookie(
        "refresh_token",
        refresh_token,
        httponly=True,
        path="/api/v1/auth",
        max_age=settings.REFRESH_TOKEN_EXPIRE_DAYS * 86400,
        **common,
    )
    response.set_cookie(
        "csrf_token",
        csrf_token,
        httponly=False,
        path="/",
        max_age=settings.REFRESH_TOKEN_EXPIRE_DAYS * 86400,
        **common,
    )


def _clear_session_cookies(response: Response) -> None:
    response.delete_cookie("access_token", path="/")
    response.delete_cookie("refresh_token", path="/api/v1/auth")
    response.delete_cookie("csrf_token", path="/")


def _device_name(user_agent: str | None) -> str | None:
    if not user_agent:
        return None
    return user_agent[:255]


async def _issue_session(db: AsyncSession, user: User, response: Response, request: Request) -> TokenResponse:
    session_id = uuid.uuid4()
    csrf_token = secrets.token_urlsafe(32)
    token_data = {
        "sub": str(user.id),
        "org_id": str(user.org_id),
        "role": user.role,
        "sid": str(session_id),
        "jti": str(uuid.uuid4()),
    }
    access_token = create_access_token(token_data)
    refresh_token = create_refresh_token(token_data)
    db.add(AuthSession(
        id=session_id,
        user_id=user.id,
        org_id=user.org_id,
        refresh_token_hash=_digest(refresh_token),
        csrf_token_hash=_digest(csrf_token),
        expires_at=datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent", "")[:2000] or None,
        device_name=_device_name(request.headers.get("user-agent")),
    ))
    await db.flush()
    _set_session_cookies(response, access_token, refresh_token, csrf_token)
    return TokenResponse(
        access_token=access_token,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        refresh_expires_in=settings.REFRESH_TOKEN_EXPIRE_DAYS * 86400,
    )


@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def register(payload: RegisterRequest, request: Request, response: Response, db: AsyncSession = Depends(get_db)):
    """Register a new user and organization."""
    user_count = await db.scalar(select(func.count()).select_from(User))
    if user_count and not settings.ALLOW_PUBLIC_REGISTRATION:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Public registration is disabled; ask an administrator to invite you",
        )
    # Check email uniqueness
    existing = await db.execute(select(User).where(User.email == payload.email))
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered",
        )

    # Check username uniqueness
    existing = await db.execute(select(User).where(User.username == payload.username))
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username already taken",
        )

    # Registration always creates a new tenant. Existing tenants are invite-only.
    slug = re.sub(r"[^a-z0-9]+", "-", payload.organization_name.lower()).strip("-")
    if not slug:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid organization name")
    result = await db.execute(select(Organization).where(Organization.slug == slug))
    org = result.scalar_one_or_none()
    if org is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Organization name is unavailable",
        )
    org = Organization(name=payload.organization_name, slug=slug)
    db.add(org)
    try:
        await db.flush()
    except IntegrityError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Organization name is unavailable",
        )

    # Create user
    user = User(
        org_id=org.id,
        email=payload.email,
        username=payload.username,
        password_hash=get_password_hash(payload.password),
        role="admin",
        is_active=True,
    )
    db.add(user)
    await db.flush()

    return await _issue_session(db, user, response, request)


@router.post("/login", response_model=TokenResponse)
async def login(payload: LoginRequest, request: Request, response: Response, db: AsyncSession = Depends(get_db)):
    """Authenticate a user and return JWT tokens."""
    ip = request.client.host if request.client else None
    result = await db.execute(select(User).where(User.email == payload.email))
    user = result.scalar_one_or_none()

    if user is None or not verify_password(payload.password, user.password_hash):
        await write_audit(
            db,
            event=AuditEvent.LOGIN_FAILURE,
            details={"email": payload.email},
            ip_address=ip,
            success=False,
        )
        # The request exits with an HTTP error, so persist this security event
        # before the request-scoped transaction is rolled back.
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is deactivated",
        )

    # Update last login
    user.last_login = datetime.now(timezone.utc)
    await db.flush()

    await write_audit(
        db,
        event=AuditEvent.LOGIN_SUCCESS,
        user_id=str(user.id),
        org_id=str(user.org_id),
        ip_address=ip,
    )

    return await _issue_session(db, user, response, request)


@router.post("/refresh", response_model=TokenResponse)
async def refresh(
    payload: RefreshRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    """Issue new access and refresh tokens from a valid refresh token."""
    cookie_token = request.cookies.get("refresh_token")
    raw_token = cookie_token or payload.refresh_token
    decoded = decode_token(raw_token) if raw_token else None
    if decoded is None or decoded.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )

    user_id = decoded.get("sub")
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
        )

    try:
        normalized_user_id = uuid.UUID(user_id)
    except (ValueError, TypeError):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid token payload")
    result = await db.execute(select(User).where(User.id == normalized_user_id))
    user = result.scalar_one_or_none()

    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )

    session_id = decoded.get("sid")
    if not session_id:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Legacy refresh token is no longer accepted")
    try:
        normalized_session_id = uuid.UUID(session_id)
    except (ValueError, TypeError):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid session identifier")

    auth_session = await db.scalar(
        select(AuthSession).where(
            AuthSession.id == normalized_session_id,
            AuthSession.user_id == user.id,
            AuthSession.org_id == user.org_id,
        )
    )
    now = datetime.now(timezone.utc)
    if not auth_session or auth_session.revoked_at or auth_session.expires_at <= now:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Session is expired or revoked")
    if not hmac.compare_digest(auth_session.refresh_token_hash, _digest(raw_token)):
        auth_session.revoked_at = now
        await db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Refresh token replay detected; session revoked")
    if cookie_token:
        csrf_token = request.headers.get("X-CSRF-Token", "")
        csrf_cookie = request.cookies.get("csrf_token", "")
        if not csrf_token or not hmac.compare_digest(csrf_token, csrf_cookie) or not hmac.compare_digest(auth_session.csrf_token_hash, _digest(csrf_token)):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "CSRF validation failed")

    csrf_token = secrets.token_urlsafe(32)
    token_data = {
        "sub": str(user.id),
        "org_id": str(user.org_id),
        "role": user.role,
        "sid": str(auth_session.id),
        "jti": str(uuid.uuid4()),
    }
    access_token = create_access_token(token_data)
    new_refresh_token = create_refresh_token(token_data)
    auth_session.refresh_token_hash = _digest(new_refresh_token)
    auth_session.csrf_token_hash = _digest(csrf_token)
    auth_session.last_used_at = now
    auth_session.expires_at = now + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    _set_session_cookies(response, access_token, new_refresh_token, csrf_token)
    await write_audit(
        db,
        event=AuditEvent.TOKEN_REFRESH,
        user_id=str(user.id),
        org_id=str(user.org_id),
        resource_type="auth_session",
        resource_id=str(auth_session.id),
        ip_address=request.client.host if request.client else None,
    )
    return TokenResponse(
        access_token=access_token,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        refresh_expires_in=settings.REFRESH_TOKEN_EXPIRE_DAYS * 86400,
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(request: Request, response: Response, db: AsyncSession = Depends(get_db)):
    raw_token = request.cookies.get("refresh_token")
    decoded = decode_token(raw_token) if raw_token else None
    if decoded and decoded.get("sid"):
        try:
            session_id = uuid.UUID(decoded["sid"])
        except (ValueError, TypeError):
            session_id = None
        auth_session = await db.get(AuthSession, session_id) if session_id else None
        if auth_session and not auth_session.revoked_at:
            csrf_token = request.headers.get("X-CSRF-Token", "")
            csrf_cookie = request.cookies.get("csrf_token", "")
            if not csrf_token or not hmac.compare_digest(csrf_token, csrf_cookie) or not hmac.compare_digest(auth_session.csrf_token_hash, _digest(csrf_token)):
                raise HTTPException(status.HTTP_403_FORBIDDEN, "CSRF validation failed")
            auth_session.revoked_at = datetime.now(timezone.utc)
            await write_audit(
                db,
                event=AuditEvent.LOGOUT,
                user_id=str(auth_session.user_id),
                org_id=str(auth_session.org_id),
                resource_type="auth_session",
                resource_id=str(auth_session.id),
                ip_address=request.client.host if request.client else None,
            )
    _clear_session_cookies(response)


@router.get("/me", response_model=UserResponse)
async def me(current_user: User = Depends(get_current_user)):
    """Return the currently authenticated user."""
    return current_user


@router.get("/sessions")
async def list_sessions(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List the caller's server-side sessions without exposing token material."""
    current_id = None
    raw_token = request.cookies.get("refresh_token")
    decoded = decode_token(raw_token) if raw_token else None
    if decoded and decoded.get("sid"):
        current_id = decoded["sid"]
    rows = (await db.execute(
        select(AuthSession).where(AuthSession.user_id == current_user.id).order_by(AuthSession.created_at.desc())
    )).scalars().all()
    now = datetime.now(timezone.utc)
    return [{
        "id": str(row.id),
        "device_name": row.device_name or "Unknown device",
        "ip_address": row.ip_address,
        "created_at": row.created_at.isoformat(),
        "last_used_at": row.last_used_at.isoformat() if row.last_used_at else None,
        "expires_at": row.expires_at.isoformat(),
        "revoked_at": row.revoked_at.isoformat() if row.revoked_at else None,
        "is_current": str(row.id) == current_id,
        "is_active": row.revoked_at is None and row.expires_at > now,
    } for row in rows]


@router.delete("/sessions/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_session(
    session_id: uuid.UUID,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    session = await db.scalar(select(AuthSession).where(AuthSession.id == session_id, AuthSession.user_id == current_user.id))
    if not session:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Session not found")
    if session.revoked_at is None:
        session.revoked_at = datetime.now(timezone.utc)
        await write_audit(db, event="auth.session.revoke", user_id=str(current_user.id), org_id=str(current_user.org_id),
            resource_type="auth_session", resource_id=str(session.id), ip_address=request.client.host if request.client else None)


@router.post("/sessions/actions/revoke-others")
async def revoke_other_sessions(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    raw_token = request.cookies.get("refresh_token")
    decoded = decode_token(raw_token) if raw_token else None
    current_id = decoded.get("sid") if decoded else None
    if not current_id:
        raise HTTPException(status.HTTP_409_CONFLICT, "Current browser session cannot be identified")
    rows = (await db.execute(select(AuthSession).where(AuthSession.user_id == current_user.id, AuthSession.revoked_at.is_(None)))).scalars().all()
    now = datetime.now(timezone.utc)
    revoked = 0
    for row in rows:
        if str(row.id) != current_id:
            row.revoked_at = now
            revoked += 1
    await write_audit(db, event="auth.session.revoke_others", user_id=str(current_user.id), org_id=str(current_user.org_id),
        resource_type="auth_session", details={"revoked": revoked}, ip_address=request.client.host if request.client else None)
    return {"revoked": revoked}
