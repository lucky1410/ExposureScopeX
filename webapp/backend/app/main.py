"""FastAPI application factory for ExposureScopeX."""

import json
import hmac
import logging
import re
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone

import redis.asyncio as aioredis
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address
from sqlalchemy import or_, select, text

from app.api.v1.router import api_router
from app.config import settings
from app.database import async_session_factory, engine
from app.models.assessment import Assessment
from app.models.auth_session import AuthSession
from app.models.scan import Scan
from app.models.user import User
from app.security import decode_token
from app.services.telemetry import observe_request
from app.services.audit import write_audit

logger = logging.getLogger("exposurescopex")

# ── Rate Limiter ──────────────────────────────────────────────────────────────

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200/minute", "2000/hour"],
    storage_uri=settings.REDIS_URL,
)


# ── Redis pool (shared across WS connections) ─────────────────────────────────

_redis_pool: aioredis.Redis | None = None


async def get_redis() -> aioredis.Redis:
    global _redis_pool
    if _redis_pool is None:
        _redis_pool = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
    return _redis_pool


# ── Lifespan ──────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("ExposureScopeX backend starting up (v%s)", settings.APP_VERSION)

    try:
        from app.services.assessment_runtime import (
            reconcile_interrupted_thread_scans,
            reconcile_stale_scans,
        )

        interrupted = await reconcile_interrupted_thread_scans()
        if interrupted:
            logger.warning("Marked %s interrupted local scan(s) as failed", interrupted)
        stale = await reconcile_stale_scans()
        if stale:
            logger.warning("Marked %s stale worker scan(s) as failed", stale)
    except Exception as exc:
        logger.warning("Interrupted scan reconciliation skipped: %s", exc)

    try:
        from app.services.finding_lifecycle import reopen_expired_suppressions

        reopened = await reopen_expired_suppressions()
        if reopened:
            logger.info("Reopened %s expired finding suppression(s)", reopened)
    except Exception as exc:
        logger.warning("Finding suppression expiry skipped: %s", exc)

    if settings.IMPORT_REAL_DATA:
        try:
            from app.services.real_data_importer import import_real_data
            await import_real_data("/app/results")
            logger.info("Real scan data import complete")
        except Exception as e:
            logger.warning("Real data import skipped: %s", e)

    yield

    # Cleanup Redis pool
    if _redis_pool:
        await _redis_pool.aclose()
    logger.info("ExposureScopeX backend shut down")


# ── App factory ───────────────────────────────────────────────────────────────

_PRODUCTION = settings.ENVIRONMENT.lower() == "production"

app = FastAPI(
    title=settings.APP_NAME,
    description="Attack Surface Management Platform — REST API",
    version=settings.APP_VERSION,
    docs_url=None if _PRODUCTION else "/docs",
    redoc_url=None if _PRODUCTION else "/redoc",
    openapi_url=None if _PRODUCTION else "/openapi.json",
    lifespan=lifespan,
)

# Rate limiting
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.BACKEND_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def record_request_telemetry(request: Request, call_next):
    started = time.monotonic()
    response = await call_next(request)
    route = request.scope.get("route")
    route_path = getattr(route, "path", request.url.path)
    observe_request(request.method, route_path, response.status_code, time.monotonic() - started)
    response.headers["Server-Timing"] = f"app;dur={(time.monotonic() - started) * 1000:.2f}"
    return response


@app.middleware("http")
async def correlate_and_audit_mutations(request: Request, call_next):
    supplied_id = request.headers.get("X-Request-ID", "")[:100]
    request_id = supplied_id if re.fullmatch(r"[A-Za-z0-9._:-]{8,100}", supplied_id) else str(uuid.uuid4())
    request.state.request_id = request_id
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    if request.method in {"POST", "PUT", "PATCH", "DELETE"} and request.url.path.startswith("/api/v1/"):
        authorization = request.headers.get("Authorization", "")
        token = authorization[7:] if authorization.lower().startswith("bearer ") else request.cookies.get("access_token")
        payload = decode_token(token) if token else None
        if payload and payload.get("type") == "access":
            try:
                async with async_session_factory() as audit_db:
                    await write_audit(
                        audit_db,
                        event=f"http.{request.method.lower()}",
                        user_id=payload.get("sub"),
                        org_id=payload.get("org_id"),
                        resource_type="api_route",
                        details={
                            "route": getattr(request.scope.get("route"), "path", request.url.path),
                            "status_code": response.status_code,
                            "request_id": request_id,
                        },
                        ip_address=request.client.host if request.client else None,
                        success=response.status_code < 400,
                    )
                    await audit_db.commit()
            except Exception:
                logger.warning("Mutation audit persistence failed for request %s", request_id, exc_info=True)
    return response


# ── Security headers middleware ────────────────────────────────────────────────

@app.middleware("http")
async def enforce_cookie_csrf(request: Request, call_next):
    """Require double-submit CSRF protection when cookie auth mutates state."""
    if (
        request.method not in {"GET", "HEAD", "OPTIONS"}
        and request.cookies.get("access_token")
        and not request.headers.get("Authorization")
        and request.url.path not in {"/api/v1/auth/login", "/api/v1/auth/register"}
    ):
        header_token = request.headers.get("X-CSRF-Token", "")
        cookie_token = request.cookies.get("csrf_token", "")
        if not header_token or not hmac.compare_digest(header_token, cookie_token):
            return JSONResponse(status_code=403, content={"detail": "CSRF validation failed"})
    return await call_next(request)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    if not settings.DEBUG:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    if _PRODUCTION:
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
        )
    return response


# ── REST routes ───────────────────────────────────────────────────────────────

app.include_router(api_router, prefix="/api/v1")


# ── WebSocket — real-time scan progress ──────────────────────────────────────

def _websocket_origin_allowed(origin: str | None) -> bool:
    """Reject browser WebSockets initiated outside configured UI origins."""
    if not origin:
        return True
    allowed = {item.rstrip("/").lower() for item in settings.BACKEND_CORS_ORIGINS}
    return origin.rstrip("/").lower() in allowed

@app.websocket("/ws/scan/{scan_id}")
async def scan_progress_ws(websocket: WebSocket, scan_id: str):
    """Stream scan progress events for a scan/target ID.

    The client subscribes to a Redis pub/sub channel `scan:<scan_id>`.
    Events published by Celery tasks (or ASM background jobs) are forwarded
    to the browser in real time.

    Message format:
        {"scan_id": "...", "event": "scan.started"|"scan.completed"|..., ...}
    """
    if not _websocket_origin_allowed(websocket.headers.get("origin")):
        await websocket.close(code=4403, reason="WebSocket origin denied")
        return

    token = websocket.cookies.get("access_token")
    payload = decode_token(token) if token else None
    try:
        user_id = uuid.UUID(str((payload or {}).get("sub")))
        org_id = uuid.UUID(str((payload or {}).get("org_id")))
        session_id = uuid.UUID(str((payload or {}).get("sid")))
        requested_id = uuid.UUID(scan_id)
    except (ValueError, TypeError, AttributeError):
        await websocket.close(code=4401, reason="Authentication required")
        return
    if not payload or payload.get("type") != "access":
        await websocket.close(code=4401, reason="Authentication required")
        return

    async with async_session_factory() as session:
        user = await session.scalar(
            select(User).where(User.id == user_id, User.org_id == org_id, User.is_active.is_(True))
        )
        auth_session = await session.scalar(
            select(AuthSession.id).where(
                AuthSession.id == session_id,
                AuthSession.user_id == user_id,
                AuthSession.org_id == org_id,
                AuthSession.revoked_at.is_(None),
                AuthSession.expires_at > datetime.now(timezone.utc),
            )
        )
        authorized_target = await session.scalar(
            select(Assessment.id)
            .outerjoin(Scan, Scan.assessment_id == Assessment.id)
            .where(
                Assessment.org_id == org_id,
                or_(Assessment.id == requested_id, Scan.id == requested_id),
            )
            .limit(1)
        )
    if not user or not auth_session or not authorized_target:
        await websocket.close(code=4403, reason="Scan access denied")
        return

    await websocket.accept()
    r = await get_redis()
    pubsub = r.pubsub()
    channel = f"scan:{scan_id}"

    try:
        await pubsub.subscribe(channel)
        logger.debug("WS client subscribed to %s", channel)

        async for message in pubsub.listen():
            if message["type"] != "message":
                continue
            try:
                data = json.loads(message["data"])
                await websocket.send_json(data)
                # Auto-close when scan is done
                if data.get("event") in (
                    "scan.completed",
                    "scan.failed",
                    "assessment.scan.completed",
                    "assessment.scan.failed",
                    "assessment.scan.timeout",
                    "assessment.scan.cancelled",
                ):
                    break
            except Exception as exc:
                logger.warning("WS message error: %s", exc)
                break

    except WebSocketDisconnect:
        logger.debug("WS client disconnected from %s", channel)
    finally:
        await pubsub.unsubscribe(channel)
        await pubsub.aclose()


# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/health")
async def health_check():
    """Process liveness check; it deliberately does not call dependencies."""
    return {
        "status": "healthy",
        "version": settings.APP_VERSION,
        "service": settings.APP_NAME,
    }


@app.get("/ready")
async def readiness_check():
    """Dependency-aware readiness check for orchestrators and load balancers."""
    checks: dict[str, str] = {}

    try:
        async with engine.connect() as connection:
            await connection.execute(text("SELECT 1"))
        checks["postgres"] = "ready"
    except Exception as exc:
        logger.warning("Readiness PostgreSQL check failed: %s", exc)
        checks["postgres"] = "unavailable"

    try:
        redis_client = await get_redis()
        if not await redis_client.ping():
            raise RuntimeError("Redis ping returned false")
        checks["redis"] = "ready"
    except Exception as exc:
        logger.warning("Readiness Redis check failed: %s", exc)
        checks["redis"] = "unavailable"

    ready = all(status == "ready" for status in checks.values())
    payload = {
        "status": "ready" if ready else "not_ready",
        "version": settings.APP_VERSION,
        "service": settings.APP_NAME,
        "checks": checks,
    }
    return JSONResponse(payload, status_code=200 if ready else 503)


@app.get("/", include_in_schema=False)
async def root():
    if _PRODUCTION:
        return {"status": "healthy", "service": settings.APP_NAME, "version": settings.APP_VERSION}
    return RedirectResponse(url="/docs")
