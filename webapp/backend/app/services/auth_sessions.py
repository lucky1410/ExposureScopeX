"""Maintenance helpers for server-side authentication sessions."""

from datetime import datetime, timedelta, timezone

from sqlalchemy import and_, delete, or_

from app.database import async_session_factory
from app.models.auth_session import AuthSession


async def purge_old_auth_sessions(retain_revoked_days: int = 30) -> int:
    cutoff = datetime.now(timezone.utc) - timedelta(days=retain_revoked_days)
    async with async_session_factory() as session:
        result = await session.execute(
            delete(AuthSession).where(
                or_(
                    AuthSession.expires_at < cutoff,
                    and_(AuthSession.revoked_at.is_not(None), AuthSession.revoked_at < cutoff),
                )
            )
        )
        await session.commit()
        return result.rowcount or 0
