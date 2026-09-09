"""Distributed per-tenant execution leases for horizontally scaled workers."""

from __future__ import annotations

import time

from app.config import settings


def _limit(org_id: str) -> int:
    from sqlalchemy import create_engine, text

    engine = create_engine(settings.DATABASE_URL.replace("+asyncpg", ""), pool_pre_ping=True)
    try:
        with engine.connect() as connection:
            value = connection.execute(
                text("SELECT max_active_scans FROM organization_execution_policies WHERE org_id=:org_id"),
                {"org_id": org_id},
            ).scalar()
            return int(value or settings.DEFAULT_MAX_ACTIVE_SCANS_PER_ORG)
    finally:
        engine.dispose()


def acquire_execution_lease(org_id: str, task_id: str, ttl_seconds: int) -> bool:
    import redis

    client = redis.from_url(settings.REDIS_URL)
    key = f"exsx:org-slots:{org_id}"
    now = int(time.time())
    expires = now + max(60, ttl_seconds)
    script = """
    redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', ARGV[1])
    if redis.call('ZSCORE', KEYS[1], ARGV[3]) then
      redis.call('ZADD', KEYS[1], ARGV[2], ARGV[3]); return 1
    end
    if redis.call('ZCARD', KEYS[1]) >= tonumber(ARGV[4]) then return 0 end
    redis.call('ZADD', KEYS[1], ARGV[2], ARGV[3])
    redis.call('EXPIRE', KEYS[1], tonumber(ARGV[5]))
    return 1
    """
    try:
        return bool(client.eval(script, 1, key, now, expires, task_id, _limit(org_id), ttl_seconds + 300))
    finally:
        client.close()


def release_execution_lease(org_id: str, task_id: str) -> None:
    import redis

    client = redis.from_url(settings.REDIS_URL)
    try:
        client.zrem(f"exsx:org-slots:{org_id}", task_id)
    finally:
        client.close()
