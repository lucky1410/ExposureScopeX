from collections.abc import AsyncIterator
import json

import asyncpg

from .config import settings
from .serialization import json_safe

_pool: asyncpg.Pool | None = None


async def _initialize_connection(conn: asyncpg.Connection) -> None:
    for type_name in ("json", "jsonb"):
        await conn.set_type_codec(
            type_name,
            schema="pg_catalog",
            encoder=lambda value: json.dumps(json_safe(value)),
            decoder=json.loads,
            format="text",
        )


async def connect() -> None:
    global _pool
    if _pool is None:
        _pool = await asyncpg.create_pool(
            settings().database_url,
            min_size=1,
            max_size=10,
            init=_initialize_connection,
        )


async def disconnect() -> None:
    global _pool
    if _pool is not None:
        await _pool.close()
        _pool = None


def pool() -> asyncpg.Pool:
    if _pool is None:
        raise RuntimeError("Database pool is not initialized")
    return _pool


async def connection() -> AsyncIterator[asyncpg.Connection]:
    async with pool().acquire() as conn:
        yield conn


def record_to_dict(record: asyncpg.Record | None) -> dict | None:
    return dict(record) if record is not None else None
