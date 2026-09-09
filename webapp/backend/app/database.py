"""Async SQLAlchemy engine, session factory, and declarative base."""

from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import declarative_base
from sqlalchemy.pool import NullPool

from app.config import settings

def _database_engine_options(use_null_pool: bool) -> dict:
    """Build engine options safe for either API or short-lived worker loops."""
    options = {"echo": settings.DEBUG, "pool_pre_ping": True}
    if use_null_pool:
        options["poolclass"] = NullPool
    else:
        options.update({"pool_size": 20, "max_overflow": 10})
    return options


engine = create_async_engine(
    settings.DATABASE_URL,
    **_database_engine_options(settings.DATABASE_NULL_POOL),
)

async_session_factory = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)

Base = declarative_base()


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Dependency that yields an async database session."""
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
