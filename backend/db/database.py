"""
SecureStorageInspector — Async Database Engine

Provides the async SQLAlchemy engine, session factory, and table
creation utilities for PostgreSQL via asyncpg.

Usage::

    from backend.db.database import get_session, create_tables

    async with get_session() as session:
        ...

    # On startup:
    await create_tables()
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from backend.config import get_settings

logger = logging.getLogger(__name__)

# ── Engine (created lazily on first access) ──────────────────────────
_engine = None
_session_factory = None


def _get_engine():
    """Create or return the cached async engine."""
    global _engine
    if _engine is None:
        settings = get_settings()
        _engine = create_async_engine(
            settings.DATABASE_URL,
            echo=False,
            pool_size=5,
            max_overflow=10,
            pool_pre_ping=True,
        )
        logger.info("Async database engine created: %s", settings.DATABASE_URL.split("@")[-1])
    return _engine


def _get_session_factory():
    """Create or return the cached session factory."""
    global _session_factory
    if _session_factory is None:
        _session_factory = async_sessionmaker(
            bind=_get_engine(),
            class_=AsyncSession,
            expire_on_commit=False,
        )
    return _session_factory


@asynccontextmanager
async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Provide an async database session as a context manager.

    Usage::

        async with get_session() as session:
            result = await session.execute(...)
    """
    factory = _get_session_factory()
    session = factory()
    try:
        yield session
        await session.commit()
    except Exception:
        await session.rollback()
        raise
    finally:
        await session.close()


async def get_session_dep() -> AsyncGenerator[AsyncSession, None]:
    """
    FastAPI dependency that yields an async session.

    Used with ``Depends(get_session_dep)`` in route handlers.
    """
    factory = _get_session_factory()
    session = factory()
    try:
        yield session
        await session.commit()
    except Exception:
        await session.rollback()
        raise
    finally:
        await session.close()


async def create_tables() -> None:
    """
    Create all ORM-mapped tables if they don't exist.

    Called once during application startup.
    """
    from backend.db.models import Base

    engine = _get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database tables created / verified.")


async def drop_tables() -> None:
    """Drop all tables (for testing only — never in production)."""
    from backend.db.models import Base

    engine = _get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    logger.warning("All database tables dropped!")


async def check_connection() -> bool:
    """
    Verify the database is reachable.

    Returns True if a simple query succeeds, False otherwise.
    """
    from sqlalchemy import text

    try:
        engine = _get_engine()
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        return True
    except Exception as exc:
        logger.error("Database health check failed: %s", exc)
        return False
