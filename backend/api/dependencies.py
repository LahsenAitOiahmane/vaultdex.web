"""
SecureStorageInspector — FastAPI Dependencies

Reusable dependency callables for route handlers.
"""

from __future__ import annotations

from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession

from backend.db.database import get_session_dep


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    FastAPI dependency: yields an async database session.

    Usage in route handlers::

        @router.get("/example")
        async def handler(db: AsyncSession = Depends(get_db)):
            ...
    """
    async for session in get_session_dep():
        yield session
