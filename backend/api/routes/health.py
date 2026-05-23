"""
SecureStorageInspector — Health Check Endpoint

Verifies that PostgreSQL and Redis are reachable and reports
available disk space for uploads.
"""

from __future__ import annotations

import logging
import shutil

from fastapi import APIRouter

from backend.api.schemas import HealthResponse
from backend.config import get_settings

logger = logging.getLogger(__name__)

router = APIRouter(tags=["health"])


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="System health check",
    description="Checks database, Redis, and disk space.",
)
async def health_check() -> HealthResponse:
    """
    Verify all backend dependencies are healthy.

    Returns:
        HealthResponse with status of each subsystem.
    """
    settings = get_settings()

    # ── Check PostgreSQL ─────────────────────────────────────────────
    from backend.db.database import check_connection
    db_ok = await check_connection()

    # ── Check Redis ──────────────────────────────────────────────────
    redis_ok = False
    try:
        import redis as redis_lib
        r = redis_lib.Redis.from_url(settings.REDIS_URL, socket_timeout=3)
        redis_ok = r.ping()
        r.close()
    except Exception as exc:
        logger.warning("Redis health check failed: %s", exc)

    # ── Check Disk Space ─────────────────────────────────────────────
    disk_mb = None
    try:
        uploads_dir = settings.UPLOADS_DIR
        uploads_dir.mkdir(parents=True, exist_ok=True)
        usage = shutil.disk_usage(str(uploads_dir))
        disk_mb = round(usage.free / (1024 * 1024), 1)
    except Exception:
        pass

    # ── Overall Status ───────────────────────────────────────────────
    overall = "healthy" if (db_ok and redis_ok) else "degraded"

    return HealthResponse(
        status=overall,
        database=db_ok,
        redis=redis_ok,
        disk_uploads_mb=disk_mb,
    )
