"""
SecureStorageInspector — FastAPI Application

Application factory that creates and configures the FastAPI app.

Usage:
    # Start the server:
    uvicorn backend.api.app:app --host 127.0.0.1 --port 8000 --reload

    # Or via Python:
    python -m backend.api.app
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from backend.api.middleware import configure_middleware
from backend.api.routes.health import router as health_router
from backend.api.routes.scans import router as scans_router
from backend.api.routes.auth import router as auth_router
from backend.config import get_settings
from backend.db.database import create_tables

logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Startup and shutdown lifecycle for the FastAPI app.

    On startup: creates database tables if they don't exist.
    On shutdown: cleanup (currently no-op, connection pool handles itself).
    """
    logger.info("═" * 60)
    logger.info("SecureStorageInspector API starting …")
    logger.info("═" * 60)

    # Create database tables on startup
    try:
        await create_tables()
        logger.info("Database tables ready.")
    except Exception as exc:
        logger.error("Failed to create database tables: %s", exc)
        logger.error("Is PostgreSQL running? Try: docker-compose up -d")
        raise

    yield

    logger.info("SecureStorageInspector API shutting down.")


def create_app() -> FastAPI:
    """
    Create and configure the FastAPI application.

    Returns:
        Fully configured FastAPI app instance.
    """
    settings = get_settings()

    app = FastAPI(
        title="SecureStorageInspector API",
        description=(
            "Automated Android APK security scanner. Upload an APK, "
            "get a full security report analysing all local storage "
            "for vulnerabilities."
        ),
        version="3.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan,
    )

    # Apply middleware (CORS, rate limiting, security headers)
    configure_middleware(app)

    # Register route modules
    app.include_router(health_router, prefix="/api/v1")
    app.include_router(auth_router, prefix="/api/v1")
    app.include_router(scans_router, prefix="/api/v1")

    logger.info(
        "API configured — host=%s, port=%d, max_upload=%d MB",
        settings.API_HOST,
        settings.API_PORT,
        settings.MAX_UPLOAD_SIZE // (1024 * 1024),
    )

    return app


# ── Application instance (imported by uvicorn) ──────────────────────
app = create_app()


# ── Direct execution support ────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn

    settings = get_settings()

    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
        datefmt="%H:%M:%S",
    )

    uvicorn.run(
        "backend.api.app:app",
        host=settings.API_HOST,
        port=settings.API_PORT,
        reload=True,
        log_level="info",
    )
