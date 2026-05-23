"""
SecureStorageInspector — API Middleware

Configures CORS, security headers, and rate limiting.
"""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from backend.config import get_settings

logger = logging.getLogger(__name__)


def get_limiter() -> Limiter:
    """Create the rate limiter instance."""
    return Limiter(key_func=get_remote_address)


# Module-level limiter for use in route decorators
limiter = get_limiter()


def configure_middleware(app: FastAPI) -> None:
    """
    Apply all middleware to the FastAPI application.

    Called once during app startup in ``app.py``.
    """
    settings = get_settings()

    # ── CORS ─────────────────────────────────────────────────────────
    # Restrict to configured origins — no wildcard (*).
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["GET", "POST", "DELETE"],
        allow_headers=["*"],
        expose_headers=["X-Request-ID"],
    )
    logger.info("CORS configured for origins: %s", settings.CORS_ORIGINS)

    # ── Rate Limiting ────────────────────────────────────────────────
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    # ── Security Headers ─────────────────────────────────────────────
    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        """
        Add security headers to every response.

        - X-Content-Type-Options: nosniff   → prevents MIME sniffing
        - X-Frame-Options: DENY             → prevents clickjacking
        - Cache-Control: no-store           → prevents caching of API responses
        - Permissions-Policy                → disables unused browser features
        """
        response: Response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=()"
        )
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; frame-ancestors 'none'"
        )
        return response
