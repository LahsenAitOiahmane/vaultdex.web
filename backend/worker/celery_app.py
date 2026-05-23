"""
SecureStorageInspector — Celery Application

Configures the Celery app for background scan processing.

Usage:
    # Start the worker (one scan at a time):
    celery -A backend.worker.celery_app worker --loglevel=info --concurrency=1

    # Check worker status:
    celery -A backend.worker.celery_app inspect active
"""

from __future__ import annotations

import logging

from celery import Celery

from backend.config import get_settings

logger = logging.getLogger(__name__)

settings = get_settings()

celery_app = Celery(
    "apk_scanner",
    broker=settings.CELERY_BROKER_URL,
    include=["backend.worker.tasks"],
)

# ── Celery configuration ─────────────────────────────────────────────
celery_app.conf.update(
    # Serialisation
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",

    # Concurrency: only one scan at a time (single emulator)
    worker_concurrency=1,
    worker_prefetch_multiplier=1,

    # No result backend — we store results in PostgreSQL directly
    result_backend=None,

    # Timezone
    timezone="UTC",
    enable_utc=True,

    # Task settings
    task_track_started=True,
    task_acks_late=True,
    task_reject_on_worker_lost=True,

    # Retry settings
    task_default_retry_delay=30,
    task_max_retries=1,

    # Broker settings
    broker_connection_retry_on_startup=True,
)

logger.info("Celery app configured — broker=%s", settings.CELERY_BROKER_URL)
