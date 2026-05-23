"""
SecureStorageInspector — Celery Tasks (v2 — Two-Phase)

Two Celery tasks:

    1. ``run_scan_task``      — Phase A: Install + Launch → WAITING_FOR_USER
    2. ``finalize_scan_task``  — Phase B: Pull + Analyse → COMPLETED

Both tasks run synchronously inside the Celery worker process. Database
updates use synchronous SQLAlchemy (a separate sync engine) since Celery
workers do not run an asyncio event loop.
"""

from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy import create_engine, update
from sqlalchemy.dialects.postgresql import JSONB as JSONB_TYPE
from sqlalchemy import cast, func
from sqlalchemy.orm import Session, sessionmaker

from backend.config import get_settings
from backend.db.models import Scan
from backend.worker.celery_app import celery_app

logger = logging.getLogger(__name__)


def _get_sync_session() -> Session:
    """
    Create a synchronous SQLAlchemy session for use inside Celery.

    Converts the async DATABASE_URL (asyncpg) to a sync one (psycopg2).
    """
    settings = get_settings()
    sync_url = settings.DATABASE_URL.replace(
        "postgresql+asyncpg://", "postgresql+psycopg2://"
    )
    engine = create_engine(sync_url, pool_pre_ping=True)
    factory = sessionmaker(bind=engine)
    return factory()


def _update_db_step(
    scan_id: str,
    current_step: str,
    log_entry: Dict[str, Any],
) -> None:
    """
    Atomically update the scan's current step and append a log entry.

    Uses PostgreSQL JSONB concatenation for race-free append.
    """
    session = _get_sync_session()
    try:
        entry_json = json.dumps([log_entry])
        stmt = (
            update(Scan)
            .where(Scan.scan_id == scan_id)
            .values(
                current_step=current_step,
                scan_log=func.coalesce(Scan.scan_log, cast("[]", JSONB_TYPE))
                + cast(entry_json, JSONB_TYPE),
            )
        )
        session.execute(stmt)
        session.commit()
    except Exception as exc:
        session.rollback()
        logger.error("Failed to update DB step for %s: %s", scan_id, exc)
    finally:
        session.close()


def _update_db_status(scan_id: str, **kwargs: Any) -> None:
    """Update arbitrary fields on the scan record."""
    session = _get_sync_session()
    try:
        stmt = update(Scan).where(Scan.scan_id == scan_id).values(**kwargs)
        session.execute(stmt)
        session.commit()
    except Exception as exc:
        session.rollback()
        logger.error("Failed to update DB status for %s: %s", scan_id, exc)
    finally:
        session.close()


def _get_scan_record(scan_id: str) -> Optional[Scan]:
    """Fetch a scan record by scan_id using a sync session."""
    session = _get_sync_session()
    try:
        from sqlalchemy import select
        stmt = select(Scan).where(Scan.scan_id == scan_id)
        result = session.execute(stmt)
        return result.scalar_one_or_none()
    finally:
        session.close()


# ══════════════════════════════════════════════════════════════════════
#  TASK 1: Phase A — Install + Launch → WAITING_FOR_USER
# ══════════════════════════════════════════════════════════════════════

@celery_app.task(
    bind=True,
    name="backend.worker.tasks.run_scan_task",
    max_retries=1,
    acks_late=True,
)
def run_scan_task(self, scan_id: str) -> Dict[str, Any]:
    """
    Celery task: Phase A — install and launch the APK.

    After this task completes, the app is running on the emulator and
    the scan status is WAITING_FOR_USER. The user interacts with the
    app, then triggers Phase B via the /finalize endpoint.
    """
    pipeline_start = time.monotonic()

    logger.info("═" * 60)
    logger.info("Celery task starting (Phase A) — scan_id=%s", scan_id)
    logger.info("═" * 60)

    # ── 1. Mark as RUNNING ───────────────────────────────────────────
    _update_db_status(
        scan_id,
        status="RUNNING",
        started_at=datetime.now(timezone.utc),
    )

    # ── 2. Load scan metadata from DB ────────────────────────────────
    scan = _get_scan_record(scan_id)
    if scan is None:
        logger.error("Scan %s not found in DB!", scan_id)
        return {"scan_id": scan_id, "status": "FAILED", "error": "Scan not found"}

    apk_path = scan.apk_path
    package_name = scan.package_name

    if not apk_path:
        _update_db_status(
            scan_id,
            status="FAILED",
            current_step="FAILED",
            error="APK path not set",
            completed_at=datetime.now(timezone.utc),
        )
        return {"scan_id": scan_id, "status": "FAILED", "error": "APK path not set"}

    # ── 3. Build ScanJob ─────────────────────────────────────────────
    from backend.worker.scan_pipeline import ScanJob, run_phase_a

    job = ScanJob(
        apk_path=apk_path,
        package_name=package_name,
        scan_id=scan_id,
    )

    # ── 4. Progress callback — writes to DB at each step ─────────────
    def progress_callback(result) -> None:
        """Called by the pipeline after each step."""
        if result.scan_log:
            latest = result.scan_log[-1]
            step = latest.get("step", "UNKNOWN")
            _update_db_step(scan_id, step, latest)

    # ── 5. Run Phase A pipeline ──────────────────────────────────────
    try:
        scan_result = run_phase_a(job, progress_callback=progress_callback)
    except Exception as exc:
        elapsed = round(time.monotonic() - pipeline_start, 2)
        error_msg = f"Pipeline crashed: {exc}"
        logger.exception("Phase A pipeline crashed for scan %s", scan_id)
        _update_db_status(
            scan_id,
            status="FAILED",
            current_step="FAILED",
            error=error_msg,
            completed_at=datetime.now(timezone.utc),
            elapsed_seconds=elapsed,
        )
        return {"scan_id": scan_id, "status": "FAILED", "error": error_msg}

    # ── 6. Check Phase A result ──────────────────────────────────────
    if not scan_result.success:
        elapsed = round(time.monotonic() - pipeline_start, 2)
        error_msg = scan_result.error or "Pipeline failed (unknown error)"
        _update_db_status(
            scan_id,
            status="FAILED",
            current_step="FAILED",
            error=error_msg,
            completed_at=datetime.now(timezone.utc),
            elapsed_seconds=elapsed,
        )
        logger.error("Phase A failed for %s: %s", scan_id, error_msg)
        return {"scan_id": scan_id, "status": "FAILED", "error": error_msg}

    # ── 7. Update DB to WAITING_FOR_USER ─────────────────────────────
    elapsed = round(time.monotonic() - pipeline_start, 2)
    resolved_package = scan_result.package_name or package_name

    _update_db_status(
        scan_id,
        status="WAITING_FOR_USER",
        current_step="WAITING",
        dump_dir=scan_result.output_dir,
        package_name=resolved_package,
        elapsed_seconds=elapsed,
    )

    logger.info("═" * 60)
    logger.info(
        "Phase A complete — scan %s is WAITING_FOR_USER (%.1fs)",
        scan_id,
        elapsed,
    )
    logger.info("═" * 60)

    return {
        "scan_id": scan_id,
        "status": "WAITING_FOR_USER",
        "package_name": resolved_package,
        "elapsed_seconds": elapsed,
    }


# ══════════════════════════════════════════════════════════════════════
#  TASK 2: Phase B — Pull + Analyse → COMPLETED
# ══════════════════════════════════════════════════════════════════════

@celery_app.task(
    bind=True,
    name="backend.worker.tasks.finalize_scan_task",
    max_retries=1,
    acks_late=True,
)
def finalize_scan_task(self, scan_id: str) -> Dict[str, Any]:
    """
    Celery task: Phase B — pull storage, analyse, and complete the scan.

    Called when the user clicks "Finalize Scan" after interacting with
    the app on the emulator.
    """
    pipeline_start = time.monotonic()

    logger.info("═" * 60)
    logger.info("Celery task starting (Phase B / Finalize) — scan_id=%s", scan_id)
    logger.info("═" * 60)

    # ── 1. Mark as FINALIZING ────────────────────────────────────────
    _update_db_status(
        scan_id,
        status="FINALIZING",
        current_step="PULL",
    )
    _update_db_step(
        scan_id,
        "PULL",
        {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "step": "PULL",
            "status": "started",
            "message": "User finalized scan. Starting data collection …",
            "detail": None,
        },
    )

    # ── 2. Load scan metadata from DB ────────────────────────────────
    scan = _get_scan_record(scan_id)
    if scan is None:
        logger.error("Scan %s not found in DB!", scan_id)
        return {"scan_id": scan_id, "status": "FAILED", "error": "Scan not found"}

    apk_path = scan.apk_path
    package_name = scan.package_name
    dump_dir = scan.dump_dir or str(get_settings().DUMPS_DIR / scan_id)

    # ── 3. Build ScanJob ─────────────────────────────────────────────
    from backend.worker.scan_pipeline import ScanJob, run_phase_b

    job = ScanJob(
        apk_path=apk_path or "",
        package_name=package_name,
        scan_id=scan_id,
        output_dir=dump_dir,
    )

    # ── 4. Progress callback ─────────────────────────────────────────
    def progress_callback(result) -> None:
        if result.scan_log:
            latest = result.scan_log[-1]
            step = latest.get("step", "UNKNOWN")
            _update_db_step(scan_id, step, latest)

    # ── 5. Run Phase B pipeline ──────────────────────────────────────
    try:
        scan_result = run_phase_b(job, progress_callback=progress_callback)
    except Exception as exc:
        elapsed = round(time.monotonic() - pipeline_start, 2)
        error_msg = f"Finalize pipeline crashed: {exc}"
        logger.exception("Phase B pipeline crashed for scan %s", scan_id)
        _update_db_status(
            scan_id,
            status="FAILED",
            current_step="FAILED",
            error=error_msg,
            completed_at=datetime.now(timezone.utc),
            elapsed_seconds=elapsed,
        )
        return {"scan_id": scan_id, "status": "FAILED", "error": error_msg}

    # ── 6. Check Phase B result ──────────────────────────────────────
    if not scan_result.success:
        elapsed = round(time.monotonic() - pipeline_start, 2)
        error_msg = scan_result.error or "Finalize failed (unknown error)"
        _update_db_status(
            scan_id,
            status="FAILED",
            current_step="FAILED",
            error=error_msg,
            completed_at=datetime.now(timezone.utc),
            elapsed_seconds=elapsed,
        )
        return {"scan_id": scan_id, "status": "FAILED", "error": error_msg}

    # ── 7. Run Analysis Engine (Phase 2) ─────────────────────────────
    _update_db_status(scan_id, status="ANALYSING", current_step="ANALYSING")
    _update_db_step(
        scan_id,
        "ANALYSING",
        {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "step": "ANALYSING",
            "status": "started",
            "message": f"Running security analysis on {package_name} …",
            "detail": "Includes static APK analysis + dynamic storage analysis.",
        },
    )

    try:
        from backend.engine.analyser import AnalysisEngine

        engine = AnalysisEngine()
        security_report = engine.analyse(
            scan_id=scan_id,
            dump_dir=dump_dir,
            package_name=package_name or "unknown",
            apk_path=apk_path,
        )

        # Log analysis breakdown to SSE
        static_count = 0
        dynamic_count = 0
        if security_report.static_analysis:
            static_count = len(security_report.static_analysis.findings)
        for area in security_report.storage_reports:
            dynamic_count += len(area.findings)

        _update_db_step(
            scan_id,
            "ANALYSING",
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "step": "ANALYSING",
                "status": "success",
                "message": (
                    f"Analysis complete — "
                    f"{static_count} static finding(s), "
                    f"{dynamic_count} dynamic finding(s), "
                    f"{security_report.total_findings} total. "
                    f"Score: {security_report.risk_score}/100 "
                    f"({security_report.risk_level.value})"
                ),
                "detail": None,
            },
        )

        # Save report as JSON file too
        engine.save_report(security_report)

    except Exception as exc:
        elapsed = round(time.monotonic() - pipeline_start, 2)
        error_msg = f"Analysis engine crashed: {exc}"
        logger.exception("Analysis crashed for scan %s", scan_id)
        _update_db_status(
            scan_id,
            status="FAILED",
            current_step="FAILED",
            error=error_msg,
            completed_at=datetime.now(timezone.utc),
            elapsed_seconds=elapsed,
        )
        return {"scan_id": scan_id, "status": "FAILED", "error": error_msg}

    # ── 8. Store report in database ──────────────────────────────────
    elapsed = round(time.monotonic() - pipeline_start, 2)
    report_dict = security_report.model_dump()

    # Serialise datetime objects for JSONB storage
    report_json = json.loads(json.dumps(report_dict, default=str))

    _update_db_step(
        scan_id,
        "DONE",
        {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "step": "DONE",
            "status": "success",
            "message": (
                f"Scan complete in {elapsed}s — "
                f"Score: {security_report.risk_score}/100 "
                f"({security_report.risk_level.value}), "
                f"{security_report.total_findings} finding(s)."
            ),
            "detail": None,
        },
    )

    _update_db_status(
        scan_id,
        status="COMPLETED",
        current_step="DONE",
        report=report_json,
        risk_score=security_report.risk_score,
        risk_level=security_report.risk_level.value,
        total_findings=security_report.total_findings,
        completed_at=datetime.now(timezone.utc),
        elapsed_seconds=elapsed,
    )

    logger.info("═" * 60)
    logger.info(
        "Scan %s COMPLETED — Score: %d/100, Findings: %d, Time: %.1fs",
        scan_id,
        security_report.risk_score,
        security_report.total_findings,
        elapsed,
    )
    logger.info("═" * 60)

    return {
        "scan_id": scan_id,
        "status": "COMPLETED",
        "risk_score": security_report.risk_score,
        "total_findings": security_report.total_findings,
        "elapsed_seconds": elapsed,
    }
