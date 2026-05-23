"""
SecureStorageInspector — Database CRUD Operations

All database interactions are centralised here. Every function takes
an ``AsyncSession`` and returns ORM objects or query results.

No raw SQL is ever constructed via string concatenation — all queries
use the SQLAlchemy ORM to prevent SQL injection.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence

from sqlalchemy import delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from backend.db.models import Scan

logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════════════
#  CREATE
# ══════════════════════════════════════════════════════════════════════

async def create_scan(
    session: AsyncSession,
    *,
    scan_id: str,
    owner_id: int,
    package_name: Optional[str] = None,
    apk_filename: Optional[str] = None,
    apk_path: Optional[str] = None,
    celery_task_id: Optional[str] = None,
) -> Scan:
    """
    Insert a new scan record in QUEUED state.

    Args:
        session:        Async database session.
        scan_id:        Unique short scan identifier.
        owner_id:       The user ID who owns the scan.
        package_name:   Android package name (extracted from APK).
        apk_filename:   Original uploaded filename (metadata only).
        apk_path:       Randomised path on disk.
        celery_task_id: Celery async task ID.

    Returns:
        The created Scan ORM object.
    """
    scan = Scan(
        scan_id=scan_id,
        owner_id=owner_id,
        package_name=package_name,
        status="QUEUED",
        apk_filename=apk_filename,
        apk_path=apk_path,
        celery_task_id=celery_task_id,
        scan_log=[],
    )
    session.add(scan)
    await session.flush()
    logger.info("Scan created: scan_id=%s, package=%s", scan_id, package_name)
    return scan


# ══════════════════════════════════════════════════════════════════════
#  READ
# ══════════════════════════════════════════════════════════════════════

async def get_scan(session: AsyncSession, scan_id: str, owner_id: Optional[int] = None) -> Optional[Scan]:
    """
    Fetch a single scan by its scan_id.

    Args:
        session: Async database session.
        scan_id: The short scan identifier.
        owner_id: Optional user ID to enforce tenancy.

    Returns:
        Scan ORM object or None if not found.
    """
    stmt = select(Scan).where(Scan.scan_id == scan_id)
    if owner_id is not None:
        stmt = stmt.where(Scan.owner_id == owner_id)
    result = await session.execute(stmt)
    return result.scalar_one_or_none()


async def list_scans(
    session: AsyncSession,
    *,
    page: int = 1,
    page_size: int = 20,
    status: Optional[str] = None,
    owner_id: Optional[int] = None,
) -> tuple[Sequence[Scan], int]:
    """
    List scans with pagination and optional status filter.

    Args:
        session:   Async database session.
        page:      Page number (1-indexed).
        page_size: Items per page.
        status:    Optional status filter (e.g. "COMPLETED").
        owner_id:  Optional user ID to enforce tenancy.

    Returns:
        Tuple of (list of Scan objects, total count).
    """
    # Build base query
    base = select(Scan)
    count_base = select(func.count(Scan.id))

    if owner_id is not None:
        base = base.where(Scan.owner_id == owner_id)
        count_base = count_base.where(Scan.owner_id == owner_id)

    if status:
        base = base.where(Scan.status == status)
        count_base = count_base.where(Scan.status == status)

    # Total count
    total_result = await session.execute(count_base)
    total = total_result.scalar_one()

    # Paginated results (newest first)
    offset = (page - 1) * page_size
    stmt = (
        base
        .order_by(Scan.created_at.desc())
        .offset(offset)
        .limit(page_size)
    )
    result = await session.execute(stmt)
    scans = result.scalars().all()

    return scans, total


async def get_scan_log(session: AsyncSession, scan_id: str, owner_id: Optional[int] = None) -> Optional[list]:
    """
    Fetch only the scan_log and status for an SSE stream.

    Returns None if the scan doesn't exist.
    """
    stmt = select(Scan.scan_log, Scan.status).where(Scan.scan_id == scan_id)
    if owner_id is not None:
        stmt = stmt.where(Scan.owner_id == owner_id)
    result = await session.execute(stmt)
    row = result.one_or_none()
    if row is None:
        return None
    return row


# ══════════════════════════════════════════════════════════════════════
#  UPDATE
# ══════════════════════════════════════════════════════════════════════

async def update_scan_status(
    session: AsyncSession,
    scan_id: str,
    *,
    status: str,
    current_step: Optional[str] = None,
    error: Optional[str] = None,
    started_at: Optional[datetime] = None,
    completed_at: Optional[datetime] = None,
    elapsed_seconds: Optional[float] = None,
) -> None:
    """
    Update the status and related fields of a scan.

    Args:
        session:         Async database session.
        scan_id:         Scan identifier.
        status:          New status value.
        current_step:    Current pipeline step (optional).
        error:           Error message if failed (optional).
        started_at:      When the scan started executing.
        completed_at:    When the scan completed.
        elapsed_seconds: Total elapsed time.
    """
    values: Dict[str, Any] = {"status": status}
    if current_step is not None:
        values["current_step"] = current_step
    if error is not None:
        values["error"] = error
    if started_at is not None:
        values["started_at"] = started_at
    if completed_at is not None:
        values["completed_at"] = completed_at
    if elapsed_seconds is not None:
        values["elapsed_seconds"] = elapsed_seconds

    stmt = update(Scan).where(Scan.scan_id == scan_id).values(**values)
    await session.execute(stmt)
    await session.commit()


async def append_scan_log_entry(
    session: AsyncSession,
    scan_id: str,
    entry: Dict[str, Any],
) -> None:
    """
    Append a single log entry to the scan's scan_log JSONB array.

    Uses PostgreSQL's JSONB concatenation operator (||) for atomic
    append without race conditions.

    Args:
        session: Async database session.
        scan_id: Scan identifier.
        entry:   Log entry dict to append.
    """
    from sqlalchemy import cast
    from sqlalchemy.dialects.postgresql import JSONB as JSONB_TYPE

    import json

    # Use raw JSONB concatenation: scan_log || '[{entry}]'::jsonb
    entry_json = json.dumps([entry])
    stmt = (
        update(Scan)
        .where(Scan.scan_id == scan_id)
        .values(
            scan_log=func.coalesce(Scan.scan_log, cast("[]", JSONB_TYPE))
            + cast(entry_json, JSONB_TYPE)
        )
    )
    await session.execute(stmt)
    await session.commit()


async def update_scan_step(
    session: AsyncSession,
    scan_id: str,
    *,
    current_step: str,
    log_entry: Dict[str, Any],
) -> None:
    """
    Atomically update the current step and append a log entry.

    This is the primary method called by the Celery task's progress
    callback.

    Args:
        session:      Async database session.
        scan_id:      Scan identifier.
        current_step: Current pipeline step name.
        log_entry:    Log entry dict to append.
    """
    from sqlalchemy import cast
    from sqlalchemy.dialects.postgresql import JSONB as JSONB_TYPE

    import json

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
    await session.execute(stmt)
    await session.commit()


async def store_report(
    session: AsyncSession,
    scan_id: str,
    *,
    report: Dict[str, Any],
    risk_score: int,
    risk_level: str,
    total_findings: int,
    elapsed_seconds: float,
) -> None:
    """
    Store the completed SecurityReport and update status to COMPLETED.

    Args:
        session:         Async database session.
        scan_id:         Scan identifier.
        report:          Full SecurityReport as a dict.
        risk_score:      Numeric risk score (0-100).
        risk_level:      Risk level label.
        total_findings:  Total number of findings.
        elapsed_seconds: Total pipeline duration.
    """
    now = datetime.now(timezone.utc)
    stmt = (
        update(Scan)
        .where(Scan.scan_id == scan_id)
        .values(
            status="COMPLETED",
            current_step="DONE",
            report=report,
            risk_score=risk_score,
            risk_level=risk_level,
            total_findings=total_findings,
            completed_at=now,
            elapsed_seconds=elapsed_seconds,
        )
    )
    await session.execute(stmt)
    await session.commit()
    logger.info(
        "Report stored: scan_id=%s, score=%d, findings=%d",
        scan_id,
        risk_score,
        total_findings,
    )


async def mark_scan_failed(
    session: AsyncSession,
    scan_id: str,
    error: str,
    elapsed_seconds: Optional[float] = None,
) -> None:
    """Mark a scan as FAILED with an error message."""
    now = datetime.now(timezone.utc)
    values: Dict[str, Any] = {
        "status": "FAILED",
        "current_step": "FAILED",
        "error": error,
        "completed_at": now,
    }
    if elapsed_seconds is not None:
        values["elapsed_seconds"] = elapsed_seconds

    stmt = update(Scan).where(Scan.scan_id == scan_id).values(**values)
    await session.execute(stmt)
    await session.commit()
    logger.error("Scan marked FAILED: scan_id=%s, error=%s", scan_id, error)


async def set_scan_dump_dir(
    session: AsyncSession,
    scan_id: str,
    dump_dir: str,
) -> None:
    """Update the dump directory path for a scan."""
    stmt = update(Scan).where(Scan.scan_id == scan_id).values(dump_dir=dump_dir)
    await session.execute(stmt)
    await session.commit()


# ══════════════════════════════════════════════════════════════════════
#  DELETE
# ══════════════════════════════════════════════════════════════════════

async def delete_scan(session: AsyncSession, scan_id: str, owner_id: Optional[int] = None) -> bool:
    """
    Delete a scan record from the database.

    Returns True if a row was deleted, False if not found.
    Does NOT delete files on disk — that's handled by the route.
    """
    stmt = delete(Scan).where(Scan.scan_id == scan_id)
    if owner_id is not None:
        stmt = stmt.where(Scan.owner_id == owner_id)
    result = await session.execute(stmt)
    await session.commit()
    deleted = result.rowcount > 0
    if deleted:
        logger.info("Scan deleted from DB: scan_id=%s", scan_id)
    return deleted

async def get_scan_stats(session: AsyncSession, owner_id: Optional[int] = None) -> Dict[str, Any]:
    """Aggregate dashboard statistics."""
    from datetime import datetime, timedelta, timezone
    
    # 1. Total Scans
    stmt_total = select(func.count(Scan.id))
    if owner_id is not None:
        stmt_total = stmt_total.where(Scan.owner_id == owner_id)
    total_scans = (await session.execute(stmt_total)).scalar_one() or 0

    # 2. Vulnerabilities Found (completed scans)
    stmt_vulns = select(func.sum(Scan.total_findings)).where(Scan.status == 'COMPLETED')
    if owner_id is not None:
        stmt_vulns = stmt_vulns.where(Scan.owner_id == owner_id)
    vulnerabilities_found = (await session.execute(stmt_vulns)).scalar_one() or 0

    # 3. Safe Apps (score < 40)
    stmt_safe = select(func.count(Scan.id)).where(Scan.status == 'COMPLETED', Scan.risk_score < 40)
    if owner_id is not None:
        stmt_safe = stmt_safe.where(Scan.owner_id == owner_id)
    safe_apps_count = (await session.execute(stmt_safe)).scalar_one() or 0

    # 4. Avg Scan Time
    stmt_avg = select(func.avg(Scan.elapsed_seconds)).where(Scan.status == 'COMPLETED')
    if owner_id is not None:
        stmt_avg = stmt_avg.where(Scan.owner_id == owner_id)
    avg_scan_time = (await session.execute(stmt_avg)).scalar_one() or 0.0

    # 5. Risk Distribution
    stmt_risk = select(Scan.risk_level, func.count(Scan.id)).where(Scan.status == 'COMPLETED').group_by(Scan.risk_level)
    if owner_id is not None:
        stmt_risk = stmt_risk.where(Scan.owner_id == owner_id)
    risk_rows = (await session.execute(stmt_risk)).all()
    risk_distribution = {row[0]: row[1] for row in risk_rows if row[0]}

    # 6. Daily Stats (last 7 days)
    now = datetime.now(timezone.utc)
    seven_days_ago = now - timedelta(days=7)
    stmt_daily = select(Scan.created_at).where(Scan.created_at >= seven_days_ago)
    if owner_id is not None:
        stmt_daily = stmt_daily.where(Scan.owner_id == owner_id)
    daily_rows = (await session.execute(stmt_daily)).scalars().all()
    
    daily_stats = {}
    for i in range(6, -1, -1):
        day_str = (now - timedelta(days=i)).strftime("%a")
        daily_stats[day_str] = 0

    for created_at in daily_rows:
        if created_at:
            # handle timezone aware vs naive
            if created_at.tzinfo is None:
                created_at = created_at.replace(tzinfo=timezone.utc)
            day_str = created_at.strftime("%a")
            if day_str in daily_stats:
                daily_stats[day_str] += 1

    return {
        "total_scans": total_scans,
        "vulnerabilities_found": int(vulnerabilities_found),
        "safe_apps": safe_apps_count,
        "avg_scan_time": float(avg_scan_time),
        "risk_distribution": risk_distribution,
        "daily_stats": [{"name": k, "value": v} for k, v in daily_stats.items()]
    }
