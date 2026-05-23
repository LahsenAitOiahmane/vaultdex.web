"""
SecureStorageInspector — Scan Endpoints

All /api/v1/scans routes: upload, status, progress (SSE), report,
list, and delete.

Security:
    - File uploads validated (extension, magic bytes, size limit).
    - Uploaded files stored with randomised UUID names.
    - Rate limiting on upload endpoint.
    - All DB queries via ORM (no SQL injection).
    - TODO(security): Authentication required before production.
    - TODO(security): CSRF protection needed if cookie-based auth added.
    - TODO(security): Antivirus/malware scanning not implemented.
"""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, UploadFile, File
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.dependencies import get_db
from backend.api.auth import get_current_user
from backend.db.models import User
from backend.api.middleware import limiter
from backend.api.schemas import (
    DeleteResponse,
    ErrorResponse,
    ScanCreateResponse,
    ScanListItem,
    ScanListResponse,
    ScanStatusResponse,
)
from backend.config import get_settings
from backend.db import crud

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/scans", tags=["scans"])

# APK magic bytes: ZIP format starts with PK (0x50, 0x4B)
_APK_MAGIC = b"PK"


# ══════════════════════════════════════════════════════════════════════
#  POST /scans — Upload APK
# ══════════════════════════════════════════════════════════════════════

@router.post(
    "",
    response_model=ScanCreateResponse,
    status_code=202,
    responses={
        400: {"model": ErrorResponse, "description": "Invalid APK file."},
        413: {"model": ErrorResponse, "description": "File too large."},
        429: {"model": ErrorResponse, "description": "Rate limit exceeded."},
    },
    summary="Upload APK and start scan",
    description="Upload an Android APK file. Returns a scan_id for tracking.",
)
@limiter.limit(lambda: get_settings().RATE_LIMIT_UPLOADS)
async def upload_apk(
    request: Request,
    file: UploadFile = File(..., description="The APK file to scan."),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Accept an APK upload, validate it, save it, and queue a scan job.

    Validation pipeline:
        1. File extension must be .apk
        2. File size must be ≤ MAX_UPLOAD_SIZE
        3. Magic bytes must be PK (ZIP format)
        4. Package name must be extractable (via aapt2 or fallback parser)
    """
    settings = get_settings()

    # ── 1. Validate extension ────────────────────────────────────────
    original_filename = file.filename or "unknown.apk"
    if not original_filename.lower().endswith(".apk"):
        raise HTTPException(
            status_code=400,
            detail=f"File must have .apk extension. Got: '{original_filename}'",
        )

    # ── 2. Read file with size check ─────────────────────────────────
    max_size = settings.MAX_UPLOAD_SIZE
    chunks = []
    total_size = 0

    while True:
        chunk = await file.read(64 * 1024)  # 64 KB chunks
        if not chunk:
            break
        total_size += len(chunk)
        if total_size > max_size:
            raise HTTPException(
                status_code=413,
                detail=(
                    f"File exceeds maximum upload size of "
                    f"{max_size // (1024 * 1024)} MB."
                ),
            )
        chunks.append(chunk)

    if total_size == 0:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    file_content = b"".join(chunks)

    # ── 3. Validate magic bytes (APK = ZIP = PK) ────────────────────
    if not file_content[:2] == _APK_MAGIC:
        raise HTTPException(
            status_code=400,
            detail="File is not a valid APK (invalid magic bytes). "
            "APK files must be in ZIP format.",
        )

    # ── 4. Save with randomised filename ─────────────────────────────
    scan_id = uuid.uuid4().hex[:12]
    safe_filename = f"{uuid.uuid4().hex}.apk"
    uploads_dir = settings.UPLOADS_DIR
    uploads_dir.mkdir(parents=True, exist_ok=True)
    apk_path = uploads_dir / safe_filename

    apk_path.write_bytes(file_content)
    logger.info(
        "APK saved: %s → %s (%d bytes)",
        original_filename,
        safe_filename,
        total_size,
    )

    # ── 5. Extract package name ──────────────────────────────────────
    package_name = _extract_package_name(str(apk_path))
    if not package_name:
        # Cleanup the file if we can't extract the package name
        apk_path.unlink(missing_ok=True)
        raise HTTPException(
            status_code=400,
            detail="Cannot extract package name from APK. "
            "The file may be corrupted or not a valid Android application.",
        )

    # ── 6. Create DB record ──────────────────────────────────────────
    scan = await crud.create_scan(
        db,
        scan_id=scan_id,
        owner_id=current_user.id,
        package_name=package_name,
        apk_filename=original_filename,
        apk_path=str(apk_path),
    )

    # ── 7. Queue Celery task ─────────────────────────────────────────
    from backend.worker.tasks import run_scan_task

    task = run_scan_task.delay(scan_id)

    # Update the celery task ID in the DB
    from sqlalchemy import update as sql_update
    from backend.db.models import Scan

    stmt = (
        sql_update(Scan)
        .where(Scan.scan_id == scan_id)
        .values(celery_task_id=task.id)
    )
    await db.execute(stmt)

    logger.info(
        "Scan queued: scan_id=%s, package=%s, celery_task=%s",
        scan_id,
        package_name,
        task.id,
    )

    return ScanCreateResponse(
        scan_id=scan_id,
        status="QUEUED",
        package_name=package_name,
        created_at=datetime.now(timezone.utc).isoformat(),
        message=(
            f"Scan queued for {package_name}. "
            f"Track progress at /api/v1/scans/{scan_id}/progress"
        ),
    )


def _extract_package_name(apk_path: str) -> Optional[str]:
    """
    Extract the package name from an APK file.

    Tries aapt2 first, then falls back to the pure-Python parser.
    Runs synchronously since it's a quick operation.
    """
    from backend.adb.adb_controller import ADBController

    try:
        adb = ADBController()
        result = adb.get_package_name(apk_path)
        if result["success"] and result.get("data"):
            return result["data"]
    except Exception as exc:
        logger.warning("Package name extraction failed: %s", exc)

    return None


# ══════════════════════════════════════════════════════════════════════
#  GET /scans — List All Scans
# ══════════════════════════════════════════════════════════════════════

@router.get(
    "",
    response_model=ScanListResponse,
    summary="List all scans",
    description="Paginated list of all scans, newest first.",
)
async def list_scans(
    page: int = 1,
    page_size: int = 20,
    status: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List scans with pagination and optional status filter."""
    if page < 1:
        page = 1
    if page_size < 1 or page_size > 100:
        page_size = 20

    scans, total = await crud.list_scans(
        db,
        page=page,
        page_size=page_size,
        status=status,
        owner_id=current_user.id,
    )

    return ScanListResponse(
        scans=[ScanListItem.from_scan(s) for s in scans],
        total=total,
        page=page,
        page_size=page_size,
    )


# ══════════════════════════════════════════════════════════════════════
#  GET /scans/stats — Dashboard Analytics
# ══════════════════════════════════════════════════════════════════════

@router.get(
    "/stats",
    summary="Get dashboard analytics",
    description="Returns aggregate statistics for the dashboard.",
)
async def get_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get aggregated dashboard stats."""
    return await crud.get_scan_stats(db, owner_id=current_user.id)

# ══════════════════════════════════════════════════════════════════════
#  GET /scans/{scan_id} — Scan Status
# ══════════════════════════════════════════════════════════════════════

@router.get(
    "/{scan_id}",
    response_model=ScanStatusResponse,
    responses={404: {"model": ErrorResponse}},
    summary="Get scan status",
    description="Returns current status and progress of a scan.",
)
async def get_scan_status(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get the current status and progress of a specific scan."""
    scan = await crud.get_scan(db, scan_id, owner_id=current_user.id)
    if scan is None:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found.")

    return ScanStatusResponse.from_scan(scan)


# ══════════════════════════════════════════════════════════════════════
#  GET /scans/{scan_id}/progress — SSE Stream
# ══════════════════════════════════════════════════════════════════════

@router.get(
    "/{scan_id}/progress",
    responses={404: {"model": ErrorResponse}},
    summary="Stream scan progress (SSE)",
    description=(
        "Server-Sent Events stream of real-time scan progress. "
        "Sends all existing log entries immediately, then streams "
        "new entries as they arrive. Closes when scan completes or fails."
    ),
)
async def stream_progress(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    SSE endpoint for real-time scan progress.

    The client opens a persistent HTTP connection. The server:
    1. Sends all existing log entries immediately (late-joiner support).
    2. Polls the DB every 1s for new entries.
    3. Closes the stream when the scan reaches DONE or FAILED.
    """
    # Verify the scan exists
    scan = await crud.get_scan(db, scan_id, owner_id=current_user.id)
    if scan is None:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found.")

    async def event_generator():
        """Async generator that yields SSE events."""
        sent_count = 0
        terminal_statuses = {"COMPLETED", "FAILED", "WAITING_FOR_USER"}

        while True:
            # Open a fresh session for each poll cycle
            from backend.db.database import get_session
            async with get_session() as session:
                row = await crud.get_scan_log(session, scan_id, owner_id=current_user.id)

            if row is None:
                # Scan was deleted while streaming
                yield f"data: {json.dumps({'step': 'ERROR', 'status': 'error', 'message': 'Scan not found'})}\n\n"
                return

            scan_log, status = row

            # Send any new log entries
            if scan_log and len(scan_log) > sent_count:
                for entry in scan_log[sent_count:]:
                    event_data = json.dumps(entry)
                    yield f"data: {event_data}\n\n"
                sent_count = len(scan_log)

            # Check if scan is terminal
            if status in terminal_statuses:
                return

            # Wait 1 second before polling again
            await asyncio.sleep(1)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",  # Disable nginx buffering
        },
    )


# ══════════════════════════════════════════════════════════════════════
#  POST /scans/{scan_id}/finalize — Trigger Phase B
# ══════════════════════════════════════════════════════════════════════

@router.post(
    "/{scan_id}/finalize",
    response_model=ScanCreateResponse,
    status_code=202,
    responses={
        400: {"model": ErrorResponse, "description": "Scan not in WAITING_FOR_USER state."},
        404: {"model": ErrorResponse, "description": "Scan not found."},
    },
    summary="Finalize scan — trigger data collection and analysis",
    description=(
        "Called after the user has finished interacting with the app on the "
        "emulator. Triggers Phase B: pull storage data, run analysis engine, "
        "and produce the security report."
    ),
)
async def finalize_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Trigger Phase B for a scan that is waiting for user input.

    Only valid when the scan status is WAITING_FOR_USER.
    Queues a Celery task that pulls storage, runs analysis, and completes.
    """
    scan = await crud.get_scan(db, scan_id, owner_id=current_user.id)
    if scan is None:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found.")

    if scan.status != "WAITING_FOR_USER":
        raise HTTPException(
            status_code=400,
            detail=(
                f"Scan '{scan_id}' is not waiting for user input. "
                f"Current status: {scan.status}. "
                f"Only scans in WAITING_FOR_USER state can be finalized."
            ),
        )

    # Queue the finalize task
    from backend.worker.tasks import finalize_scan_task

    task = finalize_scan_task.delay(scan_id)

    # Update celery task ID in DB
    from sqlalchemy import update as sql_update
    from backend.db.models import Scan as ScanModel

    stmt = (
        sql_update(ScanModel)
        .where(ScanModel.scan_id == scan_id)
        .values(celery_task_id=task.id)
    )
    await db.execute(stmt)

    logger.info(
        "Finalize queued: scan_id=%s, celery_task=%s",
        scan_id,
        task.id,
    )

    return ScanCreateResponse(
        scan_id=scan_id,
        status="FINALIZING",
        package_name=scan.package_name,
        created_at=scan.created_at.isoformat() if scan.created_at else "",
        message=(
            f"Finalizing scan for {scan.package_name}. "
            f"Pulling data and running analysis. "
            f"Track progress at /api/v1/scans/{scan_id}/progress"
        ),
    )


# ══════════════════════════════════════════════════════════════════════
#  GET /scans/{scan_id}/report — Full Report
# ══════════════════════════════════════════════════════════════════════

@router.get(
    "/{scan_id}/report",
    responses={
        404: {"model": ErrorResponse},
        409: {"model": ErrorResponse, "description": "Scan not yet completed."},
    },
    summary="Get full security report",
    description="Returns the complete SecurityReport JSON for a completed scan.",
)
async def get_report(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Retrieve the full SecurityReport for a completed scan.

    Returns 409 if the scan is still running, 404 if not found.
    """
    scan = await crud.get_scan(db, scan_id, owner_id=current_user.id)
    if scan is None:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found.")

    if scan.status != "COMPLETED":
        if scan.status == "FAILED":
            raise HTTPException(
                status_code=409,
                detail=f"Scan '{scan_id}' failed: {scan.error or 'unknown error'}",
            )
        raise HTTPException(
            status_code=409,
            detail=(
                f"Scan '{scan_id}' is still {scan.status.lower()}. "
                f"Current step: {scan.current_step or 'unknown'}."
            ),
        )

    if scan.report is None:
        raise HTTPException(
            status_code=409,
            detail=f"Scan '{scan_id}' completed but report is missing.",
        )

    return scan.report


# ══════════════════════════════════════════════════════════════════════
#  DELETE /scans/{scan_id} — Delete Scan
# ══════════════════════════════════════════════════════════════════════

@router.delete(
    "/{scan_id}",
    response_model=DeleteResponse,
    responses={404: {"model": ErrorResponse}},
    summary="Delete a scan",
    description="Deletes the scan record and all associated files (APK, dump, report).",
)
async def delete_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Delete a scan and all its associated files.

    Deletes: DB record, uploaded APK, dump folder, report JSON.
    """
    # Fetch scan first to get file paths
    scan = await crud.get_scan(db, scan_id, owner_id=current_user.id)
    if scan is None:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found.")

    # Collect paths to clean up
    paths_to_delete = []

    if scan.apk_path:
        paths_to_delete.append(Path(scan.apk_path))

    if scan.dump_dir:
        paths_to_delete.append(Path(scan.dump_dir))

    settings = get_settings()
    report_path = settings.REPORTS_DIR / f"{scan_id}.json"
    if report_path.exists():
        paths_to_delete.append(report_path)

    # Delete from database first
    deleted = await crud.delete_scan(db, scan_id, owner_id=current_user.id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found.")

    # Clean up files (best-effort, don't fail if files are missing)
    for path in paths_to_delete:
        try:
            if path.is_dir():
                shutil.rmtree(str(path), ignore_errors=True)
                logger.info("Deleted dump directory: %s", path)
            elif path.is_file():
                path.unlink(missing_ok=True)
                logger.info("Deleted file: %s", path)
        except Exception as exc:
            logger.warning("Failed to delete %s: %s", path, exc)

    return DeleteResponse(message=f"Scan '{scan_id}' deleted.")
