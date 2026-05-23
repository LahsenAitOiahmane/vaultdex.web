"""
SecureStorageInspector — API Request/Response Schemas

Pydantic models that define the contract between the API and its
consumers. These are separate from the database models and the
engine models — they only describe what the HTTP API accepts and
returns.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# ══════════════════════════════════════════════════════════════════════
#  UPLOAD RESPONSE
# ══════════════════════════════════════════════════════════════════════

class ScanCreateResponse(BaseModel):
    """Returned immediately after a successful APK upload."""
    scan_id: str = Field(..., description="Unique scan identifier for tracking.")
    status: str = Field(default="QUEUED", description="Initial scan status.")
    package_name: Optional[str] = Field(None, description="Extracted Android package name.")
    created_at: str = Field(..., description="ISO 8601 timestamp of creation.")
    message: str = Field(..., description="Human-readable status message.")


# ══════════════════════════════════════════════════════════════════════
#  SCAN STATUS
# ══════════════════════════════════════════════════════════════════════

# Map pipeline steps to approximate completion percentages
_STEP_PROGRESS = {
    "QUEUED": 0,
    "INIT": 5,
    "STATIC_ANALYSIS": 10,       # Static APK analysis (manifest, permissions)
    "RESET": 15,
    "BOOT": 25,
    "INSTALL": 35,
    "LAUNCH": 45,
    "WAITING": 50,               # Waiting for user interaction
    "WAITING_FOR_USER": 50,      # Status alias
    "PULL": 60,
    "FINALIZING": 65,            # Status alias for Phase B
    "CLEANUP": 75,
    "ZIP": 80,
    "ANALYSING": 90,
    "DONE": 100,
    "FAILED": 100,
    "COMPLETED": 100,
}


class ScanStatusResponse(BaseModel):
    """Current status of a scan, returned by GET /scans/{scan_id}."""
    scan_id: str
    package_name: Optional[str] = None
    status: str
    current_step: Optional[str] = None
    progress_pct: int = Field(
        default=0,
        ge=0,
        le=100,
        description="Approximate progress percentage.",
    )
    created_at: Optional[str] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    elapsed_seconds: Optional[float] = None
    error: Optional[str] = None

    @classmethod
    def from_scan(cls, scan) -> ScanStatusResponse:
        """Build from a Scan ORM object."""
        step = scan.current_step or scan.status
        pct = _STEP_PROGRESS.get(step, 0)
        return cls(
            scan_id=scan.scan_id,
            package_name=scan.package_name,
            status=scan.status,
            current_step=scan.current_step,
            progress_pct=pct,
            created_at=scan.created_at.isoformat() if scan.created_at else None,
            started_at=scan.started_at.isoformat() if scan.started_at else None,
            completed_at=scan.completed_at.isoformat() if scan.completed_at else None,
            elapsed_seconds=scan.elapsed_seconds,
            error=scan.error,
        )


# ══════════════════════════════════════════════════════════════════════
#  SCAN LIST
# ══════════════════════════════════════════════════════════════════════

class ScanListItem(BaseModel):
    """Summary of a scan for list views (no full report)."""
    scan_id: str
    package_name: Optional[str] = None
    status: str
    risk_score: Optional[int] = None
    risk_level: Optional[str] = None
    total_findings: Optional[int] = None
    created_at: Optional[str] = None
    completed_at: Optional[str] = None

    @classmethod
    def from_scan(cls, scan) -> ScanListItem:
        """Build from a Scan ORM object."""
        return cls(
            scan_id=scan.scan_id,
            package_name=scan.package_name,
            status=scan.status,
            risk_score=scan.risk_score,
            risk_level=scan.risk_level,
            total_findings=scan.total_findings,
            created_at=scan.created_at.isoformat() if scan.created_at else None,
            completed_at=scan.completed_at.isoformat() if scan.completed_at else None,
        )


class ScanListResponse(BaseModel):
    """Paginated list of scans."""
    scans: List[ScanListItem]
    total: int
    page: int
    page_size: int


# ══════════════════════════════════════════════════════════════════════
#  DELETE RESPONSE
# ══════════════════════════════════════════════════════════════════════

class DeleteResponse(BaseModel):
    """Returned after deleting a scan."""
    message: str


# ══════════════════════════════════════════════════════════════════════
#  ERROR RESPONSE
# ══════════════════════════════════════════════════════════════════════

class ErrorResponse(BaseModel):
    """Standard error response body."""
    detail: str


# ══════════════════════════════════════════════════════════════════════
#  HEALTH CHECK
# ══════════════════════════════════════════════════════════════════════

class HealthResponse(BaseModel):
    """System health check response."""
    status: str = Field(..., description="Overall status: 'healthy' or 'degraded'.")
    database: bool = Field(..., description="PostgreSQL reachable.")
    redis: bool = Field(..., description="Redis reachable.")
    disk_uploads_mb: Optional[float] = Field(None, description="Free disk space for uploads (MB).")
    version: str = Field(default="3.0.0", description="API version.")
