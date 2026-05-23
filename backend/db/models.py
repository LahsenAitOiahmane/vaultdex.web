"""
SecureStorageInspector — SQLAlchemy ORM Models

Defines the ``Scan`` table that stores all scan metadata, progress logs,
and the full security report as JSONB.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import (
    Column,
    DateTime,
    Float,
    Index,
    Integer,
    String,
    Text,
    func,
    ForeignKey,
    Boolean
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """SQLAlchemy declarative base for all ORM models."""
    pass


class User(Base):
    """
    Represents a registered user in the system.
    """
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    scans: Mapped[List["Scan"]] = relationship("Scan", back_populates="owner", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<User id={self.id} email={self.email!r}>"


class Scan(Base):
    """
    Represents a single APK security scan.

    Stores everything about the scan lifecycle: metadata, timing,
    step-by-step progress log, and the full SecurityReport JSON.
    """

    __tablename__ = "scans"

    # ── Primary key ──────────────────────────────────────────────────
    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    # ── Scan identification ──────────────────────────────────────────
    scan_id: Mapped[str] = mapped_column(
        String(64),
        unique=True,
        nullable=False,
        index=True,
    )
    package_name: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )
    owner_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    owner: Mapped[Optional["User"]] = relationship("User", back_populates="scans")

    # ── Status tracking ──────────────────────────────────────────────
    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="QUEUED",
        index=True,
    )
    current_step: Mapped[Optional[str]] = mapped_column(
        String(20),
        nullable=True,
    )

    # ── File paths ───────────────────────────────────────────────────
    apk_filename: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        comment="Original uploaded filename (metadata only, not used for storage).",
    )
    apk_path: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        comment="Randomised path on disk (UUID-based).",
    )
    dump_dir: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    error: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )

    # ── Timing ───────────────────────────────────────────────────────
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    started_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    elapsed_seconds: Mapped[Optional[float]] = mapped_column(
        Float,
        nullable=True,
    )

    # ── Results (JSONB) ──────────────────────────────────────────────
    scan_log: Mapped[Optional[list]] = mapped_column(
        JSONB,
        nullable=True,
        default=list,
        comment="Step-by-step log entries from the pipeline.",
    )
    report: Mapped[Optional[dict]] = mapped_column(
        JSONB,
        nullable=True,
        comment="Full SecurityReport JSON from the analysis engine.",
    )

    # ── Denormalised report summary (for list queries) ───────────────
    risk_score: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
    )
    risk_level: Mapped[Optional[str]] = mapped_column(
        String(20),
        nullable=True,
    )
    total_findings: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
    )

    # ── Celery tracking ──────────────────────────────────────────────
    celery_task_id: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )

    # ── Indexes ──────────────────────────────────────────────────────
    __table_args__ = (
        Index("idx_scans_created", "created_at"),
    )

    def __repr__(self) -> str:
        return (
            f"<Scan scan_id={self.scan_id!r} "
            f"status={self.status!r} "
            f"package={self.package_name!r}>"
        )
