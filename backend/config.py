"""
SecureStorageInspector — Central Configuration

Loads all configuration from environment variables and .env file.
Uses pydantic BaseSettings for validation and type coercion.
No secrets are hardcoded — everything is externalized.
"""

from pathlib import Path
from typing import Optional

from pydantic_settings import BaseSettings
from pydantic import Field, field_validator


# ── Project root is two levels above this file (apk-scanner/) ──────────────
PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    """
    Application-wide settings loaded from environment / .env file.

    Attributes are grouped by subsystem: ADB, Genymotion, storage paths,
    and scan-tuning knobs.
    """

    # ── ADB ──────────────────────────────────────────────────────────────
    # WSL note: we call the Windows adb.exe from WSL, so the default
    # points at the copy bundled inside this repo.
    ADB_PATH: str = Field(
        default=str(PROJECT_ROOT / "adbEXE" / "adb.exe"),
        description="Absolute path to the adb executable (use .exe on WSL/Windows).",
    )
    DEVICE_SERIAL: str = Field(
        default="127.0.0.1:5555",
        description="ADB device serial (IP:port for Genymotion emulators).",
    )

    # ── Genymotion ───────────────────────────────────────────────────────
    GENYMOTION_PATH: str = Field(
        default=r"C:\Program Files\Genymobile\Genymotion",
        description="Install directory of Genymotion (contains gmtool.exe / player.exe).",
    )
    GENYMOTION_VM_NAME: str = Field(
        default="apk_scanner_vm",
        description="Name of the Genymotion virtual device to use.",
    )
    GENYMOTION_SNAPSHOT_NAME: str = Field(
        default="clean",
        description="Snapshot to restore before every scan (must exist in the VM).",
    )

    # ── Storage paths ────────────────────────────────────────────────────
    UPLOADS_DIR: Path = Field(
        default=PROJECT_ROOT / "uploads",
        description="Directory where uploaded APK files are temporarily stored.",
    )
    DUMPS_DIR: Path = Field(
        default=PROJECT_ROOT / "dumps",
        description="Directory where ADB-pulled storage dumps are saved.",
    )
    REPORTS_DIR: Path = Field(
        default=PROJECT_ROOT / "reports",
        description="Directory where generated PDF/JSON reports are saved.",
    )

    # ── Scan tuning ──────────────────────────────────────────────────────
    MONKEY_EVENTS: int = Field(
        default=500,
        ge=1,
        description="Number of pseudo-random UI events monkey runner generates.",
    )
    BOOT_TIMEOUT: int = Field(
        default=120,
        ge=10,
        description="Max seconds to wait for the emulator to finish booting.",
    )
    SCAN_TIMEOUT: int = Field(
        default=300,
        ge=30,
        description="Max seconds for the entire scan pipeline before it is killed.",
    )
    SETTLE_DELAY: int = Field(
        default=10,
        ge=0,
        description="Seconds to wait after monkey run for storage writes to flush.",
    )
    SKIP_EMULATOR_RESET: bool = Field(
        default=False,
        description=(
            "Skip emulator reset/boot steps (dev mode). "
            "Set to true when the emulator is already running."
        ),
    )

    # ── AAPT (Android Asset Packaging Tool) ──────────────────────────────
    AAPT_PATH: Optional[str] = Field(
        default=None,
        description=(
            "Path to aapt/aapt2 executable for extracting package names. "
            "If None, a pure-Python fallback is used."
        ),
    )

    # ── Database (Phase 3) ───────────────────────────────────────────────
    DATABASE_URL: str = Field(
        default="postgresql+asyncpg://scanner:scanner_dev_password@localhost:5432/apk_scanner",
        description="Async PostgreSQL connection string (asyncpg driver).",
    )

    # ── Redis / Celery (Phase 3) ─────────────────────────────────────────
    REDIS_URL: str = Field(
        default="redis://localhost:6379/0",
        description="Redis connection URL for Celery broker and result backend.",
    )
    CELERY_BROKER_URL: str = Field(
        default="redis://localhost:6379/0",
        description="Celery message broker URL.",
    )

    # ── API (Phase 3) ────────────────────────────────────────────────────
    MAX_UPLOAD_SIZE: int = Field(
        default=100 * 1024 * 1024,
        ge=1024,
        description="Maximum APK upload size in bytes (default 100 MB).",
    )
    CORS_ORIGINS: list[str] = Field(
        default=["http://localhost:3000", "http://localhost:5173"],
        description="Allowed CORS origins for the React frontend.",
    )
    API_HOST: str = Field(
        default="127.0.0.1",
        description="Host to bind the API server to. MUST be 127.0.0.1 for security.",
    )
    API_PORT: int = Field(
        default=8000,
        ge=1,
        le=65535,
        description="Port for the API server.",
    )
    RATE_LIMIT_UPLOADS: str = Field(
        default="5/minute",
        description="Rate limit for APK upload endpoint (slowapi format).",
    )

    # ── Validators ───────────────────────────────────────────────────────
    @field_validator("UPLOADS_DIR", "DUMPS_DIR", "REPORTS_DIR", mode="before")
    @classmethod
    def _resolve_path(cls, v: str | Path) -> Path:
        """Ensure storage paths are resolved to absolute Path objects."""
        return Path(v).resolve()

    model_config = {
        "env_file": str(PROJECT_ROOT / ".env"),
        "env_file_encoding": "utf-8",
        "case_sensitive": True,
        "extra": "ignore",
    }


# ── Singleton-style accessor ─────────────────────────────────────────────
_settings: Optional[Settings] = None


def get_settings() -> Settings:
    """Return (and cache) the global Settings instance."""
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
