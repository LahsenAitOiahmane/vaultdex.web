"""
SecureStorageInspector — Scan Pipeline Orchestrator (v2 — Two-Phase)

Coordinates the full lifecycle of a single APK scan in two phases:

    Phase A (run_phase_a):
        1. Validate inputs, create directories
        2. Reset emulator (or skip in dev mode)
        3. Wait for device boot
        4. Install the APK
        5. Launch the app
        → Pipeline pauses here. User interacts with the app manually.

    Phase B (run_phase_b):
        1. Pull all storage areas from the device
        2. Clean up (force-stop, uninstall — unless dev mode)
        3. Zip the dump folder
        → Returns for analysis by the engine.

Every step is tracked with timestamps, status, and error details in a
``scan_log`` list that supports live-progress streaming to the frontend
via SSE.

This module is framework-agnostic — it does not import Celery or FastAPI.
"""

import logging
import time
import uuid
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from backend.adb.adb_controller import ADBController
from backend.adb.utils import create_scan_dirs, zip_dump
from backend.config import get_settings
from backend.emulator.genymotion_controller import GenymotionController

logger = logging.getLogger(__name__)

# Type alias
Result = Dict[str, Any]


# ══════════════════════════════════════════════════════════════════════════
#  SCAN STEP ENUM
# ══════════════════════════════════════════════════════════════════════════

class ScanStep(str, Enum):
    """Discrete steps in the scan pipeline, used for progress tracking."""
    INIT = "INIT"
    STATIC_ANALYSIS = "STATIC_ANALYSIS"  # Static APK analysis (manifest, permissions)
    RESET = "RESET"
    BOOT = "BOOT"
    INSTALL = "INSTALL"
    LAUNCH = "LAUNCH"
    WAITING = "WAITING"       # Waiting for user interaction
    PULL = "PULL"
    CLEANUP = "CLEANUP"
    ZIP = "ZIP"
    DONE = "DONE"
    FAILED = "FAILED"


# ══════════════════════════════════════════════════════════════════════════
#  LOG ENTRY BUILDER
# ══════════════════════════════════════════════════════════════════════════

def _log_entry(
    step: ScanStep,
    status: str,
    message: str,
    detail: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Build a timestamped log entry for the scan log.

    Args:
        step:    Current pipeline step.
        status:  "started", "success", "warning", "error".
        message: Human-readable description.
        detail:  Optional technical detail (stdout, error message, etc.).

    Returns:
        Dict suitable for JSON serialisation and streaming.
    """
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "step": step.value,
        "status": status,
        "message": message,
        "detail": detail,
    }


# ══════════════════════════════════════════════════════════════════════════
#  SCAN JOB DATA CLASS
# ══════════════════════════════════════════════════════════════════════════

class ScanJob:
    """
    Immutable description of a scan job.

    Attributes:
        apk_path:     Path to the uploaded APK file on disk.
        package_name: Android package name (may be None — auto-detected).
        scan_id:      Unique identifier for this scan (UUID).
        output_dir:   Base directory for storing pulled data.
    """

    def __init__(
        self,
        apk_path: str,
        package_name: Optional[str] = None,
        scan_id: Optional[str] = None,
        output_dir: Optional[str] = None,
    ) -> None:
        self.apk_path: str = apk_path
        self.package_name: Optional[str] = package_name
        self.scan_id: str = scan_id or uuid.uuid4().hex[:12]
        self.output_dir: str = output_dir or str(
            get_settings().DUMPS_DIR / self.scan_id
        )

    def to_dict(self) -> Dict[str, Any]:
        """Serialise the job to a plain dict."""
        return {
            "apk_path": self.apk_path,
            "package_name": self.package_name,
            "scan_id": self.scan_id,
            "output_dir": self.output_dir,
        }


# ══════════════════════════════════════════════════════════════════════════
#  SCAN RESULT
# ══════════════════════════════════════════════════════════════════════════

class ScanResult:
    """
    Aggregated result of a scan pipeline run.

    Holds success/failure, file paths, timing, and the full scan log.
    """

    def __init__(self, scan_id: str) -> None:
        self.scan_id: str = scan_id
        self.success: bool = False
        self.current_step: ScanStep = ScanStep.INIT
        self.package_name: Optional[str] = None
        self.output_dir: Optional[str] = None
        self.zip_path: Optional[str] = None
        self.total_files: int = 0
        self.started_at: str = datetime.now(timezone.utc).isoformat()
        self.finished_at: Optional[str] = None
        self.elapsed_seconds: float = 0.0
        self.error: Optional[str] = None
        self.scan_log: List[Dict[str, Any]] = []
        self.storage_results: Optional[Dict[str, Any]] = None
        self.static_report_path: Optional[str] = None  # Path to saved static analysis JSON

    def add_log(self, entry: Dict[str, Any]) -> None:
        """Append a log entry and update the current step."""
        self.scan_log.append(entry)
        if "step" in entry:
            try:
                self.current_step = ScanStep(entry["step"])
            except ValueError:
                pass

    def finalise(self, success: bool, error: Optional[str] = None) -> None:
        """Mark the scan as finished."""
        self.success = success
        self.error = error
        self.finished_at = datetime.now(timezone.utc).isoformat()
        self.current_step = ScanStep.DONE if success else ScanStep.FAILED

    def to_dict(self) -> Dict[str, Any]:
        """Serialise the full result for API responses / storage."""
        return {
            "scan_id": self.scan_id,
            "success": self.success,
            "current_step": self.current_step.value,
            "package_name": self.package_name,
            "output_dir": self.output_dir,
            "zip_path": self.zip_path,
            "total_files": self.total_files,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "elapsed_seconds": self.elapsed_seconds,
            "error": self.error,
            "scan_log": self.scan_log,
            "storage_results": self.storage_results,
        }


# ══════════════════════════════════════════════════════════════════════════
#  PHASE A — Install & Launch (stops at WAITING_FOR_USER)
# ══════════════════════════════════════════════════════════════════════════

def run_phase_a(
    job: ScanJob,
    progress_callback: Optional[Callable[[ScanResult], None]] = None,
) -> ScanResult:
    """
    Phase A: Validate, install, and launch the APK.

    After this completes successfully, the app is running on the emulator
    and the user can interact with it (register, login, create data, etc.).
    The pipeline pauses here — Phase B is triggered separately when the
    user clicks "Finalize".

    Pipeline steps:
        1. INIT     — create directories, resolve package name
        2. RESET    — restore emulator to clean snapshot (skipped in dev)
        3. BOOT     — wait for device to finish booting (skipped in dev)
        4. INSTALL  — push the APK onto the device
        5. LAUNCH   — open the app's main activity
        6. WAITING  — ready for user interaction

    Args:
        job:               A ScanJob describing what to scan.
        progress_callback: Optional callable invoked after each step.

    Returns:
        ScanResult with current_step = WAITING on success.
    """
    settings = get_settings()
    pipeline_start = time.monotonic()
    result = ScanResult(scan_id=job.scan_id)
    result.output_dir = job.output_dir

    def _emit(entry: Dict[str, Any]) -> None:
        """Add a log entry and optionally notify the callback."""
        result.add_log(entry)
        if progress_callback:
            try:
                progress_callback(result)
            except Exception:
                logger.debug("Progress callback raised; ignoring.")

    def _fail(step: ScanStep, message: str, detail: Optional[str] = None) -> ScanResult:
        """Mark the scan as failed and return the result."""
        _emit(_log_entry(step, "error", message, detail))
        result.elapsed_seconds = round(time.monotonic() - pipeline_start, 2)
        result.finalise(success=False, error=message)
        logger.error("Scan %s FAILED at %s: %s", job.scan_id, step.value, message)
        return result

    logger.info("═" * 60)
    logger.info("Starting Phase A — scan_id=%s", job.scan_id)
    logger.info("APK: %s", job.apk_path)
    logger.info("═" * 60)

    # ── STEP 0: INIT — validate inputs, create directories ───────────
    _emit(_log_entry(ScanStep.INIT, "started", "Initialising scan …"))

    # Validate APK exists
    apk = Path(job.apk_path)
    if not apk.is_file():
        return _fail(ScanStep.INIT, f"APK file not found: {job.apk_path}")

    # Validate file extension
    if apk.suffix.lower() != ".apk":
        return _fail(ScanStep.INIT, f"Invalid file type: {apk.suffix}")

    # Create dump directories
    dirs_result = create_scan_dirs(job.scan_id)
    if not dirs_result["success"]:
        return _fail(ScanStep.INIT, "Failed to create scan dirs", dirs_result["error"])

    # Resolve package name if not provided
    adb = ADBController()
    if not job.package_name:
        pkg_result = adb.get_package_name(job.apk_path)
        if not pkg_result["success"]:
            return _fail(
                ScanStep.INIT,
                "Could not determine package name",
                pkg_result["error"],
            )
        job.package_name = pkg_result["data"]

    result.package_name = job.package_name
    _emit(_log_entry(
        ScanStep.INIT, "success",
        f"Scan initialised for {job.package_name}",
    ))

    # ── STEP 1: STATIC ANALYSIS — analyse APK manifest ───────────────
    _emit(_log_entry(
        ScanStep.STATIC_ANALYSIS, "started",
        f"Running static analysis on {apk.name} …",
    ))

    try:
        from backend.engine.analysers.static_analyser import StaticAnalyser
        from backend.engine.analyser import AnalysisEngine
        import json as _json

        static_analyser = StaticAnalyser()
        static_result = static_analyser.analyse(job.apk_path)

        # Build the full pydantic report and save it so Phase B can load it
        # without re-running aapt2
        engine = AnalysisEngine()
        static_report = engine._build_static_report(static_result)
        static_json_path = str(Path(job.output_dir) / "static_analysis.json")
        Path(static_json_path).write_text(
            _json.dumps(static_report.model_dump(), indent=2, default=str),
            encoding="utf-8",
        )
        result.static_report_path = static_json_path

        # Build a detailed summary for the SSE log
        flag_warnings = []
        if static_result.flags.debuggable:
            flag_warnings.append("⚠ DEBUGGABLE")
        if static_result.flags.allow_backup:
            flag_warnings.append("⚠ allowBackup=true")
        if static_result.flags.uses_cleartext_traffic:
            flag_warnings.append("⚠ cleartext traffic allowed")
        if static_result.flags.test_only:
            flag_warnings.append("⚠ TEST BUILD")

        flags_str = ", ".join(flag_warnings) if flag_warnings else "No critical flags"

        _emit(_log_entry(
            ScanStep.STATIC_ANALYSIS, "success",
            f"Static analysis complete — "
            f"{static_result.total_permission_count} permission(s) "
            f"({static_result.dangerous_permission_count} dangerous), "
            f"{static_result.total_exported_components} exported component(s), "
            f"{len(static_result.findings)} finding(s). "
            f"Flags: {flags_str}",
            detail=(
                f"Package: {static_result.package_name}, "
                f"Version: {static_result.version_name} ({static_result.version_code}), "
                f"SDK: min={static_result.min_sdk} target={static_result.target_sdk}"
            ),
        ))

    except Exception as exc:
        # Static analysis failure is non-fatal — continue with install
        logger.warning("Static analysis failed: %s", exc)
        _emit(_log_entry(
            ScanStep.STATIC_ANALYSIS, "warning",
            f"Static analysis encountered an error (continuing): {exc}",
        ))

    # ── STEP 2: RESET — restore emulator to clean snapshot ───────────
    if settings.SKIP_EMULATOR_RESET:
        _emit(_log_entry(
            ScanStep.RESET, "success",
            "Skipped emulator reset (dev mode — SKIP_EMULATOR_RESET=true).",
        ))
        _emit(_log_entry(
            ScanStep.BOOT, "success",
            "Skipped boot wait (dev mode — emulator assumed running).",
        ))
        # Just verify ADB connectivity
        conn = adb.connect()
        if not conn["success"]:
            return _fail(
                ScanStep.BOOT,
                "ADB connection failed — is the emulator running?",
                conn["error"],
            )
    else:
        _emit(_log_entry(ScanStep.RESET, "started", "Resetting emulator …"))
        emu = GenymotionController()

        reset_result = emu.reset_to_snapshot()
        if not reset_result["success"]:
            return _fail(ScanStep.RESET, "Snapshot restore failed", reset_result["error"])

        _emit(_log_entry(ScanStep.RESET, "success", "Emulator reset to clean state."))

        # ── STEP 2: BOOT — start VM and wait for device ──────────────
        _emit(_log_entry(ScanStep.BOOT, "started", "Starting emulator and waiting for boot …"))

        start_result = emu.start_vm()
        if not start_result["success"]:
            return _fail(ScanStep.BOOT, "VM start failed", start_result["error"])

        boot_result = emu.wait_for_boot()
        if not boot_result["success"]:
            return _fail(ScanStep.BOOT, "Device did not boot in time", boot_result["error"])

        boot_secs = boot_result["data"]
        _emit(_log_entry(ScanStep.BOOT, "success", f"Device booted in {boot_secs}s."))

        # Ensure ADB is connected after boot
        conn = adb.connect()
        if not conn["success"]:
            return _fail(ScanStep.BOOT, "ADB connection failed after boot", conn["error"])

    # ── STEP 3: INSTALL — push APK onto device ──────────────────────
    _emit(_log_entry(ScanStep.INSTALL, "started", f"Installing {apk.name} …"))

    install_result = adb.install_apk(job.apk_path)
    if not install_result["success"]:
        return _fail(ScanStep.INSTALL, "APK installation failed", install_result["error"])

    _emit(_log_entry(ScanStep.INSTALL, "success", "APK installed."))

    # ── STEP 4: LAUNCH — open the app ────────────────────────────────
    _emit(_log_entry(ScanStep.LAUNCH, "started", "Launching app …"))

    launch_result = adb.launch_app(job.package_name)
    if not launch_result["success"]:
        _emit(_log_entry(
            ScanStep.LAUNCH, "warning",
            "App launch may have failed — check the emulator.",
            launch_result["error"],
        ))
    else:
        _emit(_log_entry(ScanStep.LAUNCH, "success", "App launched."))

    # Small delay to let the app initialise
    time.sleep(3)

    # ── STEP 5: WAITING — ready for user interaction ─────────────────
    _emit(_log_entry(
        ScanStep.WAITING, "success",
        f"App '{job.package_name}' is running on the emulator. "
        f"Interact with it now (register, login, create data, etc.). "
        f"Click 'Finalize Scan' when you are done.",
    ))

    result.elapsed_seconds = round(time.monotonic() - pipeline_start, 2)
    result.success = True
    result.current_step = ScanStep.WAITING

    logger.info("═" * 60)
    logger.info(
        "Phase A complete — scan %s is WAITING_FOR_USER (%.1fs)",
        job.scan_id,
        result.elapsed_seconds,
    )
    logger.info("═" * 60)

    return result


# ══════════════════════════════════════════════════════════════════════════
#  PHASE B — Pull, Cleanup, Zip (triggered after user interaction)
# ══════════════════════════════════════════════════════════════════════════

def run_phase_b(
    job: ScanJob,
    progress_callback: Optional[Callable[[ScanResult], None]] = None,
) -> ScanResult:
    """
    Phase B: Pull storage data, clean up, and zip.

    Called after the user has finished interacting with the app on the
    emulator and clicked "Finalize Scan".

    Pipeline steps:
        1. PULL     — extract all storage areas via ADB pull
        2. CLEANUP  — force-stop and uninstall (unless dev mode)
        3. ZIP      — compress the dump folder
        4. DONE     — return final result

    Args:
        job:               A ScanJob describing what to scan.
        progress_callback: Optional callable invoked after each step.

    Returns:
        ScanResult with the pulled data ready for analysis.
    """
    settings = get_settings()
    pipeline_start = time.monotonic()
    result = ScanResult(scan_id=job.scan_id)
    result.output_dir = job.output_dir
    result.package_name = job.package_name

    def _emit(entry: Dict[str, Any]) -> None:
        """Add a log entry and optionally notify the callback."""
        result.add_log(entry)
        if progress_callback:
            try:
                progress_callback(result)
            except Exception:
                logger.debug("Progress callback raised; ignoring.")

    def _fail(step: ScanStep, message: str, detail: Optional[str] = None) -> ScanResult:
        """Mark the scan as failed and return the result."""
        _emit(_log_entry(step, "error", message, detail))
        result.elapsed_seconds = round(time.monotonic() - pipeline_start, 2)
        result.finalise(success=False, error=message)
        logger.error("Scan %s FAILED at %s: %s", job.scan_id, step.value, message)
        return result

    logger.info("═" * 60)
    logger.info("Starting Phase B — scan_id=%s, package=%s", job.scan_id, job.package_name)
    logger.info("═" * 60)

    adb = ADBController()

    # Verify ADB connectivity
    conn = adb.connect()
    if not conn["success"]:
        return _fail(
            ScanStep.PULL,
            "ADB connection failed — is the emulator still running?",
            conn["error"],
        )

    # ── STEP 1: PULL — extract all storage ───────────────────────────
    _emit(_log_entry(ScanStep.PULL, "started", "Pulling storage from device …"))

    pull_result = adb.pull_all_storage(job.package_name, job.output_dir)
    result.storage_results = pull_result.get("data")

    if pull_result["success"]:
        total = pull_result["data"].get("total_files", 0) if pull_result["data"] else 0
        result.total_files = total
        _emit(_log_entry(
            ScanStep.PULL, "success",
            f"Pulled {total} file(s) from device.",
        ))
    else:
        # Partial pulls are still useful — log warning but continue
        total = 0
        if isinstance(pull_result.get("data"), dict):
            total = pull_result["data"].get("total_files", 0)
        result.total_files = total
        _emit(_log_entry(
            ScanStep.PULL, "warning",
            f"Some storage areas had errors ({total} file(s) pulled).",
            pull_result["error"],
        ))

    # ── STEP 2: CLEANUP — force-stop and uninstall ───────────────────
    _emit(_log_entry(ScanStep.CLEANUP, "started", "Cleaning up device …"))

    # Take a final screenshot before cleanup (best-effort)
    screenshot_dest = str(Path(job.output_dir) / "final_screenshot.png")
    adb.take_screenshot(screenshot_dest)

    adb.force_stop(job.package_name)

    if settings.SKIP_EMULATOR_RESET:
        _emit(_log_entry(
            ScanStep.CLEANUP, "success",
            "Device cleaned up (app kept installed — dev mode).",
        ))
    else:
        adb.uninstall_apk(job.package_name)
        _emit(_log_entry(ScanStep.CLEANUP, "success", "Device cleaned up, app uninstalled."))

    # ── STEP 3: ZIP — package the dump folder ────────────────────────
    _emit(_log_entry(ScanStep.ZIP, "started", "Compressing scan dump …"))

    zip_result = zip_dump(job.scan_id)
    if zip_result["success"]:
        result.zip_path = zip_result["data"]
        _emit(_log_entry(ScanStep.ZIP, "success", f"Dump zipped: {zip_result['data']}"))
    else:
        _emit(_log_entry(
            ScanStep.ZIP, "warning",
            "Zip compression failed (non-fatal).",
            zip_result["error"],
        ))

    # ── DONE ─────────────────────────────────────────────────────────
    result.elapsed_seconds = round(time.monotonic() - pipeline_start, 2)
    result.finalise(success=True)
    _emit(_log_entry(
        ScanStep.DONE, "success",
        f"Data collection complete in {result.elapsed_seconds}s — "
        f"{result.total_files} file(s) extracted.",
    ))

    logger.info("═" * 60)
    logger.info(
        "Phase B complete — scan %s DONE — %d files in %.1fs",
        job.scan_id,
        result.total_files,
        result.elapsed_seconds,
    )
    logger.info("═" * 60)

    return result


# ══════════════════════════════════════════════════════════════════════════
#  LEGACY COMPATIBILITY — run_full_scan (calls both phases without pause)
# ══════════════════════════════════════════════════════════════════════════

def run_full_scan(
    job: ScanJob,
    progress_callback: Optional[Callable[[ScanResult], None]] = None,
) -> ScanResult:
    """
    Execute the full scan pipeline (both phases) without pausing.

    This is kept for backward compatibility with tests and CLI usage.
    For the API flow, use run_phase_a() + run_phase_b() separately.
    """
    result_a = run_phase_a(job, progress_callback)
    if not result_a.success:
        return result_a

    return run_phase_b(job, progress_callback)
