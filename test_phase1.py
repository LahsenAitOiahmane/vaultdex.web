#!/usr/bin/env python3
"""
SecureStorageInspector — Phase 1 Integration Test Script

Runs through the entire scan pipeline step-by-step and prints a
detailed status report. Use this to verify your ADB + Genymotion
setup is working before moving to Phase 2.

Usage:
    # Test just the ADB connection:
    python test_phase1.py --adb-only

    # Full pipeline test with a real APK:
    python test_phase1.py --apk /path/to/app.apk

    # Full pipeline test with auto-detected package name:
    python test_phase1.py --apk /path/to/app.apk --auto-package

Environment:
    Expects a .env file at the project root (apk-scanner/.env).
    See .env.example for all required configuration keys.
"""

import argparse
import json
import logging
import os
import sys
import time
from pathlib import Path

# ── Ensure the project root is on PYTHONPATH ─────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from backend.config import get_settings
from backend.adb.adb_controller import ADBController
from backend.adb.utils import (
    create_scan_dirs,
    format_file_size,
    get_apk_package_name,
    sanitize_package_name,
    zip_dump,
)
from backend.emulator.genymotion_controller import GenymotionController, VMStatus
from backend.worker.scan_pipeline import ScanJob, ScanResult, ScanStep, run_full_scan


# ── Pretty console output ────────────────────────────────────────────
class Colours:
    """ANSI colour codes for terminal output."""
    BOLD = "\033[1m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    CYAN = "\033[96m"
    DIM = "\033[2m"
    RESET = "\033[0m"


def _ok(msg: str) -> None:
    print(f"  {Colours.GREEN}✔{Colours.RESET} {msg}")


def _warn(msg: str) -> None:
    print(f"  {Colours.YELLOW}⚠{Colours.RESET} {msg}")


def _fail(msg: str) -> None:
    print(f"  {Colours.RED}✖{Colours.RESET} {msg}")


def _info(msg: str) -> None:
    print(f"  {Colours.CYAN}ℹ{Colours.RESET} {msg}")


def _header(title: str) -> None:
    width = 60
    print()
    print(f"{Colours.BOLD}{'═' * width}{Colours.RESET}")
    print(f"{Colours.BOLD}  {title}{Colours.RESET}")
    print(f"{Colours.BOLD}{'═' * width}{Colours.RESET}")


def _subheader(title: str) -> None:
    print(f"\n{Colours.BOLD}  ── {title} ──{Colours.RESET}")


# ══════════════════════════════════════════════════════════════════════
#  TEST: Configuration
# ══════════════════════════════════════════════════════════════════════

def test_config() -> bool:
    """Verify that configuration loads correctly."""
    _subheader("Configuration")
    try:
        settings = get_settings()
        _ok(f"ADB_PATH         = {settings.ADB_PATH}")
        _ok(f"DEVICE_SERIAL    = {settings.DEVICE_SERIAL}")
        _ok(f"GENYMOTION_PATH  = {settings.GENYMOTION_PATH}")
        _ok(f"GENYMOTION_VM    = {settings.GENYMOTION_VM_NAME}")
        _ok(f"SNAPSHOT         = {settings.GENYMOTION_SNAPSHOT_NAME}")
        _ok(f"UPLOADS_DIR      = {settings.UPLOADS_DIR}")
        _ok(f"DUMPS_DIR        = {settings.DUMPS_DIR}")
        _ok(f"MONKEY_EVENTS    = {settings.MONKEY_EVENTS}")
        _ok(f"BOOT_TIMEOUT     = {settings.BOOT_TIMEOUT}s")
        _ok(f"SCAN_TIMEOUT     = {settings.SCAN_TIMEOUT}s")

        # Verify ADB binary exists
        adb = Path(settings.ADB_PATH)
        if adb.exists():
            _ok(f"ADB binary found ({format_file_size(adb.stat().st_size)})")
        else:
            _warn(f"ADB binary NOT found at {adb} — commands will fail")
            return False

        return True
    except Exception as exc:
        _fail(f"Config load failed: {exc}")
        return False


# ══════════════════════════════════════════════════════════════════════
#  TEST: ADB Connection
# ══════════════════════════════════════════════════════════════════════

def test_adb_connection() -> bool:
    """Test that ADB can reach the device."""
    _subheader("ADB Connection")
    adb = ADBController()

    # Connect
    conn = adb.connect()
    if conn["success"]:
        _ok(f"Device connected: {conn['data']}")
    else:
        _fail(f"Connection failed: {conn['error']}")
        return False

    # List packages (quick sanity check)
    pkgs = adb.get_package_list()
    if pkgs["success"]:
        count = len(pkgs["data"])
        _ok(f"Package list retrieved: {count} package(s)")
        # Show a few well-known packages to confirm it's real
        known = [p for p in pkgs["data"] if "android" in p.lower()][:3]
        for p in known:
            _info(f"  → {p}")
    else:
        _warn(f"Package list failed: {pkgs['error']}")

    # Shell test
    shell = adb.run_shell("echo ADB_SHELL_OK")
    if shell["success"] and "ADB_SHELL_OK" in (shell["data"] or ""):
        _ok("Shell command test passed")
    else:
        _warn(f"Shell test issue: {shell.get('error')}")

    return True


# ══════════════════════════════════════════════════════════════════════
#  TEST: Genymotion
# ══════════════════════════════════════════════════════════════════════

def test_genymotion() -> bool:
    """Test Genymotion VM listing and status."""
    _subheader("Genymotion Controller")
    emu = GenymotionController()

    # List VMs
    vms = emu.list_vms()
    if vms["success"]:
        vm_list = vms["data"] or []
        _ok(f"Found {len(vm_list)} VM(s)")
        for vm in vm_list[:5]:
            _info(f"  → {vm}")
    else:
        _warn(f"VM listing failed: {vms['error']}")
        _info("This is expected if gmtool is not in PATH or not installed.")
        return False

    # Check status of configured VM
    status = emu.get_vm_status()
    if status["success"]:
        _ok(f"VM '{emu.vm_name}' status: {status['data']}")
    else:
        _warn(f"VM status check failed: {status['error']}")

    return True


# ══════════════════════════════════════════════════════════════════════
#  TEST: APK Package Name Extraction
# ══════════════════════════════════════════════════════════════════════

def test_package_extraction(apk_path: str) -> bool:
    """Test package name extraction from an APK."""
    _subheader("Package Name Extraction")

    result = get_apk_package_name(apk_path)
    if result["success"]:
        _ok(f"Package name: {result['data']}")
        return True
    else:
        _fail(f"Extraction failed: {result['error']}")
        return False


# ══════════════════════════════════════════════════════════════════════
#  TEST: Utility Functions
# ══════════════════════════════════════════════════════════════════════

def test_utils() -> bool:
    """Test utility functions."""
    _subheader("Utility Functions")

    # Package name validation
    valid = sanitize_package_name("com.example.app")
    assert valid["success"], "Valid package name rejected"
    _ok("sanitize_package_name('com.example.app') → valid")

    invalid = sanitize_package_name("not-a-package")
    assert not invalid["success"], "Invalid package name accepted"
    _ok("sanitize_package_name('not-a-package') → rejected")

    # File size formatting
    assert format_file_size(0) == "0 B"
    assert format_file_size(1024) == "1.00 KB"
    assert format_file_size(1572864) == "1.50 MB"
    _ok("format_file_size() works correctly")

    # Scan dir creation
    test_id = "test_utils_check"
    settings = get_settings()
    dirs = create_scan_dirs(test_id, base_dir=settings.DUMPS_DIR)
    if dirs["success"]:
        _ok(f"create_scan_dirs() created structure at dumps/{test_id}/")
        # Clean up
        import shutil
        test_dir = settings.DUMPS_DIR / test_id
        if test_dir.exists():
            shutil.rmtree(test_dir)
            _info("  (cleaned up test directory)")
    else:
        _warn(f"create_scan_dirs() failed: {dirs['error']}")

    return True


# ══════════════════════════════════════════════════════════════════════
#  TEST: Full Pipeline
# ══════════════════════════════════════════════════════════════════════

def test_full_pipeline(apk_path: str, package_name: str | None = None) -> bool:
    """Run the complete scan pipeline end-to-end."""
    _subheader("Full Scan Pipeline")

    _info(f"APK: {apk_path}")
    if package_name:
        _info(f"Package: {package_name}")
    else:
        _info("Package: (auto-detect)")

    job = ScanJob(
        apk_path=apk_path,
        package_name=package_name,
        scan_id=f"test_{int(time.time())}",
    )

    _info(f"Scan ID: {job.scan_id}")
    _info(f"Output:  {job.output_dir}")
    print()

    # Progress callback — prints each step live
    def on_progress(result: ScanResult) -> None:
        if result.scan_log:
            entry = result.scan_log[-1]
            status = entry.get("status", "")
            step = entry.get("step", "")
            msg = entry.get("message", "")
            if status == "success":
                _ok(f"[{step}] {msg}")
            elif status == "warning":
                _warn(f"[{step}] {msg}")
            elif status == "error":
                _fail(f"[{step}] {msg}")
            else:
                _info(f"[{step}] {msg}")

    # Run it
    result = run_full_scan(job, progress_callback=on_progress)

    # ── Final report ─────────────────────────────────────────────────
    _subheader("Scan Result Summary")

    if result.success:
        _ok(f"Status:       SUCCESS")
    else:
        _fail(f"Status:       FAILED")

    _info(f"Scan ID:      {result.scan_id}")
    _info(f"Package:      {result.package_name}")
    _info(f"Files pulled: {result.total_files}")
    _info(f"Elapsed:      {result.elapsed_seconds}s")

    if result.zip_path:
        _info(f"Zip archive:  {result.zip_path}")
    if result.error:
        _fail(f"Error:        {result.error}")

    # Print the full scan log as JSON for debugging
    _subheader("Full Scan Log (JSON)")
    print(json.dumps(result.scan_log, indent=2, default=str))

    return result.success


# ══════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════

def main() -> None:
    """Entry point for the Phase 1 test script."""
    parser = argparse.ArgumentParser(
        description="SecureStorageInspector — Phase 1 Test Suite",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--apk",
        type=str,
        default=None,
        help="Path to an APK file for full pipeline testing.",
    )
    parser.add_argument(
        "--package",
        type=str,
        default=None,
        help="Android package name (e.g. com.example.app). Auto-detected if omitted.",
    )
    parser.add_argument(
        "--adb-only",
        action="store_true",
        help="Only test ADB connection (skip emulator and pipeline).",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable debug-level logging.",
    )
    args = parser.parse_args()

    # Configure logging
    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
        datefmt="%H:%M:%S",
    )
    # Reduce noise from overly chatty libraries
    logging.getLogger("urllib3").setLevel(logging.WARNING)

    _header("SecureStorageInspector — Phase 1 Tests")

    passed = 0
    failed = 0

    # Always run config test
    if test_config():
        passed += 1
    else:
        failed += 1
        _fail("Config test failed — aborting.")
        sys.exit(1)

    # Always run utils test
    if test_utils():
        passed += 1
    else:
        failed += 1

    # ADB connection
    if test_adb_connection():
        passed += 1
    else:
        failed += 1
        if args.adb_only:
            _fail("ADB test failed.")

    if args.adb_only:
        _header("Results")
        _info(f"Passed: {passed}  |  Failed: {failed}")
        sys.exit(0 if failed == 0 else 1)

    # Genymotion
    if test_genymotion():
        passed += 1
    else:
        failed += 1

    # Package extraction (only if APK provided)
    if args.apk:
        if test_package_extraction(args.apk):
            passed += 1
        else:
            failed += 1

    # Full pipeline (only if APK provided)
    if args.apk:
        if test_full_pipeline(args.apk, package_name=args.package):
            passed += 1
        else:
            failed += 1

    # ── Summary ──────────────────────────────────────────────────────
    _header("Test Results")
    total = passed + failed
    _info(f"Total: {total}  |  Passed: {passed}  |  Failed: {failed}")

    if failed == 0:
        _ok("All tests passed! Phase 1 is ready. 🚀")
    else:
        _warn(f"{failed} test(s) failed — review the output above.")

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
