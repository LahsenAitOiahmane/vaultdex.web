"""
SecureStorageInspector — Genymotion Emulator Controller

Manages the lifecycle of a Genymotion Android virtual machine via the
``gmtool`` CLI. Designed for WSL-to-Windows interop: we call gmtool.exe
through subprocess.

Key capabilities:
    - Start / stop virtual machines
    - Restore to a clean snapshot before each scan
    - Poll for boot completion via ADB
    - List available VMs and query their status

Security notes:
    - All subprocess calls use list arguments (no shell=True).
    - Every blocking operation has a configurable timeout.
    - VM names are not sanitised because they are read from config, not
      user input.  If they were user-supplied, add validation.
"""

import logging
import os
import subprocess
import time
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from backend.config import get_settings

logger = logging.getLogger(__name__)

# Type alias for structured results
Result = Dict[str, Any]


class VMStatus(str, Enum):
    """Known states a Genymotion VM can be in."""
    RUNNING = "running"
    STOPPED = "stopped"
    BOOTING = "booting"
    UNKNOWN = "unknown"


class GenymotionController:
    """
    Controls a Genymotion Android emulator through ``gmtool`` (CLI).

    The controller wraps all gmtool commands, adds timeout protection,
    and exposes a ``wait_for_boot`` method that polls ADB until the
    device reports ``sys.boot_completed=1``.

    Usage::

        emu = GenymotionController()
        emu.reset_to_snapshot("clean")
        emu.start_vm()
        emu.wait_for_boot()
        # … device is now ready for ADB operations …
        emu.stop_vm()
    """

    # Default timeout for gmtool commands (seconds)
    _CMD_TIMEOUT: int = 60

    def __init__(
        self,
        genymotion_path: Optional[str] = None,
        vm_name: Optional[str] = None,
    ) -> None:
        """
        Initialise the Genymotion controller.

        Args:
            genymotion_path: Directory containing gmtool.exe / player.exe.
                             Defaults to the value in settings.
            vm_name:         Name of the virtual device to manage.
                             Defaults to the value in settings.
        """
        settings = get_settings()
        self.genymotion_path: str = genymotion_path or settings.GENYMOTION_PATH
        self.vm_name: str = vm_name or settings.GENYMOTION_VM_NAME
        self.boot_timeout: int = settings.BOOT_TIMEOUT

        # Build the full path to gmtool executable.
        # On WSL, GENYMOTION_PATH may be a Windows-style backslash path
        # (e.g. C:\Program Files\...). POSIX os.path.join doesn't
        # understand backslashes, so we detect the dominant separator
        # and join with it.
        gp = self.genymotion_path.rstrip("/\\")
        sep = "\\" if "\\" in gp else "/"
        self._gmtool: str = gp + sep + "gmtool.exe"

        logger.info(
            "GenymotionController initialised — gmtool=%s, vm=%s",
            self._gmtool,
            self.vm_name,
        )

    # ══════════════════════════════════════════════════════════════════
    #  PRIVATE HELPERS
    # ══════════════════════════════════════════════════════════════════

    def _run_gmtool(
        self,
        args: List[str],
        timeout: Optional[int] = None,
    ) -> Result:
        """
        Execute a gmtool command and return a structured result.

        Args:
            args:    Tokens after ``gmtool`` (e.g. ``["admin", "start", vm]``).
            timeout: Per-command timeout in seconds.

        Returns:
            {success: bool, data: str (stdout), error: str | None}
        """
        timeout = timeout or self._CMD_TIMEOUT
        cmd = [self._gmtool] + args
        cmd_str = " ".join(cmd)
        logger.debug("gmtool exec: %s (timeout=%ds)", cmd_str, timeout)

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            stdout = proc.stdout.strip()
            stderr = proc.stderr.strip()

            if proc.returncode != 0:
                logger.error(
                    "gmtool command failed (rc=%d): %s",
                    proc.returncode,
                    stderr or stdout,
                )
                return {
                    "success": False,
                    "data": stdout,
                    "error": stderr or f"Exit code {proc.returncode}",
                }

            return {"success": True, "data": stdout, "error": None}

        except subprocess.TimeoutExpired:
            logger.error("gmtool command timed out after %ds: %s", timeout, cmd_str)
            return {
                "success": False,
                "data": None,
                "error": f"Command timed out after {timeout}s",
            }
        except FileNotFoundError:
            logger.error("gmtool binary not found at: %s", self._gmtool)
            return {
                "success": False,
                "data": None,
                "error": f"gmtool binary not found: {self._gmtool}",
            }
        except OSError as exc:
            logger.exception("OS error executing gmtool: %s", exc)
            return {"success": False, "data": None, "error": str(exc)}

    # ══════════════════════════════════════════════════════════════════
    #  VM LIFECYCLE
    # ══════════════════════════════════════════════════════════════════

    def start_vm(self) -> Result:
        """
        Start the Genymotion virtual machine.

        If the VM is already running, gmtool returns a success status
        and this method treats it as a no-op.

        Returns:
            {success, data: gmtool output, error}
        """
        logger.info("Starting VM '%s' …", self.vm_name)

        # Check current state first to avoid unnecessary start attempts
        status = self.get_vm_status()
        if status.get("data") == VMStatus.RUNNING:
            logger.info("VM '%s' is already running.", self.vm_name)
            return {"success": True, "data": "Already running", "error": None}

        result = self._run_gmtool(
            ["admin", "start", self.vm_name],
            timeout=120,  # VM start can be slow
        )

        if result["success"]:
            logger.info("VM '%s' start command accepted.", self.vm_name)
        return result

    def stop_vm(self) -> Result:
        """
        Gracefully stop the Genymotion virtual machine.

        Returns:
            {success, data: gmtool output, error}
        """
        logger.info("Stopping VM '%s' …", self.vm_name)

        result = self._run_gmtool(
            ["admin", "stop", self.vm_name],
            timeout=60,
        )

        if result["success"]:
            logger.info("VM '%s' stopped.", self.vm_name)
        else:
            logger.warning("VM stop may have failed: %s", result["error"])

        return result

    def reset_to_snapshot(self, snapshot_name: Optional[str] = None) -> Result:
        """
        Restore the VM to a named snapshot.

        This is called before every scan to ensure a clean device state
        (no leftover apps or data from previous scans).

        The VM should be **stopped** before restoring a snapshot. This
        method will attempt to stop it first if it detects it is running.

        Args:
            snapshot_name: Name of the snapshot. Defaults to config value.

        Returns:
            {success, data: gmtool output, error}
        """
        if snapshot_name is None:
            snapshot_name = get_settings().GENYMOTION_SNAPSHOT_NAME

        logger.info(
            "Resetting VM '%s' to snapshot '%s' …",
            self.vm_name,
            snapshot_name,
        )

        # Ensure VM is stopped before snapshot restore
        status = self.get_vm_status()
        if status.get("data") == VMStatus.RUNNING:
            logger.info("VM is running — stopping before snapshot restore …")
            stop_result = self.stop_vm()
            if not stop_result["success"]:
                return stop_result
            # Give the VM a moment to fully shut down
            time.sleep(3)

        # Try snapshot restore first (newer Genymotion versions)
        # gmtool admin snapshot restore <vm> <snapshot>
        result = self._run_gmtool(
            ["admin", "snapshot", "restore", self.vm_name, snapshot_name],
            timeout=120,
        )

        if result["success"]:
            logger.info("Snapshot '%s' restored successfully.", snapshot_name)
            return result

        # Fallback: use factoryreset (older Genymotion versions that
        # don't have the snapshot subcommand)
        logger.info(
            "Snapshot command not available, falling back to factoryreset …"
        )
        result = self._run_gmtool(
            ["admin", "factoryreset", self.vm_name],
            timeout=120,
        )

        if result["success"]:
            logger.info("Factory reset completed for VM '%s'.", self.vm_name)
        else:
            logger.error("Reset failed: %s", result["error"])

        return result

    # ══════════════════════════════════════════════════════════════════
    #  BOOT DETECTION
    # ══════════════════════════════════════════════════════════════════

    def wait_for_boot(
        self,
        timeout: Optional[int] = None,
        poll_interval: int = 5,
    ) -> Result:
        """
        Block until the Android device reports fully booted.

        Polls ``adb shell getprop sys.boot_completed`` every
        ``poll_interval`` seconds until it returns ``1`` or
        the timeout expires.

        Args:
            timeout:       Max seconds to wait (default: config BOOT_TIMEOUT).
            poll_interval: Seconds between polls (default: 5).

        Returns:
            {success, data: elapsed seconds, error}
        """
        if timeout is None:
            timeout = self.boot_timeout

        settings = get_settings()
        adb_path = settings.ADB_PATH
        serial = settings.DEVICE_SERIAL

        logger.info(
            "Waiting for device boot (timeout=%ds, poll=%ds) …",
            timeout,
            poll_interval,
        )

        start = time.monotonic()
        deadline = start + timeout

        while time.monotonic() < deadline:
            try:
                proc = subprocess.run(
                    [adb_path, "-s", serial, "shell", "getprop", "sys.boot_completed"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                output = proc.stdout.strip()
                if output == "1":
                    elapsed = round(time.monotonic() - start, 1)
                    logger.info("Device booted in %.1fs.", elapsed)
                    return {
                        "success": True,
                        "data": elapsed,
                        "error": None,
                    }
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
                logger.debug("Boot poll attempt failed: %s", exc)

            # Also try connecting via ADB in case the emulator is up but not
            # yet registered
            try:
                subprocess.run(
                    [adb_path, "connect", serial],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
                pass

            time.sleep(poll_interval)

        elapsed = round(time.monotonic() - start, 1)
        logger.error("Device did not boot within %ds.", timeout)
        return {
            "success": False,
            "data": elapsed,
            "error": f"Boot timeout after {timeout}s",
        }

    # ══════════════════════════════════════════════════════════════════
    #  VM INFORMATION
    # ══════════════════════════════════════════════════════════════════

    def list_vms(self) -> Result:
        """
        List all Genymotion virtual machines available on this host.

        Returns:
            {success, data: list of VM info strings, error}
        """
        logger.info("Listing available Genymotion VMs …")

        result = self._run_gmtool(["admin", "list"], timeout=30)
        if not result["success"]:
            return result

        # Parse gmtool output — each line is a VM entry
        vms: List[str] = [
            line.strip()
            for line in (result["data"] or "").splitlines()
            if line.strip()
        ]

        logger.info("Found %d VM(s).", len(vms))
        return {"success": True, "data": vms, "error": None}

    def get_vm_status(self) -> Result:
        """
        Query the current status of the configured VM.

        Returns:
            {success, data: VMStatus enum value, error}
        """
        logger.debug("Checking VM status for '%s' …", self.vm_name)

        result = self._run_gmtool(
            ["admin", "list"],
            timeout=15,
        )

        if not result["success"]:
            return {
                "success": False,
                "data": VMStatus.UNKNOWN,
                "error": result["error"],
            }

        # gmtool admin list outputs lines like:
        #   Name         : apk_scanner_vm
        #   State        : On  (or Off)
        #   ...
        # We search for our VM name and its adjacent state line.
        output = result["data"] or ""
        lines = output.splitlines()

        found_vm = False
        for i, line in enumerate(lines):
            # Check multiple possible gmtool output formats
            if self.vm_name in line:
                found_vm = True
                # Look at this line and subsequent lines for state
                search_block = " ".join(lines[i : i + 5]).lower()
                if "on" in search_block or "running" in search_block:
                    return {
                        "success": True,
                        "data": VMStatus.RUNNING,
                        "error": None,
                    }
                elif "off" in search_block or "stopped" in search_block:
                    return {
                        "success": True,
                        "data": VMStatus.STOPPED,
                        "error": None,
                    }
                elif "booting" in search_block or "starting" in search_block:
                    return {
                        "success": True,
                        "data": VMStatus.BOOTING,
                        "error": None,
                    }

        if not found_vm:
            logger.warning("VM '%s' not found in gmtool output.", self.vm_name)
            return {
                "success": False,
                "data": VMStatus.UNKNOWN,
                "error": f"VM '{self.vm_name}' not found. Available VMs:\n{output}",
            }

        return {"success": True, "data": VMStatus.UNKNOWN, "error": None}
