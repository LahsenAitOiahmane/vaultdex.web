"""
SecureStorageInspector — ADB Controller

Full-featured wrapper around the Android Debug Bridge (ADB) CLI.
Designed for WSL environments where we call the Windows adb.exe binary
via subprocess. Every method returns a structured result dict and logs
all actions through the Python logging module.

Security notes:
- All shell arguments are passed as lists (never shell=True) to prevent
  command injection.
- Package names are validated before being interpolated into device paths.
- Subprocess calls have mandatory timeouts to prevent hangs.
"""

import logging
import os
import shlex
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from backend.adb.utils import sanitize_package_name
from backend.config import get_settings

logger = logging.getLogger(__name__)

# Type alias for the structured result every method returns
Result = Dict[str, Any]


class ADBController:
    """
    Controls an Android device/emulator through the ADB command-line tool.

    Designed for Genymotion emulators accessible over TCP (the default
    transport on WSL-to-Windows setups).

    Usage::

        adb = ADBController()
        adb.connect()
        adb.install_apk("/path/to/app.apk")
        adb.run_monkey("com.example.app", events=500)
        adb.pull_all_storage("com.example.app", "/tmp/dump")
    """

    # ── Default subprocess timeout for short commands (seconds) ──────
    _CMD_TIMEOUT: int = 30

    # ── Storage paths on the Android device ──────────────────────────
    _SHARED_PREFS_PATH = "/data/data/{pkg}/shared_prefs/"
    _DATABASES_PATH = "/data/data/{pkg}/databases/"
    _FILES_PATH = "/data/data/{pkg}/files/"
    _CACHE_PATH = "/data/data/{pkg}/cache/"
    _EXTERNAL_PATH = "/sdcard/Android/data/{pkg}/"

    def __init__(
        self,
        adb_path: Optional[str] = None,
        device_serial: Optional[str] = None,
    ) -> None:
        """
        Initialise the ADB controller.

        Args:
            adb_path:       Path to the adb executable. Defaults to config.
            device_serial:  Device serial / IP:port. Defaults to config.
        """
        settings = get_settings()
        self.adb_path: str = adb_path or settings.ADB_PATH
        self.device_serial: str = device_serial or settings.DEVICE_SERIAL
        logger.info(
            "ADBController initialised — adb=%s, device=%s",
            self.adb_path,
            self.device_serial,
        )

    # ══════════════════════════════════════════════════════════════════
    #  PRIVATE HELPERS
    # ══════════════════════════════════════════════════════════════════

    def _run(
        self,
        args: List[str],
        timeout: Optional[int] = None,
        check: bool = False,
    ) -> Result:
        """
        Execute an ADB command and return a structured result.

        The device serial is automatically prepended via ``-s``.
        All arguments are passed as a list — **never** through ``shell=True``
        — to prevent command injection.

        Args:
            args:    Command tokens after ``adb -s <serial>``.
            timeout: Per-command timeout in seconds (default: _CMD_TIMEOUT).
            check:   If True, treat non-zero exit codes as failures.

        Returns:
            {success: bool, data: str (stdout), error: str | None}
        """
        timeout = timeout or self._CMD_TIMEOUT
        cmd = [self.adb_path, "-s", self.device_serial] + args
        cmd_str = " ".join(cmd)
        logger.debug("ADB exec: %s (timeout=%ds)", cmd_str, timeout)

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            stdout = proc.stdout.strip()
            stderr = proc.stderr.strip()

            if check and proc.returncode != 0:
                logger.error("ADB command failed (rc=%d): %s", proc.returncode, stderr)
                return {
                    "success": False,
                    "data": stdout,
                    "error": stderr or f"Exit code {proc.returncode}",
                }

            # ADB sometimes returns rc=0 but writes errors to stderr
            if proc.returncode != 0:
                logger.warning(
                    "ADB non-zero exit (rc=%d): %s", proc.returncode, stderr
                )

            return {"success": proc.returncode == 0, "data": stdout, "error": stderr or None}

        except subprocess.TimeoutExpired:
            logger.error("ADB command timed out after %ds: %s", timeout, cmd_str)
            return {
                "success": False,
                "data": None,
                "error": f"Command timed out after {timeout}s",
            }
        except FileNotFoundError:
            logger.error("ADB binary not found at: %s", self.adb_path)
            return {
                "success": False,
                "data": None,
                "error": f"ADB binary not found: {self.adb_path}",
            }
        except OSError as exc:
            logger.exception("OS error executing ADB: %s", exc)
            return {"success": False, "data": None, "error": str(exc)}

    def _validate_package(self, package: str) -> Result:
        """Validate and sanitise a package name before device operations."""
        return sanitize_package_name(package)

    def _wsl_to_windows(self, path: str) -> str:
        """
        Convert a WSL path to a Windows path
        for the Windows adb.exe binary.
        """
        path_str = str(path)
        if path_str.startswith("/mnt/c/"):
            return "C:\\" + path_str[7:].replace("/", "\\")
        return path_str

    def _windows_to_wsl(self, path: str) -> str:
        """
        Convert a Windows path to a WSL path so
        Python can read the files. Run this on the host *after* pulling
        from the device.
        """
        path_str = str(path)
        if path_str.startswith("C:\\"):
            return "/mnt/c/" + path_str[3:].replace("\\", "/")
        return path_str

    # ══════════════════════════════════════════════════════════════════
    #  CONNECTION
    # ══════════════════════════════════════════════════════════════════

    def connect(self) -> Result:
        """
        Verify that the configured device is reachable via ADB.

        For TCP-connected emulators (Genymotion), this issues
        ``adb connect <serial>`` first, then confirms with ``adb devices``.

        Returns:
            {success, data: device status string, error}
        """
        logger.info("Connecting to device %s …", self.device_serial)

        # Step 1: attempt TCP connect (harmless if already connected)
        connect_result = self._run(["connect", self.device_serial], timeout=15)
        if not connect_result["success"]:
            return connect_result

        # Step 2: verify device shows up in the device list
        devices_result = self._run(["devices"], timeout=10)
        if not devices_result["success"]:
            return devices_result

        # Parse output for our serial
        for line in (devices_result["data"] or "").splitlines():
            if self.device_serial in line and "device" in line:
                logger.info("Device %s is online.", self.device_serial)
                return {"success": True, "data": line.strip(), "error": None}

        logger.error("Device %s not found in `adb devices` output.", self.device_serial)
        return {
            "success": False,
            "data": devices_result["data"],
            "error": f"Device {self.device_serial} not listed or not authorised.",
        }

    # ══════════════════════════════════════════════════════════════════
    #  PACKAGE MANAGEMENT
    # ══════════════════════════════════════════════════════════════════

    def get_package_list(self) -> Result:
        """
        List all installed packages on the device.

        Returns:
            {success, data: list[str] of package names, error}
        """
        logger.info("Listing installed packages …")
        result = self._run(["shell", "pm", "list", "packages"], timeout=30)
        if not result["success"]:
            return result

        packages = [
            line.replace("package:", "").strip()
            for line in (result["data"] or "").splitlines()
            if line.startswith("package:")
        ]
        logger.info("Found %d packages on device.", len(packages))
        return {"success": True, "data": packages, "error": None}

    def install_apk(self, apk_path: str) -> Result:
        """
        Install an APK file onto the device.

        Uses ``adb install -r`` (replace existing) to allow re-installs.
        The APK path must exist on the *host* machine.

        Args:
            apk_path: Local filesystem path to the .apk file.

        Returns:
            {success, data: adb output, error}
        """
        apk = Path(apk_path)
        if not apk.is_file():
            msg = f"APK file not found: {apk_path}"
            logger.error(msg)
            return {"success": False, "data": None, "error": msg}

        # Validate file extension
        if apk.suffix.lower() != ".apk":
            msg = f"File does not have .apk extension: {apk.name}"
            logger.error(msg)
            return {"success": False, "data": None, "error": msg}

        logger.info("Installing APK: %s", apk_path)
        
        # Translate WSL path to Windows path for adb.exe
        win_apk_path = self._wsl_to_windows(str(apk))
        
        result = self._run(
            ["install", "-r", win_apk_path],
            timeout=120,  # large APKs may take a while
            check=True,
        )

        if result["success"]:
            logger.info("APK installed successfully: %s", apk.name)
        else:
            logger.error("APK installation failed: %s", result["error"])

        return result

    def uninstall_apk(self, package_name: str) -> Result:
        """
        Uninstall an app by package name.

        Args:
            package_name: Android package name (e.g. ``com.example.app``).

        Returns:
            {success, data: adb output, error}
        """
        validation = self._validate_package(package_name)
        if not validation["success"]:
            return validation

        logger.info("Uninstalling package: %s", package_name)
        result = self._run(["uninstall", package_name], timeout=30, check=True)

        if result["success"]:
            logger.info("Package %s uninstalled.", package_name)
        else:
            logger.warning("Uninstall may have failed: %s", result["error"])

        return result

    def get_package_name(self, apk_path: str) -> Result:
        """
        Extract the package name from an APK file.

        Tries aapt first (if configured), then falls back to the
        pure-Python binary-XML parser in ``adb.utils``.

        Args:
            apk_path: Local filesystem path to the .apk file.

        Returns:
            {success, data: package name string, error}
        """
        settings = get_settings()

        # ── Strategy 1: aapt/aapt2 ───────────────────────────────────
        if settings.AAPT_PATH:
            aapt_path = settings.AAPT_PATH
            is_aapt2 = "aapt2" in Path(aapt_path).name.lower()
            logger.debug(
                "Trying %s for package name extraction …",
                "aapt2" if is_aapt2 else "aapt",
            )
            try:
                # Both aapt and aapt2 support: dump badging <apk>
                proc = subprocess.run(
                    [aapt_path, "dump", "badging", self._wsl_to_windows(apk_path)],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                if proc.returncode == 0 and proc.stdout:
                    # Output line: "package: name='com.example' versionCode=…"
                    for line in proc.stdout.splitlines():
                        if line.startswith("package:"):
                            # Extract name='...'
                            start = line.find("name='")
                            if start != -1:
                                start += 6
                                end = line.find("'", start)
                                if end != -1:
                                    pkg = line[start:end]
                                    logger.info(
                                        "%s extracted package: %s",
                                        "aapt2" if is_aapt2 else "aapt",
                                        pkg,
                                    )
                                    return {
                                        "success": True,
                                        "data": pkg,
                                        "error": None,
                                    }
                else:
                    logger.warning(
                        "%s returned rc=%d: %s",
                        "aapt2" if is_aapt2 else "aapt",
                        proc.returncode,
                        (proc.stderr or "").strip()[:200],
                    )
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
                logger.warning("aapt failed, falling back: %s", exc)

        # ── Strategy 2: pure-Python parser ───────────────────────────
        from backend.adb.utils import get_apk_package_name

        logger.debug("Using pure-Python parser for package name …")
        return get_apk_package_name(apk_path)

    # ══════════════════════════════════════════════════════════════════
    #  STORAGE EXTRACTION
    # ══════════════════════════════════════════════════════════════════

    def _pull_dir(self, device_path: str, local_dest: str) -> Result:
        """
        Pull a directory from the device to the local filesystem.

        Creates the destination directory if it does not exist.
        Uses ``adb pull`` which recursively copies files.

        Args:
            device_path: Path on the Android device.
            local_dest:  Local directory to copy into.

        Returns:
            {success, data: file list or adb output, error}
        """
        dest = Path(local_dest)
        try:
            dest.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            return {"success": False, "data": None, "error": f"Cannot create {dest}: {exc}"}

        logger.info("Pulling %s → %s", device_path, local_dest)
        
        # Translate WSL path to Windows path for adb.exe
        win_dest = self._wsl_to_windows(str(dest))
        
        result = self._run(
            ["pull", device_path, win_dest],
            timeout=120,
        )

        if result["success"]:
            # Count files actually received
            pulled_files = list(dest.rglob("*"))
            file_count = sum(1 for f in pulled_files if f.is_file())
            logger.info("Pulled %d file(s) from %s", file_count, device_path)
            result["data"] = {
                "file_count": file_count,
                "dest": str(dest),
                "adb_output": result["data"],
            }
        else:
            # A missing directory on the device is common (app may not use it)
            # — downgrade to warning, not error.
            err_lower = (result.get("error") or "").lower()
            if "does not exist" in err_lower or "failed to stat" in err_lower:
                logger.warning("Device path does not exist: %s (skipping)", device_path)
                result["data"] = {"file_count": 0, "dest": str(dest), "adb_output": ""}
                result["success"] = True  # non-fatal
                result["error"] = None
            else:
                logger.error("Pull failed for %s: %s", device_path, result["error"])

        return result

    def pull_shared_prefs(self, package: str, dest: str) -> Result:
        """
        Pull SharedPreferences XML files from the device.

        Args:
            package: Android package name.
            dest:    Local directory for shared_prefs/.

        Returns:
            Structured result dict.
        """
        validation = self._validate_package(package)
        if not validation["success"]:
            return validation

        device_path = self._SHARED_PREFS_PATH.format(pkg=package)
        local_dest = str(Path(dest) / "shared_prefs")
        return self._pull_dir(device_path, local_dest)

    def pull_databases(self, package: str, dest: str) -> Result:
        """
        Pull SQLite / Room database files from the device.

        Args:
            package: Android package name.
            dest:    Local directory for databases/.

        Returns:
            Structured result dict.
        """
        validation = self._validate_package(package)
        if not validation["success"]:
            return validation

        device_path = self._DATABASES_PATH.format(pkg=package)
        local_dest = str(Path(dest) / "databases")
        return self._pull_dir(device_path, local_dest)

    def pull_files(self, package: str, dest: str) -> Result:
        """
        Pull internal files (app's ``files/`` directory) from the device.

        Args:
            package: Android package name.
            dest:    Local directory for files/.

        Returns:
            Structured result dict.
        """
        validation = self._validate_package(package)
        if not validation["success"]:
            return validation

        device_path = self._FILES_PATH.format(pkg=package)
        local_dest = str(Path(dest) / "files")
        return self._pull_dir(device_path, local_dest)

    def pull_cache(self, package: str, dest: str) -> Result:
        """
        Pull cache directory from the device.

        Args:
            package: Android package name.
            dest:    Local directory for cache/.

        Returns:
            Structured result dict.
        """
        validation = self._validate_package(package)
        if not validation["success"]:
            return validation

        device_path = self._CACHE_PATH.format(pkg=package)
        local_dest = str(Path(dest) / "cache")
        return self._pull_dir(device_path, local_dest)

    def pull_external_storage(self, package: str, dest: str) -> Result:
        """
        Pull external storage (sdcard) data for the package.

        Args:
            package: Android package name.
            dest:    Local directory for external/.

        Returns:
            Structured result dict.
        """
        validation = self._validate_package(package)
        if not validation["success"]:
            return validation

        device_path = self._EXTERNAL_PATH.format(pkg=package)
        local_dest = str(Path(dest) / "external")
        return self._pull_dir(device_path, local_dest)

    def pull_all_storage(self, package: str, dest: str) -> Result:
        """
        Pull ALL known storage locations for a package.

        Calls every individual pull_* method and aggregates results.
        Non-existent directories on the device are treated as warnings,
        not errors — the overall result only fails if a critical I/O
        error occurs.

        Args:
            package: Android package name.
            dest:    Base local directory (sub-folders created automatically).

        Returns:
            {success, data: {area_name: result_dict, …}, error}
        """
        validation = self._validate_package(package)
        if not validation["success"]:
            return validation

        logger.info("Pulling ALL storage for %s → %s", package, dest)

        pull_methods = {
            "shared_prefs": self.pull_shared_prefs,
            "databases": self.pull_databases,
            "files": self.pull_files,
            "cache": self.pull_cache,
            "external": self.pull_external_storage,
        }

        results: Dict[str, Result] = {}
        total_files = 0
        errors: List[str] = []

        for area, method in pull_methods.items():
            result = method(package, dest)
            results[area] = result
            if result["success"] and isinstance(result.get("data"), dict):
                total_files += result["data"].get("file_count", 0)
            elif not result["success"]:
                errors.append(f"{area}: {result.get('error', 'unknown')}")

        overall_success = len(errors) == 0
        logger.info(
            "Storage pull complete: %d file(s) total, %d error(s).",
            total_files,
            len(errors),
        )

        return {
            "success": overall_success,
            "data": {
                "results": results,
                "total_files": total_files,
                "dest": dest,
            },
            "error": "; ".join(errors) if errors else None,
        }

    # ══════════════════════════════════════════════════════════════════
    #  APP EXECUTION
    # ══════════════════════════════════════════════════════════════════

    def run_monkey(self, package: str, events: Optional[int] = None) -> Result:
        """
        Launch the app and fire random UI events using the Android
        ``monkey`` tool.

        This triggers real writes to SharedPreferences, databases, and
        files — which we later pull and analyse.

        Args:
            package: Android package name.
            events:  Number of pseudo-random events (default: from config).

        Returns:
            {success, data: monkey output, error}
        """
        validation = self._validate_package(package)
        if not validation["success"]:
            return validation

        if events is None:
            events = get_settings().MONKEY_EVENTS

        logger.info("Running monkey on %s with %d events …", package, events)

        # monkey arguments:
        #   -p <package>   restrict to this package
        #   --throttle 100 slight delay between events for stability
        #   -v             verbose output
        result = self._run(
            [
                "shell", "monkey",
                "-p", package,
                "--throttle", "100",
                "-v", str(events),
            ],
            timeout=max(events // 2, 60),  # scale timeout with event count
        )

        if result["success"]:
            logger.info("Monkey run completed for %s.", package)
        else:
            logger.error("Monkey run failed for %s: %s", package, result["error"])

        return result

    # ══════════════════════════════════════════════════════════════════
    #  SHELL & DIAGNOSTICS
    # ══════════════════════════════════════════════════════════════════

    def run_shell(self, command: str, timeout: Optional[int] = None) -> Result:
        """
        Execute an arbitrary shell command on the device.

        The command string is split into tokens using ``shlex.split`` to
        prevent injection when callers pass user-influenced strings.

        Args:
            command: Shell command to run (e.g. ``"ls /data/data"``).
            timeout: Optional override for the command timeout.

        Returns:
            {success, data: stdout, error}
        """
        # Safely tokenise the command to avoid injection
        try:
            tokens = shlex.split(command)
        except ValueError as exc:
            return {"success": False, "data": None, "error": f"Bad shell command: {exc}"}

        logger.debug("Running shell command: %s", command)
        return self._run(["shell"] + tokens, timeout=timeout or self._CMD_TIMEOUT)

    def is_app_running(self, package: str) -> Result:
        """
        Check whether a package's process is currently active on the device.

        Args:
            package: Android package name.

        Returns:
            {success, data: bool (True if running), error}
        """
        validation = self._validate_package(package)
        if not validation["success"]:
            return validation

        result = self._run(
            ["shell", "pidof", package],
            timeout=10,
        )

        if result["success"] and result["data"]:
            pid = result["data"].strip()
            logger.info("Package %s is running (PID %s).", package, pid)
            return {"success": True, "data": True, "error": None}

        logger.info("Package %s is NOT running.", package)
        return {"success": True, "data": False, "error": None}

    def take_screenshot(self, dest: str) -> Result:
        """
        Capture a screenshot from the device and pull it to the host.

        The screenshot is first taken on the device at a temporary path,
        then pulled to ``dest`` on the host, then the temp file is removed
        from the device.

        Args:
            dest: Local file path for the resulting PNG (e.g. ``/tmp/screen.png``).

        Returns:
            {success, data: local path, error}
        """
        device_tmp = "/sdcard/screenshot_tmp.png"

        logger.info("Taking screenshot → %s", dest)

        # Step 1 — capture on device
        cap = self._run(["shell", "screencap", "-p", device_tmp], timeout=15)
        if not cap["success"]:
            return cap

        # Step 2 — pull to host
        dest_path = Path(dest)
        try:
            dest_path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            return {"success": False, "data": None, "error": str(exc)}

        win_dest = self._wsl_to_windows(str(dest_path))
        pull = self._run(["pull", device_tmp, win_dest], timeout=15)

        # Step 3 — clean up device temp file (best-effort)
        self._run(["shell", "rm", "-f", device_tmp], timeout=5)

        if pull["success"]:
            logger.info("Screenshot saved: %s", dest)
            return {"success": True, "data": str(dest_path), "error": None}
        return pull

    def force_stop(self, package: str) -> Result:
        """
        Force-stop an application.

        Args:
            package: Android package name.

        Returns:
            {success, data: adb output, error}
        """
        validation = self._validate_package(package)
        if not validation["success"]:
            return validation

        logger.info("Force-stopping %s …", package)
        return self._run(["shell", "am", "force-stop", package], timeout=10)

    def launch_app(self, package: str) -> Result:
        """
        Launch the main activity of an app using ``monkey -c``.

        This is a gentler launch than the full monkey run — it only
        fires one event to open the launcher activity.

        Args:
            package: Android package name.

        Returns:
            {success, data: adb output, error}
        """
        validation = self._validate_package(package)
        if not validation["success"]:
            return validation

        logger.info("Launching %s …", package)
        return self._run(
            [
                "shell", "monkey",
                "-p", package,
                "-c", "android.intent.category.LAUNCHER",
                "1",
            ],
            timeout=15,
        )
