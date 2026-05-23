"""
SecureStorageInspector — ADB Utility Functions

Pure helper functions that do NOT require an active ADB connection.
Used by ADBController and the scan pipeline for file-system operations,
package name extraction, and directory scaffolding.
"""

import logging
import os
import re
import shutil
import struct
import zipfile
from pathlib import Path
from typing import Dict, Optional

logger = logging.getLogger(__name__)

# ── Constants ────────────────────────────────────────────────────────────
# Valid Android package name:  letters, digits, dots, underscores.
# Must have at least two segments separated by dots.
_PACKAGE_NAME_RE = re.compile(
    r"^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)+$"
)

# Android binary XML magic (first 4 bytes of AndroidManifest.xml inside APK)
_ANDROID_XML_MAGIC = 0x00080003


def get_apk_package_name(apk_path: str) -> Dict[str, object]:
    """
    Extract the package name from an APK file without aapt.

    Strategy:
        1. Open the APK (which is a ZIP file).
        2. Read the binary AndroidManifest.xml.
        3. Walk the binary-XML string pool looking for a string that
           matches the Android package-name pattern and appears right
           after the "manifest" tag.

    This is a best-effort pure-Python parser — it handles the vast
    majority of APKs but may fail on heavily obfuscated ones.

    Args:
        apk_path: Filesystem path to the .apk file.

    Returns:
        Dict with keys: success (bool), data (str | None), error (str | None).
    """
    apk = Path(apk_path)
    if not apk.is_file():
        return {"success": False, "data": None, "error": f"APK not found: {apk_path}"}

    try:
        with zipfile.ZipFile(str(apk), "r") as zf:
            if "AndroidManifest.xml" not in zf.namelist():
                return {
                    "success": False,
                    "data": None,
                    "error": "AndroidManifest.xml missing from APK",
                }
            manifest_bytes = zf.read("AndroidManifest.xml")

        package_name = _parse_package_from_binary_xml(manifest_bytes)
        if package_name is None:
            return {
                "success": False,
                "data": None,
                "error": "Could not locate package name in binary manifest",
            }

        validation = sanitize_package_name(package_name)
        if not validation["success"]:
            return validation

        logger.info("Extracted package name '%s' from %s", package_name, apk_path)
        return {"success": True, "data": package_name, "error": None}

    except zipfile.BadZipFile:
        return {"success": False, "data": None, "error": "File is not a valid ZIP/APK"}
    except Exception as exc:
        logger.exception("Unexpected error reading APK: %s", exc)
        return {"success": False, "data": None, "error": str(exc)}


def _parse_package_from_binary_xml(data: bytes) -> Optional[str]:
    """
    Walk an Android binary-XML blob and return the first string that
    looks like a valid package name from the string pool.

    The binary XML format stores all strings in a pool at the beginning.
    We decode every string in the pool, then return the first one that
    matches the Android package-name pattern — which, by convention,
    corresponds to the `package` attribute of the <manifest> tag.
    """
    if len(data) < 8:
        return None

    # ── Read the string pool header ──────────────────────────────────
    # Offset 8  → string pool chunk type (0x0001)
    # Offset 16 → string count
    # Offset 20 → style count
    # Offset 28 → strings start offset (relative to pool chunk start)
    try:
        pool_offset = 8  # string pool starts right after the XML header
        (chunk_type,) = struct.unpack_from("<H", data, pool_offset)
        if chunk_type != 0x0001:
            # Fallback: scan raw bytes for UTF-8 package strings
            return _fallback_scan(data)

        (string_count,) = struct.unpack_from("<I", data, pool_offset + 8)
        (flags,) = struct.unpack_from("<I", data, pool_offset + 16)
        (strings_start,) = struct.unpack_from("<I", data, pool_offset + 20)
        is_utf8 = bool(flags & (1 << 8))

        # String offset table begins at pool_offset + 28
        offset_table_start = pool_offset + 28
        abs_strings_start = pool_offset + strings_start

        candidates: list[str] = []
        for i in range(min(string_count, 2000)):  # cap iteration for safety
            (str_offset,) = struct.unpack_from(
                "<I", data, offset_table_start + i * 4
            )
            abs_offset = abs_strings_start + str_offset

            if is_utf8:
                decoded = _read_utf8_string(data, abs_offset)
            else:
                decoded = _read_utf16_string(data, abs_offset)

            if decoded and _PACKAGE_NAME_RE.match(decoded):
                candidates.append(decoded)

        # Filter out known Android framework strings (intent actions,
        # permissions, categories, etc.) that look like package names
        # but are NOT the app's package name.
        _FRAMEWORK_PREFIXES = (
            "android.",
            "androidx.",
            "com.android.",
            "com.google.android.",
            "org.chromium.",
        )
        app_candidates = [
            c for c in candidates
            if not c.startswith(_FRAMEWORK_PREFIXES)
        ]

        # Prefer filtered candidates; fall back to all candidates
        # if filtering removes everything (unlikely but safe).
        best = app_candidates or candidates
        if best:
            return best[0]

    except (struct.error, IndexError):
        pass

    # Last resort: raw byte scan
    return _fallback_scan(data)


def _read_utf8_string(data: bytes, offset: int) -> Optional[str]:
    """Read a UTF-8 encoded string from the binary XML string pool."""
    try:
        # Skip the encoded character count (1 or 2 bytes)
        char_len = data[offset]
        offset += 2 if char_len & 0x80 else 1
        # Read the byte length
        byte_len = data[offset]
        offset += 2 if byte_len & 0x80 else 1
        raw = data[offset: offset + byte_len]
        return raw.decode("utf-8", errors="replace")
    except (IndexError, UnicodeDecodeError):
        return None


def _read_utf16_string(data: bytes, offset: int) -> Optional[str]:
    """Read a UTF-16LE encoded string from the binary XML string pool."""
    try:
        (char_len,) = struct.unpack_from("<H", data, offset)
        if char_len & 0x8000:
            char_len = ((char_len & 0x7FFF) << 16) | struct.unpack_from(
                "<H", data, offset + 2
            )[0]
            offset += 4
        else:
            offset += 2
        raw = data[offset: offset + char_len * 2]
        return raw.decode("utf-16-le", errors="replace")
    except (struct.error, IndexError, UnicodeDecodeError):
        return None


def _fallback_scan(data: bytes) -> Optional[str]:
    """
    Last-resort regex scan over raw bytes for a package name.

    We look for ASCII-printable strings that match the package pattern,
    filtering out known Android framework strings.
    """
    _FRAMEWORK_PREFIXES = (
        "android.",
        "androidx.",
        "com.android.",
        "com.google.android.",
        "org.chromium.",
    )

    # Decode as latin-1 (never fails) and scan
    text = data.decode("latin-1", errors="replace")
    candidates = []
    for m in re.finditer(
        r"[a-zA-Z][a-zA-Z0-9_]*(?:\.[a-zA-Z][a-zA-Z0-9_]*){1,}", text
    ):
        candidate = m.group(0)
        if _PACKAGE_NAME_RE.match(candidate):
            if not candidate.startswith(_FRAMEWORK_PREFIXES):
                return candidate
            candidates.append(candidate)
    # Fall back to framework strings if nothing else found
    return candidates[0] if candidates else None


# ── Package name validation ──────────────────────────────────────────────

def sanitize_package_name(name: str) -> Dict[str, object]:
    """
    Validate that *name* is a legal Android package name.

    Returns:
        Dict with keys: success (bool), data (str | None), error (str | None).
    """
    if not name or not isinstance(name, str):
        return {"success": False, "data": None, "error": "Package name is empty"}

    # Strip whitespace that may sneak in from CLI copy-paste
    cleaned = name.strip()

    if not _PACKAGE_NAME_RE.match(cleaned):
        return {
            "success": False,
            "data": None,
            "error": (
                f"Invalid package name format: '{cleaned}'. "
                "Expected pattern like 'com.example.app'."
            ),
        }

    if len(cleaned) > 255:
        return {
            "success": False,
            "data": None,
            "error": f"Package name too long ({len(cleaned)} chars, max 255).",
        }

    return {"success": True, "data": cleaned, "error": None}


# ── Directory scaffolding ────────────────────────────────────────────────

def create_scan_dirs(scan_id: str, base_dir: Optional[Path] = None) -> Dict[str, object]:
    """
    Create the dump directory tree for a scan.

    Structure:
        <base_dir>/<scan_id>/
        ├── shared_prefs/
        ├── databases/
        ├── files/
        ├── cache/
        └── external/

    Args:
        scan_id:  Unique identifier for the scan (e.g. UUID).
        base_dir: Root dumps directory. Falls back to settings.DUMPS_DIR.

    Returns:
        Dict with success, data (dict of created paths), error.
    """
    if not scan_id or not isinstance(scan_id, str):
        return {"success": False, "data": None, "error": "scan_id is required"}

    # Sanitise scan_id — only allow alnum, hyphens, underscores
    safe_id = re.sub(r"[^a-zA-Z0-9_\-]", "_", scan_id)

    if base_dir is None:
        from backend.config import get_settings
        base_dir = get_settings().DUMPS_DIR

    scan_root = Path(base_dir) / safe_id

    subdirs = ["shared_prefs", "databases", "files", "cache", "external"]
    created: Dict[str, str] = {}

    try:
        for sub in subdirs:
            d = scan_root / sub
            d.mkdir(parents=True, exist_ok=True)
            created[sub] = str(d)
        logger.info("Created scan directories under %s", scan_root)
        return {"success": True, "data": created, "error": None}
    except OSError as exc:
        logger.exception("Failed to create scan dirs: %s", exc)
        return {"success": False, "data": None, "error": str(exc)}


# ── ZIP packaging ────────────────────────────────────────────────────────

def zip_dump(scan_id: str, base_dir: Optional[Path] = None) -> Dict[str, object]:
    """
    Compress the dump folder for a scan into a ZIP archive.

    The ZIP is written next to the scan folder:
        <base_dir>/<scan_id>.zip

    Args:
        scan_id:  Unique identifier for the scan.
        base_dir: Root dumps directory.

    Returns:
        Dict with success, data (path to zip), error.
    """
    if base_dir is None:
        from backend.config import get_settings
        base_dir = get_settings().DUMPS_DIR

    safe_id = re.sub(r"[^a-zA-Z0-9_\-]", "_", scan_id)
    scan_root = Path(base_dir) / safe_id
    zip_path = Path(base_dir) / f"{safe_id}.zip"

    if not scan_root.is_dir():
        return {
            "success": False,
            "data": None,
            "error": f"Scan directory does not exist: {scan_root}",
        }

    try:
        with zipfile.ZipFile(str(zip_path), "w", zipfile.ZIP_DEFLATED) as zf:
            for root, _dirs, files in os.walk(scan_root):
                for fname in files:
                    full = Path(root) / fname
                    arcname = full.relative_to(scan_root)
                    zf.write(str(full), str(arcname))

        size = zip_path.stat().st_size
        logger.info(
            "Zipped scan %s → %s (%s)",
            scan_id,
            zip_path,
            format_file_size(size),
        )
        return {"success": True, "data": str(zip_path), "error": None}
    except Exception as exc:
        logger.exception("Failed to zip scan dump: %s", exc)
        return {"success": False, "data": None, "error": str(exc)}


# ── Human-readable file sizes ────────────────────────────────────────────

def format_file_size(size_bytes: int) -> str:
    """
    Convert a byte count to a human-readable string.

    Examples:
        0        → "0 B"
        1024     → "1.00 KB"
        1572864  → "1.50 MB"
    """
    if size_bytes < 0:
        return "0 B"
    if size_bytes == 0:
        return "0 B"

    units = ["B", "KB", "MB", "GB", "TB"]
    idx = 0
    size = float(size_bytes)
    while size >= 1024 and idx < len(units) - 1:
        size /= 1024
        idx += 1

    if idx == 0:
        return f"{int(size)} B"
    return f"{size:.2f} {units[idx]}"
