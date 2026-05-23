"""
SecureStorageInspector — File Analyser

Recursively inspects files from the app's internal storage (``files/``)
and external storage (``external/``). Reads text files, parses JSON/XML,
scans binary files for embedded strings, and evaluates everything
against the rules engine.

Also used by the cache analyser via the shared ``scan_file_tree()``
utility function.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import defusedxml.ElementTree as ET

from backend.engine.models import (
    Finding,
    Severity,
    StorageArea,
    StorageAreaReport,
    mask_value,
)
from backend.engine.rules_engine import RulesEngine

logger = logging.getLogger(__name__)

# Maximum file size to read (1 MB — skip huge binaries)
_MAX_FILE_SIZE = 1 * 1024 * 1024

# Maximum bytes to scan in binary files for embedded strings
_MAX_BINARY_SCAN = 4096

# File extensions that are always text-readable
_TEXT_EXTENSIONS: Set[str] = {
    ".txt", ".log", ".cfg", ".conf", ".properties", ".ini",
    ".json", ".xml", ".yaml", ".yml", ".csv", ".html", ".htm",
    ".md", ".sql", ".sh", ".bat", ".py", ".js", ".ts",
}

# File extensions that indicate key/certificate material
_CRYPTO_FILE_EXTENSIONS: Set[str] = {
    ".pem", ".p12", ".pfx", ".key", ".jks", ".keystore", ".bks",
    ".cer", ".crt", ".der",
}


def scan_file_tree(
    directory: str,
    storage_area: StorageArea,
    rules_engine: RulesEngine,
    severity_boost: bool = False,
) -> StorageAreaReport:
    """
    Recursively scan a directory tree and evaluate all files.

    This is the shared implementation used by both the FileAnalyser
    and the CacheAnalyser. The ``severity_boost`` flag makes cache
    findings more severe (cache should never hold sensitive data).

    Args:
        directory:      Path to the directory to scan.
        storage_area:   Which storage area this directory represents.
        rules_engine:   The loaded rules engine.
        severity_boost: If True, bump finding severity by one level
                        (used for cache, where any sensitive data is
                        inherently worse).

    Returns:
        StorageAreaReport with all findings.
    """
    report = StorageAreaReport(area=storage_area)
    dir_path = Path(directory)

    if not dir_path.is_dir():
        report.notes.append(f"{storage_area.value}/ directory not found.")
        logger.info("Directory not found: %s", directory)
        return report

    # Gather all files (resolve symlinks: False for security)
    all_files = [
        f for f in dir_path.rglob("*")
        if f.is_file() and not f.is_symlink()
    ]

    if not all_files:
        report.notes.append(f"No files found in {storage_area.value}/.")
        return report

    report.files_scanned = len(all_files)
    logger.info("Scanning %d file(s) in %s/ …", len(all_files), storage_area.value)

    for file_path in all_files:
        try:
            # Verify the file is still within the dump directory
            # (defence against symlink attacks even though we filtered above)
            resolved = file_path.resolve()
            dir_resolved = dir_path.resolve()
            if not str(resolved).startswith(str(dir_resolved) + "/") and resolved != dir_resolved:
                logger.warning("Skipping file outside dump dir: %s", file_path)
                continue

            _analyse_single_file(
                file_path=file_path,
                base_dir=dir_path.parent,
                storage_area=storage_area,
                rules_engine=rules_engine,
                report=report,
                severity_boost=severity_boost,
            )
        except Exception as exc:
            logger.warning("Error analysing %s: %s", file_path.name, exc)
            report.notes.append(f"Error in {file_path.name}: {exc}")

    return report


def _analyse_single_file(
    file_path: Path,
    base_dir: Path,
    storage_area: StorageArea,
    rules_engine: RulesEngine,
    report: StorageAreaReport,
    severity_boost: bool = False,
) -> None:
    """
    Analyse a single file: detect type, parse content, evaluate rules.

    Args:
        file_path:      Absolute path to the file.
        base_dir:       Base directory for relative path computation.
        storage_area:   Storage area enum.
        rules_engine:   Rules engine instance.
        report:         Report to add findings to.
        severity_boost: Whether to bump severity.
    """
    relative_path = str(file_path.relative_to(base_dir))
    suffix = file_path.suffix.lower()
    file_size = file_path.stat().st_size

    # ── Check for crypto key files by extension ──────────────────
    if suffix in _CRYPTO_FILE_EXTENSIONS:
        # The file extension itself is a finding (key material in app data)
        findings = rules_engine.evaluate(
            key=file_path.name,
            value=file_path.name,
            storage_area=storage_area,
            file_path=relative_path,
            extra={"file_size": file_size, "check_type": "file_extension"},
        )
        for f in findings:
            if severity_boost:
                f = _boost_severity(f)
            report.add_finding(f)

    # ── Skip very large files ────────────────────────────────────
    if file_size > _MAX_FILE_SIZE:
        report.notes.append(
            f"{file_path.name}: Skipped (size={file_size} bytes, "
            f"max={_MAX_FILE_SIZE})."
        )
        return

    # ── Skip empty files ─────────────────────────────────────────
    if file_size == 0:
        return

    # ── Determine if text-readable ───────────────────────────────
    is_text = suffix in _TEXT_EXTENSIONS
    if not is_text:
        # Try reading as UTF-8
        is_text = _is_text_file(file_path)

    if is_text:
        if suffix == ".json":
            _analyse_json_file(file_path, relative_path, storage_area, rules_engine, report, severity_boost)
        elif suffix == ".xml":
            _analyse_xml_file(file_path, relative_path, storage_area, rules_engine, report, severity_boost)
        else:
            _analyse_text_file(file_path, relative_path, storage_area, rules_engine, report, severity_boost)
    else:
        # Binary file: scan for embedded strings
        _analyse_binary_file(file_path, relative_path, storage_area, rules_engine, report, severity_boost)


def _is_text_file(file_path: Path) -> bool:
    """Heuristic: try reading the first 512 bytes as UTF-8."""
    try:
        with open(file_path, "rb") as f:
            sample = f.read(512)
        sample.decode("utf-8")
        # Check for high ratio of printable characters
        printable = sum(1 for b in sample if 32 <= b <= 126 or b in (9, 10, 13))
        return printable / max(len(sample), 1) > 0.8
    except (UnicodeDecodeError, OSError):
        return False


def _analyse_text_file(
    file_path: Path,
    relative_path: str,
    storage_area: StorageArea,
    rules_engine: RulesEngine,
    report: StorageAreaReport,
    severity_boost: bool,
) -> None:
    """Read a text file line-by-line and evaluate each line."""
    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        logger.warning("Cannot read %s: %s", file_path.name, exc)
        return

    lines = content.splitlines()

    for line_num, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or len(stripped) < 3:
            continue

        # Try to extract key=value pairs from config-style files
        key, value = _parse_key_value(stripped)

        findings = rules_engine.evaluate(
            key=key,
            value=value,
            storage_area=storage_area,
            file_path=relative_path,
            extra={"line_number": line_num, "check_type": "text_line"},
        )

        for f in findings:
            if severity_boost:
                f = _boost_severity(f)
            report.add_finding(f)


def _analyse_json_file(
    file_path: Path,
    relative_path: str,
    storage_area: StorageArea,
    rules_engine: RulesEngine,
    report: StorageAreaReport,
    severity_boost: bool,
) -> None:
    """Parse a JSON file and recursively evaluate all key-value pairs."""
    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
        data = json.loads(content)
    except (json.JSONDecodeError, OSError) as exc:
        logger.debug("Cannot parse JSON %s: %s", file_path.name, exc)
        # Fall back to text analysis
        _analyse_text_file(file_path, relative_path, storage_area, rules_engine, report, severity_boost)
        return

    # Recursively walk the JSON structure
    pairs = _flatten_json(data)

    for key, value in pairs:
        str_value = str(value).strip()
        if not str_value or len(str_value) < 2:
            continue

        findings = rules_engine.evaluate(
            key=key,
            value=str_value,
            storage_area=storage_area,
            file_path=relative_path,
            extra={"check_type": "json_value"},
        )

        for f in findings:
            if severity_boost:
                f = _boost_severity(f)
            report.add_finding(f)


def _flatten_json(
    data: Any,
    prefix: str = "",
    pairs: Optional[List[tuple]] = None,
) -> List[tuple]:
    """
    Recursively flatten a JSON structure into (key_path, value) pairs.

    Example:
        {"user": {"email": "a@b.com"}} → [("user.email", "a@b.com")]
    """
    if pairs is None:
        pairs = []

    if isinstance(data, dict):
        for k, v in data.items():
            full_key = f"{prefix}.{k}" if prefix else k
            if isinstance(v, (dict, list)):
                _flatten_json(v, full_key, pairs)
            else:
                pairs.append((full_key, v))
    elif isinstance(data, list):
        for i, item in enumerate(data):
            full_key = f"{prefix}[{i}]"
            if isinstance(item, (dict, list)):
                _flatten_json(item, full_key, pairs)
            else:
                pairs.append((full_key, item))

    return pairs


def _analyse_xml_file(
    file_path: Path,
    relative_path: str,
    storage_area: StorageArea,
    rules_engine: RulesEngine,
    report: StorageAreaReport,
    severity_boost: bool,
) -> None:
    """Parse an XML file and evaluate attributes and text content."""
    try:
        tree = ET.parse(str(file_path))
        root = tree.getroot()
    except Exception as exc:
        logger.debug("Cannot parse XML %s: %s", file_path.name, exc)
        # Fall back to text analysis
        _analyse_text_file(file_path, relative_path, storage_area, rules_engine, report, severity_boost)
        return

    _walk_xml_element(root, relative_path, storage_area, rules_engine, report, severity_boost)


def _walk_xml_element(
    element: Any,
    relative_path: str,
    storage_area: StorageArea,
    rules_engine: RulesEngine,
    report: StorageAreaReport,
    severity_boost: bool,
) -> None:
    """Recursively walk XML elements and evaluate attributes + text."""
    # Check attributes
    for attr_name, attr_value in element.attrib.items():
        findings = rules_engine.evaluate(
            key=attr_name,
            value=str(attr_value),
            storage_area=storage_area,
            file_path=relative_path,
            extra={"xml_tag": element.tag, "check_type": "xml_attribute"},
        )
        for f in findings:
            if severity_boost:
                f = _boost_severity(f)
            report.add_finding(f)

    # Check text content
    if element.text and element.text.strip():
        tag_name = element.tag.split("}")[-1] if "}" in element.tag else element.tag
        findings = rules_engine.evaluate(
            key=tag_name,
            value=element.text.strip(),
            storage_area=storage_area,
            file_path=relative_path,
            extra={"check_type": "xml_text"},
        )
        for f in findings:
            if severity_boost:
                f = _boost_severity(f)
            report.add_finding(f)

    # Recurse into children
    for child in element:
        _walk_xml_element(child, relative_path, storage_area, rules_engine, report, severity_boost)


def _analyse_binary_file(
    file_path: Path,
    relative_path: str,
    storage_area: StorageArea,
    rules_engine: RulesEngine,
    report: StorageAreaReport,
    severity_boost: bool,
) -> None:
    """Scan the first bytes of a binary file for embedded text strings."""
    try:
        with open(file_path, "rb") as f:
            raw = f.read(_MAX_BINARY_SCAN)
    except OSError:
        return

    # Extract printable ASCII strings of length >= 8
    strings = _extract_strings(raw, min_length=8)

    for s in strings:
        findings = rules_engine.evaluate(
            key=file_path.name,
            value=s,
            storage_area=storage_area,
            file_path=relative_path,
            extra={"check_type": "binary_string"},
        )
        for f in findings:
            if severity_boost:
                f = _boost_severity(f)
            report.add_finding(f)


def _extract_strings(data: bytes, min_length: int = 8) -> List[str]:
    """Extract printable ASCII strings from binary data."""
    strings: List[str] = []
    current: List[str] = []

    for byte in data:
        if 32 <= byte <= 126:
            current.append(chr(byte))
        else:
            if len(current) >= min_length:
                strings.append("".join(current))
            current = []

    if len(current) >= min_length:
        strings.append("".join(current))

    return strings


def _parse_key_value(line: str) -> tuple[str, str]:
    """
    Attempt to parse a line as a key=value or key:value pair.

    Falls back to using the whole line as both key and value if no
    separator is found (so value-only rules can still match).
    """
    for sep in ("=", ":", "→"):
        if sep in line:
            parts = line.split(sep, 1)
            return parts[0].strip(), parts[1].strip()
    return line, line


_SEVERITY_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


def _boost_severity(finding: Finding) -> Finding:
    """
    Increase a finding's severity by one level.

    Used for cache findings — sensitive data in cache is worse than
    in persistent files because cache is meant to be disposable and
    is often not encrypted.
    """
    current_idx = _SEVERITY_ORDER.index(finding.severity)
    if current_idx < len(_SEVERITY_ORDER) - 1:
        finding.severity = _SEVERITY_ORDER[current_idx + 1]
    return finding


# ══════════════════════════════════════════════════════════════════════
#  PUBLIC ANALYSER CLASSES
# ══════════════════════════════════════════════════════════════════════

class FileAnalyser:
    """
    Analyses internal files from ``files/`` and external storage from
    ``external/``.

    External storage findings include a note that external storage is
    world-readable on Android < 10.
    """

    def __init__(self, rules_engine: RulesEngine) -> None:
        self.rules_engine = rules_engine

    def analyse(self, files_dir: str) -> StorageAreaReport:
        """Analyse the app's internal ``files/`` directory."""
        return scan_file_tree(
            directory=files_dir,
            storage_area=StorageArea.FILES,
            rules_engine=self.rules_engine,
            severity_boost=False,
        )

    def analyse_external(self, external_dir: str) -> StorageAreaReport:
        """
        Analyse the app's external storage (``/sdcard/Android/data/<pkg>/``).

        External storage is world-readable on Android < 10 (API 28 and
        below), which makes any sensitive data found here even more
        dangerous.
        """
        report = scan_file_tree(
            directory=external_dir,
            storage_area=StorageArea.EXTERNAL,
            rules_engine=self.rules_engine,
            severity_boost=False,
        )

        # Add note about external storage accessibility
        if report.findings:
            report.notes.append(
                "WARNING: External storage (/sdcard/Android/data/) is "
                "world-readable on Android < 10 (API 28 and below). "
                "Any sensitive data found here is accessible to ALL apps "
                "on older devices."
            )

        return report
