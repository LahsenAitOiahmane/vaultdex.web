"""
SecureStorageInspector — Cache Analyser

Analyses the app's cache directory. Delegates actual scanning to the
shared ``scan_file_tree()`` function from the file analyser, but with
severity boosting enabled — sensitive data in cache is inherently worse
because cache is meant to be disposable and is often not encrypted.

Also performs cache-specific checks:
    - Large cache directories (> 50 MB) flagged as data leak surface.
    - HTTP response cache detection (OkHttp, Retrofit).
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict

from backend.engine.analysers.file_analyser import scan_file_tree
from backend.engine.models import (
    Finding,
    Severity,
    StorageArea,
    StorageAreaReport,
    mask_value,
)
from backend.engine.rules_engine import RulesEngine

logger = logging.getLogger(__name__)

# Threshold for flagging large cache directories (50 MB)
_LARGE_CACHE_THRESHOLD = 50 * 1024 * 1024


class CacheAnalyser:
    """
    Analyses the app's ``cache/`` directory.

    All findings have their severity boosted by one level compared
    to the same finding in ``files/``, because cache storage should
    never contain sensitive data.
    """

    def __init__(self, rules_engine: RulesEngine) -> None:
        """
        Initialise with a shared RulesEngine instance.

        Args:
            rules_engine: The loaded rules engine for evaluation.
        """
        self.rules_engine = rules_engine

    def analyse(self, cache_dir: str) -> StorageAreaReport:
        """
        Analyse the app's cache directory.

        Args:
            cache_dir: Path to the ``cache/`` dump folder.

        Returns:
            StorageAreaReport with findings (severity-boosted).
        """
        # Delegate to shared file tree scanner with severity boost
        report = scan_file_tree(
            directory=cache_dir,
            storage_area=StorageArea.CACHE,
            rules_engine=self.rules_engine,
            severity_boost=True,  # Cache findings are more severe
        )

        cache_path = Path(cache_dir)
        if not cache_path.is_dir():
            return report

        # ── Cache-specific checks ────────────────────────────────────

        # Check total cache size
        total_size = sum(
            f.stat().st_size
            for f in cache_path.rglob("*")
            if f.is_file()
        )
        if total_size > _LARGE_CACHE_THRESHOLD:
            size_mb = round(total_size / (1024 * 1024), 1)
            report.notes.append(
                f"Large cache directory: {size_mb} MB. Large caches increase "
                "the attack surface — consider implementing cache size limits "
                "and automatic cleanup."
            )

        # Check for HTTP response cache files
        self._check_http_cache(cache_path, report)

        return report

    def _check_http_cache(self, cache_path: Path, report: StorageAreaReport) -> None:
        """
        Detect OkHttp / Retrofit HTTP response cache files.

        OkHttp cache uses a specific directory structure with a
        ``journal`` file. Cached HTTP responses may contain sensitive
        API response data (tokens, user profiles, etc.).
        """
        # OkHttp cache indicators
        journal_file = cache_path / "journal"
        if not journal_file.exists():
            # Also check subdirectories (some apps nest the cache)
            journal_files = list(cache_path.rglob("journal"))
            if not journal_files:
                return
            journal_file = journal_files[0]

        # Count cache entry files (OkHttp uses numbered files + .0/.1)
        cache_files = [
            f for f in journal_file.parent.iterdir()
            if f.is_file() and f.name != "journal"
        ]

        if cache_files:
            report.notes.append(
                f"OkHttp/Retrofit HTTP response cache detected with "
                f"{len(cache_files)} cached response(s). These may contain "
                "sensitive API responses (user data, tokens, etc.). Consider "
                "disabling response caching for sensitive endpoints."
            )

            # Sample a few cache files for sensitive content
            for cache_file in cache_files[:10]:
                try:
                    content = cache_file.read_text(
                        encoding="utf-8", errors="replace"
                    )
                    # Look for common HTTP response patterns
                    if any(
                        indicator in content.lower()
                        for indicator in [
                            "authorization",
                            "set-cookie",
                            "bearer",
                            "access_token",
                            '"token"',
                            '"password"',
                            '"email"',
                        ]
                    ):
                        relative = str(
                            cache_file.relative_to(cache_path.parent)
                        )
                        finding = Finding(
                            rule_id="CACHE-HTTP-001",
                            rule_name="Sensitive Data in HTTP Cache",
                            severity=Severity.HIGH,
                            category="session",
                            storage_area=StorageArea.CACHE,
                            file_path=relative,
                            key_or_field=cache_file.name,
                            value_preview=mask_value(
                                content[:100], visible_chars=20
                            ),
                            description=(
                                "An HTTP response cache file contains indicators "
                                "of sensitive data (tokens, cookies, credentials). "
                                "Cached API responses should not contain secrets."
                            ),
                            recommendation=(
                                "Add Cache-Control: no-store to sensitive API "
                                "responses. Disable OkHttp response caching for "
                                "authentication and user-data endpoints."
                            ),
                            extra={
                                "check_type": "http_cache",
                                "cache_file": cache_file.name,
                            },
                        )
                        report.add_finding(finding)
                except (OSError, UnicodeDecodeError):
                    pass
