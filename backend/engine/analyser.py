"""
SecureStorageInspector — Analysis Engine Orchestrator

The main entry point for Phase 2. Ties all analysers together and
produces a unified SecurityReport.

Usage::

    from backend.engine.analyser import AnalysisEngine

    engine = AnalysisEngine()
    report = engine.analyse(
        scan_id="abc123",
        dump_dir="/path/to/dumps/abc123",
        package_name="com.example.app",
    )

    # Save report as JSON
    engine.save_report(report)

    # Or get as dict
    report_dict = report.model_dump()
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Optional

from backend.config import get_settings
from backend.engine.analysers.cache_analyser import CacheAnalyser
from backend.engine.analysers.database_analyser import DatabaseAnalyser
from backend.engine.analysers.file_analyser import FileAnalyser
from backend.engine.analysers.sharedprefs_analyser import SharedPrefsAnalyser
from backend.engine.analysers.static_analyser import StaticAnalyser
from backend.engine.models import (
    ExportedComponent,
    ManifestFlagsReport,
    PermissionEntry,
    SecurityReport,
    StaticAnalysisReport,
    StorageAreaReport,
)
from backend.engine.rules_engine import RulesEngine
from backend.engine.scoring import score_report

logger = logging.getLogger(__name__)


class AnalysisEngine:
    """
    Orchestrates the full security analysis of a scan dump.

    Initialises the rules engine once, then runs all four analysers
    in sequence against the dump directory.
    """

    def __init__(self) -> None:
        """Initialise the engine and load all rules."""
        logger.info("Initialising AnalysisEngine …")
        self.rules_engine = RulesEngine()
        self.sharedprefs_analyser = SharedPrefsAnalyser(self.rules_engine)
        self.database_analyser = DatabaseAnalyser(self.rules_engine)
        self.file_analyser = FileAnalyser(self.rules_engine)
        self.cache_analyser = CacheAnalyser(self.rules_engine)
        self.static_analyser = StaticAnalyser()
        logger.info(
            "AnalysisEngine ready — %d rules loaded.",
            self.rules_engine.rule_count,
        )

    def analyse(
        self,
        scan_id: str,
        dump_dir: str,
        package_name: str,
        apk_path: Optional[str] = None,
    ) -> SecurityReport:
        """
        Run all analysers and produce a unified security report.

        This is the single entry-point for Phase 2 analysis.

        Args:
            scan_id:      Unique scan identifier (from Phase 1).
            dump_dir:     Path to the ``dumps/<scan_id>/`` directory.
            package_name: Android package name of the scanned app.
            apk_path:     Optional path to the APK file for static analysis.

        Returns:
            A fully scored SecurityReport.
        """
        start = time.monotonic()
        dump_path = Path(dump_dir)

        logger.info("═" * 60)
        logger.info("Starting analysis — scan_id=%s, package=%s", scan_id, package_name)
        logger.info("Dump directory: %s", dump_dir)
        if apk_path:
            logger.info("APK path: %s", apk_path)
        logger.info("═" * 60)

        # Validate dump directory exists
        if not dump_path.is_dir():
            logger.error("Dump directory not found: %s", dump_dir)
            report = SecurityReport(
                scan_id=scan_id,
                package_name=package_name,
            )
            report.storage_reports = []
            report.aggregate()
            score_report(report)
            return report

        # Initialise the report
        report = SecurityReport(
            scan_id=scan_id,
            package_name=package_name,
        )

        # ── 0. Static Analysis (APK manifest) ────────────────────────
        # If Phase A already ran static analysis, load from saved JSON
        precomputed_static = dump_path / "static_analysis.json"
        if precomputed_static.is_file():
            logger.info("── Loading pre-computed static analysis from Phase A …")
            try:
                import json as _json
                raw = _json.loads(precomputed_static.read_text(encoding="utf-8"))
                static_report = StaticAnalysisReport(**raw)
                report.static_analysis = static_report
                logger.info(
                    "  Static (cached): %d permission(s) (%d dangerous), "
                    "%d exported component(s), %d finding(s)",
                    static_report.total_permission_count,
                    static_report.dangerous_permission_count,
                    static_report.total_exported_components,
                    len(static_report.findings),
                )
            except Exception as exc:
                logger.warning("Failed to load cached static analysis: %s", exc)
                # Fall through to re-run
                if apk_path and Path(apk_path).is_file():
                    static_result = self.static_analyser.analyse(apk_path)
                    report.static_analysis = self._build_static_report(static_result)
        elif apk_path and Path(apk_path).is_file():
            logger.info("── Running Static Analysis (no cache found) …")
            static_result = self.static_analyser.analyse(apk_path)
            static_report = self._build_static_report(static_result)
            report.static_analysis = static_report
            logger.info(
                "  Static: %d permission(s) (%d dangerous), "
                "%d exported component(s), %d finding(s)",
                static_report.total_permission_count,
                static_report.dangerous_permission_count,
                static_report.total_exported_components,
                len(static_report.findings),
            )
        else:
            logger.info("── Skipping Static Analysis (no APK path provided)")

        # ── 1. SharedPreferences Analysis ────────────────────────────
        logger.info("── Analysing SharedPreferences …")
        sp_dir = str(dump_path / "shared_prefs")
        sp_report = self.sharedprefs_analyser.analyse(sp_dir)
        report.storage_reports.append(sp_report)
        logger.info(
            "  SharedPrefs: %d file(s), %d finding(s)",
            sp_report.files_scanned,
            len(sp_report.findings),
        )

        # ── 2. Database Analysis ─────────────────────────────────────
        logger.info("── Analysing Databases …")
        db_dir = str(dump_path / "databases")
        db_report = self.database_analyser.analyse(db_dir)
        report.storage_reports.append(db_report)
        logger.info(
            "  Databases: %d file(s), %d finding(s)",
            db_report.files_scanned,
            len(db_report.findings),
        )

        # ── 3. Files Analysis ────────────────────────────────────────
        logger.info("── Analysing Internal Files …")
        files_dir = str(dump_path / "files")
        files_report = self.file_analyser.analyse(files_dir)
        report.storage_reports.append(files_report)
        logger.info(
            "  Files: %d file(s), %d finding(s)",
            files_report.files_scanned,
            len(files_report.findings),
        )

        # ── 4. Cache Analysis ────────────────────────────────────────
        logger.info("── Analysing Cache …")
        cache_dir = str(dump_path / "cache")
        cache_report = self.cache_analyser.analyse(cache_dir)
        report.storage_reports.append(cache_report)
        logger.info(
            "  Cache: %d file(s), %d finding(s)",
            cache_report.files_scanned,
            len(cache_report.findings),
        )

        # ── 5. External Storage Analysis ─────────────────────────────
        logger.info("── Analysing External Storage …")
        external_dir = str(dump_path / "external")
        ext_report = self.file_analyser.analyse_external(external_dir)
        report.storage_reports.append(ext_report)
        logger.info(
            "  External: %d file(s), %d finding(s)",
            ext_report.files_scanned,
            len(ext_report.findings),
        )

        # ── Aggregate & Score ────────────────────────────────────────
        report.aggregate()
        score_report(report)

        elapsed = round(time.monotonic() - start, 2)

        logger.info("═" * 60)
        logger.info(
            "Analysis complete in %.2fs — Score: %d/100 (%s)",
            elapsed,
            report.risk_score,
            report.risk_level.value,
        )
        logger.info(
            "  CRITICAL=%d  HIGH=%d  MEDIUM=%d  LOW=%d  INFO=%d",
            report.severity_counts.critical,
            report.severity_counts.high,
            report.severity_counts.medium,
            report.severity_counts.low,
            report.severity_counts.info,
        )
        logger.info(
            "  Total findings: %d across %d file(s)",
            report.total_findings,
            report.total_files_scanned,
        )
        logger.info("═" * 60)

        return report

    def _build_static_report(self, result) -> StaticAnalysisReport:
        """Convert internal StaticAnalysisResult to a pydantic model."""
        from backend.engine.analysers.static_analyser import _SDK_TO_ANDROID

        permissions = [
            PermissionEntry(
                name=p.name,
                risk_level=p.risk_level,
                category=p.category,
                description=p.description,
                is_custom=p.is_custom,
            )
            for p in result.permissions
        ]

        components = []
        for comp_list in (
            result.exported_activities,
            result.exported_services,
            result.exported_receivers,
            result.exported_providers,
        ):
            for c in comp_list:
                components.append(ExportedComponent(
                    name=c.name,
                    component_type=c.component_type,
                    has_permission=c.permission is not None,
                    permission=c.permission,
                    intent_filters=c.intent_filters[:10],
                ))

        from backend.engine.models import SeverityCounts
        severity_counts = SeverityCounts()
        for f in result.findings:
            severity_counts.increment(f.severity)

        return StaticAnalysisReport(
            package_name=result.package_name,
            app_name=result.app_name,
            version_name=result.version_name,
            version_code=result.version_code,
            apk_size_bytes=result.apk_size_bytes,
            min_sdk=result.min_sdk,
            min_sdk_name=_SDK_TO_ANDROID.get(result.min_sdk, f"API {result.min_sdk}"),
            target_sdk=result.target_sdk,
            target_sdk_name=_SDK_TO_ANDROID.get(result.target_sdk, f"API {result.target_sdk}"),
            native_architectures=result.native_architectures,
            uses_features=result.uses_features,
            launchable_activity=result.launchable_activity,
            permissions=permissions,
            dangerous_permission_count=result.dangerous_permission_count,
            total_permission_count=result.total_permission_count,
            exported_components=components,
            total_exported_components=result.total_exported_components,
            manifest_flags=ManifestFlagsReport(
                debuggable=result.flags.debuggable,
                allow_backup=result.flags.allow_backup,
                uses_cleartext_traffic=result.flags.uses_cleartext_traffic,
                network_security_config=result.flags.network_security_config,
                test_only=result.flags.test_only,
            ),
            deep_links=result.deep_links,
            custom_url_schemes=result.custom_schemes,
            findings=result.findings,
            severity_counts=severity_counts,
        )

    def save_report(
        self,
        report: SecurityReport,
        output_path: Optional[str] = None,
    ) -> str:
        """
        Save the security report as a JSON file.

        Args:
            report:      The SecurityReport to save.
            output_path: Optional custom path. Defaults to
                         ``reports/<scan_id>.json``.

        Returns:
            Path to the saved JSON file.
        """
        if output_path is None:
            settings = get_settings()
            reports_dir = settings.REPORTS_DIR
            reports_dir.mkdir(parents=True, exist_ok=True)
            output_path = str(reports_dir / f"{report.scan_id}.json")

        # Ensure parent directory exists
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)

        report_dict = report.model_dump()
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report_dict, f, indent=2, default=str)

        logger.info("Report saved: %s", output_path)
        return output_path
