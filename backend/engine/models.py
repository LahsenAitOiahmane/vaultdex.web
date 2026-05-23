"""
SecureStorageInspector — Analysis Engine Data Models

Pydantic models that represent the full security report structure.
These models are the contract between the analysis engine (Phase 2),
the API (Phase 3), the dashboard (Phase 4), and the PDF exporter (Phase 5).

Every model is JSON-serialisable via pydantic's `.model_dump()`.
"""

from __future__ import annotations

import math
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# ── Engine version — bump when rules or scoring logic change ─────────
ENGINE_VERSION = "3.0.0"


# ══════════════════════════════════════════════════════════════════════
#  ENUMS
# ══════════════════════════════════════════════════════════════════════

class Severity(str, Enum):
    """Finding severity levels, ordered from most to least severe."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class StorageArea(str, Enum):
    """Android local storage areas that the engine analyses."""
    SHARED_PREFS = "shared_prefs"
    DATABASE = "databases"
    FILES = "files"
    CACHE = "cache"
    EXTERNAL = "external"


class RiskLevel(str, Enum):
    """Human-readable risk level derived from the numeric score."""
    PASS = "PASS"
    LOW_RISK = "LOW_RISK"
    MEDIUM_RISK = "MEDIUM_RISK"
    HIGH_RISK = "HIGH_RISK"
    CRITICAL_RISK = "CRITICAL_RISK"


# ══════════════════════════════════════════════════════════════════════
#  FINDING
# ══════════════════════════════════════════════════════════════════════

class Finding(BaseModel):
    """
    A single security issue discovered during analysis.

    The ``value_preview`` is intentionally truncated and masked.
    Full sensitive values are NEVER stored in the report to prevent
    the report itself from becoming a data leak.
    """

    rule_id: str = Field(
        ...,
        description="Unique identifier of the rule that triggered (e.g. CRED-001).",
    )
    rule_name: str = Field(
        ...,
        description="Human-readable rule name (e.g. 'Plaintext Password').",
    )
    severity: Severity = Field(
        ...,
        description="Severity level of this finding.",
    )
    category: str = Field(
        ...,
        description="Rule category (credentials, pii, crypto, config, session).",
    )
    storage_area: StorageArea = Field(
        ...,
        description="Which storage area this finding was in.",
    )
    file_path: str = Field(
        ...,
        description="Relative path to the file within the dump folder.",
    )
    key_or_field: str = Field(
        ...,
        description="The key name (SharedPrefs), column name (DB), or context.",
    )
    value_preview: str = Field(
        ...,
        description="Truncated + masked preview of the sensitive value.",
    )
    description: str = Field(
        ...,
        description="What the rule detected and why it matters.",
    )
    recommendation: str = Field(
        ...,
        description="Actionable fix recommendation for the developer.",
    )
    extra: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Additional context (table name for DBs, line number for files, etc.).",
    )


# ══════════════════════════════════════════════════════════════════════
#  SEVERITY COUNTS
# ══════════════════════════════════════════════════════════════════════

class SeverityCounts(BaseModel):
    """Count of findings by severity level."""
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0

    @property
    def total(self) -> int:
        """Total findings across all severities (excluding INFO)."""
        return self.critical + self.high + self.medium + self.low

    def increment(self, severity: Severity) -> None:
        """Increment the counter for a given severity."""
        attr = severity.value.lower()
        setattr(self, attr, getattr(self, attr) + 1)


# ══════════════════════════════════════════════════════════════════════
#  STORAGE AREA REPORT
# ══════════════════════════════════════════════════════════════════════

class StorageAreaReport(BaseModel):
    """Analysis results for a single storage area."""

    area: StorageArea = Field(
        ...,
        description="Which storage area this report covers.",
    )
    files_scanned: int = Field(
        default=0,
        description="Number of files inspected in this area.",
    )
    findings: List[Finding] = Field(
        default_factory=list,
        description="All security findings in this area.",
    )
    severity_counts: SeverityCounts = Field(
        default_factory=SeverityCounts,
        description="Finding counts by severity for this area.",
    )
    notes: List[str] = Field(
        default_factory=list,
        description="Informational notes (e.g. 'No SharedPreferences files found').",
    )

    def add_finding(self, finding: Finding) -> None:
        """Add a finding and update severity counts."""
        self.findings.append(finding)
        self.severity_counts.increment(finding.severity)


# ══════════════════════════════════════════════════════════════════════
#  STATIC ANALYSIS REPORT
# ══════════════════════════════════════════════════════════════════════

class PermissionEntry(BaseModel):
    """A single permission from the APK manifest."""
    name: str
    risk_level: str = "unknown"
    category: str = "other"
    description: str = ""
    is_custom: bool = False


class ExportedComponent(BaseModel):
    """An exported Android component."""
    name: str
    component_type: str  # activity, service, receiver, provider
    has_permission: bool = False
    permission: Optional[str] = None
    intent_filters: List[str] = Field(default_factory=list)


class ManifestFlagsReport(BaseModel):
    """Security-critical manifest flags."""
    debuggable: bool = False
    allow_backup: bool = True
    uses_cleartext_traffic: bool = True
    network_security_config: bool = False
    test_only: bool = False


class StaticAnalysisReport(BaseModel):
    """Complete static analysis report for an APK file."""

    # Metadata
    package_name: str = ""
    app_name: str = ""
    version_name: str = ""
    version_code: str = ""
    apk_size_bytes: int = 0
    min_sdk: int = 0
    min_sdk_name: str = ""
    target_sdk: int = 0
    target_sdk_name: str = ""

    # Hardware & Architecture
    native_architectures: List[str] = Field(default_factory=list)
    uses_features: List[str] = Field(default_factory=list)

    # Permissions
    permissions: List[PermissionEntry] = Field(default_factory=list)
    dangerous_permission_count: int = 0
    total_permission_count: int = 0

    # Exported components
    exported_components: List[ExportedComponent] = Field(default_factory=list)
    total_exported_components: int = 0
    launchable_activity: str = ""

    # Manifest flags
    manifest_flags: ManifestFlagsReport = Field(default_factory=ManifestFlagsReport)

    # Deep links
    deep_links: List[str] = Field(default_factory=list)
    custom_url_schemes: List[str] = Field(default_factory=list)

    # Findings from static analysis
    findings: List[Finding] = Field(default_factory=list)
    severity_counts: SeverityCounts = Field(default_factory=SeverityCounts)


# ══════════════════════════════════════════════════════════════════════
#  SECURITY REPORT (TOP-LEVEL)
# ══════════════════════════════════════════════════════════════════════

class SecurityReport(BaseModel):
    """
    Complete security analysis report for a single APK scan.

    This is the top-level object returned by ``AnalysisEngine.analyse()``.
    It is designed to be consumed by the API (Phase 3), dashboard (Phase 4),
    and PDF exporter (Phase 5).
    """

    scan_id: str = Field(
        ...,
        description="Unique scan identifier (matches Phase 1 scan_id).",
    )
    package_name: str = Field(
        ...,
        description="Android package name of the scanned app.",
    )
    risk_score: int = Field(
        default=0,
        ge=0,
        le=100,
        description="Overall risk score (0 = clean, 100 = critical risk).",
    )
    risk_level: RiskLevel = Field(
        default=RiskLevel.PASS,
        description="Human-readable risk level label.",
    )
    severity_counts: SeverityCounts = Field(
        default_factory=SeverityCounts,
        description="Aggregate finding counts across all storage areas.",
    )
    total_findings: int = Field(
        default=0,
        description="Total number of findings (excluding INFO).",
    )
    total_files_scanned: int = Field(
        default=0,
        description="Total files inspected across all areas.",
    )
    storage_reports: List[StorageAreaReport] = Field(
        default_factory=list,
        description="Per-area breakdown of findings.",
    )
    static_analysis: Optional[StaticAnalysisReport] = Field(
        default=None,
        description="Static analysis of the APK manifest and resources.",
    )
    analysed_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO 8601 timestamp of when analysis completed.",
    )
    engine_version: str = Field(
        default=ENGINE_VERSION,
        description="Version of the analysis engine that produced this report.",
    )

    def aggregate(self) -> None:
        """
        Recompute top-level counts from all reports (storage + static).

        Call this after all area reports have been added.
        """
        self.severity_counts = SeverityCounts()
        self.total_files_scanned = 0

        for area_report in self.storage_reports:
            self.total_files_scanned += area_report.files_scanned
            for finding in area_report.findings:
                self.severity_counts.increment(finding.severity)

        # Include static analysis findings in the totals
        if self.static_analysis:
            for finding in self.static_analysis.findings:
                self.severity_counts.increment(finding.severity)

        self.total_findings = self.severity_counts.total


# ══════════════════════════════════════════════════════════════════════
#  HELPER: VALUE MASKING
# ══════════════════════════════════════════════════════════════════════

def mask_value(value: str, visible_chars: int = 4) -> str:
    """
    Mask a sensitive value for safe inclusion in the report.

    Shows the first ``visible_chars`` characters, replaces the rest
    with ``***``. Values shorter than ``visible_chars + 1`` are fully
    masked.

    Args:
        value:         The raw sensitive value.
        visible_chars: How many leading characters to keep visible.

    Returns:
        Masked string (e.g. ``"mypa***"`` for ``"mypassword123"``).
    """
    if not value:
        return "***"
    if len(value) <= visible_chars:
        return "***"
    return value[:visible_chars] + "***"
