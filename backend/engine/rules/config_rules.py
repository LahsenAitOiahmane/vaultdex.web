"""
SecureStorageInspector — Insecure Configuration Detection Rules

Detects debug flags, cleartext traffic settings, insecure preferences,
and other configuration values that weaken the app's security posture.
"""

from __future__ import annotations

from typing import List

from backend.engine.models import Severity, StorageArea
from backend.engine.rules_engine import SecurityRule


_ALL_AREAS = list(StorageArea)


def get_rules() -> List[SecurityRule]:
    """Return all configuration-related security rules."""
    return [
        # ── Debug Mode Enabled ───────────────────────────────────────
        SecurityRule(
            id="CFG-001",
            name="Debug Mode Enabled",
            description=(
                "A debug flag is set to true in local storage. Debug mode "
                "may enable verbose logging, bypass authentication, or "
                "expose internal APIs."
            ),
            severity=Severity.MEDIUM,
            category="config",
            key_patterns=[
                r"debug",
                r"is_debug",
                r"debug_mode",
                r"debuggable",
                r"developer_mode",
                r"dev_mode",
            ],
            value_patterns=[
                r"^true$",
                r"^1$",
                r"^yes$",
                r"^on$",
                r"^enabled$",
            ],
            applies_to=_ALL_AREAS,
            match_target="both",
            recommendation=(
                "Ensure debug mode is disabled in production builds. Use "
                "BuildConfig.DEBUG for compile-time checks, not runtime flags."
            ),
            min_value_length=1,
        ),

        # ── Cleartext Traffic ────────────────────────────────────────
        SecurityRule(
            id="CFG-002",
            name="Cleartext Traffic Allowed",
            description=(
                "A configuration value suggests cleartext (HTTP) traffic is "
                "allowed. All network traffic should use TLS (HTTPS) to "
                "prevent interception."
            ),
            severity=Severity.HIGH,
            category="config",
            key_patterns=[
                r"cleartextTraffic",
                r"cleartext",
                r"usesCleartextTraffic",
                r"allow_http",
                r"http_only",
            ],
            value_patterns=[
                r"^true$",
                r"^1$",
                r"^yes$",
                r"^allowed$",
            ],
            applies_to=_ALL_AREAS,
            match_target="both",
            recommendation=(
                "Disable cleartext traffic in the network security config. "
                "Set android:usesCleartextTraffic='false' and use HTTPS "
                "for all connections."
            ),
            min_value_length=1,
        ),

        # ── SSL/TLS Pinning Disabled ─────────────────────────────────
        SecurityRule(
            id="CFG-003",
            name="SSL Pinning Disabled",
            description=(
                "Certificate pinning appears to be disabled. Without pinning, "
                "the app is vulnerable to man-in-the-middle attacks using "
                "rogue certificates."
            ),
            severity=Severity.MEDIUM,
            category="config",
            key_patterns=[
                r"ssl_pinning",
                r"cert_pinning",
                r"certificate_pinning",
                r"pin_enabled",
                r"verify_ssl",
                r"trust_all",
            ],
            value_patterns=[
                r"^false$",
                r"^0$",
                r"^no$",
                r"^disabled$",
            ],
            applies_to=_ALL_AREAS,
            match_target="both",
            recommendation=(
                "Enable certificate pinning using OkHttp CertificatePinner "
                "or the Network Security Configuration. Pin to the leaf or "
                "intermediate certificate."
            ),
            min_value_length=1,
        ),

        # ── Root / Jailbreak Detection Disabled ──────────────────────
        SecurityRule(
            id="CFG-004",
            name="Root Detection Disabled",
            description=(
                "Root or jailbreak detection appears to be disabled. Without "
                "root detection, the app's local storage is trivially "
                "accessible to any root user."
            ),
            severity=Severity.LOW,
            category="config",
            key_patterns=[
                r"root_detect",
                r"jailbreak",
                r"integrity_check",
                r"tamper_detect",
                r"rooted_device",
            ],
            value_patterns=[
                r"^false$",
                r"^0$",
                r"^no$",
                r"^disabled$",
            ],
            applies_to=_ALL_AREAS,
            match_target="both",
            recommendation=(
                "Enable runtime root/integrity detection. Consider using "
                "SafetyNet/Play Integrity API for device attestation."
            ),
            min_value_length=1,
        ),

        # ── Sensitive URL with embedded credentials ──────────────────
        SecurityRule(
            id="CFG-005",
            name="URL with Embedded Credentials",
            description=(
                "A URL containing embedded credentials (username:password) "
                "was found. Credentials in URLs are logged by proxies, "
                "browsers, and servers."
            ),
            severity=Severity.HIGH,
            category="config",
            key_patterns=[],
            value_patterns=[
                # https://user:pass@host pattern
                r"https?://[^:]+:[^@]+@",
            ],
            applies_to=_ALL_AREAS,
            match_target="value",
            recommendation=(
                "Remove credentials from URLs. Use HTTP authentication "
                "headers (Authorization: Bearer) instead."
            ),
            min_value_length=10,
        ),

        # ── Internal / Staging URLs ──────────────────────────────────
        SecurityRule(
            id="CFG-006",
            name="Internal/Staging URL Exposed",
            description=(
                "An internal, staging, or development URL was found in "
                "production storage. This exposes internal infrastructure "
                "information."
            ),
            severity=Severity.MEDIUM,
            category="config",
            key_patterns=[
                r"base_url",
                r"api_url",
                r"server_url",
                r"endpoint",
            ],
            value_patterns=[
                r"(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+)",
                r"(?:staging|dev|test|internal|preprod)\.",
            ],
            applies_to=_ALL_AREAS,
            match_target="both",
            recommendation=(
                "Ensure production builds only contain production URLs. "
                "Use build flavors/variants to manage environment-specific "
                "configuration."
            ),
            min_value_length=5,
        ),

        # ── Logging Enabled ──────────────────────────────────────────
        SecurityRule(
            id="CFG-007",
            name="Verbose Logging Enabled",
            description=(
                "Verbose or debug logging appears to be enabled. Excessive "
                "logging in production can leak sensitive data to logcat."
            ),
            severity=Severity.LOW,
            category="config",
            key_patterns=[
                r"log_level",
                r"logging",
                r"verbose",
                r"log_enabled",
            ],
            value_patterns=[
                r"^(?:debug|verbose|trace|all)$",
            ],
            applies_to=_ALL_AREAS,
            match_target="both",
            recommendation=(
                "Set log level to WARN or ERROR in production. Use "
                "BuildConfig.DEBUG to gate verbose logging."
            ),
            min_value_length=1,
        ),
    ]
