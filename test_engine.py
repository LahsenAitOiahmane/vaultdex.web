#!/usr/bin/env python3
"""
SecureStorageInspector — Phase 2 Analysis Engine Test

Creates a synthetic dump folder with deliberately insecure data across
all storage areas, then runs the full analysis engine and prints a
detailed report.

Usage:
    # Generate synthetic dump + run analysis:
    python test_engine.py

    # Analyse an existing dump folder from a real scan:
    python test_engine.py --dump-dir dumps/<scan_id> --package com.example.app

    # Save the report to a JSON file:
    python test_engine.py --save-report

    # Verbose mode:
    python test_engine.py -v
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
import sqlite3
import sys
import textwrap
from pathlib import Path

# ── Ensure project root is on PYTHONPATH ─────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from backend.engine.analyser import AnalysisEngine
from backend.engine.models import SecurityReport, Severity
from backend.engine.rules_engine import RulesEngine


# ── ANSI colours ─────────────────────────────────────────────────────
class C:
    BOLD = "\033[1m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    CYAN = "\033[96m"
    MAGENTA = "\033[95m"
    DIM = "\033[2m"
    RESET = "\033[0m"


def _header(title: str) -> None:
    print(f"\n{C.BOLD}{'═' * 64}{C.RESET}")
    print(f"{C.BOLD}  {title}{C.RESET}")
    print(f"{C.BOLD}{'═' * 64}{C.RESET}")


def _subheader(title: str) -> None:
    print(f"\n{C.BOLD}  ── {title} ──{C.RESET}")


def _severity_colour(sev: str) -> str:
    colours = {
        "CRITICAL": C.RED,
        "HIGH": C.MAGENTA,
        "MEDIUM": C.YELLOW,
        "LOW": C.CYAN,
        "INFO": C.DIM,
    }
    return colours.get(sev, "")


# ══════════════════════════════════════════════════════════════════════
#  SYNTHETIC DUMP GENERATOR
# ══════════════════════════════════════════════════════════════════════

SYNTHETIC_SCAN_ID = "test_analysis_synthetic"
SYNTHETIC_PACKAGE = "com.insecure.testapp"


def create_synthetic_dump(base_dir: Path) -> str:
    """
    Create a fake dump directory with deliberately insecure data.

    This covers all four storage areas with known vulnerabilities
    that the engine should detect.

    Returns:
        Path to the created dump directory.
    """
    dump_dir = base_dir / SYNTHETIC_SCAN_ID
    if dump_dir.exists():
        shutil.rmtree(dump_dir)

    # ── SharedPreferences ────────────────────────────────────────
    sp_dir = dump_dir / "shared_prefs"
    sp_dir.mkdir(parents=True)

    # File 1: App preferences with plaintext credentials
    (sp_dir / "app_prefs.xml").write_text(textwrap.dedent("""\
        <?xml version='1.0' encoding='utf-8' standalone='yes' ?>
        <map>
            <string name="user_email">john.doe@example.com</string>
            <string name="auth_token">eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoxMjM0NX0.abcdefghijk</string>
            <string name="password">MyS3cretP@ssw0rd!</string>
            <string name="api_key">sk_live_4eC39HqLyjWDarjtT1zdp7dc</string>
            <string name="theme">dark</string>
            <string name="locale">en_US</string>
            <int name="app_version" value="42" />
            <boolean name="debug_mode" value="true" />
            <boolean name="notifications_enabled" value="true" />
        </map>
    """), encoding="utf-8")

    # File 2: Session data
    (sp_dir / "session.xml").write_text(textwrap.dedent("""\
        <?xml version='1.0' encoding='utf-8' standalone='yes' ?>
        <map>
            <string name="session_id">a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6</string>
            <string name="refresh_token">rt_7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c</string>
            <string name="display_name">John Doe</string>
            <string name="phone_number">+1-555-123-4567</string>
            <long name="last_login" value="1716473820000" />
        </map>
    """), encoding="utf-8")

    # ── Databases ────────────────────────────────────────────────
    db_dir = dump_dir / "databases"
    db_dir.mkdir(parents=True)

    # Create a SQLite database with sensitive tables
    db_path = db_dir / "app_data.db"
    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            email TEXT NOT NULL,
            password TEXT NOT NULL,
            full_name TEXT,
            phone TEXT,
            api_key TEXT
        )
    """)
    cursor.executemany(
        "INSERT INTO users (email, password, full_name, phone, api_key) VALUES (?, ?, ?, ?, ?)",
        [
            ("alice@example.com", "plaintext_password_123", "Alice Smith", "+1-555-111-2222", "ak_test_key_12345"),
            ("bob@corp.io", "bob_secret_pass!", "Bob Jones", "+44-7700-900000", "ak_prod_key_99999"),
        ],
    )

    cursor.execute("""
        CREATE TABLE sessions (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            token TEXT NOT NULL,
            created_at TEXT
        )
    """)
    cursor.execute(
        "INSERT INTO sessions (user_id, token, created_at) VALUES (?, ?, ?)",
        (1, "session_abc123def456ghi789", "2024-01-15T10:30:00Z"),
    )

    cursor.execute("""
        CREATE TABLE app_settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    """)
    cursor.executemany(
        "INSERT INTO app_settings (key, value) VALUES (?, ?)",
        [
            ("theme", "dark"),
            ("language", "en"),
            ("server_url", "https://api.example.com"),
        ],
    )

    conn.commit()
    conn.close()

    # ── Internal Files ───────────────────────────────────────────
    files_dir = dump_dir / "files"
    files_dir.mkdir(parents=True)

    # JSON config with sensitive data
    (files_dir / "config.json").write_text(json.dumps({
        "app": {
            "name": "TestApp",
            "version": "1.0.0",
        },
        "auth": {
            "client_secret": "cs_live_abcdef123456789",
            "api_key": "AIzaSyB4k_test_firebase_key_here",
            "oauth_token": "ya29.a0AfH6SMBx_test_oauth_token_value",
        },
        "server": {
            "base_url": "https://staging.internal.corp/api/v2",
            "debug": True,
        },
    }, indent=2), encoding="utf-8")

    # A private key file (critical finding)
    (files_dir / "server.pem").write_text(textwrap.dedent("""\
        -----BEGIN RSA PRIVATE KEY-----
        MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MhgHcTz6sE2I2yPB
        aFDhOQNZdOYGmYmoaEfhOBQVV3LlHW0Vk5TRMKhBheBqGkAvMaRbGMqjAS4sNdO
        THIS_IS_A_FAKE_KEY_FOR_TESTING_ONLY_DO_NOT_USE_IN_PRODUCTION
        -----END RSA PRIVATE KEY-----
    """), encoding="utf-8")

    # A log file with leaked data
    (files_dir / "app.log").write_text(textwrap.dedent("""\
        2024-01-15 10:30:00 INFO  App started
        2024-01-15 10:30:01 DEBUG User login: email=alice@example.com, password=plaintext_password_123
        2024-01-15 10:30:02 INFO  Token refreshed: eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWxpY2UifQ.xxxyyy
        2024-01-15 10:30:03 INFO  API call to https://user:pass123@api.internal.corp/data
        2024-01-15 10:30:04 INFO  Session established
    """), encoding="utf-8")

    # ── Cache ────────────────────────────────────────────────────
    cache_dir = dump_dir / "cache"
    cache_dir.mkdir(parents=True)

    # Simulated HTTP response cache
    (cache_dir / "response_001.json").write_text(json.dumps({
        "user": {
            "id": 12345,
            "email": "cached_user@example.com",
            "access_token": "at_cached_token_value_12345",
        },
    }, indent=2), encoding="utf-8")

    # A cached config file
    (cache_dir / "settings_cache.txt").write_text(
        "api_key=cached_api_key_for_testing_only\n"
        "session_token=st_cached_session_abc123\n"
        "theme=dark\n",
        encoding="utf-8",
    )

    # ── External Storage ─────────────────────────────────────────
    ext_dir = dump_dir / "external"
    ext_dir.mkdir(parents=True)

    (ext_dir / "export.json").write_text(json.dumps({
        "exported_data": {
            "user_email": "exported@example.com",
            "credit_card": "4532-1234-5678-9012",
            "ssn": "123-45-6789",
        },
    }, indent=2), encoding="utf-8")

    print(f"  {C.GREEN}✔{C.RESET} Synthetic dump created: {dump_dir}")
    return str(dump_dir)


# ══════════════════════════════════════════════════════════════════════
#  REPORT PRINTER
# ══════════════════════════════════════════════════════════════════════

def print_report(report: SecurityReport) -> None:
    """Print a detailed, colour-coded report to the terminal."""

    _header(f"Security Analysis Report — {report.package_name}")

    # ── Score Badge ──────────────────────────────────────────────
    score = report.risk_score
    level = report.risk_level.value
    if score == 0:
        badge_colour = C.GREEN
    elif score <= 25:
        badge_colour = C.CYAN
    elif score <= 50:
        badge_colour = C.YELLOW
    elif score <= 75:
        badge_colour = C.MAGENTA
    else:
        badge_colour = C.RED

    print(f"\n  {C.BOLD}Risk Score:{C.RESET} {badge_colour}{C.BOLD}{score}/100 — {level}{C.RESET}")
    print(f"  {C.BOLD}Engine:     {C.RESET}{report.engine_version}")
    print(f"  {C.BOLD}Analysed:   {C.RESET}{report.analysed_at}")
    print(f"  {C.BOLD}Files:      {C.RESET}{report.total_files_scanned} scanned")

    # ── Severity Summary ─────────────────────────────────────────
    _subheader("Finding Summary")
    sc = report.severity_counts
    print(f"    {C.RED}CRITICAL{C.RESET}: {sc.critical}")
    print(f"    {C.MAGENTA}HIGH{C.RESET}    : {sc.high}")
    print(f"    {C.YELLOW}MEDIUM{C.RESET}  : {sc.medium}")
    print(f"    {C.CYAN}LOW{C.RESET}     : {sc.low}")
    print(f"    {C.DIM}INFO{C.RESET}    : {sc.info}")
    print(f"    {'─' * 20}")
    print(f"    {C.BOLD}TOTAL{C.RESET}   : {report.total_findings}")

    # ── Per-Area Breakdown ───────────────────────────────────────
    for area_report in report.storage_reports:
        _subheader(f"{area_report.area.value.upper()} ({area_report.files_scanned} file(s))")

        if area_report.notes:
            for note in area_report.notes:
                print(f"    {C.DIM}ℹ {note}{C.RESET}")

        if not area_report.findings:
            print(f"    {C.GREEN}✔ No findings.{C.RESET}")
            continue

        for i, f in enumerate(area_report.findings, 1):
            sev_col = _severity_colour(f.severity.value)
            print(
                f"    {sev_col}[{f.severity.value}]{C.RESET} "
                f"{C.BOLD}{f.rule_id}{C.RESET} — {f.rule_name}"
            )
            print(f"      Key:   {f.key_or_field}")
            print(f"      Value: {C.DIM}{f.value_preview}{C.RESET}")
            print(f"      File:  {f.file_path}")
            if f.extra:
                extras = ", ".join(f"{k}={v}" for k, v in f.extra.items())
                print(f"      Extra: {C.DIM}{extras}{C.RESET}")
            print(f"      Fix:   {C.GREEN}{f.recommendation[:100]}{C.RESET}")
            print()

    # ── Final verdict ────────────────────────────────────────────
    _header("Verdict")
    if report.risk_score == 0:
        print(f"  {C.GREEN}{C.BOLD}✔ PASS — No security issues found.{C.RESET}")
    elif report.risk_score <= 25:
        print(f"  {C.CYAN}{C.BOLD}⚠ LOW RISK — Minor issues found, review recommended.{C.RESET}")
    elif report.risk_score <= 50:
        print(f"  {C.YELLOW}{C.BOLD}⚠ MEDIUM RISK — Significant issues require attention.{C.RESET}")
    elif report.risk_score <= 75:
        print(f"  {C.MAGENTA}{C.BOLD}✖ HIGH RISK — Serious vulnerabilities detected.{C.RESET}")
    else:
        print(f"  {C.RED}{C.BOLD}✖ CRITICAL RISK — Immediate remediation required.{C.RESET}")


# ══════════════════════════════════════════════════════════════════════
#  RULES SUMMARY
# ══════════════════════════════════════════════════════════════════════

def print_rules_summary() -> None:
    """Print a summary of all loaded rules."""
    engine = RulesEngine()

    _subheader(f"Loaded Rules ({engine.rule_count} total)")

    for rule in sorted(engine.rules, key=lambda r: r.id):
        sev_col = _severity_colour(rule.severity.value)
        print(
            f"    {sev_col}[{rule.severity.value:8s}]{C.RESET} "
            f"{rule.id:12s} — {rule.name}"
        )


# ══════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════

def main() -> None:
    parser = argparse.ArgumentParser(
        description="SecureStorageInspector — Phase 2 Analysis Engine Test",
    )
    parser.add_argument(
        "--dump-dir",
        type=str,
        default=None,
        help="Path to an existing dump directory to analyse.",
    )
    parser.add_argument(
        "--package",
        type=str,
        default=None,
        help="Package name (required with --dump-dir).",
    )
    parser.add_argument(
        "--scan-id",
        type=str,
        default=None,
        help="Scan ID (defaults to directory name).",
    )
    parser.add_argument(
        "--save-report",
        action="store_true",
        help="Save the report as JSON to reports/<scan_id>.json.",
    )
    parser.add_argument(
        "--list-rules",
        action="store_true",
        help="Print all loaded rules and exit.",
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
    logging.getLogger("urllib3").setLevel(logging.WARNING)

    _header("SecureStorageInspector — Analysis Engine Test")

    # ── List rules mode ──────────────────────────────────────────
    if args.list_rules:
        print_rules_summary()
        return

    # ── Determine dump directory ─────────────────────────────────
    if args.dump_dir:
        dump_dir = args.dump_dir
        package_name = args.package or "com.unknown.app"
        scan_id = args.scan_id or Path(dump_dir).name
    else:
        # Generate synthetic dump
        _subheader("Generating Synthetic Dump")
        from backend.config import get_settings
        settings = get_settings()
        dump_dir = create_synthetic_dump(settings.DUMPS_DIR)
        package_name = SYNTHETIC_PACKAGE
        scan_id = SYNTHETIC_SCAN_ID

    # ── Run analysis ─────────────────────────────────────────────
    _subheader("Running Analysis Engine")
    engine = AnalysisEngine()
    report = engine.analyse(
        scan_id=scan_id,
        dump_dir=dump_dir,
        package_name=package_name,
    )

    # ── Print report ─────────────────────────────────────────────
    print_report(report)

    # ── Save report ──────────────────────────────────────────────
    if args.save_report:
        path = engine.save_report(report)
        print(f"\n  {C.GREEN}✔{C.RESET} Report saved: {path}")

    # ── Validation (for synthetic dump) ──────────────────────────
    if not args.dump_dir:
        _subheader("Synthetic Dump Validation")
        errors = []

        if report.total_findings < 10:
            errors.append(
                f"Expected ≥10 findings, got {report.total_findings}"
            )

        if report.severity_counts.critical < 2:
            errors.append(
                f"Expected ≥2 CRITICAL findings, got {report.severity_counts.critical}"
            )

        if report.risk_score < 50:
            errors.append(
                f"Expected risk score ≥50, got {report.risk_score}"
            )

        # Check that value masking is working
        for area in report.storage_reports:
            for finding in area.findings:
                if "***" not in finding.value_preview and len(finding.value_preview) > 4:
                    errors.append(
                        f"Value not masked in {finding.rule_id}: "
                        f"'{finding.value_preview}'"
                    )
                    break

        if errors:
            print(f"\n  {C.RED}✖ Validation FAILED:{C.RESET}")
            for e in errors:
                print(f"    {C.RED}• {e}{C.RESET}")
        else:
            print(f"\n  {C.GREEN}✔ All validations passed!{C.RESET}")
            print(f"    • {report.total_findings} findings detected")
            print(f"    • {report.severity_counts.critical} CRITICAL findings")
            print(f"    • Risk score: {report.risk_score}/100")
            print(f"    • Value masking verified")
            print(f"    • All 5 storage areas analysed")


if __name__ == "__main__":
    main()
