"""
SecureStorageInspector — SQLite / Room Database Analyser

Opens SQLite database files extracted from the device, inspects every
table and column, samples row data, and evaluates against the rules
engine.

Security:
    - Databases are opened in read-only mode (``?mode=ro`` URI).
    - Row sampling is capped at 100 rows per table.
    - Query execution has a timeout.
    - No SQL is constructed from user/file input — only from table/column
      names read from ``sqlite_master``, which are quoted to prevent
      injection even if a malicious APK crafted adversarial table names.
"""

from __future__ import annotations

import logging
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional

from backend.engine.models import Finding, Severity, StorageArea, StorageAreaReport, mask_value
from backend.engine.rules_engine import RulesEngine

logger = logging.getLogger(__name__)

# Maximum rows to sample from each table
_MAX_ROWS = 100

# SQLite header magic (first 16 bytes of a valid SQLite file)
_SQLITE_MAGIC = b"SQLite format 3\x00"


class DatabaseAnalyser:
    """
    Analyses SQLite / Room database files from Android app storage.

    Inspects table schemas, column names, and sampled row data for
    sensitive content.
    """

    def __init__(self, rules_engine: RulesEngine) -> None:
        """
        Initialise with a shared RulesEngine instance.

        Args:
            rules_engine: The loaded rules engine for evaluation.
        """
        self.rules_engine = rules_engine

    def analyse(self, databases_dir: str) -> StorageAreaReport:
        """
        Analyse all database files in the given directory.

        Args:
            databases_dir: Path to the ``databases/`` dump folder.

        Returns:
            StorageAreaReport with findings for this storage area.
        """
        report = StorageAreaReport(area=StorageArea.DATABASE)
        db_path = Path(databases_dir)

        if not db_path.is_dir():
            report.notes.append("Databases directory not found (app may not use SQLite/Room).")
            logger.info("Databases dir not found: %s", databases_dir)
            return report

        # Find all .db files (also check for files without extension that
        # might be SQLite databases, and journal/WAL files)
        db_files = self._find_database_files(db_path)
        if not db_files:
            report.notes.append("No database files found.")
            logger.info("No database files in %s", databases_dir)
            return report

        report.files_scanned = len(db_files)
        logger.info("Analysing %d database file(s) …", len(db_files))

        for db_file in db_files:
            try:
                self._analyse_database(db_file, db_path, report)
            except Exception as exc:
                logger.warning(
                    "Failed to analyse database %s: %s",
                    db_file.name,
                    exc,
                )
                report.notes.append(f"Analysis error in {db_file.name}: {exc}")

        # Check for WAL/journal files alongside databases (may contain
        # residual data even after deletion)
        self._check_journal_files(db_path, report)

        return report

    def _find_database_files(self, db_path: Path) -> List[Path]:
        """
        Find all SQLite database files in the directory.

        Checks both the .db extension and the file header magic bytes
        to catch databases with non-standard extensions.
        """
        candidates: List[Path] = []

        for f in db_path.rglob("*"):
            if not f.is_file():
                continue
            # Skip journal/WAL files — they're checked separately
            if f.suffix in ("-journal", "-wal", "-shm", ".db-journal", ".db-wal", ".db-shm"):
                continue
            if f.name.endswith("-journal") or f.name.endswith("-wal") or f.name.endswith("-shm"):
                continue

            # Check by extension
            if f.suffix.lower() in (".db", ".sqlite", ".sqlite3"):
                candidates.append(f)
                continue

            # Check by magic bytes (catches extensionless databases)
            try:
                with open(f, "rb") as fh:
                    header = fh.read(16)
                    if header == _SQLITE_MAGIC:
                        candidates.append(f)
            except (OSError, IOError):
                pass

        return candidates

    def _analyse_database(
        self,
        db_file: Path,
        base_dir: Path,
        report: StorageAreaReport,
    ) -> None:
        """
        Open and analyse a single SQLite database file.

        Args:
            db_file:  Path to the database file.
            base_dir: Base directory for computing relative paths.
            report:   The report to add findings to.
        """
        relative_path = str(db_file.relative_to(base_dir.parent))

        # Check if the database is encrypted (SQLCipher)
        if not self._is_sqlite(db_file):
            report.notes.append(
                f"{db_file.name}: File is not a standard SQLite database — "
                "it may be encrypted with SQLCipher (this is good practice)."
            )
            return

        # Open in read-only mode using URI
        db_uri = f"file:{db_file}?mode=ro"
        conn: Optional[sqlite3.Connection] = None

        try:
            conn = sqlite3.connect(db_uri, uri=True, timeout=10)
            conn.row_factory = sqlite3.Row

            # List all user tables
            cursor = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name NOT LIKE 'sqlite_%' AND name NOT LIKE 'android_%' "
                "ORDER BY name"
            )
            tables = [row[0] for row in cursor.fetchall()]

            if not tables:
                report.notes.append(f"{db_file.name}: Database has no user tables.")
                return

            logger.debug(
                "Database %s has %d table(s): %s",
                db_file.name,
                len(tables),
                ", ".join(tables),
            )

            for table_name in tables:
                self._analyse_table(conn, table_name, relative_path, db_file.name, report)

            # Flag the absence of encryption at the database level
            report.notes.append(
                f"{db_file.name}: Database is NOT encrypted (no SQLCipher). "
                "All data is stored in plaintext SQLite."
            )

        except sqlite3.DatabaseError as exc:
            logger.warning("SQLite error in %s: %s", db_file.name, exc)
            report.notes.append(f"{db_file.name}: SQLite error — {exc}")
        finally:
            if conn:
                conn.close()

    def _analyse_table(
        self,
        conn: sqlite3.Connection,
        table_name: str,
        relative_path: str,
        db_name: str,
        report: StorageAreaReport,
    ) -> None:
        """
        Analyse a single table: check column names and sample rows.

        Args:
            conn:          Open database connection (read-only).
            table_name:    Name of the table to inspect.
            relative_path: Relative file path for findings.
            db_name:       Database filename for context.
            report:        The report to add findings to.
        """
        # Get column info
        # We use PRAGMA which is safe — table_name comes from sqlite_master,
        # not user input. Still, we quote it for defence in depth.
        quoted_table = f'"{table_name}"'
        try:
            cursor = conn.execute(f"PRAGMA table_info({quoted_table})")
            columns = cursor.fetchall()
        except sqlite3.OperationalError as exc:
            logger.warning("Cannot read schema for table %s: %s", table_name, exc)
            return

        column_names = [col[1] for col in columns]  # col[1] is the name

        # Check column names against rules (sensitive column detection)
        for col_name in column_names:
            findings = self.rules_engine.evaluate(
                key=col_name,
                value=col_name,  # For column-name-only checks, pass name as value too
                storage_area=StorageArea.DATABASE,
                file_path=relative_path,
                extra={"database": db_name, "table": table_name, "check_type": "column_name"},
            )
            for finding in findings:
                report.add_finding(finding)

        # Sample rows and check actual values
        try:
            cursor = conn.execute(
                f"SELECT * FROM {quoted_table} LIMIT ?",
                (_MAX_ROWS,),
            )
            rows = cursor.fetchall()
        except sqlite3.OperationalError as exc:
            logger.warning("Cannot read rows from %s.%s: %s", db_name, table_name, exc)
            return

        for row_idx, row in enumerate(rows):
            for col_idx, col_name in enumerate(column_names):
                cell_value = row[col_idx]
                if cell_value is None:
                    continue

                str_value = str(cell_value).strip()
                if not str_value:
                    continue

                findings = self.rules_engine.evaluate(
                    key=col_name,
                    value=str_value,
                    storage_area=StorageArea.DATABASE,
                    file_path=relative_path,
                    extra={
                        "database": db_name,
                        "table": table_name,
                        "column": col_name,
                        "row_index": row_idx,
                    },
                )
                for finding in findings:
                    report.add_finding(finding)

    def _check_journal_files(self, db_path: Path, report: StorageAreaReport) -> None:
        """
        Check for WAL/journal files that may contain residual data.

        These files can contain data that was deleted from the main
        database but not yet vacuumed.
        """
        journal_extensions = {"-wal", "-shm", "-journal"}
        journal_files = []

        for f in db_path.rglob("*"):
            if f.is_file():
                for ext in journal_extensions:
                    if f.name.endswith(ext):
                        journal_files.append(f)
                        break

        if journal_files:
            names = ", ".join(f.name for f in journal_files[:5])
            report.notes.append(
                f"Found {len(journal_files)} journal/WAL file(s): {names}. "
                "These files may contain residual data from deleted records."
            )

    def _is_sqlite(self, db_file: Path) -> bool:
        """Check if a file is a valid (unencrypted) SQLite database."""
        try:
            with open(db_file, "rb") as f:
                header = f.read(16)
                return header == _SQLITE_MAGIC
        except (OSError, IOError):
            return False
