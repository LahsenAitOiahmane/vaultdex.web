"""
SecureStorageInspector — SharedPreferences Analyser

Parses Android SharedPreferences XML files and evaluates every key-value
pair against the rules engine. Also detects the absence of
EncryptedSharedPreferences.

XML parsing security:
    - Uses defusedxml to prevent XXE (XML External Entity) attacks from
      malicious SharedPreferences files.
    - Falls back to stdlib ElementTree with entity expansion disabled
      if defusedxml is not installed.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

# Secure XML parsing — defusedxml is mandatory (added to requirements.txt)
import defusedxml.ElementTree as ET

from backend.engine.models import Finding, StorageArea, StorageAreaReport
from backend.engine.rules_engine import RulesEngine

logger = logging.getLogger(__name__)


class SharedPrefsAnalyser:
    """
    Analyses SharedPreferences XML files from Android app storage.

    SharedPreferences store app settings and data as XML key-value pairs.
    Common tag types: <string>, <int>, <long>, <float>, <boolean>,
    <set>, <map>.
    """

    def __init__(self, rules_engine: RulesEngine) -> None:
        """
        Initialise with a shared RulesEngine instance.

        Args:
            rules_engine: The loaded rules engine for evaluation.
        """
        self.rules_engine = rules_engine

    def analyse(self, shared_prefs_dir: str) -> StorageAreaReport:
        """
        Analyse all SharedPreferences XML files in the given directory.

        Args:
            shared_prefs_dir: Path to the ``shared_prefs/`` dump folder.

        Returns:
            StorageAreaReport with findings for this storage area.
        """
        report = StorageAreaReport(area=StorageArea.SHARED_PREFS)
        prefs_path = Path(shared_prefs_dir)

        if not prefs_path.is_dir():
            report.notes.append("SharedPreferences directory not found (app may not use SharedPrefs).")
            logger.info("SharedPrefs dir not found: %s", shared_prefs_dir)
            return report

        # Find all XML files recursively
        xml_files = list(prefs_path.rglob("*.xml"))
        if not xml_files:
            report.notes.append("No SharedPreferences XML files found.")
            logger.info("No XML files in %s", shared_prefs_dir)
            return report

        report.files_scanned = len(xml_files)
        logger.info("Analysing %d SharedPreferences file(s) …", len(xml_files))

        for xml_file in xml_files:
            try:
                self._analyse_xml_file(xml_file, prefs_path, report)
            except Exception as exc:
                logger.warning(
                    "Failed to parse SharedPrefs file %s: %s",
                    xml_file.name,
                    exc,
                )
                report.notes.append(f"Parse error in {xml_file.name}: {exc}")

        # Meta-check: if ALL keys/values are human-readable (not ciphertext),
        # the app is NOT using EncryptedSharedPreferences
        if report.files_scanned > 0 and not self._looks_encrypted(xml_files):
            report.notes.append(
                "SharedPreferences are NOT encrypted. The app does not appear "
                "to use EncryptedSharedPreferences — all data is stored in "
                "plaintext XML."
            )

        return report

    def _analyse_xml_file(
        self,
        xml_file: Path,
        base_dir: Path,
        report: StorageAreaReport,
    ) -> None:
        """
        Parse a single SharedPreferences XML file and evaluate entries.

        Args:
            xml_file: Path to the XML file.
            base_dir: Base directory for computing relative paths.
            report:   The report to add findings to.
        """
        relative_path = str(xml_file.relative_to(base_dir.parent))

        # Parse with defusedxml (XXE-safe)
        tree = ET.parse(str(xml_file))
        root = tree.getroot()

        # SharedPreferences XML structure:
        # <map>
        #   <string name="key">value</string>
        #   <int name="key" value="123" />
        #   <boolean name="key" value="true" />
        #   <set name="key"><string>val1</string>...</set>
        # </map>
        for element in root:
            key = element.get("name", "")
            value = self._extract_value(element)

            if not key and not value:
                continue

            # Evaluate against all rules
            findings = self.rules_engine.evaluate(
                key=key,
                value=value,
                storage_area=StorageArea.SHARED_PREFS,
                file_path=relative_path,
                extra={"xml_file": xml_file.name, "element_tag": element.tag},
            )

            for finding in findings:
                report.add_finding(finding)

    def _extract_value(self, element: Any) -> str:
        """
        Extract the string value from a SharedPreferences XML element.

        Handles different element types:
            <string name="k">text</string>         → "text"
            <int name="k" value="123" />            → "123"
            <boolean name="k" value="true" />       → "true"
            <float name="k" value="1.5" />          → "1.5"
            <long name="k" value="999" />           → "999"
            <set name="k"><string>v1</string>…</set>→ "v1, v2, …"

        Args:
            element: An XML element from the SharedPreferences file.

        Returns:
            The value as a string.
        """
        tag = element.tag.lower() if element.tag else ""

        # <string> elements store value as text content
        if tag == "string":
            return (element.text or "").strip()

        # <set> contains child <string> elements
        if tag == "set":
            children = [
                (child.text or "").strip()
                for child in element
                if child.text
            ]
            return ", ".join(children)

        # <int>, <long>, <float>, <boolean> store value as attribute
        val = element.get("value", "")
        return str(val).strip()

    def _looks_encrypted(self, xml_files: List[Path]) -> bool:
        """
        Heuristic check: does the SharedPreferences data look encrypted?

        EncryptedSharedPreferences produces keys and values that are
        base64-encoded ciphertext blobs. If we see keys that look like
        base64 gibberish rather than human-readable names, the prefs
        are likely encrypted.

        Args:
            xml_files: List of XML file paths to sample.

        Returns:
            True if the data appears to be encrypted.
        """
        # Sample the first file
        try:
            tree = ET.parse(str(xml_files[0]))
            root = tree.getroot()
            keys = [el.get("name", "") for el in root if el.get("name")]
            if not keys:
                return False

            # EncryptedSharedPreferences keys look like:
            # "__androidx_security_crypto_encrypted_prefs_key_keyset__"
            # or long base64 strings
            encrypted_indicators = [
                "__androidx_security_crypto",
                "encrypted_prefs",
                "keyset",
            ]
            for key in keys:
                for indicator in encrypted_indicators:
                    if indicator in key.lower():
                        return True

            # If most keys are very long (>50 chars) and non-readable,
            # they're probably encrypted
            long_keys = sum(1 for k in keys if len(k) > 50)
            if long_keys > len(keys) * 0.5:
                return True

        except Exception:
            pass

        return False
