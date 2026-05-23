"""
SecureStorageInspector — Rules Engine

The rules engine is the core detection mechanism. SecurityRule objects
define what patterns to look for, in which storage areas, and at what
severity level. The RulesEngine loads all rules at startup and exposes
an ``evaluate()`` method that analysers call for every key-value pair.

Rules are extensible: add a new ``.py`` file to ``backend/engine/rules/``
that exports ``get_rules() -> list[SecurityRule]`` and it will be
automatically loaded.

No rule logic touches the filesystem directly — analysers parse files
and feed (key, value, area) tuples into the engine.
"""

from __future__ import annotations

import logging
import math
import re
from dataclasses import dataclass, field
from typing import List, Optional

from backend.engine.models import Finding, Severity, StorageArea, mask_value

logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════════════
#  SECURITY RULE DEFINITION
# ══════════════════════════════════════════════════════════════════════

@dataclass
class SecurityRule:
    """
    A single detection rule.

    Attributes:
        id:            Unique identifier (e.g. ``CRED-001``).
        name:          Human-readable name.
        description:   What this rule detects and why it matters.
        severity:      Default severity level.
        category:      Grouping (credentials, pii, crypto, config, session).
        key_patterns:  Regex patterns tested against key / column names.
        value_patterns: Regex patterns tested against the value content.
        applies_to:    Storage areas where this rule is active.
        match_target:  ``"key"`` — match key_patterns only,
                       ``"value"`` — match value_patterns only,
                       ``"both"`` — match key_patterns AND value_patterns,
                       ``"key_or_value"`` — match either.
        recommendation: Fix advice for the developer.
        enabled:       Toggle to disable without removing.
        min_value_length: Minimum value length to trigger (avoids false
                          positives on short/empty values).
        check_entropy: If True, also requires high Shannon entropy in the
                       value (useful for token detection).
    """
    id: str
    name: str
    description: str
    severity: Severity
    category: str
    key_patterns: List[str] = field(default_factory=list)
    value_patterns: List[str] = field(default_factory=list)
    applies_to: List[StorageArea] = field(
        default_factory=lambda: list(StorageArea)
    )
    match_target: str = "key"  # "key", "value", "both", "key_or_value"
    recommendation: str = ""
    enabled: bool = True
    min_value_length: int = 1
    check_entropy: bool = False

    def __post_init__(self) -> None:
        """Pre-compile regex patterns for performance."""
        self._compiled_key: List[re.Pattern] = [
            re.compile(p, re.IGNORECASE) for p in self.key_patterns
        ]
        self._compiled_value: List[re.Pattern] = [
            re.compile(p, re.IGNORECASE) for p in self.value_patterns
        ]


# ══════════════════════════════════════════════════════════════════════
#  SHANNON ENTROPY
# ══════════════════════════════════════════════════════════════════════

def shannon_entropy(text: str) -> float:
    """
    Calculate the Shannon entropy of a string in bits per character.

    High-entropy strings (> 4.5) are likely tokens, keys, or secrets.
    Low-entropy strings (< 3.0) are likely natural language or simple config.

    Args:
        text: The string to measure.

    Returns:
        Entropy in bits/char. Returns 0.0 for empty strings.
    """
    if not text:
        return 0.0

    length = len(text)
    freq: dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1

    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)

    return round(entropy, 3)


# ══════════════════════════════════════════════════════════════════════
#  RULES ENGINE
# ══════════════════════════════════════════════════════════════════════

# Entropy threshold: values above this are considered "high entropy"
# and likely to be tokens, secrets, or cryptographic material.
_ENTROPY_THRESHOLD = 4.0


class RulesEngine:
    """
    Loads all security rules and evaluates key-value pairs against them.

    Usage::

        engine = RulesEngine()
        findings = engine.evaluate(
            key="auth_token",
            value="eyJhbGciOiJIUzI1NiJ9.xxxx.yyyy",
            storage_area=StorageArea.SHARED_PREFS,
            file_path="shared_prefs/app_prefs.xml",
        )
    """

    def __init__(self) -> None:
        """Load all built-in rules."""
        self.rules: List[SecurityRule] = []
        self._load_builtin_rules()
        logger.info(
            "RulesEngine loaded %d rules (%d enabled).",
            len(self.rules),
            sum(1 for r in self.rules if r.enabled),
        )

    def _load_builtin_rules(self) -> None:
        """Import all rule modules from backend.engine.rules package."""
        from backend.engine.rules import get_all_rules
        self.rules = get_all_rules()

    def evaluate(
        self,
        key: str,
        value: str,
        storage_area: StorageArea,
        file_path: str,
        extra: Optional[dict] = None,
    ) -> List[Finding]:
        """
        Test a key-value pair against all applicable rules.

        Args:
            key:          The key name, column name, or file context.
            value:        The string value to inspect.
            storage_area: Which storage area the data comes from.
            file_path:    Relative path within the dump folder.
            extra:        Additional context (table name, line number, etc.).

        Returns:
            List of Finding objects for every triggered rule.
        """
        findings: List[Finding] = []

        for rule in self.rules:
            if not rule.enabled:
                continue

            # Skip rules that don't apply to this storage area
            if storage_area not in rule.applies_to:
                continue

            # Skip if value is too short
            if len(value) < rule.min_value_length:
                continue

            triggered = self._check_rule(rule, key, value)

            if not triggered:
                continue

            # Entropy gate: if the rule requires high entropy, verify it
            if rule.check_entropy:
                ent = shannon_entropy(value)
                if ent < _ENTROPY_THRESHOLD:
                    continue

            finding = Finding(
                rule_id=rule.id,
                rule_name=rule.name,
                severity=rule.severity,
                category=rule.category,
                storage_area=storage_area,
                file_path=file_path,
                key_or_field=key,
                value_preview=mask_value(value),
                description=rule.description,
                recommendation=rule.recommendation,
                extra=extra,
            )
            findings.append(finding)

        return findings

    def _check_rule(
        self,
        rule: SecurityRule,
        key: str,
        value: str,
    ) -> bool:
        """
        Test whether a rule matches the given key and/or value.

        Returns True if the rule is triggered.
        """
        key_match = any(p.search(key) for p in rule._compiled_key) if rule._compiled_key else False
        value_match = any(p.search(value) for p in rule._compiled_value) if rule._compiled_value else False

        if rule.match_target == "key":
            return key_match
        elif rule.match_target == "value":
            return value_match
        elif rule.match_target == "both":
            # Both key AND value must match
            return key_match and value_match
        elif rule.match_target == "key_or_value":
            return key_match or value_match
        else:
            logger.warning("Unknown match_target '%s' in rule %s", rule.match_target, rule.id)
            return False

    def get_rules_for_area(self, area: StorageArea) -> List[SecurityRule]:
        """Return all enabled rules that apply to a given storage area."""
        return [
            r for r in self.rules
            if r.enabled and area in r.applies_to
        ]

    @property
    def rule_count(self) -> int:
        """Total number of loaded rules."""
        return len(self.rules)

    @property
    def enabled_rule_count(self) -> int:
        """Number of enabled rules."""
        return sum(1 for r in self.rules if r.enabled)
