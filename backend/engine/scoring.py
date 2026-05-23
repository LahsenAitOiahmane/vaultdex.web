"""
SecureStorageInspector — Risk Scoring Engine

Deterministic scoring algorithm that converts finding counts into a
0–100 risk score and a human-readable risk level label.

The formula is:
    score = min(100, Σ (severity_weight × count))

Weights:
    CRITICAL = 25 pts each  (4 criticals = max score)
    HIGH     = 10 pts each
    MEDIUM   =  3 pts each
    LOW      =  1 pt  each
    INFO     =  0 pts

This is intentionally simple and auditable. A security team can predict
the score from the rule set alone — no ML, no randomness.
"""

from __future__ import annotations

from backend.engine.models import RiskLevel, SecurityReport, SeverityCounts


# ── Severity weights ─────────────────────────────────────────────────
_WEIGHTS = {
    "critical": 25,
    "high": 10,
    "medium": 3,
    "low": 1,
    "info": 0,
}


def calculate_risk_score(counts: SeverityCounts) -> int:
    """
    Calculate the numeric risk score from severity counts.

    Args:
        counts: Finding counts by severity level.

    Returns:
        Integer score between 0 and 100 (inclusive).
    """
    raw = (
        counts.critical * _WEIGHTS["critical"]
        + counts.high * _WEIGHTS["high"]
        + counts.medium * _WEIGHTS["medium"]
        + counts.low * _WEIGHTS["low"]
        + counts.info * _WEIGHTS["info"]
    )
    return min(100, max(0, raw))


def determine_risk_level(score: int) -> RiskLevel:
    """
    Map a numeric score to a human-readable risk level.

    Args:
        score: Risk score (0–100).

    Returns:
        RiskLevel enum value.
    """
    if score == 0:
        return RiskLevel.PASS
    elif score <= 25:
        return RiskLevel.LOW_RISK
    elif score <= 50:
        return RiskLevel.MEDIUM_RISK
    elif score <= 75:
        return RiskLevel.HIGH_RISK
    else:
        return RiskLevel.CRITICAL_RISK


def score_report(report: SecurityReport) -> None:
    """
    Compute and set the risk score and level on a SecurityReport.

    This mutates the report in-place. Call it after all storage area
    reports have been added and ``report.aggregate()`` has been called.

    Args:
        report: The SecurityReport to score.
    """
    report.risk_score = calculate_risk_score(report.severity_counts)
    report.risk_level = determine_risk_level(report.risk_score)
