"""Shared grading vocabulary for advisory and behavioral security signals."""

from __future__ import annotations

from enum import Enum


class SignalGrade(str, Enum):
    """Express evidence strength independently from advisory severity."""

    CORROBORATED_MALICIOUS = "corroborated-malicious"
    CATALOG_MATCH = "catalog-match"
    BEHAVIORAL_HIGH = "behavioral-high"
    BEHAVIORAL_WATCH = "behavioral-watch"
    ADVISORY = "advisory"
    INFO = "info"


SIGNAL_GRADE_ORDER = {
    SignalGrade.CORROBORATED_MALICIOUS: 0,
    SignalGrade.CATALOG_MATCH: 1,
    SignalGrade.BEHAVIORAL_HIGH: 2,
    SignalGrade.BEHAVIORAL_WATCH: 3,
    SignalGrade.ADVISORY: 4,
    SignalGrade.INFO: 5,
}


def grade_to_posture(grade: SignalGrade | str) -> str | None:
    """Map evidence strength to Guardian's default operator posture."""

    normalized = SignalGrade(grade)
    if normalized in {SignalGrade.CORROBORATED_MALICIOUS, SignalGrade.CATALOG_MATCH}:
        return "act_now"
    if normalized is SignalGrade.BEHAVIORAL_HIGH:
        return "fix_this_week"
    if normalized is SignalGrade.BEHAVIORAL_WATCH:
        return "watch"
    return None


def signal_operator_posture(signal: dict) -> str | None:
    """Return the operator bucket for a signal, including non-actionable info."""

    posture = signal.get("posture")
    if posture:
        return str(posture)
    if signal.get("signal_grade") == SignalGrade.INFO.value:
        return "info"
    return None


def signal_display_posture(signal: dict) -> str:
    """Format a signal posture for human output without assuming it is actionable."""

    label = signal_operator_posture(signal) or signal.get("signal_grade") or "signal"
    return str(label).replace("_", " ").replace("-", " ")
