"""Public reporting facade that re-exports focused reporting modules."""

from __future__ import annotations

# Public reporting facade. Keep imports here stable for CLI and skills while
# implementation code lives in focused report-surface modules.
from .reporting_core import (
    FAST_ROOT_TRIAGE_PACKAGE_LIMIT,
    create_triage_snapshot,
    hygiene_report,
    summary,
    triage_report,
)
from .reporting_handoff import build_handoff_markdown, write_handoff_report
from .reporting_issues import grouped_issues, open_findings
from .reporting_operator import build_operator_view, write_operator_report
from .reporting_snapshots import compare_triage_snapshots

__all__ = [
    "FAST_ROOT_TRIAGE_PACKAGE_LIMIT",
    "build_handoff_markdown",
    "build_operator_view",
    "compare_triage_snapshots",
    "create_triage_snapshot",
    "grouped_issues",
    "hygiene_report",
    "open_findings",
    "summary",
    "triage_report",
    "write_handoff_report",
    "write_operator_report",
]
