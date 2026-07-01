"""Compact scan payload shaping for skill runners and automation output."""

from __future__ import annotations

from .config import GuardianConfig
from .db import Database
from .evidence import evidence_summary
from .reporting_common import advisory_details, package_evidence_context
from .util import utc_now


def build_compact_operator_view(
    config: GuardianConfig,
    db: Database,
    *,
    root_filter: str,
    triage: dict,
    comparison: dict,
) -> dict:
    del config
    repo_evidence_summary = evidence_summary([dict(row) for row in db.current_packages_for_root(root_filter)])
    packages = triage.get("package_actions", [])
    top_packages = []
    for package in packages[:5]:
        top_packages.append(
            {
                "package_name": package.get("package_name"),
                "version": package.get("version"),
                "risk_label": package.get("risk_label"),
                "confidence": (package.get("confidence") or {}).get("label"),
                "environment_label": package.get("environment_label"),
                "role_label": package.get("role_label"),
                "highest_severity": package.get("highest_severity"),
                "advisory_links": package.get("advisory_links", [])[:2],
                "advisory_details": advisory_details(package, limit=2),
                "evidence_context": package_evidence_context(package),
            }
        )
    return {
        "root_path": root_filter,
        "generated_at": utc_now(),
        "priority_headline": triage.get("headline"),
        "full_headline": triage.get("headline"),
        "compare_headline": comparison.get("headline") or comparison.get("message"),
        "compare": {
            "new_open_count": len(comparison.get("new_open", [])),
            "resolved_count": len(comparison.get("resolved", [])),
            "evidence_changed_count": len(comparison.get("evidence_changed", [])),
            "classification_changed_count": len(comparison.get("classification_changed", [])),
            "changed_count": len(comparison.get("changed", [])),
            "unchanged_count": comparison.get("unchanged_count"),
        },
        "evidence_summary": {
            "total_unique_packages": repo_evidence_summary.get("total_unique_packages"),
            "total_evidence_rows": repo_evidence_summary.get("total_evidence_rows"),
            "package_counts": repo_evidence_summary.get("package_counts"),
        },
        "top_packages": top_packages,
        "bottom_line": _compact_bottom_line(packages),
    }


def compact_project_scan_payload(payload: dict) -> dict:
    operator = payload.get("operator_view") or {}
    threat_intel = payload.get("threat_intel") or {}
    return {
        "status": payload.get("status"),
        "compact": payload.get("compact"),
        "root_path": payload.get("root_path"),
        "elapsed_seconds": payload.get("elapsed_seconds"),
        "priority_headline": operator.get("priority_headline"),
        "compare_headline": operator.get("compare_headline") or (payload.get("comparison") or {}).get("headline") or (payload.get("comparison") or {}).get("message"),
        "compare": operator.get("compare"),
        "package_evidence": operator.get("evidence_summary"),
        "top_packages": (operator.get("top_packages") or [])[:5],
        "bottom_line": operator.get("bottom_line", [])[:3],
        "source_status": payload.get("source_status"),
        "threat_intel_entries": threat_intel.get("entries_written"),
        "operator_report_path": payload.get("operator_report_path"),
        "project_report_path": payload.get("report_path"),
        "handoff_path": payload.get("handoff_path"),
        "phases": payload.get("phases"),
    }


def _compact_bottom_line(packages: list[dict]) -> list[str]:
    if not packages:
        return ["No package remediation is currently recommended."]
    runtime = [item for item in packages if item.get("environment_label") == "runtime"]
    vendored = [item for item in packages if item.get("environment_label") == "vendored-lockfile"]
    lines = []
    if runtime:
        top = runtime[0]
        lines.append(f"Prioritize runtime-linked package `{top['package_name']}@{top['version']}` first.")
    if vendored:
        lines.append("Vendored metadata findings are lower-action unless corroborated by root lockfiles, installed runtime packages, or code usage.")
    return lines[:3]
