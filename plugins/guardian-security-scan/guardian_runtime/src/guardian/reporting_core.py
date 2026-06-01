from __future__ import annotations

from collections import defaultdict

from .config import GuardianConfig
from .db import Database
from .evidence import evidence_summary
from .reporting_issues import grouped_issues
from .triage import (
    daily_brief,
    enriched_issues,
    hygiene_report as build_hygiene_report,
    package_remediation_queue,
)


"""Core report assembly shared by CLI JSON, handoff, and operator outputs."""


FAST_ROOT_TRIAGE_PACKAGE_LIMIT = 12


def summary(db: Database) -> dict:
    packages = db.current_packages()
    by_ecosystem: dict[str, int] = {}
    for row in packages:
        by_ecosystem[row["ecosystem"]] = by_ecosystem.get(row["ecosystem"], 0) + 1
    finding_counts = {row["severity"] or "unknown": row["count"] for row in db.finding_summary()}
    return {
        "current_packages": len(packages),
        "packages_by_ecosystem": by_ecosystem,
        "open_findings_by_severity": finding_counts,
        "inventory_roots": db.list_inventory_roots(),
        "evidence_summary": evidence_summary([dict(row) for row in packages]),
    }


def triage_report(
    config: GuardianConfig,
    db: Database,
    root_filter: str | None = None,
    *,
    package_limit: int | None = FAST_ROOT_TRIAGE_PACKAGE_LIMIT,
) -> dict:
    issues = grouped_issues(db)
    resolve_clean_targets = True
    if root_filter:
        resolve_clean_targets = False
        if package_limit is not None:
            package_rows = db.root_open_package_summary(root_filter, limit=package_limit)
            package_keys = {
                (row["ecosystem"], row["package_name"], row["version"])
                for row in package_rows
            }
            issues = [
                issue
                for issue in issues
                if any((pkg["ecosystem"], pkg["package_name"], pkg["version"]) in package_keys for pkg in issue["packages"])
            ]
    issues = enriched_issues(
        config,
        db,
        issues,
        root_filter=root_filter,
        resolve_clean_targets=resolve_clean_targets,
    )
    brief = daily_brief(issues)
    packages = package_remediation_queue(issues)
    by_package_risk_label: dict[str, int] = defaultdict(int)
    for package in packages:
        by_package_risk_label[package["risk_label"]] += 1
    if packages:
        headline = (
            f"{by_package_risk_label.get('Act Now', 0)} packages act now, "
            f"{by_package_risk_label.get('Fix This Week', 0)} fix this week, "
            f"{by_package_risk_label.get('Watch', 0)} watch"
        )
    else:
        headline = brief["headline"]
    return {
        "headline": headline,
        "by_risk_label": dict(by_package_risk_label),
        "issue_by_risk_label": brief["by_risk_label"],
        "top_actions": brief["top_actions"],
        "package_actions": packages,
        "issues": issues,
    }


def hygiene_report(config: GuardianConfig, db: Database, root_filter: str | None = None) -> dict:
    return build_hygiene_report(config, db, root_filter=root_filter)


def create_triage_snapshot(
    config: GuardianConfig,
    db: Database,
    *,
    root_filter: str,
    triage: dict | None = None,
    inventory_run_ids: list[int] | None = None,
    report_path: str | None = None,
) -> dict:
    payload = triage or triage_report(config, db, root_filter=root_filter, package_limit=None)
    snapshot_id = db.create_triage_snapshot(
        root_path=root_filter,
        headline=payload["headline"],
        summary={
            "headline": payload["headline"],
            "by_risk_label": payload.get("by_risk_label", {}),
            "issue_by_risk_label": payload.get("issue_by_risk_label", {}),
            "top_actions": payload.get("top_actions", []),
        },
        package_actions=payload.get("package_actions", []),
        inventory_run_ids=inventory_run_ids,
        report_path=report_path,
    )
    return {
        "snapshot_id": snapshot_id,
        "root_path": root_filter,
        "headline": payload["headline"],
        "package_count": len(payload.get("package_actions", [])),
        "inventory_run_ids": inventory_run_ids or [],
        "report_path": report_path,
    }
