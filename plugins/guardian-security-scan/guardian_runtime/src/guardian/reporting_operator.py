"""Compact operator JSON report generation for low-token agent consumption."""

from __future__ import annotations

from pathlib import Path

from .config import GuardianConfig
from .db import Database
from .evidence import evidence_summary
from .reporting_common import (
    advisory_details,
    audit_payload,
    group_vendored_packages,
    low_action_installed_only,
    matching_repo_evidence,
    npm_audit_summary,
    operator_recommendations,
    package_evidence_context,
)
from .reporting_core import triage_report
from .reporting_snapshots import compare_triage_snapshots
from .util import slugify, utc_now, write_json


"""Compact repo-local JSON view intended for dashboards and automations."""


def build_operator_view(
    config: GuardianConfig,
    db: Database,
    *,
    root_filter: str,
) -> dict:
    full_triage = triage_report(config, db, root_filter=root_filter, package_limit=None)
    triage = triage_report(config, db, root_filter=root_filter)
    comparison = compare_triage_snapshots(db, root_filter=root_filter)
    vendored_groups = group_vendored_packages(triage["package_actions"])
    runtime_count = sum(1 for package in triage["package_actions"] if package.get("environment_label") == "runtime")
    vendored_count = sum(1 for package in triage["package_actions"] if package.get("environment_label") == "vendored-lockfile")
    isolated_count = sum(1 for package in triage["package_actions"] if package.get("environment_label") == "isolated-env")
    npm_audit_prod = npm_audit_summary(root_filter, omit_dev=True)
    npm_audit_full = npm_audit_summary(root_filter, omit_dev=False)
    repo_evidence_summary = evidence_summary([dict(row) for row in db.current_packages_for_root(root_filter)])
    grouped_vendored = []
    for group in vendored_groups:
        evidence = matching_repo_evidence(db, root_filter=root_filter, packages=group["packages"])
        grouped_vendored.append(
            {
                "source": group["source_detail"] or group["summary"],
                "confidence": group["confidence_labels"],
                "action_posture": "Low action unless corroborated by repo lockfiles, installed runtime packages, or code usage.",
                "finding_count": len(group["packages"]),
                "package_examples": [f"{package['package_name']}@{package['version']}" for package in group["packages"][:8]],
                "underlying_advisory_severity": group["severities"][0] if group.get("severities") else None,
                "advisory_ids": group["advisory_sources"][:6],
                "advisory_links": group["advisory_links"][:6],
                "evidence": {
                    "package_lock_match_count": len(evidence["package_lock_matches"]),
                    "installed_match_count": len(evidence["installed_matches"]),
                    "runtime_usage_hits": evidence["runtime_usage_hits"],
                    "npm_audit_omit_dev_total": int((npm_audit_prod or {}).get("total") or 0),
                    "npm_audit_full_total": int((npm_audit_full or {}).get("total") or 0),
                },
                "recommended_action": "Review the parent dependency chain or policy handling first; do not change app dependencies directly from this group alone.",
            }
        )
    top_packages = []
    for package in triage["package_actions"][:8]:
        top_packages.append(
            {
                "package_name": package["package_name"],
                "version": package["version"],
                "risk_label": package["risk_label"],
                "confidence": (package.get("confidence") or {}).get("label"),
                "environment_label": package.get("environment_label"),
                "role_label": package.get("role_label"),
                "highest_severity": package.get("highest_severity"),
                "reason": (package.get("issue_summaries") or [None])[0],
                "advisory_ids": package.get("advisory_sources", [])[:4],
                "advisory_links": package.get("advisory_links", [])[:4],
                "advisory_details": advisory_details(package, limit=4),
                "evidence_context": package_evidence_context(package),
                "recommended_action": (
                    "Review parent chain / no direct app action."
                    if package.get("environment_label") == "vendored-lockfile" and package.get("usage_hit_count", 0) == 0
                    else "Review parent chain / no scheduled direct app action without root-lockfile, direct dependency, or code-usage corroboration."
                    if low_action_installed_only(package)
                    else (package.get("notes") or [None])[0]
                ),
            }
        )
    compare_counts = {
        "new_open_count": len(comparison.get("new_open", [])),
        "resolved_count": len(comparison.get("resolved", [])),
        "evidence_changed_count": len(comparison.get("evidence_changed", [])),
        "classification_changed_count": len(comparison.get("classification_changed", [])),
        "changed_count": len(comparison.get("changed", [])),
        "unchanged_count": comparison.get("unchanged_count"),
    }
    return {
        "root_path": root_filter,
        "generated_at": utc_now(),
        "full_headline": full_triage["headline"],
        "priority_headline": triage["headline"],
        "compare_headline": comparison.get("headline") or comparison.get("message"),
        "compare": compare_counts,
        "perspective": {
            "runtime_linked_count": runtime_count,
            "vendored_metadata_count": vendored_count,
            "isolated_environment_count": isolated_count,
        },
        "evidence_summary": repo_evidence_summary,
        "corroboration": {
            "npm_audit_omit_dev": audit_payload(npm_audit_prod),
            "npm_audit_full": audit_payload(npm_audit_full),
        },
        "top_packages": top_packages,
        "vendored_groups": grouped_vendored,
        "bottom_line": operator_recommendations(triage["package_actions"]),
    }


def write_operator_report(
    config: GuardianConfig,
    db: Database,
    *,
    root_filter: str,
    payload: dict | None = None,
) -> Path:
    payload = payload or build_operator_view(config, db, root_filter=root_filter)
    root_slug = slugify(Path(root_filter).name)
    path = Path(config.reports_dir) / f"operator-{root_slug}-{utc_now().replace(':', '-')}.json"
    write_json(path, payload)
    return path
