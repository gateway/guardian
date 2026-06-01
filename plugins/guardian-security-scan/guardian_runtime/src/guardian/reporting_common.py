from __future__ import annotations

import json
from pathlib import Path
import subprocess

from .db import Database
from .intel import severity_rank
from .triage_signals import advisory_link_sort_key


"""Shared report helpers for corroboration, grouping, and operator wording."""


def operator_recommendations(packages: list[dict]) -> list[str]:
    if not packages:
        return ["No package remediation is currently recommended."]
    runtime = [item for item in packages if item.get("environment_label") == "runtime"]
    vendored = [item for item in packages if item.get("environment_label") == "vendored-lockfile"]
    isolated = [item for item in packages if item.get("environment_label") == "isolated-env"]
    recommendations: list[str] = []
    if runtime:
        top = runtime[0]
        recommendations.append(
            f"Prioritize runtime-linked package `{top['package_name']}@{top['version']}` first because it is tied to a real app dependency path."
        )
    if vendored and len(vendored) >= max(3, len(packages) // 2):
        recommendations.append(
            "Most current findings are vendored metadata only. Do not churn app dependencies unless the same versions appear in package-lock.json, installed runtime packages, or code usage."
        )
        recommendations.append(
            "For vendored nested lockfiles, prefer parent dependency review or policy downgrades instead of direct package remediation."
        )
    if isolated:
        recommendations.append(
            "Handle isolated-environment findings in their specific virtualenv or tooling environment, separate from main app runtime remediation."
        )
    if not runtime and vendored:
        recommendations.append(
            "Use stronger release signals such as production lockfile review, installed dependency scans, and runtime usage evidence before treating these as deployment blockers."
        )
    return recommendations[:4]


def npm_audit_summary(root_filter: str, *, omit_dev: bool) -> dict | None:
    root = Path(root_filter)
    if not (root / "package.json").exists():
        return None
    command = ["npm", "audit", "--json"]
    if omit_dev:
        command.insert(2, "--omit=dev")
    try:
        completed = subprocess.run(
            command,
            cwd=str(root),
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    stdout = (completed.stdout or "").strip()
    if not stdout:
        return {
            "available": False,
            "status": "unavailable",
            "error": (completed.stderr or "npm audit returned no JSON output").strip(),
        }
    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError:
        return {
            "available": False,
            "status": "unavailable",
            "error": "npm audit returned non-JSON output",
        }
    metadata = payload.get("metadata") or {}
    vulnerabilities = metadata.get("vulnerabilities") or {}
    total = int(vulnerabilities.get("total") or 0)
    return {
        "available": True,
        "status": "clean" if total == 0 else "vulnerabilities-found",
        "total": total,
        "counts": vulnerabilities,
    }


def matching_repo_evidence(
    db: Database,
    *,
    root_filter: str,
    packages: list[dict],
) -> dict:
    repo_rows = [dict(row) for row in db.current_packages_for_root(root_filter)]
    keys = {
        (package["ecosystem"], package["normalized_name"], package["version"])
        for package in packages
    }
    matching_rows = [
        row for row in repo_rows
        if (row["ecosystem"], row["normalized_name"], row["version"]) in keys
    ]
    package_lock_rows = [
        row for row in matching_rows
        if row.get("source_type") == "npm-lockfile"
        and not (row.get("source_file") or "").lower().endswith("/node_modules/uri-js/yarn.lock")
        and "/node_modules/" not in (row.get("source_file") or "").lower()
    ]
    installed_rows = [
        row for row in matching_rows
        if row.get("source_type") == "npm-node_modules"
    ]
    runtime_usage_hits = sum(
        int((package.get("usage_by_kind") or {}).get("runtime") or 0)
        for package in packages
    )
    return {
        "package_lock_matches": package_lock_rows,
        "installed_matches": installed_rows,
        "runtime_usage_hits": runtime_usage_hits,
    }


def audit_line(label: str, audit: dict | None) -> str:
    if not audit:
        return f"- {label}: not run"
    if not audit.get("available"):
        return f"- {label}: unavailable"
    total = int(audit.get("total") or 0)
    return f"- {label}: `{total}` vulnerabilities"


def audit_payload(audit: dict | None) -> dict | None:
    if not audit:
        return None
    return {
        "status": audit.get("status"),
        "total": int(audit.get("total") or 0),
        "available": bool(audit.get("available")),
    }


def low_action_installed_only(package: dict) -> bool:
    return (
        package.get("environment_label") in {"transitive-installed", "lockfile-only"}
        and package.get("usage_hit_count", 0) == 0
        and not package.get("direct_dependency")
    )


def group_vendored_packages(packages: list[dict]) -> list[dict]:
    grouped: dict[str, dict] = {}
    for package in packages:
        if package.get("environment_label") != "vendored-lockfile":
            continue
        source_detail = None
        root_cause = package.get("root_cause") or {}
        details = root_cause.get("details")
        if isinstance(details, str):
            source_detail = details
        key = source_detail or root_cause.get("summary") or "vendored-lockfile"
        group = grouped.setdefault(
            key,
            {
                "source_detail": source_detail,
                "summary": root_cause.get("summary") or "Vendored metadata-only findings",
                "packages": [],
                "confidence_labels": set(),
                "advisory_links": set(),
                "advisory_sources": set(),
                "risk_labels": set(),
                "severities": set(),
            },
        )
        group["packages"].append(package)
        confidence = package.get("confidence") or {}
        if confidence.get("label"):
            group["confidence_labels"].add(confidence["label"])
        group["advisory_links"].update(package.get("advisory_links", []))
        group["advisory_sources"].update(package.get("advisory_sources", []))
        group["risk_labels"].add(package.get("risk_label"))
        group["severities"].add(package.get("highest_severity"))
    results = []
    for group in grouped.values():
        group["packages"].sort(key=lambda item: (item["package_name"].lower(), item["version"]))
        group["confidence_labels"] = sorted(group["confidence_labels"])
        group["advisory_links"] = sorted(group["advisory_links"], key=advisory_link_sort_key)
        group["advisory_sources"] = sorted(group["advisory_sources"])
        group["risk_labels"] = sorted(group["risk_labels"])
        group["severities"] = sorted(group["severities"], key=lambda value: -severity_rank(value))
        results.append(group)
    results.sort(key=lambda item: (-len(item["packages"]), item["source_detail"] or item["summary"]))
    return results

