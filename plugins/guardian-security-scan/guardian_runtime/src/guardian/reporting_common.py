"""Shared reporting formatters, grouping helpers, and operator text primitives."""

from __future__ import annotations

import json
from pathlib import Path
import re
import subprocess

from .db import Database
from .intel import severity_rank
from .triage_signals import advisory_link_sort_key


"""Shared report helpers for corroboration, grouping, and operator wording."""

_ADVISORY_ID_RE = re.compile(
    r"\b(?:GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}|CVE-\d{4}-\d{4,})\b",
    re.IGNORECASE,
)


def _normalize_advisory_id(value: str | None) -> str | None:
    """Extract and normalize a CVE/GHSA identifier from free text or a URL."""

    if not value:
        return None
    match = _ADVISORY_ID_RE.search(value)
    if not match:
        return None
    raw = match.group(0)
    if raw.upper().startswith("CVE-"):
        return raw.upper()
    if raw.upper().startswith("GHSA-"):
        return f"GHSA-{raw[5:].lower()}"
    return raw


def _advisory_source_from_url(url: str | None) -> str | None:
    """Return a human-facing source label for a known advisory URL."""

    if not url:
        return None
    lower = url.lower()
    if "github.com" in lower:
        return "GitHub Advisory"
    if "api.first.org" in lower or "first.org" in lower:
        return "FIRST EPSS"
    if "nvd.nist.gov" in lower:
        return "NVD"
    if "osv.dev" in lower:
        return "OSV"
    if "gitlab.com" in lower:
        return "GitLab Advisory"
    return None


def _advisory_source_from_id(advisory_id: str | None) -> str | None:
    """Infer the source family from a normalized advisory identifier."""

    if not advisory_id:
        return None
    if advisory_id.startswith("GHSA-"):
        return "GitHub Advisory"
    if advisory_id.startswith("CVE-"):
        return "CVE"
    return None


def _unique_strings(values: list | tuple | set | None) -> list[str]:
    """Keep non-empty strings in first-seen order."""

    seen: set[str] = set()
    ordered: list[str] = []
    for value in values or []:
        if not isinstance(value, str) or not value:
            continue
        if value in seen:
            continue
        seen.add(value)
        ordered.append(value)
    return ordered


def advisory_details(package: dict, *, limit: int = 4) -> list[dict]:
    """Normalize advisory IDs, URLs, and available database details into one shape.

    Live GHSA enrichment is optional, so a package may only carry advisory links.
    This helper still returns structured rows so agents do not incorrectly treat
    populated links plus empty rich details as "missing advisory evidence."
    """

    details_by_key: dict[str, dict] = {}
    ordered_keys: list[str] = []

    def remember(key: str, row: dict) -> None:
        if key not in details_by_key:
            details_by_key[key] = row
            ordered_keys.append(key)
            return
        existing = details_by_key[key]
        for field, value in row.items():
            if value and not existing.get(field):
                existing[field] = value

    assessment = package.get("current_assessment") or {}
    for finding in assessment.get("findings") or []:
        if not isinstance(finding, dict):
            continue
        advisory_id = _normalize_advisory_id(str(finding.get("id") or ""))
        if not advisory_id:
            continue
        remember(
            advisory_id,
            {
                "id": advisory_id,
                "url": None,
                "source": finding.get("source") or _advisory_source_from_id(advisory_id),
                "severity": finding.get("severity") or package.get("highest_severity"),
                "summary": finding.get("summary"),
                "fixed_versions": finding.get("fixed_versions") or [],
            },
        )

    links = _unique_strings(package.get("advisory_links"))
    links_by_id: dict[str, str] = {}
    for link in links:
        advisory_id = _normalize_advisory_id(link)
        if advisory_id and advisory_id not in links_by_id:
            links_by_id[advisory_id] = link

    for source in _unique_strings(package.get("advisory_sources")):
        advisory_id = _normalize_advisory_id(source)
        key = advisory_id or source
        remember(
            key,
            {
                "id": advisory_id or source,
                "url": links_by_id.get(advisory_id or ""),
                "source": _advisory_source_from_id(advisory_id),
                "severity": package.get("highest_severity"),
                "summary": None,
                "fixed_versions": [],
            },
        )

    for link in links:
        advisory_id = _normalize_advisory_id(link)
        key = advisory_id or link
        remember(
            key,
            {
                "id": advisory_id,
                "url": link,
                "source": _advisory_source_from_url(link) or _advisory_source_from_id(advisory_id),
                "severity": package.get("highest_severity"),
                "summary": None,
                "fixed_versions": [],
            },
        )

    return [details_by_key[key] for key in ordered_keys[:limit]]


def package_evidence_context(package: dict) -> dict:
    """Describe how strongly the repo evidence ties a finding to this project."""

    occurrences = [item for item in package.get("occurrences") or [] if isinstance(item, dict)]
    source_types = sorted({item.get("source_type") for item in occurrences if item.get("source_type")})
    evidence_kinds = {item.get("evidence_kind") for item in occurrences if item.get("evidence_kind")}
    has_manifest = "manifest" in evidence_kinds or any("manifest" in item for item in source_types)
    has_lockfile = "lockfile" in evidence_kinds or any("lockfile" in item for item in source_types)
    has_installed = "installed" in evidence_kinds or any(
        item in {"npm-node_modules", "python-installed-metadata"} for item in source_types
    )
    direct_dependency = bool(package.get("direct_dependency"))
    environment = package.get("environment_label")
    manifest_paths = _unique_strings(package.get("manifest_paths"))

    if environment == "runtime" and direct_dependency and has_lockfile and not has_installed:
        label = "Manifest + lockfile; installed tree not present"
        summary = (
            "Direct runtime dependency is corroborated by manifest/lockfile evidence, "
            "but no installed node_modules/site-packages metadata was scanned."
        )
    elif environment == "runtime" and direct_dependency:
        label = "Runtime-linked direct dependency"
        summary = "Direct runtime dependency evidence is present for this package."
    elif environment == "runtime":
        label = "Runtime-linked"
        summary = "Runtime usage or dependency-path evidence ties this package to the project."
    elif environment == "vendored-lockfile":
        label = "Vendored metadata only"
        summary = "Finding came from nested vendored metadata and needs corroboration before direct app remediation."
    elif environment == "lockfile-only":
        label = "Lockfile-only"
        summary = "Finding is present in lockfile evidence but is not currently corroborated by installed-tree metadata or code usage."
    elif environment == "module-graph":
        label = "Go module graph"
        summary = "The module appears in go.sum but is not a direct go.mod requirement; review the parent module path before remediation."
    elif environment == "isolated-env":
        label = "Isolated environment"
        summary = "Finding is scoped to an isolated virtual environment or tooling environment."
    else:
        label = environment or "Unknown evidence context"
        summary = "Guardian found package evidence, but no stronger runtime context label is available."

    return {
        "label": label,
        "summary": summary,
        "source_types": source_types,
        "direct_dependency": direct_dependency,
        "manifest_scope": package.get("manifest_scope"),
        "manifest_paths": manifest_paths[:4],
        "installed_tree_present": has_installed,
        "lockfile_present": has_lockfile,
        "manifest_present": has_manifest,
    }


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
