"""Project-context enrichment for dependency role, environment, usage, fixed-version, and upgrade-risk evidence."""

from __future__ import annotations

import json

from .db import Database
from .planner import CandidateResolver, fixed_versions_from_osv
from .project_model import BUILD_TOOL_PACKAGES, ProjectInspector
from .root_cause import npm_explain_summary
from .triage_rules import (
    _advice_for_role,
    _direct_dependency_flag,
    _environment_based_suggestions,
    _environment_label,
    _package_key,
    _package_role,
    _upgrade_risk,
    _usage_based_suggestions,
)
from .triage_signals import (
    HYGIENE_NAME_HINTS,
    aggregate_usage_kinds,
    path_usage_hints,
    usage_summary,
)


"""Build package-level evidence context from inventory, usage, and advisories."""


def _root_cause_summary(
    root_paths: list[str],
    ecosystem: str,
    package_name: str,
    occurrences: list[dict],
    environment_label: str,
    *,
    allow_npm_explain: bool = True,
) -> dict | None:
    if environment_label == "vendored-lockfile":
        first_path = next((item.get("source_file") for item in occurrences if item.get("source_file")), None)
        project_path = next((item.get("project_path") for item in occurrences if item.get("project_path")), None)
        return {
            "kind": "vendored-lockfile",
            "summary": "Detected from a vendored lockfile under node_modules, not from the main project manifest.",
            "details": first_path or project_path,
        }
    if environment_label == "isolated-env":
        first_path = next((item.get("source_file") for item in occurrences if item.get("source_file")), None)
        return {
            "kind": "isolated-env",
            "summary": "Detected in an isolated virtual environment, separate from the main app runtime.",
            "details": first_path,
        }
    if ecosystem != "npm" or len(root_paths) != 1 or not allow_npm_explain:
        return None
    explain = npm_explain_summary(root_paths[0], package_name)
    if not explain or not explain.get("roots"):
        return None
    roots = explain["roots"][:3]
    root_names = [item["root_name"] for item in roots if item.get("root_name")]
    return {
        "kind": "npm-explain",
        "summary": ", ".join(sorted(dict.fromkeys(root_names))) if root_names else "transitive dependency chain found",
        "details": roots,
    }


def _db_assessment_for_package(
    db: Database,
    ecosystem: str,
    package_name: str,
    normalized_name: str,
    version: str,
) -> dict:
    advisories = db.advisory_map()
    findings = []
    for row in db.open_findings_for_package(
        ecosystem=ecosystem,
        normalized_name=normalized_name,
        version=version,
    ):
        item = dict(row)
        advisory = advisories.get((item["advisory_source"], item["advisory_id"]))
        advisory_dict = dict(advisory) if advisory is not None else {}
        raw_json = advisory_dict.get("raw_json")
        try:
            raw = raw_json if isinstance(raw_json, dict) else json.loads(raw_json or "{}")
        except json.JSONDecodeError:
            raw = {}
        osv_payload = raw.get("osv") if isinstance(raw, dict) else None
        if not osv_payload and advisory_dict.get("source") == "osv":
            osv_payload = raw if isinstance(raw, dict) else {}
        fixed_versions = []
        if osv_payload:
            fixed_versions = fixed_versions_from_osv(osv_payload, ecosystem, package_name)
        findings.append(
            {
                "source": item["advisory_source"],
                "id": item["advisory_id"],
                "severity": item.get("severity") or advisory_dict.get("severity"),
                "summary": advisory_dict.get("summary"),
                "fixed_versions": fixed_versions,
            }
        )
    return {
        "ecosystem": ecosystem,
        "package_name": package_name,
        "version": version,
        "findings": findings,
    }


def _occurrence_scope_summary(occurrences: list[dict]) -> dict:
    """Summarize scope for the exact package version currently being triaged.

    Manifest and code-usage checks operate at package-name level, but findings
    are version-specific. A repo can legitimately use `uuid@11` at runtime while
    still carrying a dev-only nested `uuid@8`. This helper keeps the exact
    vulnerable version's lockfile/install scope from being overwritten by
    same-name runtime usage from a different resolved version.
    """

    scopes = {str(item.get("install_scope") or "").lower() for item in occurrences}
    scopes.discard("")
    return {
        "scopes": sorted(scopes),
        "dev_only": bool(scopes) and scopes.issubset({"dev", "development", "test"}),
    }


def _version_specific_manifest_scope(manifest_scope: str, direct_dependency: bool, scope_summary: dict) -> str:
    if scope_summary["dev_only"] and not direct_dependency:
        return "test"
    return manifest_scope


def _version_specific_usage_counts(usage_counts: dict[str, int], direct_dependency: bool, scope_summary: dict) -> dict[str, int]:
    if scope_summary["dev_only"] and not direct_dependency:
        return {"runtime": 0, "build": 0, "test": usage_counts.get("test", 0)}
    return usage_counts


def _package_context(
    db: Database,
    inspector: ProjectInspector,
    resolver: CandidateResolver,
    ecosystem: str,
    package_name: str,
    normalized_name: str,
    version: str,
    occurrence_cache: dict[tuple[str, str, str], list[dict]],
    package_context_cache: dict[tuple[str, str, str], dict],
    *,
    resolve_clean_targets: bool,
) -> dict:
    key = _package_key(ecosystem, normalized_name, version)
    cached = package_context_cache.get(key)
    if cached is not None:
        return cached
    occurrences = occurrence_cache.get(key)
    if occurrences is None:
        occurrences = [
            dict(row)
            for row in db.current_package_occurrences(
                ecosystem=ecosystem,
                normalized_name=normalized_name,
                version=version,
            )
        ]
        occurrence_cache[key] = occurrences
    occurrence_paths = [
        item.get("source_file") or item.get("project_path") or item.get("root_path")
        for item in occurrences
    ]
    direct_dependency = _direct_dependency_flag(occurrences)
    usage = usage_summary(occurrences)
    usage_counts = aggregate_usage_kinds(usage)
    usage_hit_count = sum(item["hit_count"] for item in usage)
    root_paths = sorted({item["root_path"] for item in occurrences})
    manifest_scopes = []
    manifest_paths = []
    for root_path in root_paths:
        manifest = inspector.manifest_scope(
            root_path,
            ecosystem=ecosystem,
            normalized_name=normalized_name,
            occurrence_paths=occurrence_paths,
        )
        manifest_scopes.append(manifest["scope"])
        manifest_paths.extend(manifest["manifest_paths"])
    manifest_scope = "undeclared"
    for scope in ("runtime", "build", "test"):
        if scope in manifest_scopes:
            manifest_scope = scope
            break
    scope_summary = _occurrence_scope_summary(occurrences)
    manifest_scope = _version_specific_manifest_scope(manifest_scope, direct_dependency, scope_summary)
    usage_counts = _version_specific_usage_counts(usage_counts, direct_dependency, scope_summary)
    role = _package_role(package_name, manifest_scope, usage_counts, direct_dependency)
    environment_label = _environment_label(occurrences, role, usage_counts)
    root_cause = _root_cause_summary(root_paths, ecosystem, package_name, occurrences, environment_label)
    if resolve_clean_targets:
        current_assessment = resolver.assess_version(ecosystem, package_name, version)
    else:
        current_assessment = _db_assessment_for_package(db, ecosystem, package_name, normalized_name, version)
    fixed_candidates = sorted(
        {
            fixed
            for finding in current_assessment["findings"]
            for fixed in (finding.get("fixed_versions") or [])
        }
    )
    first_fixed_version = fixed_candidates[0] if fixed_candidates else None
    clean_target = {
        "recommended_clean_version": None,
        "latest_version": None,
    }
    if resolve_clean_targets:
        clean_target = resolver.recommended_clean_version(
            ecosystem,
            package_name,
            version,
            minimum_version=first_fixed_version,
        )
    recommended_clean_version = clean_target["recommended_clean_version"]
    upgrade_risk = _upgrade_risk(
        package_name,
        version,
        recommended_clean_version or first_fixed_version,
        role,
        usage_counts,
    )
    suggestions = _advice_for_role(package_name, role, manifest_scope)
    suggestions.extend(_usage_based_suggestions(package_name, role, usage))
    suggestions.extend(_environment_based_suggestions(environment_label, direct_dependency, usage_counts))
    payload = {
        "ecosystem": ecosystem,
        "package_name": package_name,
        "normalized_name": normalized_name,
        "version": version,
        "occurrences": occurrences,
        "root_paths": root_paths,
        "direct_dependency": direct_dependency,
        "manifest_scope": manifest_scope,
        "version_install_scopes": scope_summary["scopes"],
        "manifest_paths": sorted(set(manifest_paths)),
        "role": role["role"],
        "role_label": role["label"],
        "environment_label": environment_label,
        "root_cause": root_cause,
        "necessity": role["necessity"],
        "first_fixed_version": first_fixed_version,
        "recommended_clean_version": recommended_clean_version,
        "latest_version": clean_target["latest_version"],
        "upgrade_risk": upgrade_risk,
        "usage": usage,
        "usage_hit_count": usage_hit_count,
        "usage_by_kind": usage_counts,
        "current_assessment": current_assessment,
        "suggestions": suggestions,
    }
    package_context_cache[key] = payload
    return payload


def _basic_package_context(
    db: Database,
    inspector: ProjectInspector,
    ecosystem: str,
    package_name: str,
    normalized_name: str,
    version: str,
    occurrence_cache: dict[tuple[str, str, str], list[dict]],
    basic_context_cache: dict[tuple[str, str, str], dict],
    *,
    include_root_cause: bool = True,
) -> dict:
    key = _package_key(ecosystem, normalized_name, version)
    cached = basic_context_cache.get(key)
    if cached is not None:
        return cached
    occurrences = occurrence_cache.get(key)
    if occurrences is None:
        occurrences = [
            dict(row)
            for row in db.current_package_occurrences(
                ecosystem=ecosystem,
                normalized_name=normalized_name,
                version=version,
            )
        ]
        occurrence_cache[key] = occurrences
    occurrence_paths = [
        item.get("source_file") or item.get("project_path") or item.get("root_path")
        for item in occurrences
    ]
    direct_dependency = _direct_dependency_flag(occurrences)
    usage = usage_summary(occurrences)
    usage_counts = aggregate_usage_kinds(usage)
    usage_hit_count = sum(item["hit_count"] for item in usage)
    root_paths = sorted({item["root_path"] for item in occurrences})
    manifest_scopes = []
    manifest_paths = []
    for root_path in root_paths:
        manifest = inspector.manifest_scope(
            root_path,
            ecosystem=ecosystem,
            normalized_name=normalized_name,
            occurrence_paths=occurrence_paths,
        )
        manifest_scopes.append(manifest["scope"])
        manifest_paths.extend(manifest["manifest_paths"])
    manifest_scope = "undeclared"
    for scope in ("runtime", "build", "test"):
        if scope in manifest_scopes:
            manifest_scope = scope
            break
    scope_summary = _occurrence_scope_summary(occurrences)
    manifest_scope = _version_specific_manifest_scope(manifest_scope, direct_dependency, scope_summary)
    usage_counts = _version_specific_usage_counts(usage_counts, direct_dependency, scope_summary)
    role = _package_role(package_name, manifest_scope, usage_counts, direct_dependency)
    environment_label = _environment_label(occurrences, role, usage_counts)
    root_cause = _root_cause_summary(
        root_paths,
        ecosystem,
        package_name,
        occurrences,
        environment_label,
        allow_npm_explain=include_root_cause,
    )
    suggestions = _advice_for_role(package_name, role, manifest_scope)
    suggestions.extend(_usage_based_suggestions(package_name, role, usage))
    suggestions.extend(_environment_based_suggestions(environment_label, direct_dependency, usage_counts))
    payload = {
        "ecosystem": ecosystem,
        "package_name": package_name,
        "normalized_name": normalized_name,
        "version": version,
        "occurrences": occurrences,
        "root_paths": root_paths,
        "direct_dependency": direct_dependency,
        "manifest_scope": manifest_scope,
        "version_install_scopes": scope_summary["scopes"],
        "manifest_paths": sorted(set(manifest_paths)),
        "role": role["role"],
        "role_label": role["label"],
        "environment_label": environment_label,
        "root_cause": root_cause,
        "necessity": role["necessity"],
        "usage": usage,
        "usage_hit_count": usage_hit_count,
        "usage_by_kind": usage_counts,
        "suggestions": suggestions,
    }
    basic_context_cache[key] = payload
    return payload


def _cheap_hygiene_candidate(row_group: list[dict]) -> dict | None:
    representative = row_group[0]
    normalized_name = representative["normalized_name"]
    package_name = representative["package_name"]
    source_types = {row.get("source_type") for row in row_group if row.get("source_type")}
    paths = [
        row.get("source_file") or row.get("project_path") or row.get("root_path") or ""
        for row in row_group
    ]
    path_blob = " ".join(paths).lower()
    any_direct = any(row.get("direct_dependency") == 1 for row in row_group)
    install_scopes = {str(row.get("install_scope") or "").lower() for row in row_group}
    path_hints = {"runtime": 0, "build": 0, "test": 0}
    for path in paths:
        hints = path_usage_hints(path)
        for kind, count in hints.items():
            path_hints[kind] += count

    score = 0
    tags: list[str] = []
    if "yarn-lockfile" in source_types and "/node_modules/" in path_blob:
        score += 120
        tags.append("vendored-lockfile")
    if "/.venv" in path_blob or "/site-packages/" in path_blob:
        score += 110
        tags.append("isolated-env")
    if normalized_name in BUILD_TOOL_PACKAGES:
        score += 90
        tags.append("build-tool")
    if normalized_name in HYGIENE_NAME_HINTS:
        score += 80
        tags.append("named-tooling")
    if normalized_name.startswith("@types/"):
        score += 80
        tags.append("types-only")
    if any(scope in {"dev", "development", "test"} for scope in install_scopes):
        score += 60
        tags.append("install-scope")
    if path_hints["test"] > 0 and path_hints["runtime"] == 0:
        score += 55
        tags.append("test-paths")
    if path_hints["build"] > 0 and path_hints["runtime"] == 0:
        score += 45
        tags.append("build-paths")
    if not any_direct:
        score += 10
        tags.append("transitive")
    if score <= 0:
        return None
    return {
        "ecosystem": representative["ecosystem"],
        "package_name": package_name,
        "normalized_name": normalized_name,
        "version": representative["version"],
        "score": score,
        "tags": tags,
    }
