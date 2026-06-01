"""High-level triage enrichment that combines advisory severity, exploit signals, project context, and remediation advice."""

from __future__ import annotations

from .config import GuardianConfig
from .db import Database
from .intel import severity_rank
from .planner import CandidateResolver
from .project_model import ProjectInspector
from .triage_context import _basic_package_context, _cheap_hygiene_candidate, _package_context
from .triage_queue import daily_brief, package_remediation_queue, summarize_candidate
from .triage_rules import (
    _environment_label,
    _exploit_likelihood,
    _issue_labels,
    _issue_package_normalized_name,
    _package_key,
    _risk_bucket,
)
from .triage_signals import HYGIENE_NECESSITY_ORDER, keyword_signals


def enrich_issue(
    issue: dict,
    config: GuardianConfig,
    db: Database,
    inspector: ProjectInspector,
    resolver: CandidateResolver,
    occurrence_cache: dict[tuple[str, str, str], list[dict]],
    package_context_cache: dict[tuple[str, str, str], dict],
    *,
    resolve_clean_targets: bool,
) -> dict:
    """Attach project context, exploit signals, labels, and actions to one issue."""

    package_contexts = [
        _package_context(
            db,
            inspector,
            resolver,
            package["ecosystem"],
            package["package_name"],
            _issue_package_normalized_name(package),
            package["version"],
            occurrence_cache,
            package_context_cache,
            resolve_clean_targets=resolve_clean_targets,
        )
        for package in issue["packages"]
    ]
    direct_dependency = any(item["direct_dependency"] for item in package_contexts)
    usage_count = sum(item["usage_hit_count"] for item in package_contexts)
    signal_text = " ".join(
        filter(
            None,
            [issue.get("summary", ""), " ".join(issue.get("aliases", [])), " ".join(issue.get("urls", []))],
        )
    )
    signals = keyword_signals(signal_text)
    strongest_role = next(
        (item for item in package_contexts if item["role"] == "runtime"),
        package_contexts[0],
    )
    exploit_likelihood = _exploit_likelihood(config, issue.get("epss"))
    bucket = _risk_bucket(
        issue.get("severity"),
        strongest_role,
        direct_dependency,
        usage_count,
        signals,
        environment_label=strongest_role.get("environment_label", "unknown"),
        known_exploited=bool(issue.get("known_exploited")),
        malicious_package=bool(issue.get("malicious_package")),
        exploit_likelihood=exploit_likelihood,
    )
    # Action text is intentionally context-aware. Vendored metadata and
    # uncorroborated transitives should not read like immediate app upgrades.
    actions = []
    for package in package_contexts:
        environment = package.get("environment_label")
        target = package["recommended_clean_version"] or package["first_fixed_version"]
        if environment == "vendored-lockfile" and package.get("usage_hit_count", 0) == 0:
            actions.append(
                f"Review the parent dependency chain for {package['package_name']}@{package['version']}; no direct app dependency change is recommended from vendored metadata alone."
            )
        elif (
            environment in {"transitive-installed", "lockfile-only"}
            and package.get("usage_hit_count", 0) == 0
            and not package.get("direct_dependency")
        ):
            actions.append(
                f"Review the parent dependency chain for {package['package_name']}@{package['version']}; no scheduled direct app dependency change is recommended without root-lockfile, direct dependency, or code-usage corroboration."
            )
        elif environment == "isolated-env":
            actions.append(
                f"Review {package['package_name']}@{package['version']} inside its isolated environment before considering changes to the main app runtime."
            )
        elif target:
            target_label = "clean target" if package["recommended_clean_version"] else "first fixed version"
            actions.append(
                f"{package['package_name']}@{package['version']} should move to {target_label} {target} ({package['upgrade_risk']['label']})"
            )
        else:
            actions.append(
                f"{package['package_name']}@{package['version']} needs manual review because no safe upgrade target was derived automatically"
            )
    suggestions = []
    for package in package_contexts:
        suggestions.extend(package["suggestions"])
    labels = _issue_labels(issue, exploit_likelihood, package_contexts=package_contexts)
    return {
        **issue,
        "risk_bucket": bucket["bucket"],
        "risk_label": bucket["label"],
        "classification_labels": labels,
        "exploit_likelihood": exploit_likelihood,
        "signals": signals,
        "direct_dependency": direct_dependency,
        "usage_hit_count": usage_count,
        "packages": package_contexts,
        "actions": actions,
        "suggestions": sorted(set(suggestions)),
    }


def _filter_issues_for_root(issues: list[dict], root_filter: str | None) -> list[dict]:
    if not root_filter:
        return issues
    return [
        issue
        for issue in issues
        if any(root_filter == root for package in issue["packages"] for root in package["root_paths"])
    ]


def enriched_issues(
    config: GuardianConfig,
    db: Database,
    issues: list[dict],
    root_filter: str | None = None,
    *,
    resolve_clean_targets: bool = True,
) -> list[dict]:
    """Return triaged issues for a root, filtered to packages present in that root."""

    inspector = ProjectInspector()
    resolver = CandidateResolver(config)
    occurrence_cache: dict[tuple[str, str, str], list[dict]] = {}
    package_context_cache: dict[tuple[str, str, str], dict] = {}
    if root_filter:
        root_keys = {
            _package_key(row["ecosystem"], row["normalized_name"], row["version"])
            for row in db.current_packages_for_root(root_filter)
        }
        filtered = []
        for issue in issues:
            kept_packages = [
                package
                for package in issue["packages"]
                if _package_key(package["ecosystem"], _issue_package_normalized_name(package), package["version"]) in root_keys
            ]
            if kept_packages:
                filtered.append({**issue, "packages": kept_packages})
        issues = filtered
    results = [
        enrich_issue(
            issue,
            config,
            db,
            inspector,
            resolver,
            occurrence_cache,
            package_context_cache,
            resolve_clean_targets=resolve_clean_targets,
        )
        for issue in issues
    ]
    results = _filter_issues_for_root(results, root_filter)
    bucket_order = {"act_now": 0, "fix_this_week": 1, "watch": 2, "low_priority": 3}
    results.sort(key=lambda item: (bucket_order.get(item["risk_bucket"], 9), -severity_rank(item["severity"]), item["canonical_key"]))
    return results


def hygiene_report(
    config: GuardianConfig,
    db: Database,
    root_filter: str | None = None,
    *,
    limit: int | None = None,
    exclude_keys: set[tuple[str, str, str]] | None = None,
) -> dict:
    inspector = ProjectInspector()
    occurrence_cache: dict[tuple[str, str, str], list[dict]] = {}
    basic_context_cache: dict[tuple[str, str, str], dict] = {}
    rows = db.current_packages_for_root(root_filter) if root_filter else db.current_packages()
    grouped_rows: dict[tuple[str, str, str], list[dict]] = {}
    for row in rows:
        item = dict(row)
        key = (item["ecosystem"], item["normalized_name"], item["version"])
        if exclude_keys and key in exclude_keys:
            continue
        grouped_rows.setdefault(key, []).append(item)

    candidate_profiles = []
    for key, row_group in grouped_rows.items():
        candidate = _cheap_hygiene_candidate(row_group)
        if candidate is None:
            continue
        candidate_profiles.append(candidate)
    candidate_profiles.sort(
        key=lambda item: (-item["score"], item["package_name"].lower(), item["version"])
    )

    enrich_budget = max((limit or 12) * 4, 24)
    packages = []
    for candidate in candidate_profiles[:enrich_budget]:
        context = _basic_package_context(
            db,
            inspector,
            candidate["ecosystem"],
            candidate["package_name"],
            candidate["normalized_name"],
            candidate["version"],
            occurrence_cache,
            basic_context_cache,
            include_root_cause=False,
        )
        if context["environment_label"] == "vendored-lockfile" and context["usage_hit_count"] == 0:
            continue
        if context["necessity"] in HYGIENE_NECESSITY_ORDER:
            packages.append(context)
    packages.sort(
        key=lambda item: (
            HYGIENE_NECESSITY_ORDER.get(item["necessity"], 9),
            item["environment_label"],
            item["package_name"].lower(),
            item["version"],
        )
    )
    if limit is not None:
        packages = packages[:limit]
    headline = f"{len(packages)} packages look non-runtime or removable"
    return {
        "headline": headline,
        "packages": packages,
    }
