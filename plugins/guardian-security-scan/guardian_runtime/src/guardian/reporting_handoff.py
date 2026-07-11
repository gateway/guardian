"""Markdown handoff report rendering for agent-to-agent or maintainer review."""

from __future__ import annotations

from pathlib import Path

from .config import GuardianConfig
from .db import Database
from .evidence import evidence_summary
from .reporting_common import (
    advisory_details,
    audit_line,
    group_vendored_packages,
    low_action_installed_only,
    matching_repo_evidence,
    npm_audit_summary,
    operator_recommendations,
    package_evidence_context,
)
from .reporting_core import triage_report
from .reporting_snapshots import compare_triage_snapshots
from .triage import hygiene_report as build_hygiene_report
from .util import slugify, utc_now, write_text


"""Markdown handoff rendering for humans and downstream agent sessions."""


def build_handoff_markdown(
    config: GuardianConfig,
    db: Database,
    *,
    root_filter: str,
    behavioral_signals: list[dict] | None = None,
) -> str:
    behavioral_signals = behavioral_signals or []
    triage = triage_report(config, db, root_filter=root_filter)
    comparison = compare_triage_snapshots(db, root_filter=root_filter)
    if not triage["package_actions"]:
        return _build_clean_handoff_markdown(
            config,
            db,
            root_filter=root_filter,
            triage=triage,
            comparison=comparison,
            behavioral_signals=behavioral_signals,
        )
    full_triage = triage_report(config, db, root_filter=root_filter, package_limit=None)
    triage_keys = {
        (package["ecosystem"], package["normalized_name"], package["version"])
        for package in triage["package_actions"]
    }
    hygiene = build_hygiene_report(
        config,
        db,
        root_filter=root_filter,
        limit=6,
        exclude_keys=triage_keys,
    )
    repo_label = Path(root_filter).name
    vendored_count = sum(1 for package in triage["package_actions"] if package.get("environment_label") == "vendored-lockfile")
    runtime_count = sum(1 for package in triage["package_actions"] if package.get("environment_label") == "runtime")
    isolated_count = sum(1 for package in triage["package_actions"] if package.get("environment_label") == "isolated-env")
    non_vendored_packages = [package for package in triage["package_actions"] if package.get("environment_label") != "vendored-lockfile"]
    vendored_groups = group_vendored_packages(triage["package_actions"])
    npm_audit_prod = npm_audit_summary(root_filter, omit_dev=True)
    npm_audit_full = npm_audit_summary(root_filter, omit_dev=False)
    repo_evidence_summary = evidence_summary([dict(row) for row in db.current_packages_for_root(root_filter)])
    lines: list[str] = []
    lines.append(f"# Guardian Handoff: {repo_label}")
    lines.append("")
    lines.append(f"- Repository: `{root_filter}`")
    lines.append(f"- Generated at: `{utc_now()}`")
    lines.append(f"- Full repo finding set for this repository only: {full_triage['headline']}")
    lines.append(f"- Priority slice shown below for this repository only: {triage['headline']}")
    if comparison.get("status") == "ok":
        lines.append(f"- Snapshot compare: {comparison['headline']}")
    lines.append("")
    lines.append("## What This Means")
    lines.append("")
    lines.append("- `Known Vulnerable` means the installed version matches a published advisory.")
    lines.append("- `Known Exploited` means CISA KEV lists the CVE as exploited in the wild.")
    lines.append("- `Malicious Package` means an advisory source classified the package as intentionally harmful software.")
    lines.append("- `High` or `Elevated Exploit Likelihood` comes from FIRST EPSS and is a prioritization signal, not proof of compromise.")
    lines.append("- `Upgrade Breakage Risk` estimates how risky the upgrade itself is for the project.")
    lines.append("- `Vendored Metadata Only` means the hit came from nested package metadata such as `node_modules/**/yarn.lock`; treat that as lower-confidence unless it also appears in your real lockfile, installed graph, or code usage.")
    lines.append("")
    lines.append("## Guardian Perspective")
    lines.append("")
    lines.append(f"- Scope: this handoff is repo-specific for `{root_filter}` only.")
    lines.append("- Count notes:")
    lines.append("  - `Full repo finding set` counts every open package finding currently tied to this repo.")
    lines.append("  - `Priority slice` is the operator-focused subset shown below after grouping and noise reduction.")
    if comparison.get("status") == "ok":
        lines.append("  - `Snapshot compare` separates raw evidence changes from interpretation or prioritization changes.")
    lines.append(f"- Runtime-linked packages in this priority slice: `{runtime_count}`")
    lines.append(f"- Vendored metadata-only packages in this priority slice: `{vendored_count}`")
    lines.append(f"- Isolated environment packages in this priority slice: `{isolated_count}`")
    lines.append("- Evidence priority summary:")
    for label, count in repo_evidence_summary["package_counts"].items():
        lines.append(f"  - `{label}`: `{count}` unique packages")
    if vendored_count and runtime_count == 0:
        lines.append("- Most current priority items are vendored metadata rather than direct runtime dependencies. Do not churn app dependencies until the same packages show up in real lockfiles, installed runtime packages, or code usage.")
    lines.append("")
    if npm_audit_prod or npm_audit_full:
        lines.append("## Repo Corroboration")
        lines.append("")
        lines.append(audit_line("`npm audit --omit=dev`", npm_audit_prod))
        lines.append(audit_line("`npm audit`", npm_audit_full))
        lines.append("")
    lines.append("## Priority Findings")
    lines.append("")
    if not triage["package_actions"]:
        lines.append("No open package findings for this repository.")
    for package in non_vendored_packages:
        lines.append(f"### {package['risk_label']}: {package['package_name']}@{package['version']}")
        lines.append("")
        if package.get("classification_labels"):
            lines.append(f"- Labels: {', '.join(package['classification_labels'])}")
        if package.get("confidence"):
            lines.append(
                f"- Confidence: `{package['confidence']['label']}`"
            )
        lines.append(f"- Severity: `{package['highest_severity']}`")
        lines.append(f"- Findings matched: `{package['advisory_count']}`")
        if package.get("advisory_sources"):
            lines.append(f"- Advisory IDs: `{', '.join(package['advisory_sources'][:4])}`")
        if package.get("advisory_links"):
            lines.append("- Advisory links:")
            for link in package["advisory_links"][:4]:
                lines.append(f"  - {link}")
        details = advisory_details(package, limit=4)
        if details:
            lines.append("- Advisory evidence:")
            for detail in details:
                label = detail.get("id") or detail.get("source") or "advisory"
                source = f" ({detail['source']})" if detail.get("source") else ""
                url = f": {detail['url']}" if detail.get("url") else ""
                lines.append(f"  - `{label}`{source}{url}")
        lines.append(f"- Role: `{package['role_label']}`")
        lines.append(f"- Environment: `{package['environment_label']}`")
        context = package_evidence_context(package)
        lines.append(f"- Evidence context: {context['summary']}")
        if package.get("root_cause"):
            lines.append(f"- Direct parent / source: {package['root_cause']['summary']}")
        lines.append(
            "- Usage: "
            f"runtime `{package['usage_by_kind']['runtime']}`, "
            f"build `{package['usage_by_kind']['build']}`, "
            f"test `{package['usage_by_kind']['test']}`"
        )
        if package.get("recommended_clean_version"):
            if low_action_installed_only(package):
                lines.append(
                    f"- Potential clean target if corroborated: `{package['recommended_clean_version']}` "
                    f"({package['upgrade_risk']['label']}); no direct app dependency change is scheduled from installed-only transitive evidence alone."
                )
            else:
                lines.append(
                    f"- Recommended clean target: `{package['recommended_clean_version']}` "
                    f"({package['upgrade_risk']['label']})"
                )
        elif package.get("first_fixed_version"):
            if low_action_installed_only(package):
                lines.append(
                    f"- First fixed version if corroborated: `{package['first_fixed_version']}` "
                    f"({package['upgrade_risk']['label']}); review the parent chain before changing app dependencies."
                )
            else:
                lines.append(
                    f"- First fixed version: `{package['first_fixed_version']}` "
                    f"({package['upgrade_risk']['label']})"
                )
        else:
            lines.append("- Recommended clean target: manual review required")
        if package.get("upgrade_risk", {}).get("reason"):
            lines.append(f"- Upgrade breakage risk: {package['upgrade_risk']['reason']}")
        if package.get("issue_summaries"):
            lines.append(f"- Why it matters: {package['issue_summaries'][0]}")
        if package.get("usage") and package["usage"][0]["hits"]:
            lines.append("- Key usage locations:")
            for hit in package["usage"][0]["hits"][:3]:
                lines.append(f"  - `{hit['file']}:{hit['line']}`")
        if package.get("root_cause") and package["root_cause"].get("details"):
            details = package["root_cause"]["details"]
            if isinstance(details, list):
                lines.append("- Parent chains:")
                for detail in details[:3]:
                    chain = detail.get("chain")
                    if chain:
                        lines.append(f"  - `{chain}`")
            elif isinstance(details, str):
                lines.append(f"- Source detail: `{details}`")
        if package.get("notes"):
            lines.append("- Notes:")
            for note in package["notes"][:3]:
                lines.append(f"  - {note}")
        if package.get("suggestions"):
            lines.append("- Suggested approach:")
            for suggestion in package["suggestions"][:3]:
                lines.append(f"  - {suggestion}")
        lines.append("")
    for group in vendored_groups:
        evidence = matching_repo_evidence(db, root_filter=root_filter, packages=group["packages"])
        lines.append("### Watch: Vendored Metadata Group")
        lines.append("")
        if group.get("confidence_labels"):
            lines.append(f"- Confidence: `{', '.join(group['confidence_labels'])}`")
        lines.append("- Action posture: `Low action unless corroborated by repo lockfiles, installed runtime packages, or code usage.`")
        lines.append(f"- Findings grouped here: `{len(group['packages'])}` package/version entries")
        lines.append(f"- Source: `{group['source_detail'] or group['summary']}`")
        lines.append("- Evidence:")
        lines.append("  - Detected in vendored nested lockfile metadata under `node_modules`.")
        lines.append(
            "  - In `package-lock.json` or other repo-level npm lockfiles: "
            + ("matching vulnerable version present." if evidence["package_lock_matches"] else "no matching vulnerable version.")
        )
        lines.append(
            "  - In installed runtime dependency metadata: "
            + ("matching vulnerable version present." if evidence["installed_matches"] else "no matching vulnerable version.")
        )
        lines.append(
            "  - Code usage outside `node_modules`: "
            + (f"`{evidence['runtime_usage_hits']}` runtime hits." if evidence["runtime_usage_hits"] else "none detected.")
        )
        if npm_audit_prod or npm_audit_full:
            lines.append(
                "  - npm audit corroboration: "
                f"`--omit=dev` {int((npm_audit_prod or {}).get('total') or 0)} vulnerabilities, "
                f"`full` {int((npm_audit_full or {}).get('total') or 0)} vulnerabilities."
            )
        lines.append("  - Treat as lower-confidence unless corroborated by repo lockfiles, installed runtime packages, or code usage.")
        if group.get("severities"):
            lines.append(f"- Underlying advisory severity in group: `{group['severities'][0]}`")
        if group.get("advisory_sources"):
            lines.append(f"- Advisory IDs: `{', '.join(group['advisory_sources'][:6])}`")
        if group.get("advisory_links"):
            lines.append("- Advisory links:")
            for link in group["advisory_links"][:6]:
                lines.append(f"  - {link}")
        lines.append("- Packages:")
        for package in group["packages"][:8]:
            lines.append(
                f"  - `{package['package_name']}@{package['version']}` "
                f"({package['highest_severity']}, {package['risk_label']})"
            )
        if len(group["packages"]) > 8:
            lines.append(f"  - ... plus `{len(group['packages']) - 8}` more similar vendored entries")
        lines.append("- Recommended action:")
        lines.append("  - Do not change app dependencies directly from this group alone.")
        lines.append("  - Review the parent dependency chain or policy handling first.")
        lines.append("")
    lines.append("## Dependency Hygiene")
    lines.append("")
    if not hygiene["packages"]:
        lines.append("No non-runtime or removable packages were identified.")
    for package in hygiene["packages"]:
        lines.append(f"### {package['role_label']}: {package['package_name']}@{package['version']}")
        lines.append("")
        lines.append(
            "- Usage: "
            f"runtime `{package['usage_by_kind']['runtime']}`, "
            f"build `{package['usage_by_kind']['build']}`, "
            f"test `{package['usage_by_kind']['test']}`"
        )
        lines.append(f"- Environment: `{package['environment_label']}`")
        if package.get("root_cause"):
            lines.append(f"- Direct parent / source: {package['root_cause']['summary']}")
        if package.get("usage") and package["usage"][0]["hits"]:
            lines.append("- Detected usage:")
            for hit in package["usage"][0]["hits"][:2]:
                lines.append(f"  - `{hit['file']}:{hit['line']}`")
        if package.get("suggestions"):
            lines.append("- Why this is here:")
            for suggestion in package["suggestions"][:3]:
                lines.append(f"  - {suggestion}")
        lines.append("")
    lines.append("## Recommended Next Steps")
    lines.append("")
    top_runtime = next((package for package in triage["package_actions"] if package.get("environment_label") == "runtime"), None)
    top_actionable = next(
        (
            package for package in triage["package_actions"]
            if package.get("environment_label") != "vendored-lockfile"
            and not low_action_installed_only(package)
            and (package.get("recommended_clean_version") or package.get("first_fixed_version"))
        ),
        None,
    )
    if triage["package_actions"]:
        top = triage["package_actions"][0]
        if top_runtime:
            lines.append(
                f"1. Review and likely upgrade `{top_runtime['package_name']}` from `{top_runtime['version']}` to `{top_runtime.get('recommended_clean_version') or top_runtime.get('first_fixed_version') or 'manual target'}`."
            )
        elif top.get("environment_label") == "vendored-lockfile":
            lines.append(f"1. Review the parent dependency path for `{top['package_name']}` before changing app dependencies directly; this current top item is vendored metadata, not a confirmed runtime package.")
        elif top_actionable:
            lines.append(
                f"1. Review `{top_actionable['package_name']}` and assess `{top_actionable.get('recommended_clean_version') or top_actionable.get('first_fixed_version') or 'a manual target'}` in its non-runtime context."
            )
        else:
            lines.append("1. No direct package upgrade is justified from this scan alone.")
    else:
        lines.append("1. No immediate package remediation needed.")
    if top_runtime or top_actionable:
        lines.append("2. Validate affected runtime or build flows after any justified upgrade, especially files listed above under key usage locations.")
    else:
        lines.append("2. No runtime upgrade validation is warranted from this scan alone; wait for corroborating evidence before scheduling remediation.")
    lines.append("3. Treat vendored metadata, build-only packages, and test-only packages separately from production-runtime security work.")
    lines.append("4. Do not schedule upgrade work for transitive or vendored packages unless repo lockfiles, installed runtime packages, or code usage corroborate the exposure.")
    lines.append("")
    lines.append("## Bottom Line")
    lines.append("")
    for recommendation in operator_recommendations(triage["package_actions"]):
        lines.append(f"- {recommendation}")
    if vendored_groups and comparison.get("status") == "ok" and comparison.get("classification_changed"):
        lines.append("- Snapshot compare shows interpretation changed separately from raw evidence. That means Guardian may have downgraded findings without the repo necessarily changing its dependency graph.")
    lines.append("")
    _append_behavioral_signals(lines, behavioral_signals)
    lines.append("## Agent Handoff")
    lines.append("")
    lines.append("Use this report as the starting context for evidence review and only plan remediation if the repo evidence justifies it. The agent should:")
    lines.append("")
    lines.append("1. review the flagged package usage locations")
    lines.append("2. confirm whether any remediation is justified at all before considering upgrade targets")
    lines.append("3. estimate impact only if corroborated evidence justifies remediation")
    lines.append("4. propose the safest response order, including no-change if the findings remain metadata-only")
    lines.append("5. keep build-only and test-only packages out of the main runtime risk discussion unless they are directly exploitable in CI or local tooling")
    lines.append("")
    return "\n".join(lines) + "\n"


def _build_clean_handoff_markdown(
    config: GuardianConfig,
    db: Database,
    *,
    root_filter: str,
    triage: dict,
    comparison: dict,
    behavioral_signals: list[dict],
) -> str:
    repo_label = Path(root_filter).name
    npm_audit_prod = npm_audit_summary(root_filter, omit_dev=True)
    npm_audit_full = npm_audit_summary(root_filter, omit_dev=False)
    repo_evidence_summary = evidence_summary([dict(row) for row in db.current_packages_for_root(root_filter)])
    lines: list[str] = []
    lines.append(f"# Guardian Handoff: {repo_label}")
    lines.append("")
    lines.append(f"- Repository: `{root_filter}`")
    lines.append(f"- Generated at: `{utc_now()}`")
    lines.append(f"- Finding set for this repository only: {triage['headline']}")
    if comparison.get("status") == "ok":
        lines.append(f"- Snapshot compare: {comparison['headline']}")
    elif comparison.get("message"):
        lines.append(f"- Snapshot compare: {comparison['message']}")
    lines.append("")
    lines.append("## Guardian Perspective")
    lines.append("")
    lines.append("- No open package findings were identified for this repository from the currently configured Guardian sources.")
    lines.append("- Evidence priority summary:")
    for label, count in repo_evidence_summary["package_counts"].items():
        lines.append(f"  - `{label}`: `{count}` unique packages")
    lines.append("")
    if npm_audit_prod or npm_audit_full:
        lines.append("## Repo Corroboration")
        lines.append("")
        lines.append(audit_line("`npm audit --omit=dev`", npm_audit_prod))
        lines.append(audit_line("`npm audit`", npm_audit_full))
        lines.append("")
    lines.append("## Priority Findings")
    lines.append("")
    lines.append("No open package findings for this repository.")
    lines.append("")
    lines.append("## Recommended Next Steps")
    lines.append("")
    if any(item.get("posture") == "fix_this_week" for item in behavioral_signals):
        lines.append("1. Review the install-time behavior change before accepting the dependency update.")
    else:
        lines.append("1. No immediate package remediation needed.")
    lines.append("2. Keep scheduled Guardian watchlist scans enabled so newly published advisories can be caught later.")
    lines.append("3. Re-run with live GHSA enrichment when reviewing large dependency changes or release candidates.")
    lines.append("")
    lines.append("## Bottom Line")
    lines.append("")
    if behavioral_signals:
        lines.append("- No published advisory match is currently shown, but the install-time behavior changes below require evidence review.")
    else:
        lines.append("- No direct runtime, lockfile, malicious-package, or known-exploited package risk is currently shown by Guardian for this repository.")
    lines.append("- This is not proof that the repo is safe against unknown zero-days; it means no configured source matched the scanned package versions.")
    lines.append("")
    _append_behavioral_signals(lines, behavioral_signals)
    return "\n".join(lines) + "\n"


def _append_behavioral_signals(lines: list[str], signals: list[dict]) -> None:
    """Render behavioral evidence separately from published advisories."""

    lines.append("## Behavioral Signals")
    lines.append("")
    if not signals:
        lines.append("No new install-time behavior changes were detected in this scan.")
        lines.append("")
        return
    for signal in signals:
        lines.append(
            f"### {signal['posture'].replace('_', ' ').title()}: "
            f"{signal['package_name']}@{signal['version']}"
        )
        lines.append("")
        lines.append(f"- Signal: `{signal['signal_type']}`")
        lines.append(f"- Evidence grade: `{signal['signal_grade']}`")
        lines.append(f"- Evidence source: `{signal['evidence_source']}`")
        if signal.get("previous_version"):
            lines.append(f"- Previous observed version: `{signal['previous_version']}`")
        if signal.get("script_kinds"):
            lines.append(f"- Install behavior: `{', '.join(signal['script_kinds'])}`")
        lines.append(f"- Why it matters: {signal['explanation']}")
        for source_file in signal.get("source_files", [])[:3]:
            lines.append(f"- Evidence file: `{source_file}`")
        lines.append("")


def write_handoff_report(
    config: GuardianConfig,
    db: Database,
    *,
    root_filter: str,
    behavioral_signals: list[dict] | None = None,
) -> Path:
    content = build_handoff_markdown(
        config,
        db,
        root_filter=root_filter,
        behavioral_signals=behavioral_signals,
    )
    root_slug = slugify(Path(root_filter).name)
    path = Path(config.reports_dir) / f"handoff-{root_slug}-{utc_now().replace(':', '-')}.md"
    write_text(path, content)
    return path
