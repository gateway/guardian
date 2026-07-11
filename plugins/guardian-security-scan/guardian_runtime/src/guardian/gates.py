"""Package install gate helpers for checking a package/version before adding it to a project."""

from __future__ import annotations

import json
import subprocess

from .config import GuardianConfig
from .db import Database
from .http_client import GuardianHttp
from .planner import CandidateResolver
from .policy import decide_package_action
from .triage import summarize_candidate
from .util import (
    ResolvedPackageSpec,
    normalize_package_name,
    parse_npm_spec,
    parse_pip_spec,
    quote_package_path,
)


def resolve_npm_spec(config: GuardianConfig, spec: str) -> ResolvedPackageSpec:
    name, version = parse_npm_spec(spec)
    if not version:
        url = f"https://registry.npmjs.org/{quote_package_path(name)}/latest"
        data = GuardianHttp(config).get(url).json()
        version = data["version"]
    return ResolvedPackageSpec(ecosystem="npm", name=name, version=version, original_spec=spec)


def resolve_pip_spec(config: GuardianConfig, spec: str) -> ResolvedPackageSpec:
    name, version = parse_pip_spec(spec)
    if not version:
        url = f"https://pypi.org/pypi/{quote_package_path(name)}/json"
        data = GuardianHttp(config).get(url).json()
        version = data["info"]["version"]
    return ResolvedPackageSpec(ecosystem="pypi", name=name, version=version, original_spec=spec)


def assess_install_candidate(config: GuardianConfig, db: Database, ecosystem: str, name: str, version: str) -> dict:
    resolver = CandidateResolver(config)

    package = {
        "ecosystem": ecosystem,
        "package_name": name,
        "normalized_name": normalize_package_name(ecosystem, name),
        "version": version,
    }
    assessment = resolver.assess_version(ecosystem, name, version)
    findings = assessment["findings"]

    decision = decide_package_action(
        config,
        db,
        ecosystem=ecosystem,
        normalized_name=package["normalized_name"],
        version=version,
        findings=findings,
    )
    candidate_summary = summarize_candidate(findings)
    fixed_versions = sorted({fixed for finding in findings for fixed in (finding.get("fixed_versions") or [])})
    first_fixed_version = fixed_versions[0] if fixed_versions else None
    clean_target = resolver.recommended_clean_version(
        ecosystem,
        name,
        version,
        minimum_version=first_fixed_version,
    )
    recommended_version = clean_target["recommended_clean_version"] or first_fixed_version
    recommended_version_is_clean = clean_target["recommended_clean_version"] is not None
    if recommended_version:
        from .versions import classify_upgrade_jump
        upgrade_risk = classify_upgrade_jump(version, recommended_version)
    else:
        upgrade_risk = {
            "impact": "unknown",
            "label": "unknown risk",
            "reason": "no clean upgrade target was derived automatically",
        }
    return {
        "ecosystem": ecosystem,
        "name": name,
        "version": version,
        "blocked": decision.blocked,
        "action": decision.action,
        "decision_reason": decision.reason,
        "matched_exception": decision.matched_exception,
        "highest_severity": candidate_summary["highest_severity"],
        "risk_bucket": candidate_summary["risk_bucket"],
        "risk_label": candidate_summary["risk_label"],
        "signals": candidate_summary["signals"],
        "recommended_version": recommended_version,
        "recommended_version_is_clean": recommended_version_is_clean,
        "first_fixed_version": first_fixed_version,
        "latest_version": clean_target["latest_version"],
        "upgrade_risk": upgrade_risk,
        "findings": findings,
    }


def gate_install(config: GuardianConfig, db: Database, package_manager: str, specs: list[str], execute: bool) -> dict:
    if package_manager in {"npm", "pnpm"}:
        resolved = [resolve_npm_spec(config, spec) for spec in specs]
        command = ["npm", "install", *specs] if package_manager == "npm" else ["pnpm", "add", *specs]
    elif package_manager == "pip":
        resolved = [resolve_pip_spec(config, spec) for spec in specs]
        command = ["python3", "-m", "pip", "install", *specs]
    else:
        raise ValueError(f"unsupported package manager: {package_manager}")

    results = [assess_install_candidate(config, db, item.ecosystem, item.name, item.version) for item in resolved]
    blocked = any(result["blocked"] for result in results)
    payload = {"package_manager": package_manager, "blocked": blocked, "packages": results, "command": command}
    if blocked or not execute:
        return payload

    completed = subprocess.run(command, text=True)
    payload["returncode"] = completed.returncode
    return payload
