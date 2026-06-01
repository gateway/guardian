from __future__ import annotations

from .config import GuardianConfig
from .project_model import BUILD_TOOL_PACKAGES
from .triage_signals import CORE_RUNTIME_PACKAGES
from .versions import classify_upgrade_jump


"""Deterministic triage classification rules with no database side effects."""


def _package_key(ecosystem: str, normalized_name: str, version: str) -> tuple[str, str, str]:
    return (ecosystem, normalized_name, version)


def _issue_package_normalized_name(package: dict) -> str:
    if package["ecosystem"] == "pypi":
        return package["package_name"].lower().replace("_", "-")
    return package["package_name"].lower()


def _direct_dependency_flag(occurrences: list[dict]) -> bool:
    return any(item.get("direct_dependency") == 1 for item in occurrences)


def _is_vendored_lockfile_occurrence(item: dict) -> bool:
    source_type = item.get("source_type")
    source_file = (item.get("source_file") or "").lower()
    return source_type == "yarn-lockfile" and "/node_modules/" in source_file and source_file.endswith("/yarn.lock")


def _is_isolated_env_occurrence(item: dict) -> bool:
    source_file = (item.get("source_file") or "").lower()
    return "/.venv/" in source_file or "/venv/" in source_file or "/site-packages/" in source_file


def _package_role(
    package_name: str,
    manifest_scope: str,
    usage_counts: dict[str, int],
    direct_dependency: bool,
) -> dict:
    normalized = package_name.lower().replace("_", "-")
    if manifest_scope == "workspace":
        return {
            "role": "workspace-internal",
            "label": "Workspace Internal",
            "necessity": "workspace-internal",
        }
    if normalized in BUILD_TOOL_PACKAGES and usage_counts["runtime"] == 0:
        return {
            "role": "build-tooling",
            "label": "Build Tooling",
            "necessity": "build-tooling",
        }
    if manifest_scope == "test" and usage_counts["runtime"] == 0:
        return {
            "role": "test-only",
            "label": "Test Only",
            "necessity": "test-only",
        }
    if manifest_scope == "runtime" or usage_counts["runtime"] > 0:
        return {
            "role": "runtime",
            "label": "Runtime",
            "necessity": "required-runtime",
        }
    if manifest_scope == "build" or usage_counts["build"] > 0:
        return {
            "role": "build-time",
            "label": "Build-Time",
            "necessity": "required-build",
        }
    if manifest_scope == "test" or usage_counts["test"] > 0:
        return {
            "role": "test-only",
            "label": "Test Only",
            "necessity": "test-only",
        }
    if not direct_dependency and sum(usage_counts.values()) == 0:
        return {
            "role": "transitive-only",
            "label": "Transitive Only",
            "necessity": "transitive-only",
        }
    if direct_dependency and manifest_scope != "undeclared" and sum(usage_counts.values()) == 0:
        return {
            "role": "probably-unused",
            "label": "Probably Unused",
            "necessity": "candidate-for-removal",
        }
    return {
        "role": "unknown",
        "label": "Unknown",
        "necessity": "review",
    }


def _advice_for_role(package_name: str, role: dict, manifest_scope: str) -> list[str]:
    normalized = package_name.lower().replace("_", "-")
    suggestions: list[str] = []
    if role["role"] == "build-tooling":
        suggestions.append("Tooling package only; prefer patched build tooling in isolated environments rather than long-lived runtime virtualenvs.")
    if role["role"] == "test-only":
        suggestions.append("Test-only dependency; keep it out of runtime images and production bootstrap paths.")
    if role["role"] == "build-time":
        suggestions.append("Build-time dependency; exposure is usually in local builds or CI rather than request-serving runtime paths.")
    if role["role"] == "transitive-only":
        suggestions.append("Transitive package with no direct code usage detected. Usually you prune this by upgrading or removing the parent dependency, not by deleting it directly.")
    if role["necessity"] == "candidate-for-removal":
        suggestions.append("Direct dependency with no clear code usage detected; verify whether it can be removed or replaced with a simpler approach.")
    if role["role"] == "workspace-internal":
        suggestions.append("This is your own workspace package, not a third-party dependency to remove.")
    if normalized == "python-dotenv":
        suggestions.append("If environment variables are injected by shell, supervisor, or deployment config, you may not need dotenv file loading in application code.")
    if normalized == "setuptools":
        suggestions.append("Setuptools is usually packaging infrastructure, not business logic. Rebuilding the environment can be safer than pinning it as an app dependency.")
    if normalized == "pip":
        suggestions.append("pip is installer tooling, not runtime logic. Patch the virtualenv tooling layer rather than treating it as an application feature dependency.")
    if normalized == "starlette" and manifest_scope == "undeclared":
        suggestions.append("This appears to be a transitive framework package. Upgrade through the parent framework compatibility path rather than pinning Starlette blindly.")
    return suggestions


def _environment_based_suggestions(
    environment_label: str,
    direct_dependency: bool,
    usage_counts: dict[str, int],
) -> list[str]:
    suggestions: list[str] = []
    if environment_label == "vendored-lockfile" and not direct_dependency and sum(usage_counts.values()) == 0:
        suggestions.append(
            "Vendored metadata only: this was detected in a nested yarn.lock under node_modules. Do not change app dependencies unless the same package/version also appears in your real lockfile, installed graph, or code usage."
        )
        suggestions.append(
            "Prefer fixing the parent dependency chain or downgrading this evidence in policy, rather than treating it like a direct runtime package issue."
        )
    if environment_label == "isolated-env":
        suggestions.append(
            "Isolated environment finding: handle this in the specific virtualenv or tool environment, not as a main app runtime dependency."
        )
    return suggestions


def _usage_based_suggestions(package_name: str, role: dict, usage_rows: list[dict]) -> list[str]:
    hits = [
        hit
        for row in usage_rows
        for hit in row.get("hits", [])
    ]
    suggestions: list[str] = []
    if role["role"] in {"build-time", "build-tooling", "test-only"} and len(hits) == 1:
        suggestions.append(
            "Only one concrete usage was detected. Consider whether this can be replaced with a simpler built-in script or a narrower tool."
        )
    normalized = package_name.lower().replace("_", "-")
    if normalized == "playwright" and len(hits) == 1:
        suggestions.append(
            "Playwright is only used in one smoke script here. If browser-level verification is not required, a lighter HTTP-level smoke check could remove this dependency."
        )
    return suggestions


def _upgrade_risk(
    package_name: str,
    current_version: str,
    target_version: str | None,
    role: dict,
    usage_counts: dict[str, int],
) -> dict:
    if not target_version:
        return {
            "impact": "unknown",
            "label": "unknown risk",
            "reason": "no clean upgrade target was derived automatically",
        }
    base = classify_upgrade_jump(current_version, target_version)
    if base["impact"] == "high":
        return base
    if role["role"] == "test-only":
        return {
            **base,
            "reason": base["reason"] + "; package appears test-only, so runtime breakage risk is lower",
        }
    if role["role"] in {"build-time", "build-tooling"} and base["impact"] == "medium":
        return {
            **base,
            "reason": base["reason"] + "; package appears build-scoped rather than serving live requests",
        }
    if role["role"] == "runtime" and package_name.lower() in CORE_RUNTIME_PACKAGES and base["impact"] == "medium":
        return {
            "impact": "high",
            "label": "higher minor jump",
            "reason": base["reason"] + "; package is a core runtime dependency with broad application usage",
        }
    if role["role"] == "runtime" and usage_counts["runtime"] >= 10 and base["impact"] == "low":
        return {
            **base,
            "reason": base["reason"] + "; package is widely referenced in runtime code, so validate carefully despite the small version jump",
        }
    return base


def _risk_bucket(
    severity: str | None,
    role: dict,
    direct_dependency: bool,
    usage_count: int,
    signals: list[str],
    *,
    environment_label: str,
    known_exploited: bool,
    malicious_package: bool,
    exploit_likelihood: dict | None,
) -> dict:
    sev = (severity or "unknown").lower()
    if environment_label == "vendored-lockfile" and usage_count == 0:
        if sev in {"critical", "high", "medium"}:
            return {"bucket": "watch", "label": "Watch"}
        return {"bucket": "low_priority", "label": "Low Priority"}
    high_signal = any(
        item in signals
        for item in {
            "remote code execution",
            "authorization or authentication bypass",
            "arbitrary file write",
            "command injection",
            "server-side request forgery",
        }
    )
    if malicious_package:
        return {"bucket": "act_now", "label": "Act Now"}
    if known_exploited:
        return {"bucket": "act_now", "label": "Act Now"}
    if exploit_likelihood and exploit_likelihood["level"] == "high" and sev in {"critical", "high"}:
        return {"bucket": "act_now", "label": "Act Now"}
    if exploit_likelihood and exploit_likelihood["level"] == "high" and sev == "medium":
        return {"bucket": "fix_this_week", "label": "Fix This Week"}
    if environment_label in {"transitive-installed", "lockfile-only"} and not direct_dependency and usage_count == 0:
        if sev in {"critical", "high", "medium"}:
            return {"bucket": "watch", "label": "Watch"}
        return {"bucket": "low_priority", "label": "Low Priority"}
    if sev in {"critical", "high"} and high_signal and role["role"] in {"runtime", "unknown"}:
        return {"bucket": "act_now", "label": "Act Now"}
    if sev in {"critical", "high"} and (direct_dependency or usage_count > 0) and role["role"] == "runtime":
        return {"bucket": "act_now", "label": "Act Now"}
    if sev in {"critical", "high"}:
        return {"bucket": "fix_this_week", "label": "Fix This Week"}
    if sev == "medium" and role["role"] == "runtime" and (direct_dependency or usage_count > 0):
        return {"bucket": "fix_this_week", "label": "Fix This Week"}
    if sev == "medium":
        return {"bucket": "watch", "label": "Watch"}
    if sev == "unknown" and signals:
        return {"bucket": "watch", "label": "Watch"}
    return {"bucket": "low_priority", "label": "Low Priority"}


def _bucket_sort_key(bucket: str) -> int:
    order = {"act_now": 0, "fix_this_week": 1, "watch": 2, "low_priority": 3}
    return order.get(bucket, 9)


def _package_bucket_override(item: dict) -> dict | None:
    if item.get("environment_label") == "vendored-lockfile" and item.get("usage_hit_count", 0) == 0:
        severity = (item.get("highest_severity") or "unknown").lower()
        if severity in {"critical", "high", "medium"}:
            return {"bucket": "watch", "label": "Watch"}
        return {"bucket": "low_priority", "label": "Low Priority"}
    if (
        item.get("environment_label") in {"transitive-installed", "lockfile-only"}
        and item.get("usage_hit_count", 0) == 0
        and not item.get("direct_dependency")
    ):
        severity = (item.get("highest_severity") or "unknown").lower()
        if severity in {"critical", "high", "medium"}:
            return {"bucket": "watch", "label": "Watch"}
        return {"bucket": "low_priority", "label": "Low Priority"}
    return None


def _confidence_label(item: dict) -> dict:
    environment = item.get("environment_label")
    usage = item.get("usage_hit_count", 0)
    direct = bool(item.get("direct_dependency"))
    role = item.get("role")
    if environment == "runtime" and (direct or usage > 0):
        return {
            "level": "high",
            "label": "High Confidence",
            "reason": "Matches a runtime-linked package with direct dependency or code-usage evidence.",
        }
    if environment in {"transitive-installed", "lockfile-only"}:
        return {
            "level": "medium",
            "label": "Medium Confidence",
            "reason": "Matches the installed or resolved dependency graph, but not a directly-used runtime package.",
        }
    if environment == "isolated-env":
        return {
            "level": "separate",
            "label": "Separate Environment",
            "reason": "Matches a package inside an isolated virtual environment rather than the main app runtime.",
        }
    if environment == "vendored-lockfile":
        return {
            "level": "low",
            "label": "Low Confidence",
            "reason": "Matches vendored nested lockfile metadata under node_modules, not a confirmed active dependency.",
        }
    if role in {"build-time", "build-tooling", "test-only"}:
        return {
            "level": "medium",
            "label": "Medium Confidence",
            "reason": "Matches a non-runtime package in the project dependency graph.",
        }
    return {
        "level": "medium",
        "label": "Medium Confidence",
        "reason": "Matches a package/version finding, but evidence is not strongly tied to runtime usage.",
    }


def _exploit_likelihood(config: GuardianConfig, epss: dict | None) -> dict | None:
    if not epss:
        return None
    score = epss.get("score")
    percentile = epss.get("percentile")
    if percentile is not None and percentile >= config.epss_high_percentile:
        return {"level": "high", "label": "High Exploit Likelihood"}
    if score is not None and score >= config.epss_high_score:
        return {"level": "high", "label": "High Exploit Likelihood"}
    if percentile is not None and percentile >= 0.75:
        return {"level": "elevated", "label": "Elevated Exploit Likelihood"}
    if score is not None and score >= 0.05:
        return {"level": "elevated", "label": "Elevated Exploit Likelihood"}
    return {"level": "low", "label": "Low Exploit Likelihood"}


def _issue_labels(
    issue: dict,
    exploit_likelihood: dict | None,
    *,
    package_contexts: list[dict] | None = None,
) -> list[str]:
    labels = ["Known Vulnerable"]
    if issue.get("malicious_package"):
        labels.append("Malicious Package")
    if issue.get("known_exploited"):
        labels.append("Known Exploited")
    if exploit_likelihood and exploit_likelihood["level"] in {"high", "elevated"}:
        labels.append(exploit_likelihood["label"])
    if package_contexts and all(item.get("environment_label") == "vendored-lockfile" for item in package_contexts):
        labels.append("Vendored Metadata Only")
    return labels


def _environment_label(
    occurrences: list[dict],
    role: dict,
    usage_counts: dict[str, int],
) -> str:
    source_types = {item.get("source_type") for item in occurrences}
    if occurrences and all(_is_isolated_env_occurrence(item) for item in occurrences):
        return "isolated-env"
    if occurrences and all(_is_vendored_lockfile_occurrence(item) for item in occurrences):
        return "vendored-lockfile"
    if role["role"] == "runtime" or usage_counts["runtime"] > 0:
        return "runtime"
    if role["role"] in {"build-time", "build-tooling"} or usage_counts["build"] > 0:
        return "build-tooling"
    if role["role"] == "test-only" or usage_counts["test"] > 0:
        return "test-tooling"
    if "npm-lockfile" in source_types and "npm-node_modules" not in source_types:
        return "lockfile-only"
    return "transitive-installed"

