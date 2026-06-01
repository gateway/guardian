"""Prioritized package queue builders for daily briefs and remediation review."""

from __future__ import annotations

from collections import defaultdict

from .intel import severity_rank
from .triage_rules import _bucket_sort_key, _confidence_label, _package_bucket_override, _risk_bucket
from .triage_signals import advisory_link_sort_key, keyword_signals


"""Aggregate enriched issues into package queues and install-gate summaries."""


def daily_brief(enriched: list[dict]) -> dict:
    by_bucket: dict[str, int] = defaultdict(int)
    for issue in enriched:
        by_bucket[issue["risk_label"]] += 1
    top_actions = []
    for issue in enriched[:5]:
        top_actions.append(
            {
                "risk": issue["risk_label"],
                "issue": issue["canonical_key"],
                "summary": issue.get("summary"),
                "actions": issue["actions"][:2],
                "suggestions": issue.get("suggestions", [])[:2],
            }
        )
    if top_actions:
        headline = (
            f"{by_bucket.get('Act Now', 0)} act now, "
            f"{by_bucket.get('Fix This Week', 0)} fix this week, "
            f"{by_bucket.get('Watch', 0)} watch"
        )
    else:
        headline = "No open package issues detected"
    return {
        "headline": headline,
        "by_risk_label": dict(by_bucket),
        "top_actions": top_actions,
    }


def package_remediation_queue(enriched: list[dict]) -> list[dict]:
    grouped: dict[tuple[str, str, str], dict] = {}
    for issue in enriched:
        for package in issue["packages"]:
            key = (package["ecosystem"], package["package_name"], package["version"])
            current = grouped.get(key)
            if current is None:
                current = {
                    "ecosystem": package["ecosystem"],
                    "package_name": package["package_name"],
                    "normalized_name": package["normalized_name"],
                    "version": package["version"],
                    "highest_severity": issue.get("severity") or "unknown",
                    "risk_bucket": issue["risk_bucket"],
                    "risk_label": issue["risk_label"],
                    "role": package["role"],
                    "role_label": package["role_label"],
                    "environment_label": package["environment_label"],
                    "root_cause": package["root_cause"],
                    "necessity": package["necessity"],
                    "direct_dependency": package["direct_dependency"],
                    "manifest_scope": package["manifest_scope"],
                    "manifest_paths": package["manifest_paths"],
                    "usage_by_kind": package["usage_by_kind"],
                    "usage": package["usage"],
                    "usage_hit_count": package["usage_hit_count"],
                    "recommended_clean_version": package["recommended_clean_version"],
                    "first_fixed_version": package["first_fixed_version"],
                    "latest_version": package["latest_version"],
                    "upgrade_risk": package["upgrade_risk"],
                    "root_paths": package["root_paths"],
                    "classification_labels": set(issue.get("classification_labels", [])),
                    "known_exploited": bool(issue.get("known_exploited")),
                    "known_ransomware_use": bool(issue.get("known_ransomware_use")),
                    "malicious_package": bool(issue.get("malicious_package")),
                    "exploit_likelihood": issue.get("exploit_likelihood"),
                    "epss": issue.get("epss"),
                    "signals": set(issue.get("signals", [])),
                    "issue_keys": set(),
                    "issue_summaries": [],
                    "advisory_sources": set(),
                    "advisory_links": set(),
                    "advisory_count": 0,
                    "severity_counts": defaultdict(int),
                    "suggestions": set(package.get("suggestions", [])),
                    "notes": [],
                }
                grouped[key] = current
            current["advisory_count"] += 1
            severity = issue.get("severity") or "unknown"
            current["severity_counts"][severity] += 1
            if severity_rank(severity) > severity_rank(current["highest_severity"]):
                current["highest_severity"] = severity
            if _bucket_sort_key(issue["risk_bucket"]) < _bucket_sort_key(current["risk_bucket"]):
                current["risk_bucket"] = issue["risk_bucket"]
                current["risk_label"] = issue["risk_label"]
            current["classification_labels"].update(issue.get("classification_labels", []))
            current["known_exploited"] = current["known_exploited"] or bool(issue.get("known_exploited"))
            current["known_ransomware_use"] = current["known_ransomware_use"] or bool(issue.get("known_ransomware_use"))
            current["malicious_package"] = current["malicious_package"] or bool(issue.get("malicious_package"))
            if issue.get("exploit_likelihood") and (
                current.get("exploit_likelihood") is None
                or issue["exploit_likelihood"]["level"] == "high"
            ):
                current["exploit_likelihood"] = issue.get("exploit_likelihood")
            if issue.get("epss") and (
                current.get("epss") is None
                or (issue["epss"].get("score") or -1) > (current["epss"].get("score") or -1)
            ):
                current["epss"] = issue.get("epss")
            current["signals"].update(issue.get("signals", []))
            current["issue_keys"].add(issue["canonical_key"])
            current["advisory_sources"].update(issue.get("sources", []))
            current["advisory_links"].update(issue.get("urls", []))
            if issue.get("summary") and issue["summary"] not in current["issue_summaries"]:
                current["issue_summaries"].append(issue["summary"])
            current["suggestions"].update(issue.get("suggestions", []))

    results = []
    for item in grouped.values():
        bucket_override = _package_bucket_override(item)
        if bucket_override is not None:
            item["risk_bucket"] = bucket_override["bucket"]
            item["risk_label"] = bucket_override["label"]
        recommended = item["recommended_clean_version"]
        first_fixed = item["first_fixed_version"]
        if recommended:
            item["notes"].append(
                f"Recommended clean target {recommended} was rechecked against current OSV, GHSA, and local catalog sources with no known matches."
            )
        elif first_fixed:
            item["notes"].append(
                f"First fixed version appears to be {first_fixed}, but Guardian could not prove a fully clean target above it from current sources."
            )
        else:
            item["notes"].append("No automatic safe target was derived; this package needs manual remediation review.")
        if item["latest_version"] and recommended and item["latest_version"] != recommended:
            item["notes"].append(
                f"Latest published version is {item['latest_version']}; Guardian recommends the lowest clean target first to reduce breakage risk."
            )
        if item["root_cause"]:
            if item["root_cause"]["kind"] == "npm-explain":
                item["notes"].append(
                    f"Direct parent path points to: {item['root_cause']['summary']}."
                )
            elif item["root_cause"]["kind"] == "vendored-lockfile":
                item["notes"].append(item["root_cause"]["summary"])
                item["notes"].append(
                    "Treat this as lower-confidence unless the same package/version also appears in package-lock.json, an installed dependency tree, or real code usage."
                )
            elif item["root_cause"]["kind"] == "isolated-env":
                item["notes"].append(item["root_cause"]["summary"])
        if item["malicious_package"]:
            item["notes"].append("At least one advisory source classifies this as malicious software rather than an accidental vulnerability.")
        if item["known_exploited"]:
            note = "CISA KEV marks this vulnerability as exploited in the wild."
            if item["known_ransomware_use"]:
                note += " CISA also marks it as used in ransomware campaigns."
            item["notes"].append(note)
        if item["epss"]:
            score = item["epss"].get("score")
            percentile = item["epss"].get("percentile")
            if score is not None or percentile is not None:
                parts = []
                if score is not None:
                    parts.append(f"score {score:.3f}")
                if percentile is not None:
                    parts.append(f"percentile {percentile:.3f}")
                item["notes"].append(f"FIRST EPSS estimates exploit activity likelihood with {' and '.join(parts)}.")
        if item["role"] == "test-only":
            item["notes"].append("This package appears limited to tests or test harness code, so runtime exposure is lower.")
        elif item["role"] in {"build-time", "build-tooling"}:
            item["notes"].append("This package appears in build or local tooling paths rather than request-serving runtime code.")
        item["confidence"] = _confidence_label(item)
        item["classification_labels"] = sorted(item["classification_labels"])
        item["signals"] = sorted(item["signals"])
        item["issue_keys"] = sorted(item["issue_keys"])
        item["issue_summaries"] = item["issue_summaries"][:3]
        item["advisory_sources"] = sorted(item["advisory_sources"])
        item["advisory_links"] = sorted(item["advisory_links"], key=advisory_link_sort_key)
        item["severity_counts"] = dict(item["severity_counts"])
        item["suggestions"] = sorted(item["suggestions"])
        results.append(item)
    results.sort(
        key=lambda item: (
            _bucket_sort_key(item["risk_bucket"]),
            -severity_rank(item["highest_severity"]),
            item["package_name"].lower(),
            item["version"],
        )
    )
    return results


def summarize_candidate(findings: list[dict]) -> dict:
    highest = "unknown"
    for item in findings:
        if severity_rank(item.get("severity")) > severity_rank(highest):
            highest = item.get("severity") or "unknown"
    signals = keyword_signals(" ".join(filter(None, [item.get("summary", "") for item in findings])))
    bucket = _risk_bucket(
        highest,
        {"role": "runtime"},
        True,
        1,
        signals,
        environment_label="runtime",
        known_exploited=False,
        malicious_package=False,
        exploit_likelihood=None,
    )
    return {
        "highest_severity": highest,
        "risk_bucket": bucket["bucket"],
        "risk_label": bucket["label"],
        "signals": signals,
    }

