"""Issue grouping and package evidence summarization for operator reports."""

from __future__ import annotations

import json

from .db import Database
from .intel import advisory_aliases_from_row, canonical_issue_key, severity_rank


"""Normalize raw findings and advisories into canonical issue groups."""


def _advisory_raw(advisory: dict | None) -> dict:
    if not advisory:
        return {}
    raw = advisory.get("raw_json")
    if isinstance(raw, dict):
        return raw
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {}


def _apply_advisory_context(issue: dict, advisory: dict | None) -> None:
    if not advisory:
        return
    raw = _advisory_raw(advisory)
    source = advisory.get("source")
    if source == "local-catalog" and raw.get("source_type") != "official-advisory-db":
        issue["malicious_package"] = True
    if source == "kev":
        issue["known_exploited"] = True
        if str(raw.get("knownRansomwareCampaignUse", "")).lower() == "known":
            issue["known_ransomware_use"] = True
        if raw.get("dateAdded"):
            issue["kev_date_added"] = raw.get("dateAdded")
    if source == "epss":
        try:
            score = float(raw.get("epss"))
        except (TypeError, ValueError):
            score = None
        try:
            percentile = float(raw.get("percentile"))
        except (TypeError, ValueError):
            percentile = None
        current = issue.get("epss")
        if current is None or (score is not None and score > (current.get("score") or -1)):
            issue["epss"] = {
                "score": score,
                "percentile": percentile,
                "date": raw.get("date"),
            }
    ghsa_type = None
    if source == "ghsa":
        ghsa_type = raw.get("type")
    elif source == "osv":
        ghsa_type = (raw.get("ghsa") or {}).get("type")
    if ghsa_type == "malware":
        issue["malicious_package"] = True


def open_findings(db: Database) -> list[dict]:
    return [dict(row) for row in db.open_findings()]


def grouped_issues(db: Database) -> list[dict]:
    advisory_map = db.advisory_map()
    advisory_groups: dict[str, list[dict]] = {}
    for advisory in advisory_map.values():
        advisory_dict = dict(advisory)
        key = canonical_issue_key(
            advisory_dict["source"],
            advisory_dict["advisory_id"],
            advisory_aliases_from_row(advisory_dict),
        )
        advisory_groups.setdefault(key, []).append(advisory_dict)
    grouped: dict[str, dict] = {}
    for finding in open_findings(db):
        advisory = advisory_map.get((finding["advisory_source"], finding["advisory_id"]))
        advisory_dict = dict(advisory) if advisory is not None else None
        aliases = advisory_aliases_from_row(advisory_dict)
        key = canonical_issue_key(finding["advisory_source"], finding["advisory_id"], aliases)
        issue = grouped.setdefault(
            key,
            {
                "canonical_key": key,
                "severity": finding.get("severity") or "unknown",
                "summary": advisory_dict.get("summary") if advisory_dict else None,
                "aliases": set(aliases),
                "sources": [],
                "packages": [],
                "urls": set(),
                "known_exploited": False,
                "known_ransomware_use": False,
                "malicious_package": False,
                "epss": None,
                "kev_date_added": None,
            },
        )
        _apply_advisory_context(issue, advisory_dict)
        if severity_rank(finding.get("severity")) > severity_rank(issue["severity"]):
            issue["severity"] = finding.get("severity") or "unknown"
        if advisory_dict and advisory_dict.get("summary") and not issue.get("summary"):
            issue["summary"] = advisory_dict["summary"]
        issue["sources"].append(f"{finding['advisory_source']}:{finding['advisory_id']}")
        issue["packages"].append(
            {
                "ecosystem": finding["ecosystem"],
                "package_name": finding["package_name"],
                "version": finding["version"],
            }
        )
        if finding.get("details_url"):
            issue["urls"].add(finding["details_url"])

    for key, advisories in advisory_groups.items():
        issue = grouped.get(key)
        if issue is None:
            continue
        for advisory in advisories:
            _apply_advisory_context(issue, advisory)
            issue["aliases"].update(advisory_aliases_from_row(advisory))
            if severity_rank(advisory.get("severity")) > severity_rank(issue["severity"]):
                issue["severity"] = advisory.get("severity") or "unknown"
            if advisory.get("details_url"):
                issue["urls"].add(advisory["details_url"])
            if advisory.get("summary") and not issue.get("summary"):
                issue["summary"] = advisory["summary"]
            issue["sources"].append(f"{advisory['source']}:{advisory['advisory_id']}")

    results = []
    for issue in grouped.values():
        issue["sources"] = sorted(set(issue["sources"]))
        issue["aliases"] = sorted(issue["aliases"])
        seen_pkg = set()
        packages = []
        for package in issue["packages"]:
            key = (package["ecosystem"], package["package_name"], package["version"])
            if key in seen_pkg:
                continue
            seen_pkg.add(key)
            packages.append(package)
        issue["packages"] = sorted(packages, key=lambda item: (item["ecosystem"], item["package_name"], item["version"]))
        issue["urls"] = sorted(issue["urls"])
        results.append(issue)
    results.sort(key=lambda item: (-severity_rank(item["severity"]), item["canonical_key"]))
    return results
