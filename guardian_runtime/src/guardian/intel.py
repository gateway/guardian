from __future__ import annotations

import json
from typing import Iterable


SEVERITY_ORDER = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "unknown": 0,
    None: 0,
}

CANONICAL_SEVERITY_MAP = {
    "critical": "critical",
    "crit": "critical",
    "high": "high",
    "important": "high",
    "moderate": "medium",
    "medium": "medium",
    "med": "medium",
    "low": "low",
    "minor": "low",
    "unknown": "unknown",
    "none": "low",
}

CANONICAL_ALIAS_PREFIX_ORDER = ("CVE-", "GHSA-", "PYSEC-", "OSV-")


def severity_rank(value: str | None) -> int:
    return SEVERITY_ORDER.get((value or "").lower(), 0)


def normalize_severity(value: str | int | float | None) -> str | None:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return severity_from_score(float(value))
    text = str(value).strip()
    if not text:
        return None
    lowered = text.lower()
    if lowered in CANONICAL_SEVERITY_MAP:
        return CANONICAL_SEVERITY_MAP[lowered]
    try:
        return severity_from_score(float(text))
    except ValueError:
        return None


def severity_from_score(score: float | None) -> str | None:
    if score is None:
        return None
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "low"


def choose_best_severity(*candidates: str | None) -> str | None:
    best: str | None = None
    for candidate in candidates:
        normalized = normalize_severity(candidate)
        if severity_rank(normalized) > severity_rank(best):
            best = normalized
    return best


def choose_primary_url(*candidates: str | None) -> str | None:
    for candidate in candidates:
        if candidate:
            return candidate
    return None


def merge_aliases(*groups: Iterable[str] | None) -> list[str]:
    merged: list[str] = []
    seen: set[str] = set()
    for group in groups:
        if not group:
            continue
        for item in group:
            if not item:
                continue
            text = str(item).strip()
            if not text or text in seen:
                continue
            merged.append(text)
            seen.add(text)
    return merged


def canonical_issue_key(advisory_source: str, advisory_id: str, aliases: Iterable[str] | None = None) -> str:
    alias_list = merge_aliases(aliases, [advisory_id])
    for prefix in CANONICAL_ALIAS_PREFIX_ORDER:
        matches = sorted(item for item in alias_list if item.upper().startswith(prefix))
        if matches:
            return matches[0]
    return sorted(alias_list)[0] if alias_list else f"{advisory_source}:{advisory_id}"


def extract_osv_severity(vuln: dict) -> str | None:
    candidates: list[str | int | float | None] = [
        vuln.get("database_specific", {}).get("severity"),
    ]
    for affected in vuln.get("affected", []):
        candidates.append(affected.get("database_specific", {}).get("severity"))
        candidates.append(affected.get("ecosystem_specific", {}).get("severity"))
        for item in affected.get("severity", []):
            candidates.append(item.get("score"))
    for item in vuln.get("severity", []):
        candidates.append(item.get("score"))
    best: str | None = None
    for candidate in candidates:
        best = choose_best_severity(best, normalize_severity(candidate))
    return best


def extract_osv_primary_url(vuln: dict) -> str | None:
    database_source = vuln.get("database_specific", {}).get("source")
    if database_source:
        return database_source
    for reference in vuln.get("references", []):
        url = reference.get("url")
        if url:
            return url
    if vuln.get("id"):
        return f"https://osv.dev/{vuln['id']}"
    return None


def extract_ghsa_aliases(advisory: dict) -> list[str]:
    aliases = []
    if advisory.get("ghsa_id"):
        aliases.append(advisory["ghsa_id"])
    if advisory.get("cve_id"):
        aliases.append(advisory["cve_id"])
    for item in advisory.get("identifiers", []):
        if item.get("type") in {"GHSA", "CVE"} and item.get("value"):
            aliases.append(item["value"])
    return merge_aliases(aliases)


def extract_ghsa_severity(advisory: dict) -> str | None:
    severity = normalize_severity(advisory.get("severity"))
    if severity:
        return severity
    cvss = advisory.get("cvss") or {}
    severity = normalize_severity(cvss.get("score"))
    if severity:
        return severity
    cvss_severities = advisory.get("cvss_severities") or {}
    for key in ("cvss_v4", "cvss_v3"):
        section = cvss_severities.get(key) or {}
        severity = normalize_severity(section.get("score"))
        if severity:
            return severity
    return None


def extract_nvd_severity(record: dict) -> str | None:
    cve = record.get("cve", {})
    metrics = cve.get("metrics", {})
    for family in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for item in metrics.get(family, []):
            severity = normalize_severity(item.get("cvssData", {}).get("baseSeverity"))
            if severity:
                return severity
            severity = normalize_severity(item.get("baseSeverity"))
            if severity:
                return severity
            severity = normalize_severity(item.get("cvssData", {}).get("baseScore"))
            if severity:
                return severity
    return None


def extract_nvd_summary(record: dict) -> str | None:
    cve = record.get("cve", {})
    for description in cve.get("descriptions", []):
        if description.get("lang") == "en" and description.get("value"):
            return description["value"]
    return None


def extract_nvd_details_url(record: dict) -> str | None:
    cve = record.get("cve", {})
    cve_id = cve.get("id")
    if cve_id:
        return f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    return None


def advisory_aliases_from_row(advisory_row: dict | None) -> list[str]:
    if not advisory_row:
        return []
    try:
        stored = json.loads(advisory_row.get("aliases_json") or "[]")
    except json.JSONDecodeError:
        stored = []
    return merge_aliases(stored, [advisory_row.get("advisory_id")])
