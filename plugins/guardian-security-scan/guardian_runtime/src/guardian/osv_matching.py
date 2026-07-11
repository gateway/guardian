"""OSV advisory matching helpers shared by scans and install gates."""

from __future__ import annotations

from .util import normalize_ecosystem_for_osv, normalize_package_name
from .versions import compare_versions


def osv_explicit_versions_exclude_package(vuln: dict, package: dict) -> bool:
    """Return true when OSV's explicit affected versions exclude this version.

    OSV records can combine an open-ended affected range with an explicit
    `versions` list. When the explicit list exists for the matching
    package/ecosystem, Guardian treats that list as the stronger signal to avoid
    stale broad-range false positives.
    """

    package_name = str(package.get("package_name") or "").lower()
    ecosystem = normalize_ecosystem_for_osv(str(package.get("ecosystem") or "")).lower()
    version = str(package.get("version") or "")
    matching_version_sets: list[set[str]] = []
    for affected in vuln.get("affected") or []:
        affected_package = affected.get("package") or {}
        affected_name = str(affected_package.get("name") or "").lower()
        affected_ecosystem = str(affected_package.get("ecosystem") or "").lower()
        if affected_name != package_name or affected_ecosystem != ecosystem:
            continue
        versions = affected.get("versions") or []
        if isinstance(versions, list) and versions:
            matching_version_sets.append({str(item) for item in versions})
    return bool(matching_version_sets) and all(version not in versions for versions in matching_version_sets)


def osv_record_is_malicious(vuln: dict) -> bool:
    """Recognize OSV/OpenSSF malware records without relying on advisory prose."""

    if str(vuln.get("id") or "").upper().startswith("MAL-"):
        return True
    database_specific = vuln.get("database_specific") or {}
    for origin in database_specific.get("malicious-packages-origins") or []:
        if str(origin.get("source") or "").lower() in {
            "ghsa-malware",
            "ossf-package-analysis",
            "openssf-package-analysis",
        }:
            return True
    return False


def osv_version_is_affected(vuln: dict, ecosystem: str, package_name: str, version: str) -> bool:
    """Match one exact version against OSV explicit versions and ordered events."""

    normalized_name = normalize_package_name(ecosystem, package_name)
    osv_ecosystem = normalize_ecosystem_for_osv(ecosystem).lower()
    for affected in vuln.get("affected") or []:
        package = affected.get("package") or {}
        if str(package.get("ecosystem") or "").lower() != osv_ecosystem:
            continue
        if normalize_package_name(ecosystem, str(package.get("name") or "")) != normalized_name:
            continue
        explicit = {str(item) for item in affected.get("versions") or []}
        if explicit:
            if version in explicit:
                return True
            continue
        for range_item in affected.get("ranges") or []:
            if _version_matches_osv_events(version, range_item.get("events") or []):
                return True
    return False


def _version_matches_osv_events(version: str, events: list[dict]) -> bool:
    """Evaluate OSV introduced/fixed/last_affected/limit transitions conservatively."""

    affected = False
    for event in events:
        if "introduced" in event:
            introduced = str(event["introduced"])
            if introduced == "0" or compare_versions(version, introduced) >= 0:
                affected = True
        if "fixed" in event and compare_versions(version, str(event["fixed"])) >= 0:
            affected = False
        if "last_affected" in event and compare_versions(version, str(event["last_affected"])) > 0:
            affected = False
        if "limit" in event and compare_versions(version, str(event["limit"])) >= 0:
            affected = False
    return affected
