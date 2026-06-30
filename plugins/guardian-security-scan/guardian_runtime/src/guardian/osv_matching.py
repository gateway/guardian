"""OSV advisory matching helpers shared by scans and install gates."""

from __future__ import annotations

from .util import normalize_ecosystem_for_osv


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
