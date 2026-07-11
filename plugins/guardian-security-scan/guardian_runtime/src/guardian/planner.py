"""Candidate resolver for safer upgrade target selection and local catalog awareness."""

from __future__ import annotations

from functools import cmp_to_key

from .config import GuardianConfig
from .intel import choose_best_severity, extract_ghsa_severity, extract_osv_severity, merge_aliases
from .osv_matching import osv_explicit_versions_exclude_package
from .registries import LatestVersionResolver
from .sources import GitHubAdvisoriesClient, LocalCatalogMatcher, OSVClient
from .versions import compare_versions


def fixed_versions_from_osv(vuln: dict, ecosystem: str, package_name: str) -> list[str]:
    target_ecosystem = {"npm": "npm", "pypi": "PyPI"}.get(ecosystem, ecosystem)
    package_lower = package_name.lower()
    results: list[str] = []
    for affected in vuln.get("affected", []):
        package = affected.get("package", {})
        if package.get("ecosystem") != target_ecosystem:
            continue
        if (package.get("name") or "").lower() != package_lower:
            continue
        for range_item in affected.get("ranges", []):
            for event in range_item.get("events", []):
                fixed = event.get("fixed")
                if fixed:
                    results.append(fixed)
    return sorted(set(results), key=cmp_to_key(compare_versions))


def highest_fixed_boundary(findings: list[dict]) -> str | None:
    """Return the minimum version high enough to clear every matched advisory."""

    fixed = {
        version
        for finding in findings
        for version in (finding.get("fixed_versions") or [])
        if version
    }
    return max(fixed, key=cmp_to_key(compare_versions)) if fixed else None


class CandidateResolver:
    def __init__(self, config: GuardianConfig):
        self.config = config
        self.osv = OSVClient(config)
        self.ghsa = GitHubAdvisoriesClient(config)
        self.local_catalog = LocalCatalogMatcher(config)
        self.registries = LatestVersionResolver(config)
        self._assessment_cache: dict[tuple[str, str, str], dict] = {}
        self._clean_target_cache: dict[tuple[str, str, str, str | None], dict] = {}

    def assess_version(self, ecosystem: str, package_name: str, version: str) -> dict:
        key = (ecosystem, package_name, version)
        if key in self._assessment_cache:
            return self._assessment_cache[key]
        package = {
            "ecosystem": ecosystem,
            "package_name": package_name,
            "version": version,
        }
        findings: list[dict] = []
        try:
            osv_results = self.osv.query_batch([package])[0].get("vulns", [])
        except Exception:
            osv_results = []
        for vuln_stub in osv_results:
            advisory_id = vuln_stub["id"]
            try:
                vuln = self.osv.get_vulnerability(advisory_id)
            except Exception:
                vuln = {
                    "id": advisory_id,
                    "aliases": [],
                    "summary": vuln_stub.get("summary"),
                    "affected": [],
                }
            if osv_explicit_versions_exclude_package(vuln, package):
                continue
            ghsa_enrichment = None
            for ghsa_id in [item for item in merge_aliases([advisory_id], vuln.get("aliases") or []) if item.upper().startswith("GHSA-")]:
                try:
                    ghsa_enrichment = self.ghsa.query_by_ghsa_id(ghsa_id)
                except Exception:
                    ghsa_enrichment = None
                if ghsa_enrichment is not None:
                    break
            findings.append(
                {
                    "source": "osv",
                    "id": advisory_id,
                    "severity": choose_best_severity(
                        extract_osv_severity(vuln),
                        extract_ghsa_severity(ghsa_enrichment or {}),
                    ),
                    "summary": vuln.get("summary") or (ghsa_enrichment or {}).get("summary"),
                    "fixed_versions": fixed_versions_from_osv(vuln, ecosystem, package_name),
                }
            )
        try:
            ghsa_results = self.ghsa.query_exact(ecosystem, package_name, version)
        except Exception:
            ghsa_results = []
        for advisory in ghsa_results:
            findings.append(
                {
                    "source": "ghsa",
                    "id": advisory["ghsa_id"],
                    "severity": extract_ghsa_severity(advisory),
                    "summary": advisory.get("summary"),
                    "fixed_versions": [],
                }
            )
        for entry in self.local_catalog.match(ecosystem, package_name, version):
            findings.append(
                {
                    "source": "local-catalog",
                    "id": entry["id"],
                    "severity": entry.get("severity"),
                    "summary": entry.get("name"),
                    "fixed_versions": [],
                }
            )
        payload = {
            "ecosystem": ecosystem,
            "package_name": package_name,
            "version": version,
            "findings": findings,
        }
        self._assessment_cache[key] = payload
        return payload

    def recommended_clean_version(
        self,
        ecosystem: str,
        package_name: str,
        current_version: str,
        *,
        minimum_version: str | None = None,
    ) -> dict:
        cache_key = (ecosystem, package_name, current_version, minimum_version)
        if cache_key in self._clean_target_cache:
            return self._clean_target_cache[cache_key]
        try:
            available_versions = self.registries.available_versions(ecosystem, package_name)
        except Exception:
            available_versions = []
        try:
            latest_version = self.registries.latest_version(ecosystem, package_name)
        except Exception:
            latest_version = None
        floor = minimum_version or current_version
        if latest_version and latest_version not in available_versions:
            available_versions = sorted(set(available_versions + [latest_version]), key=cmp_to_key(compare_versions))
        candidate = self._first_available_at_or_after(available_versions, floor)
        visited: set[str] = set()
        while candidate and candidate not in visited:
            visited.add(candidate)
            try:
                assessment = self.assess_version(ecosystem, package_name, candidate)
            except Exception:
                break
            if not assessment["findings"]:
                payload = {
                    "recommended_clean_version": candidate,
                    "latest_version": latest_version,
                    "candidate_findings": [],
                    "available_versions_considered": sorted(visited, key=cmp_to_key(compare_versions)),
                }
                self._clean_target_cache[cache_key] = payload
                return payload
            next_floor = candidate
            fixed_candidates: list[str] = []
            for finding in assessment["findings"]:
                fixed_candidates.extend(finding.get("fixed_versions") or [])
            fixed_candidates = [item for item in fixed_candidates if compare_versions(item, candidate) > 0]
            if fixed_candidates:
                fixed_candidates.sort(key=cmp_to_key(compare_versions))
                next_floor = fixed_candidates[-1]
            else:
                next_candidate = self._next_available_after(available_versions, candidate)
                next_floor = next_candidate or candidate
            if next_floor == candidate:
                candidate = self._next_available_after(available_versions, candidate)
            else:
                candidate = self._first_available_at_or_after(available_versions, next_floor)
        try:
            current_findings = self.assess_version(ecosystem, package_name, current_version)["findings"]
        except Exception:
            current_findings = []
        payload = {
            "recommended_clean_version": None,
            "latest_version": latest_version,
            "candidate_findings": current_findings,
            "available_versions_considered": sorted(visited, key=cmp_to_key(compare_versions)),
        }
        self._clean_target_cache[cache_key] = payload
        return payload

    def _first_available_at_or_after(self, versions: list[str], floor: str) -> str | None:
        for candidate in versions:
            if compare_versions(candidate, floor) >= 0:
                return candidate
        return None

    def _next_available_after(self, versions: list[str], current: str) -> str | None:
        for candidate in versions:
            if compare_versions(candidate, current) > 0:
                return candidate
        return None
