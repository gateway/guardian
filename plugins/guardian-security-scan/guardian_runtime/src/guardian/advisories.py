"""Refresh vulnerability findings by matching inventory records against OSV, GHSA, NVD, KEV, EPSS, and local malicious-package catalogs."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from .config import GuardianConfig
from .db import Database
from .intel import (
    choose_best_severity,
    choose_primary_url,
    extract_ghsa_aliases,
    extract_ghsa_severity,
    extract_nvd_details_url,
    extract_nvd_severity,
    extract_nvd_summary,
    extract_osv_primary_url,
    extract_osv_severity,
    merge_aliases,
)
from .sources import EPSSClient, GitHubAdvisoriesClient, KEVClient, LocalCatalogMatcher, NVDClient, OSVClient
from .osv_matching import osv_explicit_versions_exclude_package


def refresh_findings(
    config: GuardianConfig,
    db: Database,
    *,
    include_ghsa: bool = False,
    ghsa_max_packages: int = 50,
    root_paths: list[str] | None = None,
    enrich_live: bool = True,
) -> dict:
    """Refresh open findings for the current package inventory.

    OSV is the broad default source. GHSA is optional and bounded because exact
    advisory queries can be expensive on large repos. Local catalogs are always
    checked so malicious-package campaigns can be caught without network access.
    """

    package_rows = [
        dict(row)
        for row in db.current_packages()
        if row["ecosystem"] in {"npm", "pypi", "go", "rubygems", "packagist"}
        and (not root_paths or row["root_path"] in root_paths)
    ]
    packages = _unique_package_versions(package_rows)
    osv = OSVClient(config)
    epss = EPSSClient(config)
    ghsa = GitHubAdvisoriesClient(config)
    kev = KEVClient(config)
    nvd = NVDClient(config)
    local_catalog = LocalCatalogMatcher(config)

    source_errors: dict[str, str] = {}
    try:
        osv_results = osv.query_batch(packages) if packages else []
    except Exception as exc:
        source_errors["osv"] = str(exc)
        osv_results = [{} for _package in packages]
    osv_by_package = {}
    for package, result in zip(packages, osv_results):
        key = (package["ecosystem"], package["normalized_name"], package["version"])
        osv_by_package[key] = result.get("vulns", [])

    # GHSA exact-match checks are intentionally capped. When a repo is too large,
    # Guardian prefers direct dependencies first instead of spending a scan budget
    # on every transitive package.
    ghsa_target_packages: dict[tuple[str, str, str], dict] = {}
    if include_ghsa:
        unique_packages = _unique_package_versions(packages)
        if len(unique_packages) <= ghsa_max_packages:
            selected = unique_packages
        else:
            direct_candidates = [
                pkg for pkg in packages
                if pkg.get("direct_dependency") == 1
            ]
            selected = _unique_package_versions(direct_candidates)[:ghsa_max_packages]
        ghsa_target_packages = {
            (pkg["ecosystem"], pkg["normalized_name"], pkg["version"]): pkg
            for pkg in selected
        }

    total_findings = 0
    ghsa_error: str | None = None
    ghsa_exact_cache: dict[tuple[str, str, str], list[dict]] = {}
    if ghsa_target_packages:
        ghsa_exact_cache, ghsa_error = _fetch_ghsa_exact_matches(
            ghsa,
            ghsa_target_packages,
            max_workers=config.ghsa_max_workers,
        )
    for package in packages:
        # Each package is resolved source-by-source, then stale findings for that
        # package/source are closed. This lets a later scan prove that a fix
        # actually removed the matching vulnerable version.
        key = (package["ecosystem"], package["normalized_name"], package["version"])
        matched_osv_ids = []
        for vuln_stub in osv_by_package.get(key, []):
            advisory_id = vuln_stub["id"]
            try:
                vuln = osv.get_vulnerability(advisory_id)
            except Exception as exc:
                source_errors.setdefault("osv", str(exc))
                vuln = {
                    "id": advisory_id,
                    "aliases": vuln_stub.get("aliases") or [],
                    "summary": vuln_stub.get("summary"),
                    "affected": vuln_stub.get("affected") or [],
                }
            if osv_explicit_versions_exclude_package(vuln, package):
                continue
            matched_osv_ids.append(advisory_id)
            osv_aliases = vuln.get("aliases") or []
            osv_severity = extract_osv_severity(vuln)
            osv_details_url = extract_osv_primary_url(vuln)
            summary = vuln.get("summary")
            ghsa_enrichment = None
            nvd_enrichment = None
            if enrich_live and osv_severity is None:
                ghsa_candidates = [
                    item
                    for item in merge_aliases([advisory_id], osv_aliases)
                    if item.upper().startswith("GHSA-")
                ]
                for ghsa_id in ghsa_candidates:
                    try:
                        ghsa_enrichment = ghsa.query_by_ghsa_id(ghsa_id)
                    except Exception as err:
                        if ghsa_error is None:
                            ghsa_error = str(err)
                        ghsa_enrichment = None
                    if ghsa_enrichment is not None:
                        break
            if enrich_live and osv_severity is None and extract_ghsa_severity(ghsa_enrichment or {}) is None:
                cve_candidates = [
                    item
                    for item in merge_aliases(osv_aliases, extract_ghsa_aliases(ghsa_enrichment or {}))
                    if item.upper().startswith("CVE-")
                ]
                for cve_id in cve_candidates:
                    try:
                        nvd_enrichment = nvd.query_by_cve_id(cve_id)
                    except Exception:
                        source_errors.setdefault("nvd", "NVD enrichment request failed")
                        nvd_enrichment = None
                    if nvd_enrichment is not None:
                        break
            severity = choose_best_severity(
                osv_severity,
                extract_ghsa_severity(ghsa_enrichment or {}),
                extract_nvd_severity(nvd_enrichment or {}),
            )
            details_url = choose_primary_url(
                (ghsa_enrichment or {}).get("html_url"),
                osv_details_url,
                extract_nvd_details_url(nvd_enrichment or {}),
            )
            summary = summary or (ghsa_enrichment or {}).get("summary") or extract_nvd_summary(nvd_enrichment or {})
            aliases = merge_aliases(
                osv_aliases,
                extract_ghsa_aliases(ghsa_enrichment or {}),
                [record.get("cve", {}).get("id") for record in [nvd_enrichment] if record],
            )
            cve_aliases = [
                alias
                for alias in aliases
                if alias.upper().startswith("CVE-")
            ]
            merged_raw = {
                "osv": vuln,
                "ghsa": ghsa_enrichment,
                "nvd": nvd_enrichment,
            }
            db.upsert_advisory(
                source="osv",
                advisory_id=advisory_id,
                summary=summary,
                severity=severity,
                details_url=details_url,
                aliases=aliases,
                published_at=vuln.get("published"),
                updated_at=vuln.get("modified"),
                withdrawn_at=vuln.get("withdrawn"),
                raw_json=merged_raw,
            )
            for cve_id in (cve_aliases if enrich_live else []):
                try:
                    kev_entry = kev.query_by_cve_id(cve_id)
                except Exception as exc:
                    source_errors.setdefault("kev", str(exc))
                    kev_entry = None
                if kev_entry is not None:
                    db.upsert_advisory(
                        source="kev",
                        advisory_id=cve_id,
                        summary=kev_entry.get("vulnerabilityName") or kev_entry.get("shortDescription"),
                        severity=None,
                        details_url=config.kev_human_url,
                        aliases=[cve_id],
                        published_at=kev_entry.get("dateAdded"),
                        updated_at=kev_entry.get("dateAdded"),
                        withdrawn_at=None,
                        raw_json=kev_entry,
                    )
                try:
                    epss_entry = epss.query_by_cve_id(cve_id)
                except Exception as exc:
                    source_errors.setdefault("epss", str(exc))
                    epss_entry = None
                if epss_entry is not None:
                    db.upsert_advisory(
                        source="epss",
                        advisory_id=cve_id,
                        summary=(
                            f"EPSS score {epss_entry.get('epss')} "
                            f"(percentile {epss_entry.get('percentile')})"
                        ),
                        severity=None,
                        details_url=f"{config.epss_api_url}?cve={cve_id}",
                        aliases=[cve_id],
                        published_at=epss_entry.get("date"),
                        updated_at=epss_entry.get("date"),
                        withdrawn_at=None,
                        raw_json=epss_entry,
                    )
            db.upsert_finding(
                ecosystem=package["ecosystem"],
                package_name=package["package_name"],
                normalized_name=package["normalized_name"],
                version=package["version"],
                advisory_source="osv",
                advisory_id=advisory_id,
                severity=severity,
                details_url=details_url,
                evidence="OSV exact version match",
            )
            total_findings += 1
        if "osv" not in source_errors:
            db.resolve_stale_findings(
                ecosystem=package["ecosystem"],
                normalized_name=package["normalized_name"],
                version=package["version"],
                advisory_source="osv",
                active_advisory_ids=matched_osv_ids,
            )

        ghsa_ids = []
        if key in ghsa_target_packages:
            ghsa_matches = ghsa_exact_cache.get(key, [])
            for advisory in ghsa_matches:
                advisory_id = advisory["ghsa_id"]
                ghsa_ids.append(advisory_id)
                severity = extract_ghsa_severity(advisory)
                db.upsert_advisory(
                    source="ghsa",
                    advisory_id=advisory_id,
                    summary=advisory.get("summary"),
                    severity=severity,
                    details_url=advisory.get("html_url"),
                    aliases=extract_ghsa_aliases(advisory),
                    published_at=advisory.get("published_at"),
                    updated_at=advisory.get("updated_at"),
                    withdrawn_at=advisory.get("withdrawn_at"),
                    raw_json=advisory,
                )
                db.upsert_finding(
                    ecosystem=package["ecosystem"],
                    package_name=package["package_name"],
                    normalized_name=package["normalized_name"],
                    version=package["version"],
                    advisory_source="ghsa",
                    advisory_id=advisory_id,
                    severity=severity,
                    details_url=advisory.get("html_url"),
                    evidence="GHSA exact version match",
                )
                total_findings += 1
            if ghsa_error is None:
                db.resolve_stale_findings(
                    ecosystem=package["ecosystem"],
                    normalized_name=package["normalized_name"],
                    version=package["version"],
                    advisory_source="ghsa",
                    active_advisory_ids=ghsa_ids,
                )

        # Local catalogs are exact-match malicious/campaign intelligence. They do
        # not need live network access and are useful for supply-chain incidents
        # that may not be fully represented in general vulnerability databases.
        local_matches = local_catalog.match(package["ecosystem"], package["package_name"], package["version"])
        local_ids = []
        for entry in local_matches:
            advisory_id = entry["id"]
            local_ids.append(advisory_id)
            db.upsert_advisory(
                source="local-catalog",
                advisory_id=advisory_id,
                summary=entry.get("name"),
                severity=entry.get("severity"),
                details_url=entry.get("source"),
                aliases=entry.get("aliases") or [],
                published_at=None,
                updated_at=None,
                withdrawn_at=None,
                raw_json=entry,
            )
            db.upsert_finding(
                ecosystem=package["ecosystem"],
                package_name=package["package_name"],
                normalized_name=package["normalized_name"],
                version=package["version"],
                advisory_source="local-catalog",
                advisory_id=advisory_id,
                severity=entry.get("severity"),
                details_url=entry.get("source"),
                evidence=f"Local exact-match catalog hit ({entry.get('_catalog_file')})",
            )
            total_findings += 1
        db.resolve_stale_findings(
            ecosystem=package["ecosystem"],
            normalized_name=package["normalized_name"],
            version=package["version"],
            advisory_source="local-catalog",
            active_advisory_ids=local_ids,
        )

    if ghsa_error is not None:
        ghsa_skipped_reason = ghsa_error
    elif ghsa_target_packages or not include_ghsa:
        ghsa_skipped_reason = None
    else:
        ghsa_skipped_reason = (
            f"package count {len(packages)} exceeds ghsa_max_packages={ghsa_max_packages} "
            "and no direct dependency subset was available"
        )

    return {
        "packages_checked": len(packages),
        "package_rows_considered": len(package_rows),
        "findings_refreshed": total_findings,
        "ghsa_included": bool(ghsa_target_packages),
        "ghsa_target_count": len(ghsa_target_packages),
        "ghsa_error": ghsa_error,
        "ghsa_skipped_reason": ghsa_skipped_reason,
        "live_enrichment": enrich_live,
        "source_errors": source_errors,
        "http_stats": {
            "osv": osv.http.stats(),
            "ghsa": ghsa.http.stats(),
            "kev": kev.http.stats(),
            "epss": epss.http.stats(),
            "nvd": nvd.http.stats(),
        },
        "api_policy": {
            "ghsa_max_workers": config.ghsa_max_workers,
            "api_request_min_interval_seconds": config.api_request_min_interval_seconds,
            "osv_batch_delay_seconds": config.osv_batch_delay_seconds,
            "http_max_retries": config.http_max_retries,
            "http_cache_ttl_seconds": config.http_cache_ttl_seconds,
        },
    }


def _unique_package_versions(packages: list[dict]) -> list[dict]:
    """Return one inventory row per ecosystem/name/version tuple."""

    selected = []
    seen: set[tuple[str, str, str]] = set()
    for package in packages:
        key = (package["ecosystem"], package["normalized_name"], package["version"])
        if key in seen:
            continue
        seen.add(key)
        selected.append(package)
    return selected


def _fetch_ghsa_exact_matches(
    ghsa: GitHubAdvisoriesClient,
    target_packages: dict[tuple[str, str, str], dict],
    *,
    max_workers: int = 2,
) -> tuple[dict[tuple[str, str, str], list[dict]], str | None]:
    cache: dict[tuple[str, str, str], list[dict]] = {}
    first_error: str | None = None
    if not target_packages:
        return cache, None
    worker_count = max(1, min(max_workers, len(target_packages)))
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = {
            executor.submit(
                ghsa.query_exact,
                package["ecosystem"],
                package["package_name"],
                package["version"],
            ): key
            for key, package in target_packages.items()
        }
        for future in as_completed(futures):
            key = futures[future]
            try:
                cache[key] = future.result()
            except Exception as err:
                cache[key] = []
                if first_error is None:
                    first_error = str(err)
    return cache, first_error
