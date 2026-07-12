"""Package-diet orchestration for usage, footprint, maintenance, and vendor review."""

from __future__ import annotations

import json
import shlex
from datetime import datetime, timezone
from pathlib import Path

from .config import GuardianConfig
from .db import Database
from .package_diet_footprint import npm_lockfile_footprints
from .package_diet_rules import (
    apply_fanout_adjustment,
    apply_maintenance_adjustment,
    assess_package,
    bloat_score,
    buckets,
    dynamic_reference_assessment,
    priority_rank,
    summary,
    usage_unavailable_assessment,
)
from .package_diet_usage import (
    SKIP_DIRS,
    dynamic_package_reference,
    symbols_from_usage,
    usage_density,
    wrapper_fanout,
)
from .usage import RIPGREP_MISSING_NOTE, build_npm_usage_index, ripgrep_available
from .util import normalize_package_name, utc_now


LARGE_REPO_MANIFEST_THRESHOLD = 50


def package_diet_scan(
    root_path: str,
    *,
    limit: int = 50,
    usage_limit: int = 8,
    config: GuardianConfig | None = None,
    db: Database | None = None,
) -> dict:
    """Build a read-only diet report from source usage and cached footprint evidence."""

    root = Path(root_path).resolve()
    manifests = _npm_manifests(root)
    usage_available = ripgrep_available()
    usage_index = build_npm_usage_index(str(root), limit_per_package=usage_limit)
    lock_footprints = npm_lockfile_footprints(root)
    packages = [
        _assess_manifest_package(
            root,
            manifest,
            package,
            usage_index,
            len(manifests) > LARGE_REPO_MANIFEST_THRESHOLD,
            lock_footprints.get(package["normalized_name"]),
            config=config,
            db=db,
            usage_available=usage_available,
        )
        for manifest in manifests
        for package in manifest["packages"]
    ]
    for package in packages:
        apply_fanout_adjustment(package)
        apply_maintenance_adjustment(package)
        package["bloat_score"] = bloat_score(package)
    packages.sort(key=lambda item: (priority_rank(item["classification"]), -item["bloat_score"], item["scope"], item["name"]))
    grouped = buckets(packages)
    footprint_count = sum(1 for item in packages if (item.get("footprint") or {}).get("status") != "unavailable")
    metadata_count = sum(1 for item in packages if (item.get("footprint") or {}).get("registry_metadata_cached"))
    return {
        "root_path": str(root),
        "generated_at": utc_now(),
        "package_count": len(packages),
        "summary": summary(packages),
        "usage_scan": {
            "status": "available" if usage_available else "unavailable",
            "note": (
                None
                if usage_available
                else f"{RIPGREP_MISSING_NOTE}; usage-based classifications were downgraded to Review."
            ),
        },
        "footprint_coverage": {
            "lockfile_packages": footprint_count,
            "registry_metadata_packages": metadata_count,
            "status": "available" if footprint_count or metadata_count else "usage-only",
            "note": (
                "Footprint data came from local lockfiles and cached registry metadata; no registry requests were made."
                if footprint_count or metadata_count
                else "Footprint metadata was unavailable; this complete report uses source-usage evidence only."
            ),
        },
        "top_candidates": {name: items[:5] for name, items in grouped.items()},
        "packages": packages[:limit],
    }


def _assess_manifest_package(
    root: Path,
    manifest: dict,
    package: dict,
    usage_index: dict[str, dict],
    large_repo: bool,
    lock_footprint: dict | None,
    *,
    config: GuardianConfig | None,
    db: Database | None,
    usage_available: bool = True,
) -> dict:
    usage = usage_index.get(package["normalized_name"]) or _empty_usage(root)
    symbols = symbols_from_usage(package["name"], usage["hits"])
    enriched = _enrich_package(package, lock_footprint, config=config, db=db)
    assessment = assess_package(enriched, usage, symbols)
    if not usage_available:
        # Without rg there is no usage evidence at all; a zero hit count must
        # never be presented as proof that a package is unused or replaceable.
        usage = {**usage, "scan_status": "unavailable", "scan_note": RIPGREP_MISSING_NOTE}
        if assessment["classification"] != "Keep":
            assessment = usage_unavailable_assessment()
    elif assessment["classification"] == "Unused Candidate":
        usage, symbols, assessment = _maybe_downgrade_dynamic_reference(root, enriched, usage, symbols, assessment)
    fanout = (
        wrapper_fanout(root, usage["hits"], enriched["name"])
        if usage_available and _should_check_fanout(usage, assessment, large_repo)
        else {"top_symbol": None, "max_hit_count": 0, "candidates": []}
    )
    result = {
        **enriched,
        "manifest_path": manifest["path"],
        "manifest_relative_path": _relative(root, Path(manifest["path"])),
        "usage": usage,
        "usage_symbols": symbols,
        "usage_density": usage_density(usage, symbols),
        "wrapper_fanout": fanout,
        **assessment,
    }
    if result["classification"] == "Vendor Candidate" and result.get("resolved_version"):
        result["watchlist_command"] = (
            "guardian watchlist add-vendored --ecosystem npm "
            f"--name {shlex.quote(result['name'])} "
            f"--version {shlex.quote(result['resolved_version'])} "
            f"--project-root {shlex.quote(str(root))} "
            f"--license {shlex.quote(result['license'])}"
        )
    return result


def _enrich_package(
    package: dict,
    lock_footprint: dict | None,
    *,
    config: GuardianConfig | None,
    db: Database | None,
) -> dict:
    lock_footprint = lock_footprint or {}
    version = lock_footprint.get("version")
    registry = None
    if version and config is not None and db is not None:
        registry = db.registry_metadata(
            "npm",
            package["normalized_name"],
            version,
            ttl_seconds=config.registry_metadata_ttl_seconds,
        )
    license_name = lock_footprint.get("license") or (registry or {}).get("license")
    published_at = (registry or {}).get("published_at")
    maintainer_count = (registry or {}).get("maintainer_count")
    deprecated = bool((registry or {}).get("deprecated"))
    age_months = _age_months(published_at)
    maintenance_dead = bool(
        age_months is not None
        and age_months > 30
        and (deprecated or (isinstance(maintainer_count, int) and maintainer_count <= 1))
    )
    return {
        **package,
        "resolved_version": version,
        "license": license_name,
        "upstream_url": (registry or {}).get("repo_url"),
        "pure_source": lock_footprint.get("pure_source"),
        "footprint": {
            "status": "available" if lock_footprint or registry else "unavailable",
            "transitive_count": lock_footprint.get("transitive_count"),
            "size_bytes": (registry or {}).get("size_bytes"),
            "registry_metadata_cached": registry is not None,
            "lockfile": lock_footprint.get("lockfile"),
        },
        "maintenance": {
            "published_at": published_at,
            "age_months": round(age_months, 1) if age_months is not None else None,
            "maintainer_count": maintainer_count,
            "deprecated": deprecated,
            "maintenance_dead": maintenance_dead,
            "reason": (
                "The last cached publish is over 30 months old and the package is deprecated or has one maintainer."
                if maintenance_dead
                else None
            ),
        },
        "watchlist_command": None,
    }


def _age_months(value: str | None) -> float | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - parsed).total_seconds() / (30.4375 * 86400)


def _maybe_downgrade_dynamic_reference(
    root: Path,
    package: dict,
    usage: dict,
    symbols: list[str],
    assessment: dict,
) -> tuple[dict, list[str], dict]:
    dynamic_usage = dynamic_package_reference(root, package["name"])
    if not dynamic_usage["hit_count"]:
        return usage, symbols, assessment
    return (
        dynamic_usage,
        symbols_from_usage(package["name"], dynamic_usage["hits"]),
        dynamic_reference_assessment(),
    )


def _should_check_fanout(usage: dict, assessment: dict, large_repo: bool) -> bool:
    if not usage.get("hit_count"):
        return False
    if assessment["classification"] not in {"Review", "Replace Candidate", "Vendor Candidate"}:
        return False
    return not large_repo or assessment["classification"] == "Replace Candidate"


def _npm_manifests(root: Path) -> list[dict]:
    manifests = []
    for path in sorted(root.rglob("package.json")):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        manifests.append({"path": str(path), "packages": _manifest_packages(payload)})
    return manifests


def _manifest_packages(payload: dict) -> list[dict]:
    packages = []
    for field, scope in (
        ("dependencies", "runtime"),
        ("optionalDependencies", "optional"),
        ("devDependencies", "development"),
        ("peerDependencies", "peer"),
    ):
        values = payload.get(field)
        if not isinstance(values, dict):
            continue
        for name, spec in sorted(values.items()):
            packages.append(
                {
                    "ecosystem": "npm",
                    "name": name,
                    "normalized_name": normalize_package_name("npm", name),
                    "specifier": str(spec),
                    "scope": scope,
                    "manifest_field": field,
                }
            )
    return packages


def _empty_usage(root: Path) -> dict:
    return {"root_path": str(root), "hit_count": 0, "hits": []}


def _relative(root: Path, path: Path) -> str:
    try:
        return str(path.relative_to(root))
    except Exception:
        return str(path)
