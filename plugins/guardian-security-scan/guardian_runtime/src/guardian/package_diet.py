"""Package-diet workflow for unused dependency and replace-with-native review."""

from __future__ import annotations

"""Package-diet scan orchestration.

This module keeps repo traversal and report assembly separate from scoring
rules and source-usage analysis so the cleanup workflow stays maintainable.
"""

import json
from pathlib import Path

from .package_diet_rules import (
    apply_fanout_adjustment,
    assess_package,
    bloat_score,
    buckets,
    dynamic_reference_assessment,
    priority_rank,
    summary,
)
from .package_diet_usage import (
    SKIP_DIRS,
    dynamic_package_reference,
    symbols_from_usage,
    usage_density,
    wrapper_fanout,
)
from .usage import build_npm_usage_index
from .util import normalize_package_name, utc_now


LARGE_REPO_MANIFEST_THRESHOLD = 50


def package_diet_scan(root_path: str, *, limit: int = 50, usage_limit: int = 8) -> dict:
    root = Path(root_path).resolve()
    manifests = _npm_manifests(root)
    usage_index = build_npm_usage_index(str(root), limit_per_package=usage_limit)
    packages = [
        _assess_manifest_package(root, manifest, package, usage_index, len(manifests) > LARGE_REPO_MANIFEST_THRESHOLD)
        for manifest in manifests
        for package in manifest["packages"]
    ]
    for package in packages:
        apply_fanout_adjustment(package)
        package["bloat_score"] = bloat_score(package)
    packages.sort(key=lambda item: (priority_rank(item["classification"]), -item["bloat_score"], item["scope"], item["name"]))
    grouped = buckets(packages)
    return {
        "root_path": str(root),
        "generated_at": utc_now(),
        "package_count": len(packages),
        "summary": summary(packages),
        "top_candidates": {name: items[:5] for name, items in grouped.items()},
        "packages": packages[:limit],
    }


def _assess_manifest_package(
    root: Path,
    manifest: dict,
    package: dict,
    usage_index: dict[str, dict],
    large_repo: bool,
) -> dict:
    usage = usage_index.get(package["normalized_name"]) or _empty_usage(root)
    symbols = symbols_from_usage(package["name"], usage["hits"])
    assessment = assess_package(package, usage, symbols)
    if assessment["classification"] == "Unused Candidate":
        usage, symbols, assessment = _maybe_downgrade_dynamic_reference(root, package, usage, symbols, assessment)
    fanout = (
        wrapper_fanout(root, usage["hits"], package["name"])
        if _should_check_fanout(usage, assessment, large_repo)
        else {"top_symbol": None, "max_hit_count": 0, "candidates": []}
    )
    return {
        **package,
        "manifest_path": manifest["path"],
        "manifest_relative_path": _relative(root, Path(manifest["path"])),
        "usage": usage,
        "usage_symbols": symbols,
        "usage_density": usage_density(usage, symbols),
        "wrapper_fanout": fanout,
        **assessment,
    }


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
    if assessment["classification"] not in {"Review", "Replace Candidate"}:
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
