"""OpenSSF malicious-packages sparse selection and OSV record normalization."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Callable

from .intel import merge_aliases
from .osv_matching import osv_record_is_malicious, osv_version_is_affected
from .util import normalize_package_name, slugify


GitRunner = Callable[[list[str]], str]


def openssf_entries_for_packages(
    *,
    source_dir: Path,
    package_index: dict[tuple[str, str], dict],
    source_id: str,
    confidence: str,
    sparse_paths: list[str] | None = None,
) -> tuple[list[dict], dict]:
    """Convert current-inventory OpenSSF records into exact-version entries."""

    entries: list[dict] = []
    stats = {
        "json_files_read": 0,
        "malicious_records_matched": 0,
        "withdrawn_records_skipped": 0,
        "non_malicious_records_skipped": 0,
        "valid_records_no_version_match": 0,
    }
    paths = sparse_paths or openssf_sparse_paths_for_packages(source_dir, package_index)
    for path in _candidate_files(source_dir, paths):
        stats["json_files_read"] += 1
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            stats["non_malicious_records_skipped"] += 1
            continue
        if record.get("withdrawn"):
            stats["withdrawn_records_skipped"] += 1
            continue
        if not osv_record_is_malicious(record):
            stats["non_malicious_records_skipped"] += 1
            continue
        matched = _record_versions(record, package_index)
        if not matched:
            stats["valid_records_no_version_match"] += 1
            continue
        stats["malicious_records_matched"] += 1
        advisory_id = str(record.get("id") or path.stem)
        for (ecosystem, normalized_name), versions in matched.items():
            package = package_index[(ecosystem, normalized_name)]
            references = record.get("references") or []
            reference_url = next(
                (item.get("url") for item in references if item.get("url")),
                f"https://osv.dev/vulnerability/{advisory_id}",
            )
            entries.append({
                "id": f"{source_id}:{advisory_id}:{slugify(package['display_name'])}",
                "name": record.get("summary") or advisory_id,
                "ecosystem": ecosystem,
                "package": package["display_name"],
                "versions": sorted(versions),
                "severity": "critical",
                "source": reference_url,
                "source_type": "malicious-package-db",
                "confidence": confidence,
                "aliases": merge_aliases(record.get("aliases") or [], [advisory_id]),
                "upstream_source": "openssf-malicious-packages",
            })
    return entries, stats


def openssf_sparse_paths_for_packages(
    source_dir: Path,
    package_index: dict[tuple[str, str], dict],
    *,
    git_runner: GitRunner | None = None,
) -> list[str]:
    """Return the smallest safe sparse-checkout set for an inventory."""

    paths: set[str] = {"README.md", "LICENSE"}
    pypi_dir_map: dict[str, str] | None = None
    for (ecosystem, normalized_name), package in sorted(package_index.items()):
        if ecosystem == "npm":
            package_path = _safe_package_path(package["display_name"], scoped=True)
        elif ecosystem == "pypi":
            if pypi_dir_map is None:
                pypi_dir_map = _ecosystem_dir_map(source_dir, "pypi", git_runner=git_runner)
            package_path = pypi_dir_map.get(normalized_name) or _safe_package_path(
                package["display_name"], scoped=False
            )
        else:
            continue
        if package_path:
            paths.add(f"osv/malicious/{ecosystem}/{package_path}")
    return sorted(paths)


def _record_versions(
    record: dict,
    package_index: dict[tuple[str, str], dict],
) -> dict[tuple[str, str], list[str]]:
    """Intersect one OSV record with exact versions in the current inventory."""

    matched: dict[tuple[str, str], list[str]] = {}
    for affected in record.get("affected") or []:
        affected_package = affected.get("package") or {}
        ecosystem = str(affected_package.get("ecosystem") or "").lower()
        if ecosystem not in {"npm", "pypi"}:
            continue
        package_name = str(affected_package.get("name") or "")
        key = (ecosystem, normalize_package_name(ecosystem, package_name))
        package = package_index.get(key)
        if package is None:
            continue
        versions = [
            version
            for version in package["versions"]
            if osv_version_is_affected(record, ecosystem, package_name, version)
        ]
        if versions:
            matched[key] = versions
    return matched


def _ecosystem_dir_map(
    source_dir: Path,
    ecosystem: str,
    *,
    git_runner: GitRunner | None,
) -> dict[str, str]:
    args = [
        "git", "-C", str(source_dir), "ls-tree", "-d", "--name-only",
        f"HEAD:osv/malicious/{ecosystem}",
    ]
    try:
        output = git_runner(args) if git_runner else _run_git(args)
    except RuntimeError:
        return {}
    return {
        normalize_package_name(ecosystem, line.strip()): line.strip()
        for line in output.splitlines()
        if line.strip()
    }


def _safe_package_path(package_name: str, *, scoped: bool) -> str | None:
    """Reject traversal and malformed package names before constructing paths."""

    parts = package_name.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        return None
    if len(parts) > (2 if scoped and package_name.startswith("@") else 1):
        return None
    return "/".join(parts)


def _candidate_files(source_dir: Path, sparse_paths: list[str]) -> list[Path]:
    files: list[Path] = []
    for relative in sparse_paths:
        target = source_dir / relative
        if target.is_dir():
            files.extend(sorted(target.glob("MAL-*.json")))
    return files


def _run_git(args: list[str]) -> str:
    result = subprocess.run(args, text=True, capture_output=True, timeout=240)
    if result.returncode != 0:
        raise RuntimeError(f"{' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout
