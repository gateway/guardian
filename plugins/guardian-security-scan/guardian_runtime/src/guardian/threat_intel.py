"""Threat-intelligence ingestion for advisory YAML sources and generated local exact-match catalogs."""

from __future__ import annotations

import json
import math
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from .advisory_yaml import PARSER_VERSION, audit_advisory_yaml_corpus, parse_advisory_yaml
from .config import GuardianConfig
from .db import Database
from .integrity import sha256_file
from .intel import merge_aliases, normalize_severity, severity_from_score, severity_rank
from .openssf_intel import openssf_entries_for_packages, openssf_sparse_paths_for_packages
from .source_contract import threat_intel_source_contract
from .util import normalize_package_name, slugify, utc_now, write_json, write_text
from .versions import version_range_is_supported, version_satisfies_range


DEFAULT_THREAT_INTEL_SOURCES = {
    "schema_version": "1.0",
    "sources": [
        {
            "id": "gitlab-advisory-db",
            "type": "gitlab-advisory-db",
            "enabled": True,
            "repo": "https://gitlab.com/gitlab-org/advisories-community.git",
            "license": "MIT",
            "ecosystems": ["npm", "pypi"],
            "severity_floor": "high",
            "stale_after_hours": 24,
            "confidence": "Official Advisory Database",
            "description": "MIT-licensed open-source edition of the GitLab Advisory Database.",
        },
        {
            "id": "openssf-malicious-packages",
            "type": "openssf-malicious-packages",
            "enabled": False,
            "repo": "https://github.com/ossf/malicious-packages.git",
            "license": "Apache-2.0",
            "ecosystems": ["npm", "pypi"],
            "stale_after_hours": 24,
            "confidence": "OpenSSF Malicious Packages",
            "description": "OpenSSF OSV-format reports for packages identified as malicious or unwanted.",
        }
    ],
}


def ensure_default_threat_intel_sources(config: GuardianConfig) -> dict:
    path = Path(config.threat_intel_sources_path)
    if not path.exists():
        write_json(path, DEFAULT_THREAT_INTEL_SOURCES)
        return load_threat_intel_sources(path)
    payload = load_threat_intel_sources(path)
    existing_ids = {item.get("id") for item in payload["sources"]}
    missing = [item for item in DEFAULT_THREAT_INTEL_SOURCES["sources"] if item["id"] not in existing_ids]
    if missing:
        payload["sources"].extend(missing)
        write_json(path, payload)
    return payload


def load_threat_intel_sources(path: Path) -> dict:
    if not path.exists():
        raise RuntimeError(f"threat-intel source config does not exist: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema_version") != "1.0":
        raise RuntimeError(f"unsupported threat-intel source schema: {data.get('schema_version')}")
    if not isinstance(data.get("sources"), list):
        raise RuntimeError("threat-intel source config must contain a sources list")
    return data


def ingest_threat_intel(
    config: GuardianConfig,
    db: Database,
    *,
    source_config_path: Path | None = None,
    root_paths: list[str] | None = None,
    ecosystems: list[str] | None = None,
    severity_floor: str | None = None,
    include_malicious_sources: bool = False,
) -> dict:
    source_config = load_threat_intel_sources(source_config_path or Path(config.threat_intel_sources_path))
    packages = _current_unique_packages(db, root_paths=root_paths, ecosystems=ecosystems)
    package_index = _index_packages(packages)
    entries: list[dict] = []
    source_reports: list[dict] = []

    for source in source_config["sources"]:
        source_type = source.get("type")
        enabled_for_mode = source.get("enabled", True) or (
            include_malicious_sources and source_type == "openssf-malicious-packages"
        )
        if not enabled_for_mode:
            source_reports.append({"id": source.get("id"), "status": "disabled"})
            continue
        if source_type not in {"gitlab-advisory-db", "openssf-malicious-packages"}:
            source_reports.append({"id": source.get("id"), "status": "skipped", "reason": f"unsupported type {source_type}"})
            continue
        effective_floor = severity_floor or source.get("severity_floor") or "high"
        selected_index = _filter_index_for_source(package_index, source.get("ecosystems") or [])
        started = time.monotonic()
        try:
            if source_type == "gitlab-advisory-db":
                report = ingest_gitlab_advisory_db_source(config, source, selected_index, effective_floor)
            else:
                report = ingest_openssf_malicious_source(config, source, selected_index)
        except Exception as exc:
            report = {
                "id": source.get("id"),
                "type": source_type,
                "status": "error",
                "error": str(exc),
                "entries_written": 0,
                "elapsed_seconds": round(time.monotonic() - started, 4),
                "source_health": _source_health_for_failed_source(config, source),
                "entries": [],
            }
        report["elapsed_seconds"] = report.get("elapsed_seconds", round(time.monotonic() - started, 4))
        source_reports.append(report)
        entries.extend(report["entries"])

    timestamp = utc_now().replace(":", "-")
    catalog_path = Path(config.local_catalog_dirs[0]) / f"guardian-threat-intel-{timestamp}.json"
    report_json_path = Path(config.reports_dir) / f"threat-intel-ingest-{timestamp}.json"
    report_md_path = Path(config.reports_dir) / f"threat-intel-ingest-{timestamp}.md"
    catalog = {
        "schema_version": "0.1.0",
        "_comment": (
            "Generated by Guardian threat-intel ingest. Entries are exact package versions "
            "from the current Guardian inventory matched against upstream advisory ranges."
        ),
        "generated_at": utc_now(),
        "parser": PARSER_VERSION,
        "sources": [
            {
                "id": item.get("id"),
                "type": item.get("type"),
                "status": item.get("status"),
                "revision": item.get("revision"),
                "source_health": item.get("source_health"),
                "license": item.get("license"),
            }
            for item in source_reports
        ],
        "entries": sorted(entries, key=lambda item: (item["ecosystem"], item["package"], item["versions"], item["id"])),
    }
    _prune_generated_threat_intel_catalogs(Path(config.local_catalog_dirs[0]))
    write_json(catalog_path, catalog)
    catalog_sha256 = sha256_file(catalog_path)

    failed_sources = [item for item in source_reports if item.get("status") == "error"]
    payload = {
        "status": "partial" if failed_sources else "ok",
        "package_versions_considered": len(packages),
        "root_paths": root_paths or "all-current-roots",
        "ecosystems": ecosystems or "all-supported",
        "severity_floor": severity_floor or "source-default",
        "catalog_path": str(catalog_path),
        "catalog_sha256": catalog_sha256,
        "parser": PARSER_VERSION,
        "report_path": str(report_json_path),
        "markdown_path": str(report_md_path),
        "entries_written": len(entries),
        "source_reports": [
            {key: value for key, value in item.items() if key != "entries"}
            for item in source_reports
        ],
        "source_contracts": [threat_intel_source_contract(item) for item in source_reports],
    }
    write_json(report_json_path, payload)
    write_text(report_md_path, build_threat_intel_markdown(payload))
    return payload


def ingest_gitlab_advisory_db_source(
    config: GuardianConfig,
    source: dict,
    package_index: dict[tuple[str, str], dict],
    severity_floor: str,
) -> dict:
    source_id = source["id"]
    source_dir = _prepare_gitlab_source_dir(config, source)
    paths = _gitlab_sparse_paths_for_packages(source_dir, package_index)
    if source.get("repo") and not source.get("path"):
        _git_sparse_checkout(source_dir, paths)
    entries, stats = gitlab_advisory_entries_for_packages(
        source_dir=source_dir,
        package_index=package_index,
        severity_floor=severity_floor,
        source_id=source_id,
        confidence=source.get("confidence") or "Official Advisory Database",
    )
    return {
        "id": source_id,
        "type": "gitlab-advisory-db",
        "status": "ok",
        "path": str(source_dir),
        "revision": _git_revision(source_dir),
        "source_health": _source_health(source_dir, source),
        "license": source.get("license") or "MIT",
        "parser": PARSER_VERSION,
        "package_directories_requested": len(paths),
        "entries_written": len(entries),
        "severity_floor": severity_floor,
        "entries": entries,
        **stats,
    }


def ingest_openssf_malicious_source(
    config: GuardianConfig,
    source: dict,
    package_index: dict[tuple[str, str], dict],
) -> dict:
    """Sparse-checkout OpenSSF records only for packages in the current inventory."""

    source_id = source["id"]
    source_dir = _prepare_git_source_dir(config, source)
    paths = openssf_sparse_paths_for_packages(
        source_dir,
        package_index,
        git_runner=lambda args: _run_git(args, cwd=None, capture=True).stdout,
    )
    if source.get("repo") and not source.get("path"):
        _git_sparse_checkout(source_dir, paths)
    entries, stats = openssf_entries_for_packages(
        source_dir=source_dir,
        package_index=package_index,
        source_id=source_id,
        confidence=source.get("confidence") or "OpenSSF Malicious Packages",
        sparse_paths=paths,
    )
    return {
        "id": source_id,
        "type": "openssf-malicious-packages",
        "status": "ok",
        "path": str(source_dir),
        "revision": _git_revision(source_dir),
        "source_health": _source_health(source_dir, source),
        "license": source.get("license") or "Apache-2.0",
        "package_directories_requested": len(paths),
        "entries_written": len(entries),
        "entries": entries,
        **stats,
    }


def gitlab_advisory_entries_for_packages(
    *,
    source_dir: Path,
    package_index: dict[tuple[str, str], dict],
    severity_floor: str,
    source_id: str,
    confidence: str,
) -> tuple[list[dict], dict]:
    entries: list[dict] = []
    stats = {
        "yaml_files_read": 0,
        "advisories_matched_by_range": 0,
        "advisories_below_severity_floor": 0,
        "advisories_withdrawn_duplicate_skipped": 0,
        "advisories_unknown_severity": 0,
        "unsupported_range_count": 0,
        "valid_range_no_match_count": 0,
    }
    for advisory_path in _candidate_advisory_files(source_dir, package_index):
        stats["yaml_files_read"] += 1
        advisory = _load_yaml(advisory_path)
        if gitlab_advisory_is_withdrawn_duplicate(advisory):
            stats["advisories_withdrawn_duplicate_skipped"] += 1
            continue
        package_slug = advisory.get("package_slug") or ""
        ecosystem, package_name = _split_package_slug(package_slug)
        if ecosystem is None or package_name is None:
            continue
        normalized = normalize_package_name(ecosystem, package_name)
        package_payload = package_index.get((ecosystem, normalized))
        if package_payload is None:
            continue
        severity = extract_gitlab_advisory_severity(advisory)
        if severity is None:
            stats["advisories_unknown_severity"] += 1
        if severity_rank(severity) < severity_rank(severity_floor):
            stats["advisories_below_severity_floor"] += 1
            continue
        affected_range = advisory.get("affected_range")
        if not version_range_is_supported(affected_range):
            stats["unsupported_range_count"] += 1
            continue
        matched_versions = [
            version
            for version in sorted(package_payload["versions"])
            if version_satisfies_range(version, affected_range)
        ]
        if not matched_versions:
            stats["valid_range_no_match_count"] += 1
            continue
        stats["advisories_matched_by_range"] += 1
        advisory_id = str(advisory.get("identifier") or advisory_path.stem)
        urls = advisory.get("urls") or []
        entries.append(
            {
                "id": f"{source_id}:{advisory_id}",
                "name": advisory.get("title") or advisory_id,
                "ecosystem": ecosystem,
                "package": package_payload["display_name"],
                "versions": matched_versions,
                "severity": severity or "unknown",
                "source": urls[0] if urls else _gitlab_advisory_url(ecosystem, package_name, advisory_id),
                "source_type": "official-advisory-db",
                "confidence": confidence,
                "aliases": merge_aliases(advisory.get("identifiers") or [], [advisory_id]),
                "affected_range": affected_range,
                "fixed_versions": advisory.get("fixed_versions") or [],
                "upstream_source": "gitlab-advisory-db",
            }
        )
    return entries, stats


def gitlab_advisory_is_withdrawn_duplicate(advisory: dict) -> bool:
    title = str(advisory.get("title") or "").lower()
    description = str(advisory.get("description") or "").lower()
    combined = f"{title}\n{description}"
    return (
        "withdrawn because it is a duplicate" in combined
        or "this advisory has been withdrawn" in combined and "duplicate" in combined
        or title.startswith("duplicate advisory:")
    )


def extract_gitlab_advisory_severity(advisory: dict) -> str | None:
    explicit = normalize_severity(advisory.get("severity"))
    if explicit:
        return explicit
    for key in ("cvss_v4", "cvss_v3"):
        score = cvss3_base_score(str(advisory.get(key) or ""))
        severity = severity_from_score(score) if score is not None else None
        if severity:
            return severity
    return normalize_severity(advisory.get("cvss_score"))


def cvss3_base_score(vector: str) -> float | None:
    if not vector.startswith("CVSS:3."):
        return None
    metrics: dict[str, str] = {}
    for part in vector.split("/")[1:]:
        if ":" not in part:
            continue
        key, value = part.split(":", 1)
        metrics[key] = value
    try:
        av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[metrics["AV"]]
        ac = {"L": 0.77, "H": 0.44}[metrics["AC"]]
        scope = metrics["S"]
        if scope == "U":
            pr = {"N": 0.85, "L": 0.62, "H": 0.27}[metrics["PR"]]
        else:
            pr = {"N": 0.85, "L": 0.68, "H": 0.5}[metrics["PR"]]
        ui = {"N": 0.85, "R": 0.62}[metrics["UI"]]
        c = {"H": 0.56, "L": 0.22, "N": 0.0}[metrics["C"]]
        i = {"H": 0.56, "L": 0.22, "N": 0.0}[metrics["I"]]
        a = {"H": 0.56, "L": 0.22, "N": 0.0}[metrics["A"]]
    except KeyError:
        return None
    impact_subscore = 1 - ((1 - c) * (1 - i) * (1 - a))
    if impact_subscore <= 0:
        return 0.0
    exploitability = 8.22 * av * ac * pr * ui
    if scope == "U":
        impact = 6.42 * impact_subscore
        score = min(impact + exploitability, 10)
    else:
        impact = 7.52 * (impact_subscore - 0.029) - 3.25 * pow(impact_subscore - 0.02, 15)
        score = min(1.08 * (impact + exploitability), 10)
    return _round_up_1_decimal(score)


def build_threat_intel_markdown(payload: dict) -> str:
    lines = [
        "# Guardian Threat Intel Ingest",
        "",
        f"- Entries written: `{payload['entries_written']}`",
        f"- Package versions considered: `{payload['package_versions_considered']}`",
        f"- Catalog: `{payload['catalog_path']}`",
        "",
        "## Sources",
    ]
    for source in payload["source_reports"]:
        files_read = source.get("yaml_files_read", source.get("json_files_read", 0))
        lines.append(
            f"- `{source.get('id')}`: {source.get('entries_written', 0)} entries, "
            f"{files_read} advisory files read, revision `{source.get('revision') or 'unknown'}`"
        )
        if source.get("advisories_below_severity_floor"):
            lines.append(f"- `{source.get('id')}` below severity floor: {source['advisories_below_severity_floor']}")
        if source.get("valid_range_no_match_count"):
            lines.append(f"- `{source.get('id')}` valid ranges with no current version match: {source['valid_range_no_match_count']}")
        if source.get("unsupported_range_count"):
            lines.append(f"- `{source.get('id')}` unsupported ranges skipped without guessing: {source['unsupported_range_count']}")
        health = source.get("source_health") or {}
        if health:
            lines.append(
                f"- `{source.get('id')}` freshness: {health.get('mode')}, fetched `{health.get('fetched_at') or 'unknown'}`, "
                f"stale={health.get('stale')}"
            )
    lines.extend(
        [
            "",
            "## Next Step",
            "",
            "Run `guardian assess refresh` for the same root so the new exact-match catalog participates in normal Guardian findings, operator JSON, snapshots, and handoff reports.",
            "",
        ]
    )
    return "\n".join(lines)


def _current_unique_packages(
    db: Database,
    *,
    root_paths: list[str] | None,
    ecosystems: list[str] | None,
) -> list[dict]:
    rows = [dict(row) for row in db.current_packages()]
    selected = []
    seen: set[tuple[str, str, str]] = set()
    allowed_ecosystems = set(ecosystems or [])
    allowed_roots = set(root_paths or [])
    for row in rows:
        if allowed_ecosystems and row["ecosystem"] not in allowed_ecosystems:
            continue
        if allowed_roots and row["root_path"] not in allowed_roots:
            continue
        key = (row["ecosystem"], row["normalized_name"], row["version"])
        if key in seen:
            continue
        seen.add(key)
        selected.append(row)
    return selected


def _prune_generated_threat_intel_catalogs(directory: Path) -> None:
    if not directory.exists():
        return
    for path in directory.glob("guardian-threat-intel-*.json"):
        try:
            path.unlink()
        except OSError:
            pass


def _index_packages(packages: list[dict]) -> dict[tuple[str, str], dict]:
    index: dict[tuple[str, str], dict] = {}
    for package in packages:
        key = (package["ecosystem"], package["normalized_name"])
        payload = index.setdefault(
            key,
            {
                "ecosystem": package["ecosystem"],
                "normalized_name": package["normalized_name"],
                "display_name": package["package_name"],
                "versions": set(),
            },
        )
        payload["versions"].add(package["version"])
    return index


def _filter_index_for_source(
    package_index: dict[tuple[str, str], dict],
    ecosystems: Iterable[str],
) -> dict[tuple[str, str], dict]:
    allowed = set(ecosystems)
    if not allowed:
        return package_index
    return {key: value for key, value in package_index.items() if key[0] in allowed}


def _prepare_gitlab_source_dir(config: GuardianConfig, source: dict) -> Path:
    return _prepare_git_source_dir(config, source)


def _prepare_git_source_dir(config: GuardianConfig, source: dict) -> Path:
    """Prepare a shallow sparse source checkout shared by advisory databases."""

    if source.get("path"):
        path = Path(source["path"])
        if not path.exists():
            raise RuntimeError(f"GitLab advisory source path does not exist: {path}")
        return path
    cache_dir = Path(config.threat_intel_cache_dir) / slugify(source["id"])
    repo = source.get("repo")
    if not repo:
        raise RuntimeError(f"source {source.get('id')} is missing repo")
    if not cache_dir.exists():
        _run_git(["git", "clone", "--depth", "1", "--filter=blob:none", "--sparse", repo, str(cache_dir)], cwd=None)
    else:
        if _git_remote_url(cache_dir) != repo:
            _run_git(["git", "-C", str(cache_dir), "remote", "set-url", "origin", repo], cwd=None)
        _run_git(["git", "-C", str(cache_dir), "fetch", "--depth", "1", "origin", "HEAD"], cwd=None)
        _run_git(["git", "-C", str(cache_dir), "reset", "--hard", "FETCH_HEAD"], cwd=None)
    _write_source_fetch_marker(cache_dir)
    return cache_dir


def _gitlab_sparse_paths_for_packages(source_dir: Path, package_index: dict[tuple[str, str], dict]) -> list[str]:
    paths: set[str] = {"README.md"}
    pypi_dir_map: dict[str, str] | None = None
    for ecosystem, normalized_name in sorted(package_index):
        if ecosystem == "npm":
            paths.add(f"npm/{normalized_name}")
        elif ecosystem == "pypi":
            if pypi_dir_map is None:
                pypi_dir_map = _gitlab_ecosystem_dir_map(source_dir, "pypi")
            paths.add(pypi_dir_map.get(normalized_name, f"pypi/{normalized_name}"))
    return sorted(paths)


def _gitlab_ecosystem_dir_map(source_dir: Path, ecosystem: str) -> dict[str, str]:
    try:
        result = _run_git(
            ["git", "-C", str(source_dir), "ls-tree", "-d", "--name-only", "HEAD", ecosystem],
            cwd=None,
            capture=True,
        )
    except RuntimeError:
        return {}
    mapping: dict[str, str] = {}
    for line in result.stdout.splitlines():
        package_name = line.split("/", 1)[1] if "/" in line else line
        mapping[normalize_package_name(ecosystem, package_name)] = line
    return mapping


def _git_sparse_checkout(source_dir: Path, paths: list[str]) -> None:
    process = subprocess.run(
        ["git", "-C", str(source_dir), "sparse-checkout", "set", "--stdin"],
        input="\n".join(paths) + "\n",
        text=True,
        capture_output=True,
        timeout=120,
    )
    if process.returncode != 0:
        raise RuntimeError(f"git sparse-checkout failed: {process.stderr.strip()}")


def _candidate_advisory_files(source_dir: Path, package_index: dict[tuple[str, str], dict]) -> list[Path]:
    paths = _gitlab_sparse_paths_for_packages(source_dir, package_index)
    files: list[Path] = []
    for directory in paths:
        target = source_dir / directory
        if target.is_dir():
            files.extend(sorted(target.glob("*.yml")))
    return files


def _load_yaml(path: Path) -> dict:
    return parse_advisory_yaml(path.read_text(encoding="utf-8"))


def _split_package_slug(package_slug: str) -> tuple[str | None, str | None]:
    if "/" not in package_slug:
        return None, None
    ecosystem, package_name = package_slug.split("/", 1)
    ecosystem = ecosystem.lower()
    if ecosystem not in {"npm", "pypi"}:
        return None, None
    return ecosystem, package_name


def _gitlab_advisory_url(ecosystem: str, package_name: str, advisory_id: str) -> str:
    return f"https://advisories.gitlab.com/pkg/{ecosystem}/{package_name}/{advisory_id}/"


def _git_revision(source_dir: Path) -> str | None:
    try:
        result = _run_git(["git", "-C", str(source_dir), "rev-parse", "HEAD"], cwd=None, capture=True)
    except RuntimeError:
        return None
    return result.stdout.strip() or None


def _git_remote_url(source_dir: Path) -> str | None:
    try:
        result = _run_git(["git", "-C", str(source_dir), "remote", "get-url", "origin"], cwd=None, capture=True)
    except RuntimeError:
        return None
    return result.stdout.strip() or None


def _write_source_fetch_marker(source_dir: Path) -> None:
    marker = source_dir / ".guardian-source-health.json"
    write_json(
        marker,
        {
            "fetched_at": utc_now(),
            "revision": _git_revision(source_dir),
            "remote_url": _git_remote_url(source_dir),
        },
    )


def _source_health(source_dir: Path, source: dict) -> dict:
    marker = source_dir / ".guardian-source-health.json"
    payload = {}
    if marker.exists():
        try:
            payload = json.loads(marker.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            payload = {}
    fetched_at = payload.get("fetched_at")
    stale_after_hours = float(source.get("stale_after_hours") or 24)
    age_hours = _age_hours(fetched_at)
    return {
        "mode": "remote-refreshed" if source.get("repo") and not source.get("path") else "local-path",
        "remote_url": payload.get("remote_url") or source.get("repo"),
        "fetched_at": fetched_at,
        "age_hours": age_hours,
        "stale_after_hours": stale_after_hours,
        "stale": age_hours is None or age_hours > stale_after_hours,
    }


def _source_health_for_failed_source(config: GuardianConfig, source: dict) -> dict:
    if source.get("path"):
        return {"mode": "local-path", "stale": True, "error": "source failed before health check"}
    cache_dir = Path(config.threat_intel_cache_dir) / slugify(source.get("id") or "unknown-source")
    if cache_dir.exists():
        return _source_health(cache_dir, source)
    return {"mode": "unavailable", "remote_url": source.get("repo"), "stale": True}


def _age_hours(timestamp: str | None) -> float | None:
    if not timestamp:
        return None
    try:
        parsed = datetime.fromisoformat(timestamp)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return round((datetime.now(timezone.utc) - parsed).total_seconds() / 3600, 4)


def _run_git(
    args: list[str],
    *,
    cwd: Path | None,
    capture: bool = False,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        args,
        cwd=str(cwd) if cwd else None,
        text=True,
        capture_output=True,
        timeout=240,
    )
    if result.returncode != 0:
        raise RuntimeError(f"{' '.join(args)} failed: {result.stderr.strip()}")
    return result


def _round_up_1_decimal(value: float) -> float:
    return math.ceil(value * 10) / 10.0
