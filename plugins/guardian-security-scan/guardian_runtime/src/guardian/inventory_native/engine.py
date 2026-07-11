"""Native inventory engine that walks candidate files and emits normalized package records."""

from __future__ import annotations

import json
from pathlib import Path
import time
from typing import Iterable

from guardian.config import GuardianConfig
from guardian.util import read_ndjson, slugify, write_json

from .cargo import parse_cargo_lock
from .composer import parse_composer_lock
from .golang import parse_go_mod, parse_go_sum
from .npm import parse_node_package_json, parse_package_json_manifest, parse_package_lock, parse_pnpm_lock, parse_yarn_lock
from .pypi import parse_pyproject_manifest, parse_python_metadata, parse_requirements_manifest, parse_uv_lock
from .walker import PYTHON_REQUIREMENTS_PATTERN
from .walker import candidate_files


def scan_packages(
    root: str,
    *,
    ecosystems: Iterable[str],
    include_installed: bool,
    excludes: Iterable[str] = (),
) -> list[dict]:
    return scan_package_records(
        root,
        ecosystems=ecosystems,
        include_installed=include_installed,
        excludes=excludes,
    )[0]


def scan_package_records(
    root: str,
    *,
    ecosystems: Iterable[str],
    include_installed: bool,
    excludes: Iterable[str] = (),
) -> tuple[list[dict], dict]:
    root_path = Path(root).resolve()
    selected = set(ecosystems)
    records: list[dict] = []
    candidate_count = 0
    candidate_counts_by_name: dict[str, int] = {}
    source_counts: dict[str, int] = {}
    evidence_counts: dict[str, int] = {}
    started = time.perf_counter()
    for path in candidate_files(root_path, include_installed=include_installed, excludes=excludes):
        candidate_count += 1
        candidate_counts_by_name[path.name] = candidate_counts_by_name.get(path.name, 0) + 1
        before = len(records)
        if "npm" in selected:
            if path.name in {".package-lock.json", "package-lock.json", "npm-shrinkwrap.json"}:
                records.extend(parse_package_lock(path, root_path))
            elif path.name == "pnpm-lock.yaml":
                records.extend(parse_pnpm_lock(path, root_path))
            elif path.name == "yarn.lock":
                records.extend(parse_yarn_lock(path, root_path))
            elif path.name == "package.json" and "node_modules" not in path.parts:
                records.extend(parse_package_json_manifest(path, root_path))
            elif include_installed and path.name == "package.json" and "node_modules" in path.parts:
                records.extend(parse_node_package_json(path, root_path))
        if "pypi" in selected:
            if path.name == "uv.lock":
                records.extend(parse_uv_lock(path, root_path))
            elif path.name == "pyproject.toml":
                records.extend(parse_pyproject_manifest(path, root_path))
            elif PYTHON_REQUIREMENTS_PATTERN.match(path.name):
                records.extend(parse_requirements_manifest(path, root_path))
            elif include_installed and path.name in {"METADATA", "PKG-INFO"}:
                records.extend(parse_python_metadata(path, root_path))
        if "go" in selected:
            if path.name == "go.mod":
                records.extend(parse_go_mod(path, root_path))
            elif path.name == "go.sum":
                records.extend(parse_go_sum(path, root_path))
        if "crates.io" in selected and path.name == "Cargo.lock":
            records.extend(parse_cargo_lock(path, root_path))
        if "packagist" in selected and path.name == "composer.lock":
            records.extend(parse_composer_lock(path, root_path))
        for record in records[before:]:
            source_type = record.get("source_type") or "unknown"
            evidence_kind = record.get("evidence_kind") or "unknown"
            source_counts[source_type] = source_counts.get(source_type, 0) + 1
            evidence_counts[evidence_kind] = evidence_counts.get(evidence_kind, 0) + 1
    deduped = _dedupe(records)
    metrics = {
        "engine": "guardian-native",
        "root": str(root_path),
        "ecosystems": sorted(selected),
        "include_installed": include_installed,
        "elapsed_seconds": round(time.perf_counter() - started, 4),
        "candidate_file_count": candidate_count,
        "candidate_counts_by_name": dict(sorted(candidate_counts_by_name.items())),
        "raw_record_count": len(records),
        "package_count": len(deduped),
        "deduped_count": len(records) - len(deduped),
        "source_type_counts": dict(sorted(source_counts.items())),
        "evidence_kind_counts": dict(sorted(evidence_counts.items())),
    }
    return deduped, metrics


def scan_to_ndjson(
    config: GuardianConfig,
    root: str,
    *,
    ecosystems: Iterable[str],
    include_installed: bool,
    excludes: Iterable[str] = (),
) -> Path:
    output_path = Path(config.scans_dir) / f"{slugify(root)}-guardian-native-inventory.ndjson"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    records, metrics = scan_package_records(root, ecosystems=ecosystems, include_installed=include_installed, excludes=excludes)
    with output_path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
    metrics_path = output_path.with_suffix(".metrics.json")
    write_json(metrics_path, metrics)
    return output_path


def load_native_packages(path: Path) -> list[dict]:
    return [record for record in read_ndjson(path) if record.get("record_type") == "package"]


def _read_metrics(path: Path) -> dict | None:
    metrics_path = path.with_suffix(".metrics.json")
    if not metrics_path.exists():
        return None
    try:
        return json.loads(metrics_path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _dedupe(records: list[dict]) -> list[dict]:
    by_key: dict[tuple[str, str, str, str, str], dict] = {}
    for record in records:
        key = (
            record.get("ecosystem", ""),
            record.get("normalized_name", ""),
            record.get("version", ""),
            record.get("source_type", ""),
            record.get("source_file", ""),
        )
        by_key.setdefault(key, record)
    return [by_key[key] for key in sorted(by_key)]


def _package_key(item: dict) -> tuple[str, str, str, str]:
    return (
        item.get("ecosystem", ""),
        item.get("normalized_name", ""),
        item.get("version", ""),
        item.get("source_type", ""),
    )


def _evidence_key(item: dict) -> tuple[str, str, str, str, str]:
    return (
        item.get("ecosystem", ""),
        item.get("normalized_name", ""),
        item.get("version", ""),
        item.get("source_type", ""),
        item.get("source_file") or "",
    )


def _package_key_to_dict(key: tuple[str, str, str, str]) -> dict:
    return {
        "ecosystem": key[0],
        "normalized_name": key[1],
        "version": key[2],
        "source_type": key[3],
    }


def _evidence_key_to_dict(key: tuple[str, str, str, str, str]) -> dict:
    payload = _package_key_to_dict(key[:4])
    payload["source_file"] = key[4]
    return payload
