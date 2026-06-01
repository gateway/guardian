"""Inventory service that runs native scanners, stores package records, and imports NDJSON inventory data."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

from .config import GuardianConfig
from .db import Database
from .inventory_native import scan_to_ndjson
from .util import read_ndjson


DEFAULT_ECOSYSTEMS = ("npm", "pypi")
SUPPORTED_ENGINES = {"guardian-native"}


def _effective_engine(config: GuardianConfig, requested_engine: str | None, ecosystems: Iterable[str]) -> str:
    engine = requested_engine or config.inventory_engine
    if engine == "auto":
        engine = config.inventory_engine
    if engine not in SUPPORTED_ENGINES:
        raise ValueError(f"unsupported inventory engine: {engine}")
    supported = set(config.inventory_native_supported_ecosystems)
    unsupported = sorted(set(ecosystems) - supported)
    if unsupported:
        raise ValueError(f"guardian-native does not support ecosystems: {', '.join(unsupported)}")
    return engine


def _metrics_path(ndjson_path: Path) -> Path:
    return ndjson_path.with_suffix(".metrics.json")


def _load_metrics(ndjson_path: Path) -> dict | None:
    path = _metrics_path(ndjson_path)
    if not path.exists():
        return None
    try:
        import json

        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def load_package_records(path: Path) -> list[dict]:
    return [record for record in read_ndjson(path) if record.get("record_type") == "package"]


def scan_roots(
    config: GuardianConfig,
    db: Database,
    roots: Iterable[str],
    ecosystems: Iterable[str] = DEFAULT_ECOSYSTEMS,
    include_installed: bool = False,
    excludes: Iterable[str] = (),
    engine: str | None = None,
) -> list[dict]:
    results = []
    for root in roots:
        selected_engine = _effective_engine(config, engine, ecosystems)
        ndjson_path = scan_to_ndjson(
            config=config,
            root=root,
            ecosystems=ecosystems,
            include_installed=include_installed,
            excludes=excludes,
        )
        run_id = db.start_inventory_run(
            root_path=root,
            profile="project",
            source=selected_engine,
            ndjson_path=str(ndjson_path),
        )
        packages = load_package_records(ndjson_path)
        count = db.insert_inventory_packages(run_id, packages)
        db.finish_inventory_run(run_id, package_count=count)
        results.append(
            {
                "root": root,
                "packages": count,
                "ndjson_path": str(ndjson_path),
                "run_id": run_id,
                "engine": selected_engine,
                "fallback_reason": None,
                "metrics": _load_metrics(ndjson_path),
            }
        )
    return results


def import_ndjson(db: Database, root: str, ndjson_path: Path) -> dict:
    run_id = db.start_inventory_run(
        root_path=root,
        profile="project",
        source="import",
        ndjson_path=str(ndjson_path),
    )
    packages = load_package_records(ndjson_path)
    count = db.insert_inventory_packages(run_id, packages)
    db.finish_inventory_run(run_id, package_count=count)
    return {"root": root, "packages": count, "ndjson_path": str(ndjson_path), "run_id": run_id}
