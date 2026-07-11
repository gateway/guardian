"""Composer lockfile inventory parsing for Packagist packages."""

from __future__ import annotations

import json
from pathlib import Path

from .records import package_record


def parse_composer_lock(path: Path, root: Path) -> list[dict]:
    """Read production and development packages from composer.lock."""

    try:
        payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return []
    direct = _composer_direct_dependencies(path.parent / "composer.json")
    records = []
    for field, scope in (("packages", "prod"), ("packages-dev", "dev")):
        for item in payload.get(field) or []:
            if not isinstance(item, dict) or not item.get("name") or not item.get("version"):
                continue
            name = str(item["name"])
            version = str(item["version"]).lstrip("v")
            dist = item.get("dist") if isinstance(item.get("dist"), dict) else {}
            source = item.get("source") if isinstance(item.get("source"), dict) else {}
            records.append(
                package_record(
                    root=root,
                    ecosystem="packagist",
                    package_name=name,
                    version=version,
                    source_file=path,
                    source_type="composer-lockfile",
                    package_manager="composer",
                    confidence="high",
                    direct_dependency=name.lower() in direct,
                    install_scope=scope,
                    evidence_kind="lockfile",
                    raw_metadata={
                        "integrity": dist.get("shasum") or source.get("reference"),
                        "resolved": dist.get("url") or source.get("url"),
                        "module_graph": name.lower() not in direct,
                    },
                )
            )
    return records


def _composer_direct_dependencies(path: Path) -> set[str]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return set()
    direct = set()
    for field in ("require", "require-dev"):
        requirements = payload.get(field)
        if isinstance(requirements, dict):
            direct.update(
                str(name).lower()
                for name in requirements
                if "/" in str(name) and not str(name).lower().startswith(("php", "ext-", "lib-"))
            )
    return direct
