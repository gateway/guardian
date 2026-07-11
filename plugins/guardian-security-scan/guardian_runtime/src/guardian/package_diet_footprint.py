"""Offline npm lockfile footprint and exact-version context for package diet."""

from __future__ import annotations

import json
from pathlib import Path, PurePosixPath

from .package_diet_usage import SKIP_DIRS
from .util import normalize_package_name


def npm_lockfile_footprints(root: Path) -> dict[str, dict]:
    """Return the strongest observed direct-package footprint across npm lockfiles."""

    footprints: dict[str, dict] = {}
    for path in sorted(root.rglob("package-lock.json")):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        for name, item in _lockfile_package_footprints(payload).items():
            current = footprints.get(name)
            if current is None or item["transitive_count"] > current["transitive_count"]:
                footprints[name] = {**item, "lockfile": str(path)}
    return footprints


def _lockfile_package_footprints(payload: dict) -> dict[str, dict]:
    packages = payload.get("packages")
    if isinstance(packages, dict):
        return _modern_lockfile_footprints(packages)
    dependencies = payload.get("dependencies")
    if isinstance(dependencies, dict):
        return _legacy_lockfile_footprints(dependencies)
    return {}


def _modern_lockfile_footprints(packages: dict) -> dict[str, dict]:
    root_item = packages.get("") if isinstance(packages.get(""), dict) else {}
    direct_names = set()
    for field in ("dependencies", "optionalDependencies", "devDependencies", "peerDependencies"):
        values = root_item.get(field)
        if isinstance(values, dict):
            direct_names.update(str(name) for name in values)
    result = {}
    for name in sorted(direct_names):
        node_key = _resolve_node(packages, "", name)
        item = packages.get(node_key) if node_key else None
        if not isinstance(item, dict) or not item.get("version"):
            continue
        descendants: set[str] = set()
        _walk_modern_dependencies(packages, node_key, descendants)
        descendants.discard(node_key)
        result[normalize_package_name("npm", name)] = {
            "version": str(item["version"]),
            "transitive_count": len(descendants),
            "license": _license_value(item.get("license")),
            "pure_source": not bool(
                item.get("hasInstallScript")
                or item.get("gypfile")
                or item.get("os")
                or item.get("cpu")
            ),
        }
    return result


def _walk_modern_dependencies(packages: dict, node_key: str, visited: set[str]) -> None:
    if node_key in visited:
        return
    visited.add(node_key)
    item = packages.get(node_key)
    if not isinstance(item, dict):
        return
    dependency_names = set()
    for field in ("dependencies", "optionalDependencies"):
        values = item.get(field)
        if isinstance(values, dict):
            dependency_names.update(str(name) for name in values)
    for dependency in dependency_names:
        child = _resolve_node(packages, node_key, dependency)
        if child:
            _walk_modern_dependencies(packages, child, visited)


def _resolve_node(packages: dict, node_key: str, dependency: str) -> str | None:
    """Approximate Node resolution by walking parent node_modules segments."""

    current = PurePosixPath(node_key)
    search_roots = [current]
    search_roots.extend(current.parents)
    for base in search_roots:
        prefix = "" if str(base) in {"", "."} else f"{base.as_posix()}/"
        candidate = f"{prefix}node_modules/{dependency}"
        if candidate in packages:
            return candidate
    fallback = f"node_modules/{dependency}"
    return fallback if fallback in packages else None


def _legacy_lockfile_footprints(dependencies: dict) -> dict[str, dict]:
    result = {}
    for name, item in dependencies.items():
        if not isinstance(item, dict) or not item.get("version"):
            continue
        descendants: set[tuple[str, str]] = set()
        _walk_legacy_dependencies(item.get("dependencies") or {}, descendants)
        result[normalize_package_name("npm", name)] = {
            "version": str(item["version"]),
            "transitive_count": len(descendants),
            "license": _license_value(item.get("license")),
            "pure_source": not bool(item.get("hasInstallScript") or item.get("gypfile")),
        }
    return result


def _walk_legacy_dependencies(dependencies: dict, visited: set[tuple[str, str]]) -> None:
    for name, item in dependencies.items():
        if not isinstance(item, dict) or not item.get("version"):
            continue
        key = (str(name), str(item["version"]))
        if key in visited:
            continue
        visited.add(key)
        _walk_legacy_dependencies(item.get("dependencies") or {}, visited)


def _license_value(value) -> str | None:
    if isinstance(value, str):
        return value.strip() or None
    if isinstance(value, dict):
        candidate = value.get("type")
        return str(candidate).strip() if candidate else None
    return None
