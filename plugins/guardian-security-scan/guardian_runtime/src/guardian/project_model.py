"""Manifest inspection helpers that classify dependency scope and code ownership inside a project."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .util import normalize_package_name

try:
    import tomllib
except Exception:  # pragma: no cover
    tomllib = None


TEST_GROUP_NAMES = {"dev", "test", "tests", "testing", "lint", "typecheck", "types", "docs", "smoke"}
BUILD_TOOL_PACKAGES = {"setuptools", "wheel", "pip"}


def _parse_requirement_name(spec: str) -> str | None:
    for stop in ["[", ">", "<", "=", "!", "~", " ", ";"]:
        if stop in spec:
            spec = spec.split(stop, 1)[0]
    spec = spec.strip()
    return spec or None


@dataclass
class ManifestRecord:
    """Normalized dependency declarations from one project manifest."""

    ecosystem: str
    path: str
    root_dir: str
    package_name: str | None
    dependencies: set[str]
    dev_dependencies: set[str]
    build_dependencies: set[str]


class ProjectInspector:
    """Cache and query package manifests for dependency-scope evidence."""

    def __init__(self) -> None:
        self._cache: dict[str, list[ManifestRecord]] = {}

    def manifests_for_root(self, root_path: str) -> list[ManifestRecord]:
        """Discover supported manifests once per root and reuse them during triage."""

        if root_path in self._cache:
            return self._cache[root_path]
        root = Path(root_path)
        manifests: list[ManifestRecord] = []
        for path in root.rglob("package.json"):
            if "node_modules" in path.parts:
                continue
            record = self._parse_package_json(path)
            if record:
                manifests.append(record)
        if tomllib is not None:
            for path in root.rglob("pyproject.toml"):
                if any(part in {".venv", "venv", "node_modules"} for part in path.parts):
                    continue
                record = self._parse_pyproject(path)
                if record:
                    manifests.append(record)
        self._cache[root_path] = manifests
        return manifests

    def _parse_package_json(self, path: Path) -> ManifestRecord | None:
        """Read npm dependency scopes from package.json without package-manager calls."""

        try:
            payload = json.loads(path.read_text())
        except Exception:
            return None
        deps = {normalize_package_name("npm", item) for item in (payload.get("dependencies") or {}).keys()}
        dev = {normalize_package_name("npm", item) for item in (payload.get("devDependencies") or {}).keys()}
        build = {
            normalize_package_name("npm", item)
            for item in (payload.get("optionalDependencies") or {}).keys()
        }
        return ManifestRecord(
            ecosystem="npm",
            path=str(path),
            root_dir=str(path.parent),
            package_name=normalize_package_name("npm", payload.get("name", "")) if payload.get("name") else None,
            dependencies=deps,
            dev_dependencies=dev,
            build_dependencies=build,
        )

    def _parse_pyproject(self, path: Path) -> ManifestRecord | None:
        """Read Python dependency scopes from pyproject.toml using stdlib tomllib."""

        try:
            payload = tomllib.loads(path.read_text())
        except Exception:
            return None
        project = payload.get("project") or {}
        deps = set()
        for item in project.get("dependencies") or []:
            name = _parse_requirement_name(item)
            if name:
                deps.add(normalize_package_name("pypi", name))
        dev = set()
        for group_name, entries in (project.get("optional-dependencies") or {}).items():
            target = dev if group_name.lower() in TEST_GROUP_NAMES else deps
            for item in entries or []:
                name = _parse_requirement_name(item)
                if name:
                    target.add(normalize_package_name("pypi", name))
        build = set()
        for item in ((payload.get("build-system") or {}).get("requires") or []):
            name = _parse_requirement_name(item)
            if name:
                build.add(normalize_package_name("pypi", name))
        poetry = (payload.get("tool") or {}).get("poetry") or {}
        for name in (poetry.get("dependencies") or {}).keys():
            if name != "python":
                deps.add(normalize_package_name("pypi", name))
        for group_name, group_payload in ((poetry.get("group") or {}).items()):
            dep_map = (group_payload or {}).get("dependencies") or {}
            target = dev if group_name.lower() in TEST_GROUP_NAMES else deps
            for name in dep_map.keys():
                if name != "python":
                    target.add(normalize_package_name("pypi", name))
        return ManifestRecord(
            ecosystem="pypi",
            path=str(path),
            root_dir=str(path.parent),
            package_name=normalize_package_name("pypi", project.get("name", "")) if project.get("name") else None,
            dependencies=deps,
            dev_dependencies=dev,
            build_dependencies=build,
        )

    def manifest_scope(
        self,
        root_path: str,
        *,
        ecosystem: str,
        normalized_name: str,
        occurrence_paths: list[str],
    ) -> dict:
        """Classify a package as runtime, test, build, workspace, or undeclared.

        Triage uses this to avoid treating a build/test-only package the same as
        a runtime dependency when deciding whether a finding is actionable.
        """

        manifests = [item for item in self.manifests_for_root(root_path) if item.ecosystem == ecosystem]
        matched: list[ManifestRecord] = []
        for occurrence in occurrence_paths:
            try:
                occurrence_path = Path(occurrence).resolve()
            except Exception:
                continue
            candidates = []
            for manifest in manifests:
                try:
                    manifest_root = Path(manifest.root_dir).resolve()
                    occurrence_path.relative_to(manifest_root)
                except Exception:
                    continue
                candidates.append(manifest)
            if candidates:
                candidates.sort(key=lambda item: len(Path(item.root_dir).parts), reverse=True)
                matched.append(candidates[0])
        if not matched:
            matched = manifests
        dependency_paths = []
        scope = "undeclared"
        for manifest in matched:
            if normalized_name and manifest.package_name == normalized_name:
                dependency_paths.append(manifest.path)
                scope = "workspace"
                continue
            if normalized_name in manifest.dependencies:
                dependency_paths.append(manifest.path)
                scope = "runtime"
            elif normalized_name in manifest.dev_dependencies and scope != "runtime":
                dependency_paths.append(manifest.path)
                scope = "test"
            elif normalized_name in manifest.build_dependencies and scope not in {"runtime", "test"}:
                dependency_paths.append(manifest.path)
                scope = "build"
        if normalized_name in BUILD_TOOL_PACKAGES and scope == "undeclared":
            scope = "build"
        return {
            "scope": scope,
            "manifest_paths": sorted(set(dependency_paths)),
        }
