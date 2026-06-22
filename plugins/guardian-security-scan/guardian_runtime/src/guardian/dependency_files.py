"""Dependency-file fingerprinting for lightweight daily watch scans."""

from __future__ import annotations

from pathlib import Path

from .integrity import sha256_file
from .inventory_native.walker import candidate_files


def fingerprint_dependency_files(
    root: str | Path,
    *,
    include_installed: bool = False,
    excludes: list[str] | None = None,
) -> list[dict]:
    """Return stable fingerprints for dependency manifests and lockfiles."""

    root_path = Path(root).resolve()
    fingerprints = []
    for path in candidate_files(root_path, include_installed=include_installed, excludes=excludes or []):
        stat = path.stat()
        fingerprints.append(
            {
                "file_path": _relative_path(root_path, path),
                "file_kind": dependency_file_kind(path),
                "size_bytes": stat.st_size,
                "mtime_ns": stat.st_mtime_ns,
                "sha256": sha256_file(path),
            }
        )
    fingerprints.sort(key=lambda item: item["file_path"])
    return fingerprints


def dependency_file_kind(path: Path) -> str:
    """Classify a dependency file enough for operator reporting and future policies."""

    name = path.name
    if name in {"package-lock.json", ".package-lock.json", "npm-shrinkwrap.json"}:
        return "npm-lock"
    if name == "pnpm-lock.yaml":
        return "pnpm-lock"
    if name == "yarn.lock":
        return "yarn-lock"
    if name == "package.json":
        return "npm-manifest"
    if name == "uv.lock":
        return "uv-lock"
    if name == "pyproject.toml":
        return "python-manifest"
    if name in {"METADATA", "PKG-INFO"}:
        return "python-installed-metadata"
    return "dependency-file"


def _relative_path(root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(root).as_posix()
    except ValueError:
        return path.resolve().as_posix()
