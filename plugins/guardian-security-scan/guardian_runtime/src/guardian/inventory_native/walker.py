from __future__ import annotations

from collections.abc import Iterable, Iterator
import os
from pathlib import Path


DEFAULT_EXCLUDES = {
    ".git",
    ".hg",
    ".svn",
    ".next",
    "dist",
    "build",
    "coverage",
    ".cache",
    ".turbo",
}

DEFAULT_MAX_FILE_BYTES = 25 * 1024 * 1024

LOCKFILE_NAMES = {
    ".package-lock.json",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "pnpm-lock.yaml",
    "yarn.lock",
}

PYTHON_TREE_EXCLUDES = {
    "__pycache__",
    ".pytest_cache",
    "tests",
    "test",
    "docs",
    "doc",
    "examples",
}


def _is_under(path: Path, name: str) -> bool:
    return name in path.parts


def _node_modules_rel_parts(path: Path) -> tuple[str, ...] | None:
    parts = path.parts
    if "node_modules" not in parts:
        return None
    index = len(parts) - 1 - list(reversed(parts)).index("node_modules")
    return parts[index + 1 :]


def _is_node_package_root(rel_parts: tuple[str, ...]) -> bool:
    return len(rel_parts) == 1 or (len(rel_parts) == 2 and rel_parts[0].startswith("@"))


def _is_pnpm_package_root(rel_parts: tuple[str, ...]) -> bool:
    if len(rel_parts) == 4 and rel_parts[0] == ".pnpm" and rel_parts[2] == "node_modules":
        return True
    return len(rel_parts) == 5 and rel_parts[0] == ".pnpm" and rel_parts[2] == "node_modules" and rel_parts[3].startswith("@")


def _node_package_rel_parts(path: Path) -> tuple[str, ...] | None:
    rel_parts = _node_modules_rel_parts(path)
    if rel_parts is None:
        return None
    if path.name == "package.json":
        rel_parts = rel_parts[:-1]
    return rel_parts if _is_node_package_root(rel_parts) or _is_pnpm_package_root(rel_parts) else None


def _is_package_metadata_dir(path: Path) -> bool:
    return path.name.endswith(".dist-info") or path.name.endswith(".egg-info")


def _is_python_package_root(path: Path) -> bool:
    return path.name in {"site-packages", "dist-packages"}


def _is_under_python_package_root(path: Path) -> bool:
    return "site-packages" in path.parts or "dist-packages" in path.parts


def _is_vendored_python_metadata(path: Path) -> bool:
    parts = path.parts
    for marker in ("site-packages", "dist-packages"):
        if marker not in parts:
            continue
        index = parts.index(marker)
        rel = parts[index + 1 :]
        return "_vendor" in rel or "vendor" in rel or len(rel) > 2
    return False


def _prune_installed_dirs(current: Path, dirs: list[str], exclude_names: set[str]) -> list[str]:
    """Keep installed scans metadata-focused instead of crawling package source trees."""
    node_rel = _node_modules_rel_parts(current)
    if node_rel is not None:
        if len(node_rel) == 0:
            return sorted(item for item in dirs if item not in exclude_names and item != ".bin")
        if node_rel == (".pnpm",):
            return sorted(item for item in dirs if item not in exclude_names)
        if len(node_rel) == 2 and node_rel[0] == ".pnpm":
            return ["node_modules"] if "node_modules" in dirs and "node_modules" not in exclude_names else []
        if len(node_rel) == 3 and node_rel[0] == ".pnpm" and node_rel[2] == "node_modules":
            return sorted(item for item in dirs if item not in exclude_names and item != ".bin")
        if len(node_rel) == 4 and node_rel[0] == ".pnpm" and node_rel[2] == "node_modules" and node_rel[3].startswith("@"):
            return sorted(item for item in dirs if item not in exclude_names)
        if len(node_rel) == 1 and node_rel[0].startswith("@"):
            return sorted(item for item in dirs if item not in exclude_names)
        if _is_node_package_root(node_rel):
            return ["node_modules"] if "node_modules" in dirs and "node_modules" not in exclude_names else []
        return []

    if _is_under_python_package_root(current):
        if _is_package_metadata_dir(current):
            return []
        return sorted(item for item in dirs if item not in exclude_names and item not in PYTHON_TREE_EXCLUDES)

    if _is_python_package_root(current):
        return sorted(
            item
            for item in dirs
            if item not in exclude_names and (item.endswith(".dist-info") or item.endswith(".egg-info"))
        )
    if _is_package_metadata_dir(current):
        return []
    parent = current.parent
    if _is_python_package_root(parent) and not _is_package_metadata_dir(current):
        return []
    return sorted(item for item in dirs if item not in exclude_names)


def _safe_file(path: Path, max_file_bytes: int) -> bool:
    try:
        return path.stat().st_size <= max_file_bytes
    except OSError:
        return False


def candidate_files(
    root: str | Path,
    *,
    include_installed: bool,
    excludes: Iterable[str] = (),
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
) -> Iterator[Path]:
    root_path = Path(root).resolve()
    exclude_names = set(DEFAULT_EXCLUDES)
    exclude_names.update(excludes)
    if not include_installed:
        exclude_names.update({"node_modules", ".venv", "venv"})

    for current_raw, dirs, files in os.walk(root_path, topdown=True, followlinks=False):
        current = Path(current_raw)
        dirs[:] = [
            item
            for item in _prune_installed_dirs(current, dirs, exclude_names)
            if not (current / item).is_symlink()
        ]
        for filename in sorted(files):
            path = current / filename
            if path.is_symlink() or not _safe_file(path, max_file_bytes):
                continue
            if filename in LOCKFILE_NAMES:
                yield path
                continue
            if include_installed and filename == "package.json" and _is_under(path, "node_modules"):
                if _node_package_rel_parts(path) is not None:
                    yield path
                continue
            if include_installed and filename in {"METADATA", "PKG-INFO"}:
                parent = path.parent.name
                if parent.endswith(".dist-info") or parent.endswith(".egg-info"):
                    yield path
