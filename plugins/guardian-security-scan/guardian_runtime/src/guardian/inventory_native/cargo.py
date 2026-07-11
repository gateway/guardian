"""Cargo.lock inventory parser with a narrow dependency-free TOML reader."""

from __future__ import annotations

import re
from pathlib import Path

from .records import package_record


def parse_cargo_lock(path: Path, root: Path) -> list[dict]:
    """Read crates.io package versions and checksums without running Cargo."""

    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    direct_names = _cargo_direct_dependencies(path.parent / "Cargo.toml")
    records = []
    packages: list[dict] = []
    current: dict[str, str] | None = None
    for line in lines:
        stripped = line.strip()
        if stripped == "[[package]]":
            if current:
                packages.append(current)
            current = {}
            continue
        if current is None:
            continue
        match = re.match(r'^(name|version|source|checksum)\s*=\s*"((?:\\.|[^"])*)"\s*$', stripped)
        if match:
            current[match.group(1)] = _unescape_toml_string(match.group(2))
    if current:
        packages.append(current)

    for item in packages:
        name = item.get("name")
        version = item.get("version")
        source = str(item.get("source") or "")
        if not name or not version or not _is_crates_io_source(source):
            continue
        direct = str(name).lower() in direct_names
        records.append(
            package_record(
                root=root,
                ecosystem="crates.io",
                package_name=str(name),
                version=str(version),
                source_file=path,
                source_type="cargo-lockfile",
                package_manager="cargo",
                confidence="high",
                direct_dependency=direct,
                install_scope="prod" if direct else None,
                evidence_kind="lockfile",
                raw_metadata={
                    "integrity": item.get("checksum"),
                    "resolved": source,
                    "module_graph": not direct,
                },
            )
        )
    return records


def _cargo_direct_dependencies(path: Path) -> set[str]:
    """Collect direct dependency keys from normal Cargo dependency tables."""

    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return set()
    names: set[str] = set()
    dependency_section = False
    for raw_line in lines:
        line = re.sub(r"\s+#.*$", "", raw_line.strip())
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip().strip('"')
            dependency_section = section in {"dependencies", "build-dependencies"} or section.endswith(
                (".dependencies", ".build-dependencies")
            )
            continue
        if dependency_section:
            match = re.match(r'^([A-Za-z0-9_-]+)\s*=\s*', line)
            if match:
                names.add(match.group(1).lower())
    return names


def _is_crates_io_source(source: str) -> bool:
    return source.startswith("registry+") or source.startswith("sparse+") and "crates.io" in source


def _unescape_toml_string(value: str) -> str:
    """Decode escapes used in Cargo's generated basic strings."""

    return bytes(value, "utf-8").decode("unicode_escape")
