"""Go module manifest and checksum inventory parsing."""

from __future__ import annotations

import re
from pathlib import Path

from .records import package_record


_REQUIRE_RE = re.compile(r"^([^\s]+)\s+([^\s]+)(?:\s+//\s*(indirect))?$")


def parse_go_mod(path: Path, root: Path) -> list[dict]:
    """Read exact Go module requirements and preserve direct/indirect intent."""

    requirements = go_mod_requirements(path)
    return [
        package_record(
            root=root,
            ecosystem="go",
            package_name=name,
            version=item["version"],
            source_file=path,
            source_type="go-mod-manifest",
            package_manager="go",
            confidence="high",
            direct_dependency=not item["indirect"],
            install_scope="prod" if not item["indirect"] else None,
            evidence_kind="manifest",
            raw_metadata={"indirect": item["indirect"], "module_graph": item["indirect"]},
        )
        for name, item in sorted(requirements.items())
    ]


def parse_go_sum(path: Path, root: Path) -> list[dict]:
    """Collapse go.sum artifact and go.mod hashes into one exact module record."""

    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    requirements = go_mod_requirements(path.parent / "go.mod")
    checksums: dict[tuple[str, str], dict[str, str]] = {}
    for line in lines:
        fields = line.split()
        if len(fields) != 3:
            continue
        name, raw_version, checksum = fields
        checksum_kind = "go-mod" if raw_version.endswith("/go.mod") else "module"
        version = raw_version.removesuffix("/go.mod")
        checksums.setdefault((name, version), {})[checksum_kind] = checksum

    records = []
    for (name, version), hashes in sorted(checksums.items()):
        direct_info = requirements.get(name)
        direct = not direct_info["indirect"] if direct_info else False
        records.append(
            package_record(
                root=root,
                ecosystem="go",
                package_name=name,
                version=version,
                source_file=path,
                source_type="go-sum-lockfile",
                package_manager="go",
                confidence="high" if direct else "medium",
                direct_dependency=direct,
                install_scope="prod" if direct else None,
                evidence_kind="lockfile",
                raw_metadata={
                    "integrity": hashes.get("module"),
                    "go_mod_integrity": hashes.get("go-mod"),
                    "module_graph": not direct,
                },
            )
        )
    return records


def go_mod_requirements(path: Path) -> dict[str, dict]:
    """Parse both block and single-line require forms without executing Go."""

    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return {}
    requirements: dict[str, dict] = {}
    in_require_block = False
    for raw_line in lines:
        line = raw_line.strip()
        if line == "require (":
            in_require_block = True
            continue
        if in_require_block and line == ")":
            in_require_block = False
            continue
        if line.startswith("require "):
            line = line[len("require ") :].strip()
        elif not in_require_block:
            continue
        match = _REQUIRE_RE.match(line)
        if not match:
            continue
        name, version, indirect = match.groups()
        requirements[name] = {"version": version, "indirect": indirect == "indirect"}
    return requirements
