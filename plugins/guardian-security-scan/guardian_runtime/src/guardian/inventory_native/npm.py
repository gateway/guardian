"""npm, pnpm, Yarn, and installed node_modules parsers for native inventory scans."""

from __future__ import annotations

import json
import re
from pathlib import Path

from .records import package_record

NPM_LIFECYCLE_SCRIPTS = {
    "preinstall",
    "install",
    "postinstall",
    "prepare",
    "preprepare",
    "postprepare",
}


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _manifest_dependency_info(lockfile: Path) -> dict[str, tuple[bool, str]]:
    package_json = lockfile.parent / "package.json"
    if not package_json.exists():
        return {}
    try:
        payload = _load_json(package_json)
    except Exception:
        return {}
    result: dict[str, tuple[bool, str]] = {}
    for field, scope in (
        ("dependencies", "prod"),
        ("optionalDependencies", "prod"),
        ("devDependencies", "dev"),
        ("peerDependencies", "prod"),
    ):
        value = payload.get(field)
        if isinstance(value, dict):
            for name in value:
                result[name.lower()] = (True, scope)
    return result


def parse_package_lock(path: Path, root: Path) -> list[dict]:
    """Parse npm package-lock and shrinkwrap files into package records."""

    try:
        payload = _load_json(path)
    except Exception:
        return []
    manifest = _manifest_dependency_info(path)
    records: list[dict] = []
    packages = payload.get("packages")
    if isinstance(packages, dict):
        root_pkg = packages.get("") if isinstance(packages.get(""), dict) else {}
        root_deps = {}
        for field, scope in (
            ("dependencies", "prod"),
            ("optionalDependencies", "prod"),
            ("devDependencies", "dev"),
        ):
            deps = root_pkg.get(field)
            if isinstance(deps, dict):
                for name in deps:
                    root_deps[name.lower()] = (True, scope)
        for key, item in sorted(packages.items()):
            if not key or not isinstance(item, dict):
                continue
            version = item.get("version")
            if not version:
                continue
            name = item.get("name") or _name_from_node_modules_key(key)
            if not name:
                continue
            direct, scope = root_deps.get(name.lower(), manifest.get(name.lower(), (False, "dev" if item.get("dev") else "prod")))
            records.append(
                package_record(
                    root=root,
                    ecosystem="npm",
                    package_name=name,
                    version=version,
                    source_file=path,
                    source_type="npm-lockfile",
                    package_manager="npm",
                    confidence="high",
                    direct_dependency=direct,
                    install_scope=scope,
                    evidence_kind="lockfile",
                    raw_metadata={"lockfile_version": payload.get("lockfileVersion")},
                )
            )
        return records
    dependencies = payload.get("dependencies")
    if isinstance(dependencies, dict):
        _walk_v1_dependencies(path, root, dependencies, records, manifest, direct_level=True)
    return records


def _walk_v1_dependencies(
    path: Path,
    root: Path,
    dependencies: dict,
    records: list[dict],
    manifest: dict[str, tuple[bool, str]],
    *,
    direct_level: bool,
) -> None:
    for name, item in sorted(dependencies.items()):
        if not isinstance(item, dict) or not item.get("version"):
            continue
        manifest_direct, manifest_scope = manifest.get(name.lower(), (False, "dev" if item.get("dev") else "prod"))
        direct = manifest_direct or direct_level
        scope = manifest_scope if manifest_direct else ("dev" if item.get("dev") else "prod")
        records.append(
            package_record(
                root=root,
                ecosystem="npm",
                package_name=name,
                version=item["version"],
                source_file=path,
                source_type="npm-lockfile",
                package_manager="npm",
                confidence="high",
                direct_dependency=direct,
                install_scope=scope,
                evidence_kind="lockfile",
            )
        )
        nested = item.get("dependencies")
        if isinstance(nested, dict):
            _walk_v1_dependencies(path, root, nested, records, manifest, direct_level=False)


def _name_from_node_modules_key(key: str) -> str | None:
    parts = key.split("node_modules/")
    if not parts:
        return None
    tail = parts[-1].strip("/")
    if not tail:
        return None
    bits = tail.split("/")
    if bits[0].startswith("@") and len(bits) >= 2:
        return f"{bits[0]}/{bits[1]}"
    return bits[0]


def parse_node_package_json(path: Path, root: Path) -> list[dict]:
    """Parse installed node_modules package metadata for corroboration scans."""

    try:
        payload = _load_json(path)
    except Exception:
        return []
    name = payload.get("name")
    version = payload.get("version")
    if not name or not version:
        return []
    scripts = payload.get("scripts") if isinstance(payload.get("scripts"), dict) else {}
    lifecycle = sorted(name for name in scripts if name in NPM_LIFECYCLE_SCRIPTS)
    package_manager = "pnpm" if ".pnpm" in path.parts else "npm"
    source_type = "pnpm-node_modules" if package_manager == "pnpm" else "npm-node_modules"
    return [
        package_record(
            root=root,
            ecosystem="npm",
            package_name=name,
            version=version,
            source_file=path,
            source_type=source_type,
            package_manager=package_manager,
            confidence="high",
            direct_dependency=None,
            install_scope=None,
            evidence_kind="installed",
            raw_metadata={
                "has_lifecycle_scripts": bool(lifecycle),
                "lifecycle_scripts": lifecycle,
            },
        )
    ]


_PNPM_PACKAGE_RE = re.compile(r"^  ([^\s].*):\s*$")


def parse_pnpm_lock(path: Path, root: Path) -> list[dict]:
    """Parse pnpm lockfiles with a small purpose-built reader."""

    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return []
    manifest = _manifest_dependency_info(path)
    records: list[dict] = []
    in_packages = False
    current_key: str | None = None
    current_fields: dict[str, str] = {}

    def flush() -> None:
        if not current_key:
            return
        parsed = _parse_pnpm_package_key(current_key)
        if parsed is None:
            return
        name, version = parsed
        direct, manifest_scope = manifest.get(name.lower(), (False, None))
        scope = manifest_scope or ("dev" if current_fields.get("dev") == "true" else "prod")
        records.append(
            package_record(
                root=root,
                ecosystem="npm",
                package_name=name,
                version=version,
                source_file=path,
                source_type="pnpm-lockfile",
                package_manager="pnpm",
                confidence="high",
                direct_dependency=direct,
                install_scope=scope,
                evidence_kind="lockfile",
                raw_metadata={"requires_build": current_fields.get("requiresBuild") == "true"},
            )
        )

    for line in lines:
        if line.strip() == "packages:":
            in_packages = True
            continue
        if in_packages and line and not line.startswith(" "):
            flush()
            break
        if not in_packages:
            continue
        match = _PNPM_PACKAGE_RE.match(line)
        if match:
            flush()
            current_key = match.group(1).strip().strip("'\"")
            current_fields = {}
            continue
        if current_key and line.startswith("    ") and ":" in line:
            key, value = line.strip().split(":", 1)
            current_fields[key] = value.strip().strip("'\"")
    else:
        if in_packages:
            flush()
    return records


def _parse_pnpm_package_key(key: str) -> tuple[str, str] | None:
    key = key.strip().strip("'\"").split("(", 1)[0]
    if key.startswith("/"):
        key = key[1:]
    if key.startswith("@"):
        slash = key.find("/")
        if slash <= 0:
            return None
        at = key.rfind("@")
        if at > slash:
            name = key[:at]
            version = key[at + 1 :].split("_", 1)[0]
            return (name, version) if version else None
        parts = key.split("/")
        if len(parts) >= 3:
            name = "/".join(parts[:2])
            version = parts[2].split("_", 1)[0]
            return (name, version) if version else None
        return None
    if "@" in key:
        name, version = key.rsplit("@", 1)
        version = version.split("_", 1)[0]
        return (name, version) if name and version else None
    if "/" not in key:
        return None
    name, version = key.split("/", 1)
    version = version.split("_", 1)[0]
    return (name, version) if name and version else None


def parse_yarn_lock(path: Path, root: Path) -> list[dict]:
    """Parse Yarn lockfiles, including low-confidence vendored nested locks."""

    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return []
    manifest = _manifest_dependency_info(path)
    vendored = "node_modules" in path.parts
    records: list[dict] = []
    current_header: str | None = None
    current_version: str | None = None

    def flush() -> None:
        if not current_header or not current_version:
            return
        name = _package_name_from_yarn_header(current_header)
        if not name or name == "__metadata":
            return
        direct, scope = manifest.get(name.lower(), (False, None))
        records.append(
            package_record(
                root=root,
                ecosystem="npm",
                package_name=name,
                version=current_version,
                source_file=path,
                source_type="yarn-lockfile",
                package_manager="yarn",
                confidence="low" if vendored else "high",
                direct_dependency=direct if not vendored else False,
                install_scope=scope,
                evidence_kind="vendored-metadata" if vendored else "lockfile",
                vendored_metadata=vendored,
            )
        )

    for line in lines:
        if not line.strip() or line.startswith("#"):
            continue
        if not line.startswith((" ", "\t")) and line.rstrip().endswith(":"):
            flush()
            current_header = line.rstrip()[:-1].strip().strip('"')
            current_version = None
            continue
        if current_header and line.lstrip().startswith("version "):
            current_version = line.strip().split(" ", 1)[1].strip().strip('"')
    flush()
    return records


def _package_name_from_yarn_header(header: str) -> str | None:
    first = header.split(",", 1)[0].strip().strip('"')
    first = first.split("@npm:", 1)[-1]
    if first.startswith("@"):
        slash = first.find("/")
        at = first.find("@", slash + 1)
        return first[:at] if at > slash else first
    at = first.find("@")
    return first[:at] if at > 0 else first or None
