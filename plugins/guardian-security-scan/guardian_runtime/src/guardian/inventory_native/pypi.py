"""Python package metadata parser for installed PyPI distributions."""

from __future__ import annotations

import json
from email.parser import Parser
from pathlib import Path
import re

from .records import package_record


def parse_requirements_manifest(path: Path, root: Path) -> list[dict]:
    """Parse exact pins from pip requirements files without resolving ranges.

    Requirements files often contain lower bounds (`pkg>=1.2`) or unpinned
    package names. Treating those as installed versions would create false
    positives, so Guardian only emits package evidence for exact `==` pins.
    """

    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return []
    records: list[dict] = []
    scope = _requirements_scope(path)
    for line_number, raw_line in enumerate(lines, start=1):
        requirement = _clean_requirements_line(raw_line)
        if not requirement:
            continue
        parsed = _exact_python_requirement(requirement)
        if parsed is None:
            continue
        name, version = parsed
        records.append(
            package_record(
                root=root,
                ecosystem="pypi",
                package_name=name,
                version=version,
                source_file=path,
                source_type="requirements-manifest",
                package_manager="pip",
                confidence="medium",
                direct_dependency=True,
                install_scope=scope,
                evidence_kind="manifest",
                raw_metadata={"raw_specifier": requirement, "line": line_number},
            )
        )
    return records


def parse_uv_lock(path: Path, root: Path) -> list[dict]:
    """Parse exact package versions from uv.lock without requiring TOML packages."""

    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return []
    direct_scopes = _direct_dependency_scopes_from_pyproject(path.parent / "pyproject.toml")
    records: list[dict] = []
    current: dict[str, str] = {}

    def flush() -> None:
        name = current.get("name")
        version = current.get("version")
        if not name or not version:
            return
        normalized = _normalize_python_name(name)
        direct = normalized in direct_scopes if direct_scopes else None
        install_scope = direct_scopes.get(normalized)
        sdist_url = current.get("sdist_url")
        sdist_only = bool(sdist_url and current.get("has_wheel") != "true")
        records.append(
            package_record(
                root=root,
                ecosystem="pypi",
                package_name=name,
                version=version,
                source_file=path,
                source_type="uv-lockfile",
                package_manager="uv",
                confidence="high",
                direct_dependency=direct,
                install_scope=install_scope,
                evidence_kind="lockfile",
                raw_metadata={
                    "direct_dependency_names_available": bool(direct_scopes),
                    "has_install_script": sdist_only,
                    "install_script_kinds": ["sdist-install"] if sdist_only else [],
                    "install_script_evidence_source": "sdist-heuristic",
                    "sdist_url": sdist_url,
                },
            )
        )

    for line in lines:
        stripped = line.strip()
        if stripped == "[[package]]":
            flush()
            current = {}
            continue
        if not current and not stripped.startswith(("name =", "version =")):
            continue
        if stripped.startswith("name ="):
            value = _quoted_value(stripped)
            if value:
                current["name"] = value
            continue
        if stripped.startswith("version ="):
            value = _quoted_value(stripped)
            if value:
                current["version"] = value
            continue
        if stripped.startswith("sdist ="):
            url_match = re.search(r'url\s*=\s*"([^"]+)"', stripped)
            if url_match:
                current["sdist_url"] = url_match.group(1)
            continue
        if stripped.startswith("wheels = ["):
            current["has_wheel"] = "true"
    flush()
    return records


def parse_pyproject_manifest(path: Path, root: Path) -> list[dict]:
    """Parse exact project/package pins from pyproject.toml conservatively."""

    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []
    records: list[dict] = []
    project_name = _project_scalar(text, "name")
    project_version = _project_scalar(text, "version")
    if project_name and project_version:
        records.append(
            package_record(
                root=root,
                ecosystem="pypi",
                package_name=project_name,
                version=project_version,
                source_file=path,
                source_type="pyproject-manifest",
                package_manager=_build_backend_name(text) or "python",
                confidence="medium",
                direct_dependency=True,
                install_scope="prod",
                evidence_kind="manifest",
                raw_metadata={"package_self": True},
            )
        )

    for requirement, scope in _project_dependency_requirements(text):
        parsed = _exact_python_requirement(requirement)
        if parsed is None:
            continue
        name, version = parsed
        records.append(
            package_record(
                root=root,
                ecosystem="pypi",
                package_name=name,
                version=version,
                source_file=path,
                source_type="pyproject-manifest",
                package_manager=_build_backend_name(text) or "python",
                confidence="medium",
                direct_dependency=True,
                install_scope=scope,
                evidence_kind="manifest",
                raw_metadata={"raw_specifier": requirement},
            )
        )
    return records


def parse_python_metadata(path: Path, root: Path) -> list[dict]:
    try:
        text = _header_block(path)
        metadata = Parser().parsestr(text)
    except Exception:
        return []
    name = metadata.get("Name")
    version = metadata.get("Version")
    if not name or not version:
        return []
    source_type = "pypi-dist-info" if path.parent.name.endswith(".dist-info") else "pypi-egg-info"
    installer = _read_sibling(path, "INSTALLER")
    direct_url = _read_json_sibling(path, "direct_url.json")
    direct_source_url = (direct_url or {}).get("url") if isinstance(direct_url, dict) else None
    sdist_install = _looks_like_sdist_url(direct_source_url)
    isolated = any(part in {".venv", "venv", "site-packages", "dist-packages"} for part in path.parts)
    vendored = _is_vendored_python_metadata(path)
    return [
        package_record(
            root=root,
            ecosystem="pypi",
            package_name=name,
            version=version,
            source_file=path,
            source_type=source_type,
            package_manager=(installer or "pip").strip() or "pip",
            confidence="low" if vendored else "high" if source_type == "pypi-dist-info" else "medium",
            direct_dependency=None,
            install_scope=None,
            evidence_kind="vendored-metadata" if vendored else "installed",
            vendored_metadata=vendored,
            isolated_environment=isolated,
            raw_metadata={
                "installer": installer,
                "direct_url": direct_url,
                "vendored_metadata": vendored,
                "has_install_script": True if sdist_install else None,
                "install_script_kinds": ["sdist-install"] if sdist_install else [],
                "install_script_evidence_source": "sdist-heuristic",
            },
        )
    ]


def _header_block(path: Path) -> str:
    lines = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            break
        lines.append(line)
    return "\n".join(lines)


def _read_sibling(path: Path, name: str) -> str | None:
    sibling = path.parent / name
    if not sibling.exists():
        return None
    try:
        return sibling.read_text(encoding="utf-8", errors="replace").strip()
    except Exception:
        return None


def _read_json_sibling(path: Path, name: str) -> dict | None:
    sibling = path.parent / name
    if not sibling.exists():
        return None
    try:
        return json.loads(sibling.read_text(encoding="utf-8"))
    except Exception:
        return None


def _is_vendored_python_metadata(path: Path) -> bool:
    parts = path.parts
    for marker in ("site-packages", "dist-packages"):
        if marker not in parts:
            continue
        index = parts.index(marker)
        rel = parts[index + 1 :]
        return "_vendor" in rel or "vendor" in rel or len(rel) > 2
    return False


def _looks_like_sdist_url(url: str | None) -> bool:
    """Recognize source archives that can execute Python build hooks."""

    lowered = (url or "").lower().split("#", 1)[0].split("?", 1)[0]
    return lowered.endswith((".tar.gz", ".tar.bz2", ".tar.xz", ".tgz", ".zip"))


def _requirements_scope(path: Path) -> str:
    """Infer whether a requirements file is runtime or test/dev scoped."""

    lower_parts = {part.lower() for part in path.parts}
    lower_name = path.name.lower()
    if lower_parts.intersection({"test", "tests", "tests-unit", "testing", "docs", "examples"}):
        return "dev"
    if any(marker in lower_name for marker in ("dev", "test", "lint", "type", "doc")):
        return "dev"
    return "prod"


def _clean_requirements_line(line: str) -> str | None:
    """Remove comments and unsupported pip options from one requirements line."""

    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    if stripped.startswith(("-", "--")):
        return None
    if "://" in stripped or stripped.startswith(("git+", "hg+", "svn+", "bzr+")):
        return None
    return _strip_inline_comment(stripped).strip() or None


def _strip_inline_comment(line: str) -> str:
    """Strip comments that are separated from the requirement by whitespace."""

    return re.sub(r"\s+#.*$", "", line)


def _quoted_value(line: str) -> str | None:
    match = re.search(r'=\s*"([^"]+)"', line)
    return match.group(1) if match else None


def _normalize_python_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _project_scalar(text: str, key: str) -> str | None:
    in_project = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped == "[project]":
            in_project = True
            continue
        if in_project and stripped.startswith("["):
            return None
        if in_project and stripped.startswith(f"{key} ="):
            return _quoted_value(stripped)
    return None


def _build_backend_name(text: str) -> str | None:
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("build-backend ="):
            value = _quoted_value(stripped)
            if value:
                return value.split(".", 1)[0]
    return None


def _direct_dependency_scopes_from_pyproject(path: Path) -> dict[str, str]:
    """Map direct project dependencies to their runtime or optional scope."""

    if not path.exists():
        return {}
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return {}
    scopes: dict[str, str] = {}
    priority = {"prod": 0, "dev": 1, "optional": 2}
    for requirement, scope in _project_dependency_requirements(text):
        name = _requirement_name(requirement)
        if name:
            normalized = _normalize_python_name(name)
            current = scopes.get(normalized)
            if current is None or priority[scope] < priority[current]:
                scopes[normalized] = scope
    return scopes


def _project_dependency_requirements(text: str) -> list[tuple[str, str]]:
    requirements: list[tuple[str, str]] = []
    current_scope = "prod"
    collecting = False
    in_project = False
    in_optional = False

    for line in text.splitlines():
        stripped = line.strip()
        if stripped == "[project]":
            in_project = True
            in_optional = False
            continue
        if stripped == "[project.optional-dependencies]":
            in_project = False
            in_optional = True
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            in_project = False
            in_optional = False
            collecting = False
            continue
        if in_project and stripped.startswith("dependencies = ["):
            current_scope = "prod"
            collecting = True
            requirements.extend((_req, current_scope) for _req in _requirements_from_line(stripped))
            if stripped.endswith("]"):
                collecting = False
            continue
        if in_optional and re.match(r"^[A-Za-z0-9_.-]+\s*=\s*\[", stripped):
            option = stripped.split("=", 1)[0].strip()
            current_scope = "dev" if option == "dev" else "optional"
            collecting = True
            requirements.extend((_req, current_scope) for _req in _requirements_from_line(stripped))
            if stripped.endswith("]"):
                collecting = False
            continue
        if collecting:
            requirements.extend((_req, current_scope) for _req in _requirements_from_line(stripped))
            if stripped.endswith("]"):
                collecting = False
    return requirements


def _requirements_from_line(line: str) -> list[str]:
    return re.findall(r'"([^"]+)"', line)


def _requirement_name(requirement: str) -> str | None:
    match = re.match(r"\s*([A-Za-z0-9_.-]+)", requirement)
    return match.group(1) if match else None


def _exact_python_requirement(requirement: str) -> tuple[str, str] | None:
    name = _requirement_name(requirement)
    if not name:
        return None
    match = re.search(r"(?<![<>=!~])==\s*([A-Za-z0-9_.!+*-]+)", requirement)
    if not match:
        return None
    version = match.group(1).strip()
    if "*" in version:
        return None
    return name, version
