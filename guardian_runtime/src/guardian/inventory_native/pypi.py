from __future__ import annotations

import json
from email.parser import Parser
from pathlib import Path

from .records import package_record


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
            raw_metadata={"installer": installer, "direct_url": direct_url, "vendored_metadata": vendored},
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
