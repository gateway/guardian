"""General source usage search used by triage and package review flows."""

from __future__ import annotations

import subprocess
import re
from functools import lru_cache
from pathlib import Path

from .util import normalize_package_name


SEARCH_EXCLUDES = [
    "--glob", "!node_modules/**",
    "--glob", "!.venv/**",
    "--glob", "!venv/**",
    "--glob", "!dist/**",
    "--glob", "!build/**",
    "--glob", "!.next/**",
    "--glob", "!coverage/**",
]

RG_TIMEOUT_SECONDS = 10
INDEX_RG_TIMEOUT_SECONDS = 30
INDEX_IMPORT_PATTERN = r"""(?:from\s+|import\s*\(\s*|require\(\s*|import\s+)['"]([^'"]+)['"]"""


def import_candidates(ecosystem: str, package_name: str) -> list[str]:
    if ecosystem == "pypi":
        base = package_name.replace("-", "_").replace(".", "_")
        return [base]
    return [package_name]


def patterns_for_package(ecosystem: str, package_name: str) -> list[str]:
    patterns: list[str] = []
    for candidate in import_candidates(ecosystem, package_name):
        if ecosystem == "pypi":
            patterns.extend([
                rf"\bimport\s+{candidate}\b",
                rf"\bfrom\s+{candidate}(?:\.|\s+import\b)",
            ])
        else:
            patterns.extend([
                rf"import\s+['\"]{candidate}(?:/[^'\"]*)?['\"]",
                rf"from\s+['\"]{candidate}(?:/[^'\"]*)?['\"]",
                rf"require\(\s*['\"]{candidate}(?:/[^'\"]*)?['\"]\s*\)",
                rf"import\(\s*['\"]{candidate}(?:/[^'\"]*)?['\"]\s*\)",
            ])
    return patterns


@lru_cache(maxsize=4096)
def find_package_usage(root_path: str, ecosystem: str, package_name: str, limit: int = 8) -> dict:
    root = Path(root_path)
    if not root.exists():
        return {"root_path": root_path, "hit_count": 0, "hits": []}
    hits: list[dict] = []
    patterns = patterns_for_package(ecosystem, package_name)
    seen: set[tuple[str, int]] = set()
    for pattern in patterns:
        cmd = [
            "rg",
            "-n",
            "-S",
            "--color",
            "never",
            *SEARCH_EXCLUDES,
            pattern,
            str(root),
        ]
        try:
            completed = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=RG_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            continue
        except Exception:
            continue
        if completed.returncode not in {0, 1}:
            continue
        for line in completed.stdout.splitlines():
            parts = line.split(":", 2)
            if len(parts) != 3:
                continue
            file_path, line_number, snippet = parts
            key = (file_path, int(line_number))
            if key in seen:
                continue
            seen.add(key)
            hits.append({
                "file": file_path,
                "line": int(line_number),
                "snippet": snippet.strip(),
            })
            if len(hits) >= limit:
                return {"root_path": root_path, "hit_count": len(hits), "hits": hits}
    return {"root_path": root_path, "hit_count": len(hits), "hits": hits}


def build_npm_usage_index(root_path: str, *, limit_per_package: int = 80) -> dict[str, dict]:
    root = Path(root_path)
    if not root.exists():
        return {}
    cmd = [
        "rg",
        "-n",
        "-S",
        "--color",
        "never",
        *SEARCH_EXCLUDES,
        INDEX_IMPORT_PATTERN,
        str(root),
    ]
    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=INDEX_RG_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        return {}
    except Exception:
        return {}
    if completed.returncode not in {0, 1}:
        return {}
    index: dict[str, dict] = {}
    seen: set[tuple[str, str, int]] = set()
    for line in completed.stdout.splitlines():
        parts = line.split(":", 2)
        if len(parts) != 3:
            continue
        file_path, line_number, snippet = parts
        try:
            line_int = int(line_number)
        except ValueError:
            continue
        for specifier in _import_specifiers(snippet):
            package_name = _npm_package_from_specifier(specifier)
            if not package_name:
                continue
            normalized = normalize_package_name("npm", package_name)
            key = (normalized, file_path, line_int)
            if key in seen:
                continue
            seen.add(key)
            payload = index.setdefault(
                normalized,
                {
                    "root_path": root_path,
                    "hit_count": 0,
                    "hits": [],
                    "truncated": False,
                },
            )
            payload["hit_count"] += 1
            if len(payload["hits"]) < limit_per_package:
                payload["hits"].append({"file": file_path, "line": line_int, "snippet": snippet.strip()})
            else:
                payload["truncated"] = True
    return index


def _import_specifiers(snippet: str) -> list[str]:
    return [match.group(1) for match in re.finditer(INDEX_IMPORT_PATTERN, snippet)]


def _npm_package_from_specifier(specifier: str) -> str | None:
    if not specifier or specifier.startswith((".", "/", "#")):
        return None
    parts = specifier.split("/")
    if specifier.startswith("@"):
        if len(parts) < 2:
            return None
        return "/".join(parts[:2])
    return parts[0]
