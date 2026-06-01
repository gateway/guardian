from __future__ import annotations

"""Source-usage helpers for dependency cleanup analysis.

This module centralizes bounded ripgrep calls, wrapper-fanout checks, and
dynamic string-reference detection so large repos cannot stall the diet scan.
"""

import re
import subprocess
from pathlib import Path


SKIP_DIRS = {"node_modules", ".git", ".venv", "venv", "dist", "build", ".next", "coverage"}
IDENTIFIER_RG_TIMEOUT_SECONDS = 8
IDENTIFIER_RG_MAX_COUNT_PER_FILE = 20
IDENTIFIER_FANOUT_HIT_CAP = 200
DYNAMIC_REFERENCE_TIMEOUT_SECONDS = 8
DYNAMIC_REFERENCE_HIT_CAP = 20


def symbols_from_usage(package_name: str, hits: list[dict]) -> list[str]:
    symbols: set[str] = set()
    escaped = re.escape(package_name)
    for hit in hits:
        snippet = hit.get("snippet") or ""
        symbols.update(_named_import_symbols(snippet, escaped))
        subpath = re.search(r"['\"]" + escaped + r"/([^'\"]+)['\"]", snippet)
        if subpath:
            symbols.add(subpath.group(1).split("/", 1)[0])
        symbols.update(_named_require_symbols(snippet, escaped))
    return sorted(symbols)


def usage_density(usage: dict, symbols: list[str]) -> dict:
    hit_count = int(usage.get("hit_count") or 0)
    symbol_count = len(symbols)
    if hit_count == 0:
        label = "none"
    elif hit_count <= 2 and symbol_count <= 2:
        label = "low"
    elif hit_count <= 5:
        label = "medium"
    else:
        label = "high"
    return {
        "label": label,
        "hit_count": hit_count,
        "symbol_count": symbol_count,
        "symbols": symbols,
    }


def wrapper_fanout(root: Path, hits: list[dict], package_name: str) -> dict:
    candidates: list[dict] = []
    for hit in hits[:5]:
        path = Path(hit["file"])
        if not path.exists() or any(part in SKIP_DIRS for part in path.parts):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for symbol in exported_symbols_near_import(text, package_name):
            usage = identifier_usage(root, symbol, exclude_file=path)
            if usage["hit_count"] > 0:
                candidates.append(
                    {
                        "symbol": symbol,
                        "hit_count": usage["hit_count"],
                        "hits": usage["hits"][:5],
                    }
                )
    candidates.sort(key=lambda item: (-item["hit_count"], item["symbol"]))
    top = candidates[0] if candidates else None
    return {
        "top_symbol": top["symbol"] if top else None,
        "max_hit_count": top["hit_count"] if top else 0,
        "candidates": candidates[:3],
    }


def exported_symbols_near_import(text: str, package_name: str) -> list[str]:
    lines = text.splitlines()
    import_indexes = [
        index
        for index, line in enumerate(lines)
        if f"'{package_name}'" in line or f'"{package_name}"' in line
    ]
    if not import_indexes:
        return []
    symbols: set[str] = set()
    lower_bound = min(import_indexes)
    upper_bound = min(len(lines), max(import_indexes) + 80)
    window = "\n".join(lines[lower_bound:upper_bound])
    for pattern in (
        r"export\s+function\s+([A-Za-z_$][\w$]*)",
        r"export\s+const\s+([A-Za-z_$][\w$]*)",
        r"export\s+\{\s*([^}]+)\s*\}",
    ):
        for match in re.finditer(pattern, window):
            symbols.update(_split_export_symbols(match.group(1)))
    return sorted(symbols)


def identifier_usage(root: Path, symbol: str, *, exclude_file: Path) -> dict:
    hits: list[dict] = []
    seen: set[tuple[str, int]] = set()
    cmd = [
        "rg",
        "-n",
        "-S",
        "--color",
        "never",
        "--max-count",
        str(IDENTIFIER_RG_MAX_COUNT_PER_FILE),
        *[item for pair in (("--glob", f"!{part}/**") for part in SKIP_DIRS) for item in pair],
        rf"\b{re.escape(symbol)}\b",
        str(root),
    ]
    completed = _run_rg(cmd, IDENTIFIER_RG_TIMEOUT_SECONDS)
    if completed is None:
        return {"hit_count": 0, "hits": []}
    for line in completed.stdout.splitlines():
        parsed = _parse_rg_line(line)
        if parsed is None:
            continue
        file_path, line_number, snippet = parsed
        try:
            if Path(file_path).resolve() == exclude_file.resolve():
                continue
        except Exception:
            pass
        key = (file_path, line_number)
        if key in seen:
            continue
        seen.add(key)
        hits.append({"file": file_path, "line": line_number, "snippet": snippet})
        if len(hits) >= IDENTIFIER_FANOUT_HIT_CAP:
            return {"hit_count": len(hits), "hits": hits[:8], "truncated": True}
    return {"hit_count": len(hits), "hits": hits[:8]}


def dynamic_package_reference(root: Path, package_name: str) -> dict:
    hits: list[dict] = []
    cmd = [
        "rg",
        "-n",
        "-S",
        "--fixed-strings",
        "--color",
        "never",
        *[item for pair in (("--glob", f"!{part}/**") for part in SKIP_DIRS) for item in pair],
        package_name,
        str(root),
    ]
    completed = _run_rg(cmd, DYNAMIC_REFERENCE_TIMEOUT_SECONDS)
    if completed is None:
        return {"root_path": str(root), "hit_count": 0, "hits": []}
    seen: set[tuple[str, int]] = set()
    for line in completed.stdout.splitlines():
        parsed = _parse_rg_line(line)
        if parsed is None:
            continue
        file_path, line_number, snippet = parsed
        if is_metadata_reference(Path(file_path)):
            continue
        key = (file_path, line_number)
        if key in seen:
            continue
        seen.add(key)
        hits.append({"file": file_path, "line": line_number, "snippet": snippet})
        if len(hits) >= DYNAMIC_REFERENCE_HIT_CAP:
            return {
                "root_path": str(root),
                "hit_count": len(hits),
                "hits": hits,
                "reference_kind": "dynamic-string",
                "truncated": True,
            }
    return {"root_path": str(root), "hit_count": len(hits), "hits": hits, "reference_kind": "dynamic-string"}


def is_metadata_reference(path: Path) -> bool:
    name = path.name
    if name in {"package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "npm-shrinkwrap.json"}:
        return True
    if name == "knip.config.ts":
        return True
    if path.suffix.lower() in {".md", ".json", ".yaml", ".yml", ".lock"}:
        return True
    return False


def _named_import_symbols(snippet: str, escaped_package_name: str) -> set[str]:
    symbols: set[str] = set()
    named = re.search(r"import\s+\{([^}]+)\}\s+from\s+['\"]" + escaped_package_name, snippet)
    if named:
        symbols.update(_split_export_symbols(named.group(1)))
    return symbols


def _named_require_symbols(snippet: str, escaped_package_name: str) -> set[str]:
    symbols: set[str] = set()
    require_named = re.search(r"\{([^}]+)\}\s*=\s*require\(\s*['\"]" + escaped_package_name, snippet)
    if require_named:
        for item in require_named.group(1).split(","):
            symbol = item.strip().split(":", 1)[0].strip()
            if symbol:
                symbols.add(symbol)
    return symbols


def _split_export_symbols(value: str) -> set[str]:
    if "," not in value:
        symbol = value.strip().split(" as ", 1)[0].strip()
        return {symbol} if symbol else set()
    symbols = set()
    for item in value.split(","):
        symbol = item.strip().split(" as ", 1)[0].strip()
        if symbol:
            symbols.add(symbol)
    return symbols


def _run_rg(cmd: list[str], timeout_seconds: int) -> subprocess.CompletedProcess[str] | None:
    try:
        completed = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=timeout_seconds)
    except (subprocess.TimeoutExpired, Exception):
        return None
    if completed.returncode not in {0, 1}:
        return None
    return completed


def _parse_rg_line(line: str) -> tuple[str, int, str] | None:
    parts = line.split(":", 2)
    if len(parts) != 3:
        return None
    file_path, line_number, snippet = parts
    try:
        line_int = int(line_number)
    except ValueError:
        return None
    return file_path, line_int, snippet.strip()
