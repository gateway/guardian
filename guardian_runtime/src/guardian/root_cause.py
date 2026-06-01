from __future__ import annotations

import json
import subprocess
from functools import lru_cache
from pathlib import Path


def _choose_root_type(node: dict) -> str:
    node_type = node.get("type")
    if node_type in {"prod", "dev", "peer", "peerOptional", "optional"}:
        return node_type
    return "unknown"


def _walk_dependents(node: dict, chain: list[dict], results: list[dict]) -> None:
    current = {
        "name": node.get("name"),
        "version": node.get("version"),
        "type": _choose_root_type(node),
        "location": node.get("location"),
    }
    next_chain = chain + [current]
    dependents = node.get("dependents") or []
    if not dependents:
        results.append(
            {
                "chain": next_chain,
                "root_name": current["name"],
                "root_type": current["type"],
            }
        )
        return
    for dependent in dependents:
        parent = dependent.get("from") or {}
        if parent.get("location") and not parent.get("name"):
            results.append(
                {
                    "chain": next_chain,
                    "root_name": None,
                    "root_type": dependent.get("type") or "unknown",
                }
            )
            continue
        _walk_dependents(parent, next_chain, results)


@lru_cache(maxsize=1024)
def npm_explain_summary(root_path: str, package_name: str) -> dict | None:
    root = Path(root_path)
    if not (root / "package.json").exists():
        return None
    try:
        completed = subprocess.run(
            ["npm", "explain", package_name, "--json"],
            cwd=str(root),
            capture_output=True,
            text=True,
            check=False,
        )
    except Exception:
        return None
    output = (completed.stdout or "").strip()
    if not output:
        return None
    try:
        payload = json.loads(output)
    except json.JSONDecodeError:
        return None
    if isinstance(payload, dict) and payload.get("error"):
        return None
    if not isinstance(payload, list):
        return None
    chains: list[dict] = []
    for item in payload:
        _walk_dependents(item, [], chains)
    if not chains:
        return None
    roots: list[dict] = []
    seen: set[tuple[str | None, str]] = set()
    for chain_info in chains:
        key = (chain_info["root_name"], chain_info["root_type"])
        if key in seen:
            continue
        seen.add(key)
        roots.append(
            {
                "root_name": chain_info["root_name"],
                "root_type": chain_info["root_type"],
                "chain": " -> ".join(
                    part["name"]
                    for part in reversed(chain_info["chain"])
                    if part.get("name")
                ),
            }
        )
    return {
        "package_name": package_name,
        "roots": roots,
    }
