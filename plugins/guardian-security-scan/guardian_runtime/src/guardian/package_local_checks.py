"""Deterministic local checks and cache identity for the pre-install gate."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from .config import GuardianConfig
from .db import Database
from .signals import SignalGrade
from .sources import LocalCatalogMatcher, catalog_verification_status
from .typosquat import detect_typosquat


def local_package_verdict(
    config: GuardianConfig,
    db: Database,
    ecosystem: str,
    name: str,
    version: str | None,
    *,
    catalog_matcher: LocalCatalogMatcher | None = None,
) -> dict:
    """Evaluate non-network package signals for command-wide hook preflight."""

    ecosystem = ecosystem.lower()
    if ecosystem not in {"npm", "pypi"}:
        raise ValueError(f"unsupported ecosystem: {ecosystem}")
    if not name.strip():
        raise ValueError("package name is required")
    requested_version = (version or "").strip()
    resolved_version = requested_version if is_exact_version(requested_version) else None
    signals = detect_typosquat(ecosystem, name, db=db)
    signals.extend(
        local_catalog_signals(
            config,
            ecosystem,
            name,
            resolved_version,
            catalog_matcher=catalog_matcher,
        )
    )
    if blocked_by_grade(config, signals):
        verdict = "block"
        explanation = "Blocked by an exact malicious-package catalog match."
    elif signals:
        verdict = "warn"
        explanation = "Package name resembles a popular package; verify it before installation."
    else:
        verdict = "allow"
        explanation = "No local malicious-catalog or package-name signal was found."
    return {
        "verdict": verdict,
        "ecosystem": ecosystem,
        "name": name,
        "requested_version": requested_version or None,
        "resolved_version": resolved_version,
        "signals": signals,
        "explanation": explanation,
        "sources": {
            "typosquat": {"status": "checked", "network": False},
            "local_catalog": {
                "status": (
                    "matched"
                    if any(item.get("signal_type") == "malicious-catalog-match" for item in signals)
                    else "checked"
                ),
                "network": False,
            },
        },
        "cache_hit": False,
    }


def local_catalog_signals(
    config: GuardianConfig,
    ecosystem: str,
    name: str,
    version: str | None,
    *,
    catalog_matcher: LocalCatalogMatcher | None = None,
) -> list[dict]:
    """Return exact malicious-catalog matches, excluding advisory-only catalogs."""

    if not version:
        return []
    return [
        {
            "signal_type": "malicious-catalog-match",
            "signal_grade": (
                SignalGrade.CORROBORATED_MALICIOUS.value
                if catalog_verification_status(entry, version) == "corroborated"
                else SignalGrade.CATALOG_MATCH.value
            ),
            "source": "local-catalog",
            "id": entry["id"],
            "catalog": entry.get("_catalog_file"),
            "name": entry.get("name"),
            "url": entry.get("source"),
            "explanation": (
                f"Exact package/version match in Guardian catalog: {entry.get('name') or entry['id']}."
            ),
        }
        for entry in (catalog_matcher or LocalCatalogMatcher(config)).match(ecosystem, name, version)
        if entry.get("source_type") != "official-advisory-db"
    ]


def blocked_by_grade(config: GuardianConfig, signals: list[dict]) -> bool:
    """Apply the configured fail-closed grades to a set of package signals."""

    blocked = set(config.preinstall_gate_block_grades)
    return any(signal.get("signal_grade") in blocked for signal in signals)


def is_exact_version(value: str) -> bool:
    """Reject tags and ranges so exact-version sources receive concrete versions."""

    return bool(value) and re.match(r"^v?\d", value) is not None and not re.search(r"[<>=~^*|,\s]", value)


def package_cache_context(
    config: GuardianConfig,
    db: Database,
    ecosystem: str,
    normalized_name: str,
    requested_version: str,
) -> str:
    """Bind cached decisions to local intelligence, policy, and registry evidence."""

    catalog_state = []
    for directory in sorted(config.local_catalog_dirs):
        for path in sorted(Path(directory).rglob("*.json")):
            try:
                stat = path.stat()
            except OSError:
                continue
            catalog_state.append((str(path), stat.st_size, stat.st_mtime_ns))
    payload = {
        "block_grades": sorted(config.preinstall_gate_block_grades),
        "catalog_state": catalog_state,
        "registry_fetched_at": None,
    }
    if is_exact_version(requested_version):
        registry = db.registry_metadata(ecosystem, normalized_name, requested_version)
        payload["registry_fetched_at"] = registry.get("fetched_at") if registry else None
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
