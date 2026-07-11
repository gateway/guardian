"""Aggregate offline and mode-gated behavioral dependency signals."""

from __future__ import annotations

from .config import GuardianConfig
from .db import Database
from .install_scripts import detect_install_script_changes
from .lockfile_hygiene import detect_lockfile_hygiene
from .registry_intel import detect_registry_metadata_changes
from .typosquat import detect_new_package_typosquats


def behavioral_signals_for_runs(
    config: GuardianConfig,
    db: Database,
    root: str,
    run_ids: list[int],
    *,
    registry_intel_mode: str,
) -> dict:
    """Combine local and registry signals using one deterministic priority order."""

    if registry_intel_mode not in {"off", "changed", "deep"}:
        raise ValueError(f"unsupported registry_intel_mode: {registry_intel_mode}")
    signals = detect_install_script_changes(db, root)
    signals.extend(detect_lockfile_hygiene(config, db, root))
    signals.extend(detect_new_package_typosquats(db, root, run_ids))
    if registry_intel_mode == "off":
        registry = {
            "status": "disabled",
            "candidates": 0,
            "selected": 0,
            "signals": [],
            "errors": [],
            "http_stats": {"requests": 0, "cache_hits": 0, "bytes_downloaded": 0},
        }
    else:
        registry = detect_registry_metadata_changes(
            config,
            db,
            root,
            run_ids,
            include_baseline=registry_intel_mode == "deep",
        )
        signals.extend(registry["signals"])
    return {
        "signals": sorted(
            signals,
            key=lambda item: (
                item.get("posture_rank", 9),
                (item.get("package_name") or "").lower(),
                item.get("signal_type") or "",
            ),
        ),
        "registry_intel": registry,
    }
