from __future__ import annotations


SCAN_MODE_PRESETS = {
    "daily": {
        "include_installed": False,
        "include_ghsa": False,
        "include_threat_intel": True,
        "write_handoff": False,
        "compact": True,
        "snapshot_full": True,
        "max_seconds": 60,
    },
    "standard": {
        "include_installed": False,
        "include_ghsa": False,
        "include_threat_intel": True,
        "write_handoff": False,
        "compact": False,
        "snapshot_full": True,
        "max_seconds": 120,
    },
    "deep": {
        "include_installed": True,
        "include_ghsa": True,
        "include_threat_intel": True,
        "write_handoff": False,
        "compact": False,
        "snapshot_full": True,
        "max_seconds": 300,
    },
    "handoff": {
        "include_installed": True,
        "include_ghsa": True,
        "include_threat_intel": True,
        "write_handoff": True,
        "compact": False,
        "snapshot_full": True,
        "max_seconds": 300,
    },
}


def apply_scan_mode(
    mode: str,
    *,
    include_installed: bool = False,
    include_ghsa: bool = False,
    include_threat_intel: bool = False,
    write_handoff: bool = False,
    compact: bool | None = None,
) -> dict:
    if mode not in SCAN_MODE_PRESETS:
        raise ValueError(f"unknown scan mode: {mode}")
    preset = dict(SCAN_MODE_PRESETS[mode])
    if include_installed:
        preset["include_installed"] = True
    if include_ghsa:
        preset["include_ghsa"] = True
    if include_threat_intel:
        preset["include_threat_intel"] = True
    if write_handoff:
        preset["write_handoff"] = True
    if compact is not None:
        preset["compact"] = compact
    return preset
