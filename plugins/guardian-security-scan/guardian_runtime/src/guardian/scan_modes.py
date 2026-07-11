"""Named scan-mode defaults for daily, standard, deep, and handoff scans."""

from __future__ import annotations


SCAN_MODE_PRESETS = {
    "daily": {
        "include_installed": False,
        "include_ghsa": False,
        "include_threat_intel": True,
        "include_openssf_malicious": False,
        "registry_intel_mode": "off",
        "write_handoff": False,
        "compact": True,
        "snapshot_full": True,
        "max_seconds": 60,
    },
    "standard": {
        "include_installed": False,
        "include_ghsa": False,
        "include_threat_intel": True,
        "include_openssf_malicious": False,
        "registry_intel_mode": "changed",
        "write_handoff": False,
        "compact": False,
        "snapshot_full": True,
        "max_seconds": 120,
    },
    "deep": {
        "include_installed": True,
        "include_ghsa": True,
        "include_threat_intel": True,
        "include_openssf_malicious": True,
        "registry_intel_mode": "deep",
        "write_handoff": False,
        "compact": False,
        "snapshot_full": True,
        "max_seconds": 300,
    },
    "handoff": {
        "include_installed": True,
        "include_ghsa": True,
        "include_threat_intel": True,
        "include_openssf_malicious": True,
        "registry_intel_mode": "deep",
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
    include_openssf_malicious: bool = False,
    include_registry_intel: bool = False,
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
    if include_openssf_malicious:
        preset["include_openssf_malicious"] = True
    if include_registry_intel and preset["registry_intel_mode"] == "off":
        preset["registry_intel_mode"] = "changed"
    if write_handoff:
        preset["write_handoff"] = True
    if compact is not None:
        preset["compact"] = compact
    return preset
