"""Local exact-match catalog matcher for malicious or campaign-specific package intelligence."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from ..config import GuardianConfig
from ..util import normalize_package_name


class LocalCatalogMatcher:
    source_name = "local-catalog"

    def __init__(self, config: GuardianConfig):
        self.config = config
        self.entries = self._load_entries()

    def _load_entries(self) -> list[dict]:
        entries_by_key: dict[tuple[str, str, str], tuple[int, dict]] = {}
        for directory in self.config.local_catalog_dirs:
            path = Path(directory)
            if not path.exists():
                continue
            for file in sorted(path.rglob("*.json")):
                data = json.loads(file.read_text())
                priority = 1 if ".guardian-verified" in file.parts else 0
                for entry in data.get("entries", []):
                    entry = dict(entry)
                    entry["_catalog_file"] = str(file)
                    identity = str(entry.get("id") or json.dumps(
                        [entry.get("name"), entry.get("versions") or []],
                        sort_keys=True,
                    ))
                    key = (
                        identity,
                        str(entry.get("ecosystem") or ""),
                        str(entry.get("package") or ""),
                    )
                    current = entries_by_key.get(key)
                    if current is None or priority >= current[0]:
                        entries_by_key[key] = (priority, entry)
        return [item[1] for item in entries_by_key.values()]

    def match(self, ecosystem: str, package_name: str, version: str) -> list[dict]:
        normalized_name = normalize_package_name(ecosystem, package_name)
        matches = []
        for entry in self.entries:
            if entry.get("ecosystem") != ecosystem:
                continue
            if normalize_package_name(ecosystem, entry.get("package", "")) != normalized_name:
                continue
            if version not in entry.get("versions", []):
                continue
            matches.append(entry)
        return matches


def catalog_verification_status(entry: dict, version: str) -> str | None:
    """Return persisted verification for the exact matched version, if present."""

    verification = entry.get("verification") or {}
    version_state = (verification.get("versions") or {}).get(version) or {}
    return version_state.get("status") or verification.get("status")
