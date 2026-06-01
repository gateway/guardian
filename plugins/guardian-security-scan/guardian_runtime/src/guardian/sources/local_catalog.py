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
        entries: list[dict] = []
        for directory in self.config.local_catalog_dirs:
            path = Path(directory)
            if not path.exists():
                continue
            for file in sorted(path.glob("*.json")):
                data = json.loads(file.read_text())
                for entry in data.get("entries", []):
                    entry = dict(entry)
                    entry["_catalog_file"] = str(file)
                    entries.append(entry)
        return entries

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
