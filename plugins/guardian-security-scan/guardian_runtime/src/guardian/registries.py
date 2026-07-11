"""Registry metadata helpers for ecosystem-specific package lookup conventions."""

from __future__ import annotations

import json
from functools import cmp_to_key

from .config import GuardianConfig
from .http_client import GuardianHttp
from .util import quote_package_path
from .versions import compare_versions


class LatestVersionResolver:
    def __init__(self, config: GuardianConfig):
        self.config = config
        self.http = GuardianHttp(config)
        self._cache: dict[tuple[str, str], str | None] = {}
        self._versions_cache: dict[tuple[str, str], list[str]] = {}

    def _fetch_json(self, url: str) -> dict | None:
        try:
            return self.http.get(url).json()
        except Exception:
            return None

    def latest_version(self, ecosystem: str, package_name: str) -> str | None:
        key = (ecosystem, package_name)
        if key in self._cache:
            return self._cache[key]
        if ecosystem == "npm":
            url = f"https://registry.npmjs.org/{quote_package_path(package_name)}/latest"
        elif ecosystem == "pypi":
            url = f"https://pypi.org/pypi/{quote_package_path(package_name)}/json"
        else:
            self._cache[key] = None
            return None
        payload = self._fetch_json(url)
        if payload is None:
            self._cache[key] = None
            return None
        if ecosystem == "npm":
            version = payload.get("version")
        else:
            version = payload.get("info", {}).get("version")
        self._cache[key] = version or None
        return self._cache[key]

    def available_versions(self, ecosystem: str, package_name: str) -> list[str]:
        key = (ecosystem, package_name)
        if key in self._versions_cache:
            return self._versions_cache[key]
        versions: list[str] = []
        if ecosystem == "npm":
            url = f"https://registry.npmjs.org/{quote_package_path(package_name)}"
            payload = self._fetch_json(url)
            if payload:
                versions = list((payload.get("versions") or {}).keys())
        elif ecosystem == "pypi":
            url = f"https://pypi.org/pypi/{quote_package_path(package_name)}/json"
            payload = self._fetch_json(url)
            if payload:
                versions = list((payload.get("releases") or {}).keys())
        versions = sorted(set(item for item in versions if item), key=cmp_to_key(compare_versions))
        self._versions_cache[key] = versions
        return versions
