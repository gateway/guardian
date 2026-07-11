"""NVD client for CVE detail and severity enrichment."""

from __future__ import annotations

import json
from urllib.parse import urlencode

from ..config import GuardianConfig
from ..http_client import GuardianHttp


class NVDClient:
    source_name = "nvd"

    def __init__(self, config: GuardianConfig):
        self.config = config
        self.http = GuardianHttp(config)
        self._cve_cache: dict[str, dict | None] = {}

    def query_by_cve_id(self, cve_id: str) -> dict | None:
        if cve_id in self._cve_cache:
            return self._cve_cache[cve_id]
        url = f"{self.config.nvd_api_url}?{urlencode({'cveId': cve_id})}"
        data = self.http.get(url).json()
        vulnerabilities = data.get("vulnerabilities", [])
        payload = vulnerabilities[0] if vulnerabilities else None
        self._cve_cache[cve_id] = payload
        return payload
