"""FIRST EPSS client for CVE exploit-likelihood enrichment."""

from __future__ import annotations

import json
from urllib.parse import urlencode

from ..config import GuardianConfig
from ..http_client import GuardianHttp


class EPSSClient:
    source_name = "epss"

    def __init__(self, config: GuardianConfig):
        self.config = config
        self.http = GuardianHttp(config)
        self._cache: dict[str, dict | None] = {}

    def query_by_cve_id(self, cve_id: str) -> dict | None:
        if cve_id in self._cache:
            return self._cache[cve_id]
        params = urlencode({"cve": cve_id})
        url = f"{self.config.epss_api_url}?{params}"
        data = self.http.get(url).json()
        rows = data.get("data", [])
        payload = rows[0] if rows else None
        self._cache[cve_id] = payload
        return payload
