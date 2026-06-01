from __future__ import annotations

import json
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from ..config import GuardianConfig


class NVDClient:
    source_name = "nvd"

    def __init__(self, config: GuardianConfig):
        self.config = config
        self._cve_cache: dict[str, dict | None] = {}

    def query_by_cve_id(self, cve_id: str) -> dict | None:
        if cve_id in self._cve_cache:
            return self._cve_cache[cve_id]
        url = f"{self.config.nvd_api_url}?{urlencode({'cveId': cve_id})}"
        request = Request(
            url,
            headers={"User-Agent": self.config.user_agent},
            method="GET",
        )
        with urlopen(request, timeout=self.config.request_timeout_seconds) as response:
            data = json.loads(response.read().decode("utf-8"))
        vulnerabilities = data.get("vulnerabilities", [])
        payload = vulnerabilities[0] if vulnerabilities else None
        self._cve_cache[cve_id] = payload
        return payload
