from __future__ import annotations

import json
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from ..config import GuardianConfig


class EPSSClient:
    source_name = "epss"

    def __init__(self, config: GuardianConfig):
        self.config = config
        self._cache: dict[str, dict | None] = {}

    def query_by_cve_id(self, cve_id: str) -> dict | None:
        if cve_id in self._cache:
            return self._cache[cve_id]
        params = urlencode({"cve": cve_id})
        url = f"{self.config.epss_api_url}?{params}"
        request = Request(
            url,
            headers={"User-Agent": self.config.user_agent},
            method="GET",
        )
        with urlopen(request, timeout=self.config.request_timeout_seconds) as response:
            data = json.loads(response.read().decode("utf-8"))
        rows = data.get("data", [])
        payload = rows[0] if rows else None
        self._cache[cve_id] = payload
        return payload
