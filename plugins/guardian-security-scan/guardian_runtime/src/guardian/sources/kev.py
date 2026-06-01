from __future__ import annotations

import json
from urllib.request import Request, urlopen

from ..config import GuardianConfig


class KEVClient:
    source_name = "kev"

    def __init__(self, config: GuardianConfig):
        self.config = config
        self._catalog: dict[str, dict] | None = None

    def _load_catalog(self) -> dict[str, dict]:
        if self._catalog is not None:
            return self._catalog
        request = Request(
            self.config.kev_catalog_url,
            headers={"User-Agent": self.config.user_agent},
            method="GET",
        )
        with urlopen(request, timeout=self.config.request_timeout_seconds) as response:
            data = json.loads(response.read().decode("utf-8"))
        vulnerabilities = data.get("vulnerabilities", [])
        self._catalog = {
            item["cveID"]: item
            for item in vulnerabilities
            if item.get("cveID")
        }
        return self._catalog

    def query_by_cve_id(self, cve_id: str) -> dict | None:
        return self._load_catalog().get(cve_id)
