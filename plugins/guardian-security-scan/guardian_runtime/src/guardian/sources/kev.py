"""CISA Known Exploited Vulnerabilities client for exploited-in-the-wild enrichment."""

from __future__ import annotations

import json

from ..config import GuardianConfig
from ..http_client import GuardianHttp


class KEVClient:
    source_name = "kev"

    def __init__(self, config: GuardianConfig):
        self.config = config
        self.http = GuardianHttp(config)
        self._catalog: dict[str, dict] | None = None

    def _load_catalog(self) -> dict[str, dict]:
        if self._catalog is not None:
            return self._catalog
        data = self.http.get(self.config.kev_catalog_url).json()
        vulnerabilities = data.get("vulnerabilities", [])
        self._catalog = {
            item["cveID"]: item
            for item in vulnerabilities
            if item.get("cveID")
        }
        return self._catalog

    def query_by_cve_id(self, cve_id: str) -> dict | None:
        return self._load_catalog().get(cve_id)
