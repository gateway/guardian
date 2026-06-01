from __future__ import annotations

import json
from typing import Iterable, List
from urllib.parse import quote
from urllib.request import Request, urlopen

from ..config import GuardianConfig
from ..util import chunked, normalize_ecosystem_for_osv


class OSVClient:
    source_name = "osv"

    def __init__(self, config: GuardianConfig):
        self.config = config
        self._vuln_cache: dict[str, dict] = {}

    def query_batch(self, packages: list[dict]) -> list[dict]:
        results: list[dict] = []
        for batch in chunked(packages, 1000):
            queries = [
                {
                    "package": {
                        "name": package["package_name"],
                        "ecosystem": normalize_ecosystem_for_osv(package["ecosystem"]),
                    },
                    "version": package["version"],
                }
                for package in batch
            ]
            payload = json.dumps({"queries": queries}).encode("utf-8")
            request = Request(
                self.config.osv_api_url,
                data=payload,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": self.config.user_agent,
                },
                method="POST",
            )
            with urlopen(request, timeout=self.config.request_timeout_seconds) as response:
                data = json.loads(response.read().decode("utf-8"))
            results.extend(data.get("results", []))
        return results

    def get_vulnerability(self, advisory_id: str) -> dict:
        cached = self._vuln_cache.get(advisory_id)
        if cached is not None:
            return cached
        url = f"{self.config.osv_vuln_api_url}/{quote(advisory_id, safe='')}"
        request = Request(
            url,
            headers={"User-Agent": self.config.user_agent},
            method="GET",
        )
        with urlopen(request, timeout=self.config.request_timeout_seconds) as response:
            payload = json.loads(response.read().decode("utf-8"))
        self._vuln_cache[advisory_id] = payload
        return payload
