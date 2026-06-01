"""GitHub Security Advisories client for exact package/version and advisory-id lookups."""

from __future__ import annotations

import json
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from ..config import GuardianConfig, github_token
from ..util import encode_affects, normalize_ecosystem_for_ghsa


class GitHubAdvisoriesClient:
    source_name = "ghsa"

    def __init__(self, config: GuardianConfig):
        self.config = config
        self.token = github_token()
        self._ghsa_id_cache: dict[str, dict | None] = {}

    def query_exact(self, ecosystem: str, package_name: str, version: str) -> list[dict]:
        advisories: list[dict] = []
        for advisory_type in ["reviewed", "malware"]:
            params = urlencode(
                {
                    "ecosystem": normalize_ecosystem_for_ghsa(ecosystem),
                    "affects": encode_affects(package_name, version),
                    "type": advisory_type,
                    "per_page": 100,
                }
            )
            url = f"{self.config.ghsa_api_url}?{params}"
            headers = {
                "Accept": "application/vnd.github+json",
                "User-Agent": self.config.user_agent,
                "X-GitHub-Api-Version": "2026-03-10",
            }
            if self.token:
                headers["Authorization"] = f"Bearer {self.token}"
            request = Request(url, headers=headers, method="GET")
            with urlopen(request, timeout=self.config.request_timeout_seconds) as response:
                data = json.loads(response.read().decode("utf-8"))
            advisories.extend(data)
        deduped = {}
        for advisory in advisories:
            deduped[advisory["ghsa_id"]] = advisory
        return list(deduped.values())

    def query_by_ghsa_id(self, ghsa_id: str) -> dict | None:
        if ghsa_id in self._ghsa_id_cache:
            return self._ghsa_id_cache[ghsa_id]
        params = urlencode({"ghsa_id": ghsa_id, "per_page": 1})
        url = f"{self.config.ghsa_api_url}?{params}"
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": self.config.user_agent,
            "X-GitHub-Api-Version": "2026-03-10",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        request = Request(url, headers=headers, method="GET")
        with urlopen(request, timeout=self.config.request_timeout_seconds) as response:
            data = json.loads(response.read().decode("utf-8"))
        payload = data[0] if data else None
        self._ghsa_id_cache[ghsa_id] = payload
        return payload
