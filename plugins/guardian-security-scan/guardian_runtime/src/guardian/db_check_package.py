"""SQLite cache accessors for pre-install package verdicts."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone

from .util import utc_now


class CheckPackageCacheMixin:
    """Cache complete verdicts so repeated install checks stay sub-second."""

    conn: sqlite3.Connection

    def cached_package_verdict(
        self,
        ecosystem: str,
        normalized_name: str,
        version: str,
        *,
        ttl_seconds: int,
        cache_context: str,
    ) -> dict | None:
        cutoff = (datetime.now(timezone.utc) - timedelta(seconds=max(0, ttl_seconds))).replace(microsecond=0).isoformat()
        row = self.conn.execute(
            """
            SELECT verdict_json, checked_at
            FROM check_package_cache
            WHERE ecosystem = ? AND normalized_name = ? AND version = ?
              AND checked_at >= ?
            """,
            (ecosystem, normalized_name, version, cutoff),
        ).fetchone()
        if row is None:
            return None
        payload = json.loads(row["verdict_json"])
        if payload.get("cache_context") != cache_context:
            return None
        payload["cache_hit"] = True
        payload["cached_at"] = row["checked_at"]
        return payload

    def upsert_package_verdict(
        self,
        ecosystem: str,
        normalized_name: str,
        version: str,
        verdict: dict,
    ) -> None:
        checked_at = utc_now()
        payload = {**verdict, "cache_hit": False, "checked_at": checked_at}
        self.conn.execute(
            """
            INSERT INTO check_package_cache (
              ecosystem, normalized_name, version, verdict_json, checked_at
            ) VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(ecosystem, normalized_name, version) DO UPDATE SET
              verdict_json = excluded.verdict_json,
              checked_at = excluded.checked_at
            """,
            (ecosystem, normalized_name, version, json.dumps(payload, sort_keys=True), checked_at),
        )
        self.conn.commit()

    def invalidate_package_verdicts(self, ecosystem: str, normalized_name: str) -> None:
        """Discard cached decisions after an operator changes package policy."""

        self.conn.execute(
            "DELETE FROM check_package_cache WHERE ecosystem = ? AND normalized_name = ?",
            (ecosystem, normalized_name),
        )
        self.conn.commit()
