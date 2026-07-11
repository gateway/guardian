"""SQLite outreach ledger for duplicate and daily-cap enforcement."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone

from .util import utc_now


class OutreachStoreMixin:
    """Persist one durable decision per repository/advisory/package identity."""

    conn: sqlite3.Connection

    def outreach_entry(self, repo: str, advisory_id: str, package: str) -> dict | None:
        row = self.conn.execute(
            "SELECT * FROM outreach_log WHERE repo = ? AND advisory_id = ? AND package = ?",
            (repo.lower(), advisory_id.upper(), package.lower()),
        ).fetchone()
        if row is None:
            return None
        return {**dict(row), "details": json.loads(row["details_json"])}

    def outreach_count_today(self) -> int:
        today = datetime.now(timezone.utc).date().isoformat()
        row = self.conn.execute(
            """
            SELECT COUNT(*) AS count
            FROM outreach_log
            WHERE substr(created_at, 1, 10) = ?
              AND action IN ('eligible-awaiting-confirmation', 'public-pr', 'open-issue', 'private-report')
            """,
            (today,),
        ).fetchone()
        return int(row["count"] if row else 0)

    def record_outreach(
        self,
        *,
        repo: str,
        advisory_id: str,
        package: str,
        action: str,
        url: str | None,
        details: dict,
    ) -> dict:
        now = utc_now()
        self.conn.execute(
            """
            INSERT INTO outreach_log (
              repo, advisory_id, package, action, url, details_json, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(repo, advisory_id, package) DO UPDATE SET
              action = excluded.action,
              url = COALESCE(excluded.url, outreach_log.url),
              details_json = excluded.details_json,
              updated_at = excluded.updated_at
            """,
            (
                repo.lower(), advisory_id.upper(), package.lower(), action, url,
                json.dumps(details, sort_keys=True), now, now,
            ),
        )
        self.conn.commit()
        return self.outreach_entry(repo, advisory_id, package) or {}
