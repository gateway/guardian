"""SQLite observation ledger for lockfile and requirement hygiene signals."""

from __future__ import annotations

import json
import sqlite3

from .util import utc_now


class LockfileHygieneStoreMixin:
    """Persist stable observation identities so unchanged scans stay silent."""

    conn: sqlite3.Connection

    def lockfile_hygiene_state(self, root_path: str) -> dict[str, dict]:
        rows = self.conn.execute(
            "SELECT * FROM lockfile_hygiene_state WHERE root_path = ? AND present = 1",
            (root_path,),
        )
        return {
            row["observation_key"]: {
                **json.loads(row["payload_json"]),
                "evidence_hash": row["evidence_hash"],
            }
            for row in rows
        }

    def replace_lockfile_hygiene_state(self, root_path: str, observations: list[dict]) -> None:
        """Upsert current observations and retire conditions no longer present."""

        now = utc_now()
        keys = {item["observation_key"] for item in observations}
        for item in observations:
            previous = self.conn.execute(
                "SELECT evidence_hash, last_changed_at FROM lockfile_hygiene_state WHERE root_path = ? AND observation_key = ?",
                (root_path, item["observation_key"]),
            ).fetchone()
            changed_at = (
                previous["last_changed_at"]
                if previous and previous["evidence_hash"] == item["evidence_hash"]
                else now
            )
            self.conn.execute(
                """
                INSERT INTO lockfile_hygiene_state (
                  root_path, observation_key, evidence_hash, payload_json,
                  first_seen_at, last_seen_at, last_changed_at, present
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 1)
                ON CONFLICT(root_path, observation_key) DO UPDATE SET
                  evidence_hash = excluded.evidence_hash,
                  payload_json = excluded.payload_json,
                  last_seen_at = excluded.last_seen_at,
                  last_changed_at = excluded.last_changed_at,
                  present = 1
                """,
                (
                    root_path,
                    item["observation_key"],
                    item["evidence_hash"],
                    json.dumps(item, sort_keys=True),
                    now,
                    now,
                    changed_at,
                ),
            )
        rows = self.conn.execute(
            "SELECT observation_key FROM lockfile_hygiene_state WHERE root_path = ? AND present = 1",
            (root_path,),
        ).fetchall()
        for row in rows:
            if row["observation_key"] not in keys:
                self.conn.execute(
                    "UPDATE lockfile_hygiene_state SET present = 0, last_seen_at = ? WHERE root_path = ? AND observation_key = ?",
                    (now, root_path, row["observation_key"]),
                )
        self.conn.commit()
