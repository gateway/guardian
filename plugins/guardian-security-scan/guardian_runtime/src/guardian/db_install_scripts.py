"""SQLite persistence for package install-script observations and drift."""

from __future__ import annotations

import json
import sqlite3

from .util import utc_now


class InstallScriptStoreMixin:
    """Store observations without erasing the history needed for comparisons."""

    conn: sqlite3.Connection

    def install_script_state(
        self,
        root_path: str,
        ecosystem: str,
        normalized_name: str,
        version: str,
        evidence_source: str,
    ) -> sqlite3.Row | None:
        return self.conn.execute(
            """
            SELECT * FROM install_script_state
            WHERE root_path = ? AND ecosystem = ? AND normalized_name = ?
              AND version = ? AND evidence_source = ?
            """,
            (root_path, ecosystem, normalized_name, version, evidence_source),
        ).fetchone()

    def latest_install_script_state(
        self,
        root_path: str,
        ecosystem: str,
        normalized_name: str,
        evidence_source: str,
        *,
        exclude_version: str | None = None,
    ) -> sqlite3.Row | None:
        query = """
            SELECT * FROM install_script_state
            WHERE root_path = ? AND ecosystem = ? AND normalized_name = ?
              AND evidence_source = ?
        """
        params: list[object] = [root_path, ecosystem, normalized_name, evidence_source]
        if exclude_version is not None:
            query += " AND version != ?"
            params.append(exclude_version)
        query += " ORDER BY last_seen_at DESC, id DESC LIMIT 1"
        return self.conn.execute(query, params).fetchone()

    def upsert_install_script_state(self, observation: dict) -> None:
        now = utc_now()
        has_script = observation.get("has_install_script")
        encoded_has_script = None if has_script is None else int(bool(has_script))
        self.conn.execute(
            """
            INSERT INTO install_script_state (
              root_path, ecosystem, normalized_name, version,
              has_install_script, script_kinds_json, scripts_sha256,
              evidence_source, first_seen_at, last_seen_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(root_path, ecosystem, normalized_name, version, evidence_source)
            DO UPDATE SET
              has_install_script = excluded.has_install_script,
              script_kinds_json = excluded.script_kinds_json,
              scripts_sha256 = excluded.scripts_sha256,
              last_seen_at = excluded.last_seen_at
            """,
            (
                observation["root_path"],
                observation["ecosystem"],
                observation["normalized_name"],
                observation["version"],
                encoded_has_script,
                json.dumps(observation.get("script_kinds") or [], sort_keys=True),
                observation.get("scripts_sha256"),
                observation["evidence_source"],
                now,
                now,
            ),
        )

    def commit_install_script_states(self) -> None:
        self.conn.commit()
