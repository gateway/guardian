from __future__ import annotations

import json
import sqlite3

from .util import utc_now


class SnapshotStoreMixin:
    """SQLite helpers for persisted triage snapshots and comparisons."""

    conn: sqlite3.Connection

    def create_triage_snapshot(
        self,
        *,
        root_path: str,
        headline: str,
        summary: dict,
        package_actions: list[dict],
        inventory_run_ids: list[int] | None = None,
        report_path: str | None = None,
    ) -> int:
        created_at = utc_now()
        cursor = self.conn.execute(
            """
            INSERT INTO triage_snapshots (
              created_at, root_path, inventory_run_ids_json, headline, report_path, summary_json
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                created_at,
                root_path,
                json.dumps(inventory_run_ids or []),
                headline,
                report_path,
                json.dumps(summary, sort_keys=True),
            ),
        )
        snapshot_id = int(cursor.lastrowid)
        rows = []
        for package in package_actions:
            rows.append(
                (
                    snapshot_id,
                    package["ecosystem"],
                    package["package_name"],
                    package["normalized_name"],
                    package["version"],
                    package.get("risk_label"),
                    package.get("highest_severity"),
                    int(package.get("advisory_count") or 0),
                    package.get("role_label"),
                    package.get("environment_label"),
                    package.get("recommended_clean_version"),
                    package.get("first_fixed_version"),
                    json.dumps(package.get("issue_keys", []), sort_keys=True),
                    json.dumps(package.get("classification_labels", []), sort_keys=True),
                    json.dumps(package.get("notes", []), sort_keys=True),
                )
            )
        if rows:
            self.conn.executemany(
                """
                INSERT INTO triage_snapshot_packages (
                  snapshot_id, ecosystem, package_name, normalized_name, version,
                  risk_label, highest_severity, advisory_count, role_label, environment_label,
                  recommended_clean_version, first_fixed_version, issue_keys_json,
                  classification_labels_json, notes_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )
        self.conn.commit()
        return snapshot_id

    def latest_triage_snapshots(self, root_path: str, limit: int = 2) -> list[sqlite3.Row]:
        return list(
            self.conn.execute(
                """
                SELECT *
                FROM triage_snapshots
                WHERE root_path = ?
                ORDER BY created_at DESC, id DESC
                LIMIT ?
                """,
                (root_path, limit),
            )
        )

    def get_triage_snapshot(self, snapshot_id: int) -> sqlite3.Row | None:
        return self.conn.execute(
            """
            SELECT *
            FROM triage_snapshots
            WHERE id = ?
            """,
            (snapshot_id,),
        ).fetchone()

    def triage_snapshot_packages(self, snapshot_id: int) -> list[sqlite3.Row]:
        return list(
            self.conn.execute(
                """
                SELECT *
                FROM triage_snapshot_packages
                WHERE snapshot_id = ?
                ORDER BY CASE COALESCE(highest_severity, 'unknown')
                  WHEN 'critical' THEN 1
                  WHEN 'high' THEN 2
                  WHEN 'medium' THEN 3
                  WHEN 'low' THEN 4
                  ELSE 5
                END, package_name, version
                """,
                (snapshot_id,),
            )
        )
