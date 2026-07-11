"""SQLite persistence methods for inventory runs and current package state."""

from __future__ import annotations

import json
import sqlite3
from typing import Iterable, List

from .util import utc_now


class InventoryStoreMixin:
    """SQLite helpers for inventory runs and current package state."""

    conn: sqlite3.Connection

    def start_inventory_run(self, root_path: str, profile: str, source: str, ndjson_path: str) -> int:
        now = utc_now()
        cursor = self.conn.execute(
            """
            INSERT INTO inventory_runs (started_at, root_path, profile, source, ndjson_path, status)
            VALUES (?, ?, ?, ?, ?, 'running')
            """,
            (now, root_path, profile, source, ndjson_path),
        )
        self.conn.commit()
        return int(cursor.lastrowid)

    def finish_inventory_run(self, run_id: int, package_count: int, status: str = "complete") -> None:
        self.conn.execute(
            """
            UPDATE inventory_runs
            SET completed_at = ?, status = ?, package_count = ?
            WHERE id = ?
            """,
            (utc_now(), status, package_count, run_id),
        )
        self.conn.commit()

    def insert_inventory_packages(self, run_id: int, packages: Iterable[dict]) -> int:
        run_row = self.conn.execute(
            "SELECT root_path FROM inventory_runs WHERE id = ?",
            (run_id,),
        ).fetchone()
        if run_row is None:
            raise ValueError(f"unknown run id {run_id}")
        root_path = run_row["root_path"]
        rows = []
        package_list = list(packages)
        seen_keys: set[tuple[str, str, str, str]] = set()
        now = utc_now()
        for record in package_list:
            rows.append(
                (
                    run_id,
                    record.get("ecosystem", ""),
                    record.get("package_name", ""),
                    record.get("normalized_name", ""),
                    record.get("version", ""),
                    record.get("project_path"),
                    record.get("source_file"),
                    record.get("source_type"),
                    record.get("package_manager"),
                    record.get("root_kind"),
                    record.get("confidence"),
                    1 if record.get("direct_dependency") else 0 if record.get("direct_dependency") is not None else None,
                    record.get("install_scope"),
                    json.dumps(record, sort_keys=True),
                )
            )
            state_key = (
                record.get("ecosystem", ""),
                record.get("normalized_name", ""),
                record.get("version", ""),
                record.get("source_file") or "",
            )
            seen_keys.add(state_key)
            self.conn.execute(
                """
                INSERT INTO package_state (
                  root_path, ecosystem, package_name, normalized_name, version,
                  project_path, source_file, source_type, package_manager,
                  root_kind, confidence, direct_dependency, install_scope,
                  first_seen_at, last_seen_at, present, last_run_id,
                  first_seen_run_id, raw_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
                ON CONFLICT(root_path, ecosystem, normalized_name, version, source_file) DO UPDATE SET
                  package_name = excluded.package_name,
                  project_path = excluded.project_path,
                  source_type = excluded.source_type,
                  package_manager = excluded.package_manager,
                  root_kind = excluded.root_kind,
                  confidence = excluded.confidence,
                  direct_dependency = excluded.direct_dependency,
                  install_scope = excluded.install_scope,
                  last_seen_at = excluded.last_seen_at,
                  present = 1,
                  last_run_id = excluded.last_run_id,
                  raw_json = excluded.raw_json
                """,
                (
                    root_path,
                    record.get("ecosystem", ""),
                    record.get("package_name", ""),
                    record.get("normalized_name", ""),
                    record.get("version", ""),
                    record.get("project_path"),
                    record.get("source_file"),
                    record.get("source_type"),
                    record.get("package_manager"),
                    record.get("root_kind"),
                    record.get("confidence"),
                    1 if record.get("direct_dependency") else 0 if record.get("direct_dependency") is not None else None,
                    record.get("install_scope"),
                    now,
                    now,
                    run_id,
                    run_id,
                    json.dumps(record, sort_keys=True),
                ),
            )
        self.conn.executemany(
            """
            INSERT INTO inventory_packages (
              run_id, ecosystem, package_name, normalized_name, version,
              project_path, source_file, source_type, package_manager,
              root_kind, confidence, direct_dependency, install_scope, raw_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )
        stale_rows = self.conn.execute(
            """
            SELECT ecosystem, normalized_name, version, COALESCE(source_file, '') AS source_file_key
            FROM package_state
            WHERE root_path = ? AND present = 1
            """,
            (root_path,),
        ).fetchall()
        for row in stale_rows:
            key = (row["ecosystem"], row["normalized_name"], row["version"], row["source_file_key"])
            if key not in seen_keys:
                self.conn.execute(
                    """
                    UPDATE package_state
                    SET present = 0, last_run_id = ?, last_seen_at = ?
                    WHERE root_path = ? AND ecosystem = ? AND normalized_name = ? AND version = ? AND COALESCE(source_file, '') = ?
                    """,
                    (run_id, now, root_path, row["ecosystem"], row["normalized_name"], row["version"], row["source_file_key"]),
                )
        self.conn.commit()
        return len(rows)

    def current_packages(self) -> List[sqlite3.Row]:
        query = """
        SELECT *
        FROM package_state
        WHERE present = 1
        ORDER BY ecosystem, normalized_name, version
        """
        return list(self.conn.execute(query))

    def current_packages_for_root(self, root_path: str) -> List[sqlite3.Row]:
        return list(
            self.conn.execute(
                """
                SELECT *
                FROM package_state
                WHERE present = 1 AND root_path = ?
                ORDER BY ecosystem, normalized_name, version
                """,
                (root_path,),
            )
        )

    def has_prior_inventory_run(self, root_path: str) -> bool:
        """Return whether the root has a completed baseline before its latest run."""

        row = self.conn.execute(
            "SELECT COUNT(*) AS run_count FROM inventory_runs WHERE root_path = ? AND status = 'complete'",
            (root_path,),
        ).fetchone()
        return bool(row and int(row["run_count"]) > 1)

    def new_package_names_for_runs(self, root_path: str, run_ids: list[int]) -> List[sqlite3.Row]:
        """Return package names first introduced by the supplied inventory runs."""

        if not run_ids:
            return []
        placeholders = ",".join("?" for _run_id in run_ids)
        return list(
            self.conn.execute(
                f"""
                SELECT DISTINCT
                  current.ecosystem,
                  current.package_name,
                  current.normalized_name
                FROM package_state current
                WHERE current.root_path = ?
                  AND current.present = 1
                  AND current.first_seen_run_id IN ({placeholders})
                  AND NOT EXISTS (
                    SELECT 1
                    FROM package_state prior
                    WHERE prior.root_path = current.root_path
                      AND prior.ecosystem = current.ecosystem
                      AND prior.normalized_name = current.normalized_name
                      AND (
                        prior.first_seen_run_id IS NULL
                        OR prior.first_seen_run_id NOT IN ({placeholders})
                      )
                  )
                ORDER BY current.ecosystem, current.normalized_name
                """,
                [root_path, *run_ids, *run_ids],
            )
        )

    def root_open_package_summary(self, root_path: str, limit: int = 20) -> list[sqlite3.Row]:
        return list(
            self.conn.execute(
                """
                WITH repo_packages AS (
                  SELECT DISTINCT ecosystem, package_name, normalized_name, version
                  FROM package_state
                  WHERE present = 1 AND root_path = ?
                )
                SELECT
                  rp.ecosystem,
                  rp.package_name,
                  rp.normalized_name,
                  rp.version,
                  COUNT(*) AS finding_count,
                  MAX(
                    CASE COALESCE(f.severity, 'unknown')
                      WHEN 'critical' THEN 4
                      WHEN 'high' THEN 3
                      WHEN 'medium' THEN 2
                      WHEN 'low' THEN 1
                      ELSE 0
                    END
                  ) AS severity_rank
                FROM repo_packages rp
                JOIN findings f
                  ON f.ecosystem = rp.ecosystem
                 AND f.normalized_name = rp.normalized_name
                 AND f.version = rp.version
                WHERE f.status = 'open'
                GROUP BY rp.ecosystem, rp.package_name, rp.normalized_name, rp.version
                ORDER BY severity_rank DESC, finding_count DESC, rp.package_name, rp.version
                LIMIT ?
                """,
                (root_path, limit),
            )
        )
