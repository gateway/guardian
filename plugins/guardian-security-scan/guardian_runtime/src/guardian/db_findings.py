"""SQLite persistence methods for advisories and open/resolved package findings."""

from __future__ import annotations

import json
import sqlite3

from .util import utc_now


class FindingStoreMixin:
    """SQLite helpers for advisory metadata and active finding state."""

    conn: sqlite3.Connection

    def upsert_advisory(
        self,
        source: str,
        advisory_id: str,
        summary: str | None,
        severity: str | None,
        details_url: str | None,
        aliases: list[str] | None,
        published_at: str | None,
        updated_at: str | None,
        withdrawn_at: str | None,
        raw_json: dict,
    ) -> None:
        now = utc_now()
        self.conn.execute(
            """
            INSERT INTO advisories (
              source, advisory_id, summary, severity, details_url, aliases_json,
              published_at, updated_at, withdrawn_at, raw_json, first_seen_at, last_seen_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(source, advisory_id) DO UPDATE SET
              summary = excluded.summary,
              severity = excluded.severity,
              details_url = excluded.details_url,
              aliases_json = excluded.aliases_json,
              published_at = excluded.published_at,
              updated_at = excluded.updated_at,
              withdrawn_at = excluded.withdrawn_at,
              raw_json = excluded.raw_json,
              last_seen_at = excluded.last_seen_at
            """,
            (
                source,
                advisory_id,
                summary,
                severity,
                details_url,
                json.dumps(aliases or []),
                published_at,
                updated_at,
                withdrawn_at,
                json.dumps(raw_json, sort_keys=True),
                now,
                now,
            ),
        )
        self.conn.commit()

    def resolve_stale_findings(
        self,
        ecosystem: str,
        normalized_name: str,
        version: str,
        advisory_source: str,
        active_advisory_ids: list[str],
    ) -> None:
        query = """
        UPDATE findings
        SET status = 'resolved', resolved_at = ?
        WHERE ecosystem = ?
          AND normalized_name = ?
          AND version = ?
          AND advisory_source = ?
          AND status = 'open'
        """
        params = [utc_now(), ecosystem, normalized_name, version, advisory_source]
        if active_advisory_ids:
            placeholders = ",".join("?" for _ in active_advisory_ids)
            query += f" AND advisory_id NOT IN ({placeholders})"
            params.extend(active_advisory_ids)
        self.conn.execute(query, params)
        self.conn.commit()

    def upsert_finding(
        self,
        ecosystem: str,
        package_name: str,
        normalized_name: str,
        version: str,
        advisory_source: str,
        advisory_id: str,
        severity: str | None,
        details_url: str | None,
        evidence: str,
    ) -> None:
        now = utc_now()
        self.conn.execute(
            """
            INSERT INTO findings (
              ecosystem, package_name, normalized_name, version,
              advisory_source, advisory_id, severity, details_url,
              evidence, status, first_seen_at, last_seen_at, resolved_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, NULL)
            ON CONFLICT(normalized_name, version, advisory_source, advisory_id) DO UPDATE SET
              package_name = excluded.package_name,
              severity = excluded.severity,
              details_url = excluded.details_url,
              evidence = excluded.evidence,
              status = 'open',
              last_seen_at = excluded.last_seen_at,
              resolved_at = NULL
            """,
            (
                ecosystem,
                package_name,
                normalized_name,
                version,
                advisory_source,
                advisory_id,
                severity,
                details_url,
                evidence,
                now,
                now,
            ),
        )
        self.conn.commit()

    def finding_summary(self) -> list[sqlite3.Row]:
        return list(
            self.conn.execute(
                """
                SELECT severity, COUNT(*) AS count
                FROM findings
                WHERE status = 'open'
                GROUP BY severity
                ORDER BY CASE severity
                  WHEN 'critical' THEN 1
                  WHEN 'high' THEN 2
                  WHEN 'medium' THEN 3
                  WHEN 'low' THEN 4
                  ELSE 5
                END
                """
            )
        )

    def open_findings(self) -> list[sqlite3.Row]:
        return list(
            self.conn.execute(
                """
                SELECT *
                FROM findings
                WHERE status = 'open'
                ORDER BY CASE severity
                  WHEN 'critical' THEN 1
                  WHEN 'high' THEN 2
                  WHEN 'medium' THEN 3
                  WHEN 'low' THEN 4
                  ELSE 5
                END, normalized_name, version
                """
            )
        )

    def open_findings_for_package(
        self,
        *,
        ecosystem: str,
        normalized_name: str,
        version: str,
    ) -> list[sqlite3.Row]:
        return list(
            self.conn.execute(
                """
                SELECT *
                FROM findings
                WHERE status = 'open'
                  AND ecosystem = ?
                  AND normalized_name = ?
                  AND version = ?
                ORDER BY CASE severity
                  WHEN 'critical' THEN 1
                  WHEN 'high' THEN 2
                  WHEN 'medium' THEN 3
                  WHEN 'low' THEN 4
                  ELSE 5
                END, advisory_source, advisory_id
                """,
                (ecosystem, normalized_name, version),
            )
        )

    def advisory_map(self) -> dict[tuple[str, str], sqlite3.Row]:
        rows = self.conn.execute("SELECT * FROM advisories").fetchall()
        return {(row["source"], row["advisory_id"]): row for row in rows}

    def current_package_occurrences(
        self,
        *,
        ecosystem: str,
        normalized_name: str,
        version: str,
    ) -> list[sqlite3.Row]:
        return list(
            self.conn.execute(
                """
                SELECT *
                FROM package_state
                WHERE present = 1
                  AND ecosystem = ?
                  AND normalized_name = ?
                  AND version = ?
                ORDER BY root_path, source_file
                """,
                (ecosystem, normalized_name, version),
            )
        )

    def list_inventory_roots(self) -> list[str]:
        rows = self.conn.execute(
            """
            SELECT DISTINCT root_path
            FROM package_state
            WHERE present = 1
            ORDER BY root_path
            """
        ).fetchall()
        return [row["root_path"] for row in rows]
