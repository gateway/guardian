"""SQLite cache and history accessors for registry metadata intelligence."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone

from .util import utc_now


class RegistryMetadataStoreMixin:
    """Persist exact-version registry observations without replacing prior versions."""

    conn: sqlite3.Connection

    def registry_metadata(
        self,
        ecosystem: str,
        normalized_name: str,
        version: str,
        *,
        ttl_seconds: int | None = None,
    ) -> dict | None:
        params: list[object] = [ecosystem, normalized_name, version]
        freshness = ""
        if ttl_seconds is not None:
            cutoff = (
                datetime.now(timezone.utc) - timedelta(seconds=max(0, ttl_seconds))
            ).replace(microsecond=0).isoformat()
            freshness = " AND fetched_at >= ?"
            params.append(cutoff)
        row = self.conn.execute(
            f"""
            SELECT * FROM registry_metadata_state
            WHERE ecosystem = ? AND normalized_name = ? AND version = ?{freshness}
            """,
            params,
        ).fetchone()
        if row is None:
            return None
        payload = json.loads(row["metadata_json"])
        payload["fetched_at"] = row["fetched_at"]
        payload["cache_hit"] = True
        return payload

    def upsert_registry_metadata(self, metadata: dict) -> None:
        fetched_at = metadata.get("fetched_at") or utc_now()
        self.conn.execute(
            """
            INSERT INTO registry_metadata_state (
              ecosystem, package_name, normalized_name, version, published_at,
              maintainers_hash, provenance_present, deprecated, yanked, repo_url,
              size_bytes, has_install_script, metadata_json, fetched_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(ecosystem, normalized_name, version) DO UPDATE SET
              package_name = excluded.package_name,
              published_at = excluded.published_at,
              maintainers_hash = excluded.maintainers_hash,
              provenance_present = excluded.provenance_present,
              deprecated = excluded.deprecated,
              yanked = excluded.yanked,
              repo_url = excluded.repo_url,
              size_bytes = excluded.size_bytes,
              has_install_script = excluded.has_install_script,
              metadata_json = excluded.metadata_json,
              fetched_at = excluded.fetched_at
            """,
            (
                metadata["ecosystem"],
                metadata["package_name"],
                metadata["normalized_name"],
                metadata["version"],
                metadata.get("published_at"),
                metadata.get("maintainers_hash"),
                _optional_bool(metadata.get("provenance_present")),
                _optional_bool(metadata.get("deprecated")),
                _optional_bool(metadata.get("yanked")),
                metadata.get("repo_url"),
                metadata.get("size_bytes"),
                _optional_bool(metadata.get("has_install_script")),
                json.dumps(metadata, sort_keys=True),
                fetched_at,
            ),
        )
        self.conn.commit()

    def changed_package_versions_for_runs(
        self,
        root_path: str,
        run_ids: list[int],
        *,
        include_baseline: bool,
    ) -> list[sqlite3.Row]:
        """Return versions first observed now, skipping a first-scan baseline by default."""

        if not run_ids:
            return []
        placeholders = ",".join("?" for _run_id in run_ids)
        prior_run = self.conn.execute(
            f"SELECT 1 FROM inventory_runs WHERE root_path = ? AND id NOT IN ({placeholders}) LIMIT 1",
            [root_path, *run_ids],
        ).fetchone()
        if prior_run is None and not include_baseline:
            return []
        return list(
            self.conn.execute(
                f"""
                SELECT
                  current.ecosystem,
                  current.package_name,
                  current.normalized_name,
                  current.version,
                  MAX(COALESCE(current.direct_dependency, 0)) AS direct_dependency,
                  ? AS had_prior_inventory
                FROM package_state current
                WHERE current.root_path = ?
                  AND current.present = 1
                  AND current.first_seen_run_id IN ({placeholders})
                  AND current.ecosystem IN ('npm', 'pypi')
                  AND NOT EXISTS (
                    SELECT 1 FROM package_state same_version
                    WHERE same_version.root_path = current.root_path
                      AND same_version.ecosystem = current.ecosystem
                      AND same_version.normalized_name = current.normalized_name
                      AND same_version.version = current.version
                      AND (
                        same_version.first_seen_run_id IS NULL
                        OR same_version.first_seen_run_id NOT IN ({placeholders})
                      )
                  )
                GROUP BY current.ecosystem, current.package_name, current.normalized_name, current.version
                ORDER BY direct_dependency DESC, current.ecosystem, current.normalized_name
                """,
                [1 if prior_run is not None else 0, root_path, *run_ids, *run_ids],
            )
        )

    def prior_package_versions(
        self,
        root_path: str,
        ecosystem: str,
        normalized_name: str,
        current_version: str,
        run_ids: list[int],
    ) -> list[str]:
        placeholders = ",".join("?" for _run_id in run_ids) if run_ids else "NULL"
        return [
            row["version"]
            for row in self.conn.execute(
                f"""
                SELECT version, MAX(last_seen_at) AS seen_at
                FROM package_state
                WHERE root_path = ? AND ecosystem = ? AND normalized_name = ?
                  AND version != ?
                  AND (first_seen_run_id IS NULL OR first_seen_run_id NOT IN ({placeholders}))
                GROUP BY version
                ORDER BY seen_at DESC, version DESC
                """,
                [root_path, ecosystem, normalized_name, current_version, *run_ids],
            )
        ]


def _optional_bool(value) -> int | None:
    if value is None:
        return None
    return 1 if value else 0
