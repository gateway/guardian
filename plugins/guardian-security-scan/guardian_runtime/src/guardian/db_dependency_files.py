"""SQLite persistence for dependency manifest and lockfile fingerprints."""

from __future__ import annotations

import sqlite3
from typing import Iterable

from .util import utc_now


class DependencyFileStoreMixin:
    """Track dependency-file fingerprints so daily automation can skip unchanged repos."""

    conn: sqlite3.Connection

    def dependency_file_state(self, root_path: str, *, present_only: bool = True) -> list[sqlite3.Row]:
        """Return known dependency-file fingerprints for a root."""

        where = "WHERE root_path = ?"
        if present_only:
            where += " AND present = 1"
        return list(
            self.conn.execute(
                f"""
                SELECT *
                FROM dependency_file_state
                {where}
                ORDER BY file_path
                """,
                (root_path,),
            )
        )

    def record_dependency_file_state(self, root_path: str, fingerprints: Iterable[dict]) -> dict:
        """Persist current fingerprints and return a compact change summary."""

        now = utc_now()
        current = {item["file_path"]: dict(item) for item in fingerprints}
        previous_rows = self.dependency_file_state(root_path, present_only=True)
        previous = {row["file_path"]: dict(row) for row in previous_rows}

        added = sorted(path for path in current if path not in previous)
        removed = sorted(path for path in previous if path not in current)
        changed = sorted(
            path
            for path, item in current.items()
            if path in previous and item["sha256"] != previous[path]["sha256"]
        )
        unchanged = sorted(
            path
            for path, item in current.items()
            if path in previous and item["sha256"] == previous[path]["sha256"]
        )

        for path, item in current.items():
            previous_item = previous.get(path)
            last_changed_at = (
                previous_item["last_changed_at"]
                if previous_item and previous_item["sha256"] == item["sha256"]
                else now
            )
            self.conn.execute(
                """
                INSERT INTO dependency_file_state (
                  root_path, file_path, file_kind, size_bytes, mtime_ns, sha256,
                  first_seen_at, last_seen_at, last_changed_at, present
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
                ON CONFLICT(root_path, file_path) DO UPDATE SET
                  file_kind = excluded.file_kind,
                  size_bytes = excluded.size_bytes,
                  mtime_ns = excluded.mtime_ns,
                  sha256 = excluded.sha256,
                  last_seen_at = excluded.last_seen_at,
                  last_changed_at = excluded.last_changed_at,
                  present = 1
                """,
                (
                    root_path,
                    path,
                    item["file_kind"],
                    item["size_bytes"],
                    item["mtime_ns"],
                    item["sha256"],
                    now,
                    now,
                    last_changed_at,
                ),
            )

        for path in removed:
            self.conn.execute(
                """
                UPDATE dependency_file_state
                SET present = 0, last_seen_at = ?
                WHERE root_path = ? AND file_path = ?
                """,
                (now, root_path, path),
            )
        self.conn.commit()

        return {
            "root_path": root_path,
            "current_count": len(current),
            "known_before_count": len(previous),
            "added": added,
            "changed": changed,
            "removed": removed,
            "unchanged_count": len(unchanged),
            "has_changes": bool(added or changed or removed),
        }
