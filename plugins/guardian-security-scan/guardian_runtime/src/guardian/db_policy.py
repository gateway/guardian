"""SQLite persistence methods for policy exceptions and remediation lifecycle records."""

from __future__ import annotations

import sqlite3

from .util import utc_now


class PolicyStoreMixin:
    """SQLite helpers for operator-approved policy exceptions."""

    conn: sqlite3.Connection

    def add_policy_exception(
        self,
        *,
        ecosystem: str,
        normalized_name: str,
        version: str | None,
        advisory_source: str | None,
        canonical_key: str | None,
        action: str,
        reason: str,
        expires_at: str | None,
        created_by: str | None,
    ) -> None:
        self.conn.execute(
            """
            INSERT INTO policy_exceptions (
              ecosystem, normalized_name, version, advisory_source, canonical_key,
              action, reason, created_at, expires_at, created_by, active
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
            """,
            (
                ecosystem,
                normalized_name,
                version,
                advisory_source,
                canonical_key,
                action,
                reason,
                utc_now(),
                expires_at,
                created_by,
            ),
        )
        self.conn.commit()

    def active_policy_exceptions(
        self,
        *,
        ecosystem: str,
        normalized_name: str,
        version: str | None,
    ) -> list[sqlite3.Row]:
        return list(
            self.conn.execute(
                """
                SELECT *
                FROM policy_exceptions
                WHERE active = 1
                  AND ecosystem = ?
                  AND normalized_name = ?
                  AND (version IS NULL OR version = ?)
                  AND (expires_at IS NULL OR expires_at > ?)
                ORDER BY created_at DESC
                """,
                (ecosystem, normalized_name, version, utc_now()),
            )
        )

    def list_policy_exceptions(self) -> list[sqlite3.Row]:
        return list(
            self.conn.execute(
                """
                SELECT *
                FROM policy_exceptions
                WHERE active = 1
                  AND (expires_at IS NULL OR expires_at > ?)
                ORDER BY created_at DESC
                """,
                (utc_now(),),
            )
        )
