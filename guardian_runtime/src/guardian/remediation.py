from __future__ import annotations

import json
import sqlite3

from .db import Database
from .util import utc_now


OPEN_STATUSES = {"open", "reintroduced"}


def sync_remediation_lifecycle(
    db: Database,
    *,
    root_filter: str,
    current_snapshot_id: int,
) -> dict:
    snapshot = db.get_triage_snapshot(current_snapshot_id)
    if snapshot is None:
        raise ValueError(f"unknown snapshot id: {current_snapshot_id}")
    current_entries = _snapshot_entries(db, current_snapshot_id, root_filter)
    existing = _existing_items(db, root_filter)
    now = utc_now()
    opened = []
    still_open = []
    reintroduced = []

    for key, entry in current_entries.items():
        item = existing.get(key)
        if item is None:
            item_id = _insert_item(db, entry, current_snapshot_id, now)
            _insert_event(
                db,
                item_id=item_id,
                event_type="opened",
                snapshot_id=current_snapshot_id,
                summary=f"First seen in snapshot {current_snapshot_id}.",
                raw=entry,
                now=now,
            )
            opened.append(entry)
            continue
        item_id = int(item["id"])
        if item["status"] == "resolved":
            _update_item_open(
                db,
                item_id=item_id,
                entry=entry,
                current_snapshot_id=current_snapshot_id,
                now=now,
                status="reintroduced",
                increment_reintroduced=True,
            )
            _insert_event(
                db,
                item_id=item_id,
                event_type="reintroduced",
                snapshot_id=current_snapshot_id,
                summary=f"Previously resolved finding reappeared in snapshot {current_snapshot_id}.",
                raw=entry,
                now=now,
            )
            reintroduced.append(entry)
        else:
            _update_item_open(
                db,
                item_id=item_id,
                entry=entry,
                current_snapshot_id=current_snapshot_id,
                now=now,
                status="reintroduced" if item["status"] == "reintroduced" else "open",
                increment_reintroduced=False,
            )
            still_open.append(entry)

    resolved = []
    current_keys = set(current_entries)
    for key, item in existing.items():
        if item["status"] not in OPEN_STATUSES or key in current_keys:
            continue
        resolution_summary = _resolution_summary(db, item, root_filter)
        _resolve_item(
            db,
            item_id=int(item["id"]),
            snapshot_id=current_snapshot_id,
            resolution_summary=resolution_summary,
            now=now,
        )
        _insert_event(
            db,
            item_id=int(item["id"]),
            event_type="resolved",
            snapshot_id=current_snapshot_id,
            summary=resolution_summary,
            raw=dict(item),
            now=now,
        )
        resolved.append(dict(item))

    db.conn.commit()
    return {
        "root_path": root_filter,
        "snapshot_id": current_snapshot_id,
        "opened_count": len(opened),
        "still_open_count": len(still_open),
        "resolved_count": len(resolved),
        "reintroduced_count": len(reintroduced),
        "opened": [_public_entry(item) for item in opened[:25]],
        "resolved": [_public_entry(item) for item in resolved[:25]],
        "reintroduced": [_public_entry(item) for item in reintroduced[:25]],
    }


def remediation_status(db: Database, *, root_filter: str, limit: int = 50) -> dict:
    rows = [
        dict(row)
        for row in db.conn.execute(
            """
            SELECT *
            FROM remediation_items
            WHERE root_path = ?
            ORDER BY
              CASE status
                WHEN 'reintroduced' THEN 1
                WHEN 'open' THEN 2
                WHEN 'resolved' THEN 3
                ELSE 4
              END,
              last_seen_at DESC,
              package_name,
              version,
              issue_key
            LIMIT ?
            """,
            (root_filter, limit),
        )
    ]
    counts = {
        row["status"]: int(row["count"])
        for row in db.conn.execute(
            """
            SELECT status, COUNT(*) AS count
            FROM remediation_items
            WHERE root_path = ?
            GROUP BY status
            """,
            (root_filter,),
        )
    }
    recent_resolved = [
        _public_entry(dict(row))
        for row in db.conn.execute(
            """
            SELECT *
            FROM remediation_items
            WHERE root_path = ? AND status = 'resolved'
            ORDER BY resolved_at DESC, id DESC
            LIMIT ?
            """,
            (root_filter, min(limit, 25)),
        )
    ]
    return {
        "root_path": root_filter,
        "counts": counts,
        "items": [_public_entry(row) for row in rows],
        "recent_resolved": recent_resolved,
    }


def _snapshot_entries(db: Database, snapshot_id: int, root_filter: str) -> dict[tuple[str, str, str, str], dict]:
    entries = {}
    for row in db.triage_snapshot_packages(snapshot_id):
        item = dict(row)
        issue_keys = _json_list(item.get("issue_keys_json"))
        for issue_key in issue_keys or ["unknown"]:
            entry = {
                "root_path": root_filter,
                "ecosystem": item["ecosystem"],
                "package_name": item["package_name"],
                "normalized_name": item["normalized_name"],
                "version": item["version"],
                "issue_key": issue_key,
                "risk_label": item.get("risk_label"),
                "highest_severity": item.get("highest_severity"),
                "environment_label": item.get("environment_label"),
                "snapshot_package": item,
            }
            entries[_entry_key(entry)] = entry
    return entries


def _existing_items(db: Database, root_filter: str) -> dict[tuple[str, str, str, str], sqlite3.Row]:
    rows = db.conn.execute(
        """
        SELECT *
        FROM remediation_items
        WHERE root_path = ?
        """,
        (root_filter,),
    ).fetchall()
    return {
        (row["ecosystem"], row["normalized_name"], row["version"], row["issue_key"]): row
        for row in rows
    }


def _entry_key(entry: dict) -> tuple[str, str, str, str]:
    return (entry["ecosystem"], entry["normalized_name"], entry["version"], entry["issue_key"])


def _insert_item(db: Database, entry: dict, snapshot_id: int, now: str) -> int:
    cursor = db.conn.execute(
        """
        INSERT INTO remediation_items (
          root_path, ecosystem, package_name, normalized_name, version, issue_key,
          status, risk_label, highest_severity, environment_label,
          first_seen_snapshot_id, last_seen_snapshot_id,
          first_seen_at, last_seen_at, raw_json
        )
        VALUES (?, ?, ?, ?, ?, ?, 'open', ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            entry["root_path"],
            entry["ecosystem"],
            entry["package_name"],
            entry["normalized_name"],
            entry["version"],
            entry["issue_key"],
            entry.get("risk_label"),
            entry.get("highest_severity"),
            entry.get("environment_label"),
            snapshot_id,
            snapshot_id,
            now,
            now,
            json.dumps(entry, sort_keys=True),
        ),
    )
    return int(cursor.lastrowid)


def _update_item_open(
    db: Database,
    *,
    item_id: int,
    entry: dict,
    current_snapshot_id: int,
    now: str,
    status: str,
    increment_reintroduced: bool,
) -> None:
    db.conn.execute(
        """
        UPDATE remediation_items
        SET status = ?,
            risk_label = ?,
            highest_severity = ?,
            environment_label = ?,
            last_seen_snapshot_id = ?,
            last_seen_at = ?,
            resolved_snapshot_id = NULL,
            resolved_at = NULL,
            resolution_summary = NULL,
            reintroduced_count = reintroduced_count + ?,
            raw_json = ?
        WHERE id = ?
        """,
        (
            status,
            entry.get("risk_label"),
            entry.get("highest_severity"),
            entry.get("environment_label"),
            current_snapshot_id,
            now,
            1 if increment_reintroduced else 0,
            json.dumps(entry, sort_keys=True),
            item_id,
        ),
    )


def _resolve_item(db: Database, *, item_id: int, snapshot_id: int, resolution_summary: str, now: str) -> None:
    db.conn.execute(
        """
        UPDATE remediation_items
        SET status = 'resolved',
            resolved_snapshot_id = ?,
            resolved_at = ?,
            resolution_summary = ?
        WHERE id = ?
        """,
        (snapshot_id, now, resolution_summary, item_id),
    )


def _insert_event(
    db: Database,
    *,
    item_id: int,
    event_type: str,
    snapshot_id: int,
    summary: str,
    raw: dict,
    now: str,
) -> None:
    db.conn.execute(
        """
        INSERT INTO remediation_events (item_id, event_type, created_at, snapshot_id, summary, raw_json)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (item_id, event_type, now, snapshot_id, summary, json.dumps(raw, sort_keys=True, default=str)),
    )


def _resolution_summary(db: Database, item: sqlite3.Row, root_filter: str) -> str:
    current_versions = [
        row["version"]
        for row in db.conn.execute(
            """
            SELECT DISTINCT version
            FROM package_state
            WHERE root_path = ?
              AND ecosystem = ?
              AND normalized_name = ?
              AND present = 1
            ORDER BY version
            """,
            (root_filter, item["ecosystem"], item["normalized_name"]),
        )
    ]
    if not current_versions:
        return f"Confirmed fixed in snapshot by absence: {item['package_name']} is no longer present in the current inventory."
    if item["version"] not in current_versions:
        return (
            f"Confirmed fixed in snapshot: vulnerable version {item['version']} is no longer present; "
            f"current inventory has {item['package_name']} version(s): {', '.join(current_versions[:6])}."
        )
    return (
        f"Confirmed resolved in triage snapshot: {item['package_name']}@{item['version']} remains in inventory "
        "but no longer matches the tracked advisory evidence."
    )


def _public_entry(item: dict) -> dict:
    return {
        "root_path": item.get("root_path"),
        "ecosystem": item.get("ecosystem"),
        "package_name": item.get("package_name"),
        "normalized_name": item.get("normalized_name"),
        "version": item.get("version"),
        "issue_key": item.get("issue_key"),
        "status": item.get("status"),
        "risk_label": item.get("risk_label"),
        "highest_severity": item.get("highest_severity"),
        "environment_label": item.get("environment_label"),
        "first_seen_snapshot_id": item.get("first_seen_snapshot_id"),
        "last_seen_snapshot_id": item.get("last_seen_snapshot_id"),
        "resolved_snapshot_id": item.get("resolved_snapshot_id"),
        "first_seen_at": item.get("first_seen_at"),
        "last_seen_at": item.get("last_seen_at"),
        "resolved_at": item.get("resolved_at"),
        "reintroduced_count": item.get("reintroduced_count"),
        "resolution_summary": item.get("resolution_summary"),
    }


def _json_list(value: str | None) -> list[str]:
    if not value:
        return []
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return []
    return parsed if isinstance(parsed, list) else []
