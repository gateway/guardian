"""Snapshot creation and comparison rendering for new/resolved/changed finding tracking."""

from __future__ import annotations

import json

from .db import Database


def compare_triage_snapshots(
    db: Database,
    *,
    root_filter: str,
    current_snapshot_id: int | None = None,
    previous_snapshot_id: int | None = None,
) -> dict:
    """Compare persisted triage snapshots as evidence drift and classification drift."""

    current_snapshot = db.get_triage_snapshot(current_snapshot_id) if current_snapshot_id else None
    previous_snapshot = db.get_triage_snapshot(previous_snapshot_id) if previous_snapshot_id else None
    if current_snapshot is None or (previous_snapshot_id is None and previous_snapshot is None):
        snapshots = db.latest_triage_snapshots(root_filter, limit=2)
        if current_snapshot is None and snapshots:
            current_snapshot = snapshots[0]
        if previous_snapshot is None and len(snapshots) > 1:
            previous_snapshot = snapshots[1]
    if current_snapshot is None:
        return {
            "root_path": root_filter,
            "status": "missing",
            "message": "No snapshots recorded for this root yet.",
        }
    if previous_snapshot is None:
        return {
            "root_path": root_filter,
            "status": "baseline_only",
            "current_snapshot": dict(current_snapshot),
            "message": "Only one snapshot exists for this root, so there is nothing to compare yet.",
        }

    current_packages = {
        (row["ecosystem"], row["normalized_name"], row["version"]): dict(row)
        for row in db.triage_snapshot_packages(int(current_snapshot["id"]))
    }
    previous_packages = {
        (row["ecosystem"], row["normalized_name"], row["version"]): dict(row)
        for row in db.triage_snapshot_packages(int(previous_snapshot["id"]))
    }
    new_keys = sorted(set(current_packages) - set(previous_packages))
    resolved_keys = sorted(set(previous_packages) - set(current_packages))
    common_keys = sorted(set(current_packages) & set(previous_packages))

    evidence_changed = []
    classification_changed = []
    changed = []
    unchanged = []
    for key in common_keys:
        current = current_packages[key]
        previous = previous_packages[key]
        evidence_deltas = {}
        for field in (
            "highest_severity",
            "advisory_count",
            "issue_keys_json",
        ):
            if current.get(field) != previous.get(field):
                evidence_deltas[field] = {"before": previous.get(field), "after": current.get(field)}
        classification_deltas = {}
        for field in (
            "risk_label",
            "recommended_clean_version",
            "first_fixed_version",
            "environment_label",
            "role_label",
            "classification_labels_json",
        ):
            if current.get(field) != previous.get(field):
                classification_deltas[field] = {"before": previous.get(field), "after": current.get(field)}
        entry = {
            "ecosystem": current["ecosystem"],
            "package_name": current["package_name"],
            "normalized_name": current["normalized_name"],
            "version": current["version"],
            "current": current,
            "previous": previous,
        }
        if evidence_deltas:
            entry["evidence_changes"] = evidence_deltas
        if classification_deltas:
            entry["classification_changes"] = classification_deltas
        if evidence_deltas or classification_deltas:
            merged = {}
            merged.update(evidence_deltas)
            merged.update(classification_deltas)
            entry["changes"] = merged
            changed.append(entry)
            if evidence_deltas:
                evidence_changed.append(entry)
            if classification_deltas:
                classification_changed.append(entry)
        else:
            unchanged.append(entry)

    current_summary = json.loads(current_snapshot["summary_json"])
    previous_summary = json.loads(previous_snapshot["summary_json"])
    headline = (
        f"{len(new_keys)} new evidence, {len(resolved_keys)} resolved evidence, "
        f"{len(evidence_changed)} evidence changed, {len(classification_changed)} classification changed, "
        f"{len(unchanged)} unchanged"
    )
    return {
        "root_path": root_filter,
        "status": "ok",
        "headline": headline,
        "current_snapshot": dict(current_snapshot),
        "previous_snapshot": dict(previous_snapshot),
        "current_summary": current_summary,
        "previous_summary": previous_summary,
        "new_open": [current_packages[key] for key in new_keys],
        "resolved": [previous_packages[key] for key in resolved_keys],
        "evidence_changed": evidence_changed,
        "classification_changed": classification_changed,
        "changed": changed,
        "unchanged_count": len(unchanged),
    }
