"""Source-status contract helpers that explain which intelligence feeds ran, skipped, or errored."""

from __future__ import annotations


def threat_intel_source_contract(source: dict) -> dict:
    health = source.get("source_health") or {}
    return {
        "source_id": source.get("id"),
        "source_type": source.get("type"),
        "status": source.get("status"),
        "fetched_at": health.get("fetched_at"),
        "revision": source.get("revision"),
        "remote_url": health.get("remote_url"),
        "confidence": source.get("confidence") or "Official Advisory Database",
        "license": source.get("license") or "MIT",
        "records_read": source.get("yaml_files_read"),
        "matches": source.get("entries_written"),
        "errors": [source.get("error")] if source.get("error") else [],
        "stale": health.get("stale"),
        "parser": source.get("parser"),
    }


def live_source_contract(
    *,
    source_id: str,
    status: str,
    records_read: int | None = None,
    matches: int | None = None,
    error: str | None = None,
    skipped_reason: str | None = None,
) -> dict:
    errors = []
    if error:
        errors.append(error)
    if skipped_reason:
        errors.append(skipped_reason)
    return {
        "source_id": source_id,
        "source_type": "live-api",
        "status": status,
        "fetched_at": None,
        "revision": None,
        "remote_url": None,
        "confidence": "Live advisory query",
        "license": None,
        "records_read": records_read,
        "matches": matches,
        "errors": errors,
        "stale": None,
        "parser": None,
    }
