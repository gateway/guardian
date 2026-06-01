"""Export exact-match advisory catalogs for external review and fixture checks."""

from __future__ import annotations

from pathlib import Path

from .config import GuardianConfig
from .db import Database
from .util import slugify, utc_now, write_json


def export_exact_match_catalog(config: GuardianConfig, db: Database) -> Path:
    rows = db.open_findings()
    entries_by_key: dict[tuple[str, str, str], dict] = {}
    for row in rows:
        key = (row["ecosystem"], row["package_name"], row["advisory_id"])
        if key not in entries_by_key:
            entries_by_key[key] = {
                "id": f"guardian-{slugify(row['advisory_source'])}-{slugify(row['advisory_id'])}",
                "name": f"{row['package_name']} ({row['advisory_source']} {row['advisory_id']})",
                "ecosystem": row["ecosystem"],
                "package": row["package_name"],
                "versions": [],
                "severity": row["severity"] or "unknown",
                "source": row["details_url"] or "",
            }
        entries_by_key[key]["versions"].append(row["version"])

    payload = {
        "schema_version": "0.1.0",
        "_comment": "Guardian export of currently open exact-version findings.",
        "entries": [],
    }
    for entry in entries_by_key.values():
        entry["versions"] = sorted(set(entry["versions"]))
        payload["entries"].append(entry)
    payload["entries"].sort(key=lambda item: (item["ecosystem"], item["package"], item["id"]))

    exports_dir = Path(config.exports_dir)
    path = exports_dir / f"guardian-exact-match-catalog-{utc_now().replace(':', '-')}.json"
    write_json(path, payload)
    return path
