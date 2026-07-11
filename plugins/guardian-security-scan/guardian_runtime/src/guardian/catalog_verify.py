"""Cross-verify local exact-match catalogs against OSV malicious records."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from .catalog_integrity import atomic_write_json
from .config import GuardianConfig
from .osv_matching import osv_record_is_malicious
from .sources import OSVClient
from .util import utc_now


def verify_local_catalogs(config: GuardianConfig) -> dict:
    """Verify each exact package/version while preserving prior state on outages."""

    catalog_files = _catalog_files(config)
    loaded: list[tuple[Path, dict]] = []
    queries: list[dict] = []
    query_keys: list[tuple[str, str, str]] = []
    seen_keys: set[tuple[str, str, str]] = set()
    file_errors: list[dict] = []
    for path in catalog_files:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            file_errors.append({"path": str(path), "status": "error", "error": str(exc)})
            continue
        if not isinstance(payload.get("entries"), list):
            continue
        loaded.append((path, payload))
        for entry in payload["entries"]:
            ecosystem = str(entry.get("ecosystem") or "").lower()
            package = str(entry.get("package") or "")
            if ecosystem not in {"npm", "pypi"} or not package:
                continue
            for version in entry.get("versions") or []:
                key = (ecosystem, package, str(version))
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                query_keys.append(key)
                queries.append({"ecosystem": ecosystem, "package_name": package, "version": str(version)})

    osv = OSVClient(config)
    results_by_key: dict[tuple[str, str, str], dict] = {}
    source_errors: list[str] = []
    for offset in range(0, len(queries), 500):
        query_batch = queries[offset : offset + 500]
        key_batch = query_keys[offset : offset + 500]
        try:
            results = osv.query_batch(query_batch)
        except Exception as exc:
            source_errors.append(str(exc))
            for key in key_batch:
                results_by_key[key] = {"status": "skipped", "advisory_ids": [], "error": str(exc)}
            continue
        for key, result in zip(key_batch, results):
            results_by_key[key] = _verification_for_result(osv, result)

    checked_at = utc_now()
    entry_reports: list[dict] = []
    changed_files = 0
    for path, payload in loaded:
        changed = False
        for entry in payload["entries"]:
            ecosystem = str(entry.get("ecosystem") or "").lower()
            package = str(entry.get("package") or "")
            versions = [str(item) for item in entry.get("versions") or []]
            if ecosystem not in {"npm", "pypi"} or not package or not versions:
                continue
            previous = entry.get("verification") or {}
            version_states = dict(previous.get("versions") or {})
            current_states = []
            for version in versions:
                result = results_by_key.get((ecosystem, package, version), {"status": "skipped", "advisory_ids": []})
                current_states.append(result["status"])
                if result["status"] != "skipped":
                    version_states[version] = {**result, "checked_at": checked_at, "source": "osv"}
                    changed = True
            aggregate = _aggregate_status(current_states)
            if changed:
                stored_statuses = [
                    version_states[version].get("status", "skipped")
                    for version in versions
                    if version in version_states
                ]
                entry["verification"] = {
                    "status": _aggregate_status(stored_statuses),
                    "checked_at": checked_at,
                    "source": "osv",
                    "versions": {version: version_states[version] for version in versions if version in version_states},
                }
            entry_reports.append({
                "id": entry.get("id"),
                "ecosystem": ecosystem,
                "package": package,
                "status": aggregate,
                "versions": {version: results_by_key.get((ecosystem, package, version), {"status": "skipped"}) for version in versions},
                "catalog": str(path),
            })
        if changed:
            atomic_write_json(path, payload)
            changed_files += 1

    counts = Counter(item["status"] for item in entry_reports)
    return {
        "status": "partial" if source_errors or file_errors else "ok",
        "checked_at": checked_at,
        "catalog_files": len(loaded),
        "catalog_files_changed": changed_files,
        "exact_versions_queried": len(queries),
        "entry_counts": dict(counts),
        "entries": entry_reports,
        "source_errors": source_errors,
        "file_errors": file_errors,
        "http_stats": osv.http.stats(),
    }


def _verification_for_result(osv: OSVClient, result: dict) -> dict:
    malicious: list[dict] = []
    for stub in result.get("vulns") or []:
        advisory_id = str(stub.get("id") or "")
        if not advisory_id.upper().startswith("MAL-") and not osv_record_is_malicious(stub):
            continue
        detail = stub
        try:
            detail = osv.get_vulnerability(advisory_id)
        except Exception:
            pass
        if osv_record_is_malicious(detail) or advisory_id.upper().startswith("MAL-"):
            malicious.append(detail)
    if not malicious:
        return {"status": "uncorroborated", "advisory_ids": []}
    active = [item for item in malicious if not item.get("withdrawn")]
    return {
        "status": "corroborated" if active else "withdrawn",
        "advisory_ids": sorted({str(item.get("id")) for item in malicious if item.get("id")}),
    }


def _aggregate_status(statuses: list[str]) -> str:
    if not statuses or all(item == "skipped" for item in statuses):
        return "skipped"
    if "corroborated" in statuses:
        return "corroborated"
    evaluated = [item for item in statuses if item != "skipped"]
    if evaluated and all(item == "withdrawn" for item in evaluated):
        return "withdrawn"
    return "uncorroborated"


def _catalog_files(config: GuardianConfig) -> list[Path]:
    selected: set[Path] = set()
    for directory in config.local_catalog_dirs:
        root = Path(directory)
        managed = root / ".guardian-verified"
        managed_names = {path.name for path in managed.glob("*.json")} if managed.is_dir() else set()
        for path in root.rglob("*.json"):
            if path.parent == root and path.name in managed_names:
                continue
            selected.add(path)
    return sorted(selected)
