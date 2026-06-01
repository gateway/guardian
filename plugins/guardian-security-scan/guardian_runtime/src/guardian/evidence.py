from __future__ import annotations

import json
from collections import defaultdict
from typing import Iterable


EVIDENCE_PRIORITY = {
    "runtime-confirmed": 5,
    "installed-only": 4,
    "lockfile-only": 3,
    "isolated-environment": 2,
    "vendored-metadata": 1,
    "uncorroborated": 0,
}


def evidence_label_for_record(record: dict) -> str:
    source_type = record.get("source_type") or ""
    source_file = record.get("source_file") or ""
    raw = _raw_record(record)
    if raw.get("vendored_metadata") or raw.get("evidence_kind") == "vendored-metadata":
        return "vendored-metadata"
    if raw.get("isolated_environment"):
        return "isolated-environment"
    if source_type in {"npm-node_modules", "pypi-dist-info", "pypi-egg-info"}:
        return "installed-only"
    if source_type in {"npm-lockfile", "pnpm-lockfile", "yarn-lockfile"}:
        if "/node_modules/" in source_file:
            return "installed-only"
        return "lockfile-only"
    return "uncorroborated"


def evidence_summary(rows: Iterable[dict]) -> dict:
    grouped: dict[tuple[str, str, str], set[str]] = defaultdict(set)
    row_count_by_label: dict[str, int] = defaultdict(int)
    for row in rows:
        label = evidence_label_for_record(row)
        row_count_by_label[label] += 1
        key = (
            row.get("ecosystem") or "",
            row.get("normalized_name") or "",
            row.get("version") or "",
        )
        grouped[key].add(label)

    package_count_by_label: dict[str, int] = defaultdict(int)
    for labels in grouped.values():
        package_count_by_label[_best_package_label(labels)] += 1

    ordered_labels = sorted(EVIDENCE_PRIORITY, key=lambda item: -EVIDENCE_PRIORITY[item])
    return {
        "package_counts": {label: package_count_by_label.get(label, 0) for label in ordered_labels},
        "evidence_row_counts": {label: row_count_by_label.get(label, 0) for label in ordered_labels},
        "total_unique_packages": len(grouped),
        "total_evidence_rows": sum(row_count_by_label.values()),
        "priority_order": ordered_labels,
    }


def _best_package_label(labels: set[str]) -> str:
    if "vendored-metadata" in labels and len(labels) == 1:
        return "vendored-metadata"
    if "installed-only" in labels and "lockfile-only" in labels:
        return "runtime-confirmed"
    if "installed-only" in labels:
        return "installed-only"
    if "lockfile-only" in labels:
        return "lockfile-only"
    if "isolated-environment" in labels:
        return "isolated-environment"
    if "vendored-metadata" in labels:
        return "vendored-metadata"
    return "uncorroborated"


def _raw_record(row: dict) -> dict:
    raw = row.get("raw_json")
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str) and raw:
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            return {}
    return {}
