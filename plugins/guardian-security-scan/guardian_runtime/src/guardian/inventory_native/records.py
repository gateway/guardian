"""Canonical package-record builder used by native inventory parsers."""

from __future__ import annotations

import hashlib
from pathlib import Path

from guardian.util import normalize_package_name, utc_now


SCANNER_NAME = "guardian-inventory"
SCHEMA_VERSION = "1.0.0"
SCANNER_VERSION = "0.1.0"


def record_id(record: dict) -> str:
    identity = "\x00".join(
        [
            record.get("record_type", "package"),
            record.get("root_path", ""),
            record.get("ecosystem", ""),
            record.get("normalized_name", ""),
            record.get("version", ""),
            record.get("source_type", ""),
            record.get("source_file", ""),
        ]
    )
    return f"package:{hashlib.sha256(identity.encode('utf-8')).hexdigest()[:32]}"


def project_path_for(root: Path, source_file: Path) -> str:
    parent = source_file.parent
    parts = list(parent.parts)
    if "node_modules" in parts:
        index = parts.index("node_modules")
        return str(Path(*parts[:index])) if index > 0 else str(root)
    if source_file.name in {"METADATA", "PKG-INFO"}:
        for marker in ("site-packages", "dist-packages"):
            if marker in parts:
                index = parts.index(marker)
                return str(Path(*parts[:index])) if index > 0 else str(root)
    return str(parent)


def package_record(
    *,
    root: Path,
    package_name: str,
    version: str,
    ecosystem: str,
    source_file: Path,
    source_type: str,
    package_manager: str,
    confidence: str,
    direct_dependency: bool | None = None,
    install_scope: str | None = None,
    root_kind: str = "project_root",
    evidence_kind: str,
    vendored_metadata: bool = False,
    isolated_environment: bool = False,
    raw_metadata: dict | None = None,
) -> dict:
    normalized_name = normalize_package_name(ecosystem, package_name)
    record = {
        "record_type": "package",
        "schema_version": SCHEMA_VERSION,
        "scanner_name": SCANNER_NAME,
        "scanner_version": SCANNER_VERSION,
        "scan_time": utc_now(),
        "root_path": str(root),
        "ecosystem": ecosystem,
        "package_name": package_name,
        "normalized_name": normalized_name,
        "version": str(version),
        "project_path": project_path_for(root, source_file),
        "root_kind": root_kind,
        "package_manager": package_manager,
        "source_type": source_type,
        "source_file": str(source_file),
        "confidence": confidence,
        "direct_dependency": direct_dependency,
        "install_scope": install_scope,
        "evidence_kind": evidence_kind,
        "vendored_metadata": vendored_metadata,
        "isolated_environment": isolated_environment,
        "raw_metadata": raw_metadata or {},
    }
    record["record_id"] = record_id(record)
    return record
