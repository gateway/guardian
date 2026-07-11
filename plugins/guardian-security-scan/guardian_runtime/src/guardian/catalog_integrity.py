"""Hash-manifest verification and atomic writes for managed catalog files."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from urllib.parse import quote

from .config import PLUGIN_ROOT, GuardianConfig
from .http_client import GuardianHttp


CATALOG_MANIFEST_PATH = PLUGIN_ROOT / "data" / "catalog_manifest.json"


def refresh_verified_catalogs(
    config: GuardianConfig,
    *,
    base_url: str | None = None,
    manifest_path: Path | None = None,
) -> dict:
    """Fetch every manifest-pinned catalog and publish only a complete verified set."""

    manifest_file = manifest_path or CATALOG_MANIFEST_PATH
    try:
        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
        files = _validated_manifest_files(manifest)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return _refresh_result("error", manifest_file, [], [str(exc)])
    remote_base = (base_url or manifest.get("remote_base_url") or "").rstrip("/")
    if not remote_base:
        return _refresh_result("error", manifest_file, files, ["catalog manifest has no remote_base_url"])

    http = GuardianHttp(config)
    staged: dict[str, bytes] = {}
    errors: list[str] = []
    file_reports: list[dict] = []
    for item in files:
        name = item["name"]
        url = f"{remote_base}/{quote(name, safe='')}"
        result = http.get(url, cache=False)
        if result.error:
            errors.append(f"{name}: {result.error}")
            file_reports.append({"name": name, "status": "download-error", "url": url})
            continue
        actual = hashlib.sha256(result.body).hexdigest()
        if actual != item["sha256"]:
            errors.append(f"{name}: SHA-256 mismatch (expected {item['sha256']}, got {actual})")
            file_reports.append({"name": name, "status": "hash-mismatch", "url": url})
            continue
        try:
            payload = json.loads(result.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            errors.append(f"{name}: invalid catalog JSON: {exc}")
            file_reports.append({"name": name, "status": "invalid-json", "url": url})
            continue
        if not isinstance(payload, dict) or not isinstance(payload.get("entries"), list):
            errors.append(f"{name}: catalog must contain an entries array")
            file_reports.append({"name": name, "status": "invalid-schema", "url": url})
            continue
        staged[name] = result.body
        file_reports.append({"name": name, "status": "verified", "url": url, "sha256": actual})

    if errors or len(staged) != len(files):
        return _refresh_result("error", manifest_file, files, errors, file_reports, http.stats())

    destination = Path(config.local_catalog_dirs[0]) / ".guardian-verified"
    destination.mkdir(parents=True, exist_ok=True)
    for name, body in staged.items():
        atomic_write_bytes(destination / name, body)
    expected_names = set(staged)
    for path in destination.glob("*.json"):
        if path.name not in expected_names:
            path.unlink()
    payload = _refresh_result("ok", manifest_file, files, [], file_reports, http.stats())
    payload["destination"] = str(destination)
    return payload


def atomic_write_json(path: Path, payload: dict) -> None:
    atomic_write_bytes(path, (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8"))


def atomic_write_bytes(path: Path, body: bytes) -> None:
    """Write a catalog beside its destination, fsync it, then replace atomically."""

    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
    finally:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass


def _validated_manifest_files(manifest: dict) -> list[dict]:
    if manifest.get("schema_version") != "1.0":
        raise ValueError("unsupported catalog manifest schema")
    files = manifest.get("files")
    if not isinstance(files, list) or not files:
        raise ValueError("catalog manifest must contain files")
    validated = []
    for item in files:
        name = item.get("name") if isinstance(item, dict) else None
        digest = item.get("sha256") if isinstance(item, dict) else None
        if not isinstance(name, str) or Path(name).name != name or not name.endswith(".json"):
            raise ValueError(f"unsafe catalog filename in manifest: {name!r}")
        if not isinstance(digest, str) or len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
            raise ValueError(f"invalid SHA-256 for catalog {name}")
        validated.append({"name": name, "sha256": digest, "size": item.get("size")})
    return validated


def _refresh_result(
    status: str,
    manifest_path: Path,
    files: list[dict],
    errors: list[str],
    file_reports: list[dict] | None = None,
    http_stats: dict | None = None,
) -> dict:
    return {
        "status": status,
        "manifest_path": str(manifest_path),
        "files_expected": len(files),
        "files": file_reports or [],
        "errors": errors,
        "http_stats": http_stats or {},
        "source_contract": {
            "source": "guardian-release-catalogs",
            "status": "healthy" if status == "ok" else "degraded",
            "integrity": "sha256-verified" if status == "ok" else "rejected-fail-closed",
            "usable_for_resolution": status == "ok",
        },
    }
