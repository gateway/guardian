#!/usr/bin/env python3
"""Deterministic WS4 tests for MAL handling, catalog verification, and refresh."""

from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
PLUGIN_ROOT = REPO_ROOT / "plugins" / "guardian-security-scan"
sys.path.insert(0, str(PLUGIN_ROOT / "guardian_runtime" / "src"))

from guardian.advisories import refresh_findings  # noqa: E402
from guardian.catalog_integrity import refresh_verified_catalogs  # noqa: E402
from guardian.catalog_verify import verify_local_catalogs  # noqa: E402
from guardian.check_package import check_package  # noqa: E402
from guardian.config import GuardianConfig  # noqa: E402
from guardian.db import Database  # noqa: E402
from guardian.osv_matching import osv_record_is_malicious, osv_version_is_affected  # noqa: E402
from guardian.reporting_issues import grouped_issues  # noqa: E402
from guardian.sources import LocalCatalogMatcher  # noqa: E402
from guardian.openssf_intel import openssf_entries_for_packages  # noqa: E402
from guardian.threat_intel import ensure_default_threat_intel_sources  # noqa: E402
from guardian.triage_rules import _issue_signal_grade  # noqa: E402


def malicious_record(advisory_id: str, package: str, *, withdrawn: bool = False) -> dict:
    payload = {
        "id": advisory_id,
        "summary": f"Malicious code in {package}",
        "affected": [{
            "package": {"ecosystem": "npm", "name": package},
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}],
        }],
        "database_specific": {
            "malicious-packages-origins": [{"source": "ghsa-malware"}],
        },
        "references": [{"type": "ADVISORY", "url": f"https://osv.dev/vulnerability/{advisory_id}"}],
    }
    if withdrawn:
        payload["withdrawn"] = "2026-01-02T00:00:00Z"
    return payload


ACTIVE = malicious_record("MAL-2026-100", "malicious-fixture")
WITHDRAWN = malicious_record("MAL-2026-101", "withdrawn-fixture", withdrawn=True)


class IntelHandler(BaseHTTPRequestHandler):
    """Serve OSV test records and hash-manifest catalog files."""

    catalog_bodies: dict[str, bytes] = {}

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(length) or b"{}")
        results = []
        for query in payload.get("queries", []):
            name = (query.get("package") or {}).get("name")
            if name in {"malicious-fixture", "osv-only-malicious"}:
                vulns = [{"id": ACTIVE["id"]}]
            elif name == "withdrawn-fixture":
                vulns = [{"id": WITHDRAWN["id"]}]
            else:
                vulns = []
            results.append({"vulns": vulns})
        self._send({"results": results})

    def do_GET(self) -> None:  # noqa: N802
        if self.path.endswith(ACTIVE["id"]):
            self._send(ACTIVE)
            return
        if self.path.endswith(WITHDRAWN["id"]):
            self._send(WITHDRAWN)
            return
        name = self.path.rsplit("/", 1)[-1]
        body = type(self).catalog_bodies.get(name)
        if body is None:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args) -> None:
        return

    def _send(self, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def config_for(tmp: Path, port: int) -> GuardianConfig:
    catalog_dir = tmp / "catalogs"
    catalog_dir.mkdir(parents=True, exist_ok=True)
    return GuardianConfig(
        development_roots=[str(tmp)],
        local_catalog_dirs=[str(catalog_dir)],
        db_path=str(tmp / "guardian.db"),
        exports_dir=str(tmp / "exports"),
        reports_dir=str(tmp / "reports"),
        scans_dir=str(tmp / "scans"),
        threat_intel_sources_path=str(tmp / "sources.json"),
        threat_intel_cache_dir=str(tmp / "cache"),
        osv_api_url=f"http://127.0.0.1:{port}/querybatch",
        osv_vuln_api_url=f"http://127.0.0.1:{port}/vulns",
        npm_registry_url=f"http://127.0.0.1:{port}/registry",
        api_request_min_interval_seconds=0,
        request_timeout_seconds=1,
        http_max_retries=0,
    )


def write_fixture_catalog(path: Path) -> None:
    path.write_text(json.dumps({
        "schema_version": "0.1.0",
        "entries": [
            {
                "id": "local-active", "name": "active fixture", "ecosystem": "npm",
                "package": "malicious-fixture", "versions": ["1.0.0"], "severity": "critical",
                "source": "https://example.test/active", "source_type": "malicious-package-db",
            },
            {
                "id": "local-withdrawn", "name": "withdrawn fixture", "ecosystem": "npm",
                "package": "withdrawn-fixture", "versions": ["1.0.0"], "severity": "critical",
                "source": "https://example.test/withdrawn", "source_type": "malicious-package-db",
            },
            {
                "id": "local-only", "name": "local-only fixture", "ecosystem": "npm",
                "package": "local-only-fixture", "versions": ["1.0.0"], "severity": "critical",
                "source": "https://example.test/local", "source_type": "malicious-package-db",
            },
        ],
    }, indent=2) + "\n")


def assert_osv_helpers() -> None:
    if not osv_record_is_malicious(ACTIVE):
        raise AssertionError("MAL record was not classified as malicious")
    if not osv_version_is_affected(ACTIVE, "npm", "malicious-fixture", "100.0.0"):
        raise AssertionError("open-ended malicious range did not match")
    fixed = malicious_record("MAL-2026-102", "bounded-fixture")
    fixed["affected"][0]["ranges"][0]["events"].append({"fixed": "2.0.0"})
    if osv_version_is_affected(fixed, "npm", "bounded-fixture", "2.0.0"):
        raise AssertionError("OSV fixed boundary remained affected")


def assert_catalog_verification(config: GuardianConfig, db: Database, catalog_path: Path) -> None:
    result = verify_local_catalogs(config)
    expected = {"corroborated": 1, "withdrawn": 1, "uncorroborated": 1}
    if result["status"] != "ok" or result["entry_counts"] != expected:
        raise AssertionError(f"catalog verification mismatch: {result}")
    persisted = json.loads(catalog_path.read_text())
    statuses = {entry["id"]: entry["verification"]["versions"]["1.0.0"]["status"] for entry in persisted["entries"]}
    if statuses != {
        "local-active": "corroborated",
        "local-withdrawn": "withdrawn",
        "local-only": "uncorroborated",
    }:
        raise AssertionError(f"version verification was not persisted exactly: {statuses}")
    verdict = check_package(config, db, "npm", "malicious-fixture", "1.0.0")
    if verdict["verdict"] != "block" or verdict["signals"][0]["signal_grade"] != "corroborated-malicious":
        raise AssertionError(f"corroborated local match did not receive strongest grade: {verdict}")
    osv_only = check_package(config, db, "npm", "osv-only-malicious", "1.0.0")
    if osv_only["verdict"] != "block" or not any(
        item.get("source") == "osv-malicious" and item.get("signal_grade") == "catalog-match"
        for item in osv_only["signals"]
    ):
        raise AssertionError(f"OSV MAL pre-install result did not block: {osv_only}")


def assert_offline_preserves_verification(config: GuardianConfig, catalog_path: Path) -> None:
    before = catalog_path.read_bytes()
    config.osv_api_url = "http://127.0.0.1:1/querybatch"
    result = verify_local_catalogs(config)
    if (
        result["status"] != "partial"
        or result["entry_counts"].get("skipped") != result["exact_versions_queried"]
    ):
        raise AssertionError(f"offline catalog verify did not report skipped: {result}")
    if catalog_path.read_bytes() != before:
        raise AssertionError("offline verification changed persisted catalog state")


def assert_osv_mal_finding(config: GuardianConfig, db: Database, root: Path) -> None:
    config.osv_api_url = config.osv_vuln_api_url.rsplit("/", 1)[0] + "/querybatch"
    run_id = db.start_inventory_run(str(root), "default", "test", "")
    db.insert_inventory_packages(run_id, [{
        "ecosystem": "npm", "package_name": "malicious-fixture", "normalized_name": "malicious-fixture",
        "version": "1.0.0", "source_file": "package-lock.json", "source_type": "npm-lockfile",
        "direct_dependency": True, "install_scope": "prod",
    }])
    refresh_findings(config, db, root_paths=[str(root)], enrich_live=False)
    findings = [dict(row) for row in db.open_findings()]
    if not any(item["advisory_source"] == "osv-malicious" and item["advisory_id"] == ACTIVE["id"] for item in findings):
        raise AssertionError(f"MAL finding was not source-labeled: {findings}")
    issues = grouped_issues(db)
    malicious = next(item for item in issues if ACTIVE["id"] in item["canonical_key"])
    if not malicious["malicious_package"] or _issue_signal_grade(malicious) != "catalog-match":
        raise AssertionError(f"MAL issue did not retain malicious evidence grade: {malicious}")


def assert_openssf_ingest(tmp: Path) -> None:
    source = tmp / "openssf"
    package_dir = source / "osv" / "malicious" / "npm" / "malicious-fixture"
    package_dir.mkdir(parents=True)
    (package_dir / f"{ACTIVE['id']}.json").write_text(json.dumps(ACTIVE))
    withdrawn_dir = source / "osv" / "malicious" / "npm" / "withdrawn-fixture"
    withdrawn_dir.mkdir(parents=True)
    (withdrawn_dir / f"{WITHDRAWN['id']}.json").write_text(json.dumps(WITHDRAWN))
    package_index = {
        ("npm", "malicious-fixture"): {
            "ecosystem": "npm", "normalized_name": "malicious-fixture",
            "display_name": "malicious-fixture", "versions": {"1.0.0"},
        },
        ("npm", "withdrawn-fixture"): {
            "ecosystem": "npm", "normalized_name": "withdrawn-fixture",
            "display_name": "withdrawn-fixture", "versions": {"1.0.0"},
        },
    }
    entries, stats = openssf_entries_for_packages(
        source_dir=source,
        package_index=package_index,
        source_id="openssf-malicious-packages",
        confidence="OpenSSF Malicious Packages",
    )
    if len(entries) != 1 or entries[0]["package"] != "malicious-fixture" or entries[0]["versions"] != ["1.0.0"]:
        raise AssertionError(f"OpenSSF exact entry mismatch: {entries}")
    if stats["withdrawn_records_skipped"] != 1:
        raise AssertionError(f"OpenSSF withdrawn record was not skipped: {stats}")


def assert_source_config_migration(config: GuardianConfig) -> None:
    path = Path(config.threat_intel_sources_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({
        "schema_version": "1.0",
        "sources": [{
            "id": "gitlab-advisory-db", "type": "gitlab-advisory-db",
            "enabled": False, "repo": "https://example.test/custom.git",
        }],
    }))
    migrated = ensure_default_threat_intel_sources(config)
    by_id = {item["id"]: item for item in migrated["sources"]}
    if "openssf-malicious-packages" not in by_id or by_id["openssf-malicious-packages"]["enabled"] is not False:
        raise AssertionError(f"optional OpenSSF source was not added disabled: {migrated}")
    if by_id["gitlab-advisory-db"]["enabled"] is not False or by_id["gitlab-advisory-db"]["repo"] != "https://example.test/custom.git":
        raise AssertionError(f"source migration overwrote operator settings: {migrated}")


def assert_catalog_refresh(config: GuardianConfig, tmp: Path, port: int) -> None:
    bodies = {
        "one.json": json.dumps({
            "schema_version": "0.1.0",
            "entries": [{
                "id": "duplicate-entry", "ecosystem": "npm", "package": "duplicate-fixture",
                "versions": ["1.0.0"], "source_type": "malicious-package-db",
            }],
        }, sort_keys=True).encode(),
        "two.json": json.dumps({"schema_version": "0.1.0", "entries": [{"id": "two"}]}, sort_keys=True).encode(),
    }
    IntelHandler.catalog_bodies = dict(bodies)
    manifest = {
        "schema_version": "1.0",
        "remote_base_url": f"http://127.0.0.1:{port}/catalogs",
        "files": [
            {"name": name, "sha256": hashlib.sha256(body).hexdigest(), "size": len(body)}
            for name, body in sorted(bodies.items())
        ],
    }
    manifest_path = tmp / "manifest.json"
    manifest_path.write_text(json.dumps(manifest))
    top_level_copy = Path(config.local_catalog_dirs[0]) / "one.json"
    top_level_copy.write_bytes(bodies["one.json"])
    success = refresh_verified_catalogs(config, manifest_path=manifest_path)
    destination = Path(success.get("destination") or "")
    if success["status"] != "ok" or {path.name for path in destination.glob("*.json")} != set(bodies):
        raise AssertionError(f"verified catalog refresh failed: {success}")
    duplicate_matches = LocalCatalogMatcher(config).match("npm", "duplicate-fixture", "1.0.0")
    if len(duplicate_matches) != 1 or ".guardian-verified" not in duplicate_matches[0]["_catalog_file"]:
        raise AssertionError(f"managed catalog did not supersede seeded duplicate: {duplicate_matches}")
    before = {path.name: path.read_bytes() for path in destination.glob("*.json")}
    IntelHandler.catalog_bodies["two.json"] = b'{"entries":[{"tampered":true}]}'
    rejected = refresh_verified_catalogs(config, manifest_path=manifest_path)
    after = {path.name: path.read_bytes() for path in destination.glob("*.json")}
    if rejected["status"] != "error" or rejected["source_contract"]["integrity"] != "rejected-fail-closed":
        raise AssertionError(f"tampered catalog refresh was not rejected: {rejected}")
    if after != before:
        raise AssertionError("failed catalog refresh partially modified managed catalogs")


def main() -> int:
    assert_osv_helpers()
    with tempfile.TemporaryDirectory(prefix="guardian-catalog-intel-") as raw_tmp:
        tmp = Path(raw_tmp)
        server = ThreadingHTTPServer(("127.0.0.1", 0), IntelHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            config = config_for(tmp / "state", server.server_port)
            assert_source_config_migration(config)
            catalog_path = Path(config.local_catalog_dirs[0]) / "fixture.json"
            write_fixture_catalog(catalog_path)
            db = Database(config.db_path)
            db.initialize()
            try:
                assert_catalog_verification(config, db, catalog_path)
                assert_osv_mal_finding(config, db, tmp / "project")
            finally:
                db.close()
            assert_openssf_ingest(tmp)
            assert_catalog_refresh(config, tmp, server.server_port)
            assert_offline_preserves_verification(config, catalog_path)
        finally:
            server.shutdown()
            server.server_close()
    print("catalog intelligence tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
