#!/usr/bin/env python3
"""Deterministic WS5 tests for changed-package registry metadata signals."""

from __future__ import annotations

import json
import sys
import tempfile
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
PLUGIN_ROOT = REPO_ROOT / "plugins" / "guardian-security-scan"
sys.path.insert(0, str(PLUGIN_ROOT / "guardian_runtime" / "src"))

from guardian.config import GuardianConfig  # noqa: E402
from guardian.check_package import check_package  # noqa: E402
from guardian.db import Database  # noqa: E402
from guardian.ops import run_daily_watch  # noqa: E402
from guardian.registry_intel import detect_registry_metadata_changes  # noqa: E402
from guardian.scan_modes import apply_scan_mode  # noqa: E402


NOW = datetime.now(timezone.utc)


class RegistryHandler(BaseHTTPRequestHandler):
    request_count = 0
    request_paths: list[str] = []

    def do_GET(self) -> None:  # noqa: N802
        type(self).request_count += 1
        type(self).request_paths.append(self.path)
        if self.path.startswith("/npm/drift-package/"):
            version = self.path.rsplit("/", 1)[-1]
            current = version == "2.0.0"
            self._send({
                "name": "drift-package",
                "version": version,
                "maintainers": [{
                    "name": "maintainer-b" if current else "maintainer-a",
                    "email": "b@example.test" if current else "a@example.test",
                }],
                "repository": {"url": "git+https://github.com/example/new.git" if current else "git+https://github.com/example/old.git"},
                "deprecated": "replace this release" if current else None,
                "scripts": {"postinstall": "node setup.js"} if current else {},
                "dist": {"unpackedSize": 2000 if current else 1000} if current else {"attestations": {"url": "https://example.test/attestation"}, "unpackedSize": 1000},
            })
            return
        if self.path.startswith("/npm/drift-package"):
            self._send({
                "dist-tags": {"latest": "2.0.0"},
                "time": {
                    "1.0.0": (NOW - timedelta(days=30)).isoformat(),
                    "2.0.0": (NOW - timedelta(hours=24)).isoformat(),
                },
                "versions": {
                    "1.0.0": {
                        "maintainers": [{"name": "maintainer-a", "email": "a@example.test"}],
                        "repository": {"url": "git+https://github.com/example/old.git"},
                        "dist": {"attestations": {"url": "https://example.test/attestation"}, "unpackedSize": 1000},
                    },
                    "2.0.0": {
                        "maintainers": [{"name": "maintainer-b", "email": "b@example.test"}],
                        "repository": {"url": "git+https://github.com/example/new.git"},
                        "deprecated": "replace this release",
                        "scripts": {"postinstall": "node setup.js"},
                        "dist": {"unpackedSize": 2000},
                    },
                },
            })
            return
        if self.path.startswith("/npm/watch-package"):
            self._send({
                "dist-tags": {"latest": "1.0.0"},
                "time": {"1.0.0": (NOW - timedelta(days=10)).isoformat()},
                "versions": {
                    "1.0.0": {
                        "maintainers": [{"name": "watch"}],
                        "repository": {"url": "https://github.com/example/watch"},
                        "dist": {"unpackedSize": 500},
                    }
                },
            })
            return
        if self.path.startswith("/pypi/yanked-package/"):
            version = self.path.split("/")[3]
            current = version == "2.0.0"
            self._send({
                "info": {
                    "name": "yanked-package",
                    "version": version,
                    "project_urls": {"Repository": "https://github.com/example/new-pypi" if current else "https://github.com/example/old-pypi"},
                },
                "urls": [{
                    "upload_time_iso_8601": (
                        NOW - (timedelta(hours=12) if current else timedelta(days=100))
                    ).isoformat(),
                    "yanked": current,
                    "yanked_reason": "bad artifact" if current else None,
                    "size": 1234,
                }],
            })
            return
        self.send_error(404)

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
    return GuardianConfig(
        development_roots=[str(tmp)],
        local_catalog_dirs=[str(tmp / "catalogs")],
        db_path=str(tmp / "guardian.db"),
        exports_dir=str(tmp / "exports"),
        reports_dir=str(tmp / "reports"),
        scans_dir=str(tmp / "scans"),
        threat_intel_sources_path=str(tmp / "sources.json"),
        threat_intel_cache_dir=str(tmp / "cache"),
        npm_registry_url=f"http://127.0.0.1:{port}/npm",
        pypi_registry_url=f"http://127.0.0.1:{port}/pypi",
        api_request_min_interval_seconds=0,
        request_timeout_seconds=1,
        http_max_retries=0,
        registry_intel_max_packages=20,
    )


def record(ecosystem: str, name: str, version: str) -> dict:
    return {
        "ecosystem": ecosystem,
        "package_name": name,
        "normalized_name": name,
        "version": version,
        "source_file": "package-lock.json" if ecosystem == "npm" else "uv.lock",
        "source_type": "npm-lockfile" if ecosystem == "npm" else "uv-lockfile",
        "direct_dependency": True,
        "install_scope": "prod",
    }


def assert_version_drift(config: GuardianConfig, db: Database, root: Path) -> None:
    baseline = db.start_inventory_run(str(root), "default", "test", "")
    db.insert_inventory_packages(
        baseline,
        [record("npm", "drift-package", "1.0.0"), record("pypi", "yanked-package", "1.0.0")],
    )
    first = detect_registry_metadata_changes(config, db, str(root), [baseline])
    if first["status"] != "skipped-unchanged" or first["http_stats"]["requests"] != 0:
        raise AssertionError(f"first standard baseline should make zero registry calls: {first}")

    changed = db.start_inventory_run(str(root), "default", "test", "")
    db.insert_inventory_packages(
        changed,
        [record("npm", "drift-package", "2.0.0"), record("pypi", "yanked-package", "2.0.0")],
    )
    second = detect_registry_metadata_changes(config, db, str(root), [changed])
    npm_paths = [path for path in RegistryHandler.request_paths if path.startswith("/npm/drift-package")]
    if npm_paths[:1] != ["/npm/drift-package/2.0.0"] or "/npm/drift-package/1.0.0" not in npm_paths:
        raise AssertionError(f"npm registry intel should fetch exact version documents first: {npm_paths}")
    signal_types = {item["signal_type"] for item in second["signals"]}
    expected = {
        "version-published-recently",
        "maintainer-set-changed",
        "provenance-disappeared",
        "package-deprecated",
        "release-yanked",
        "repo-url-missing-or-changed",
    }
    if not expected.issubset(signal_types):
        raise AssertionError(f"registry drift signals missing: expected={expected} got={signal_types} report={second}")
    provenance = next(item for item in second["signals"] if item["signal_type"] == "provenance-disappeared")
    if provenance["signal_grade"] != "behavioral-high" or provenance["posture"] != "fix_this_week":
        raise AssertionError(f"provenance loss was not high signal: {provenance}")
    info = [item for item in second["signals"] if item["signal_grade"] == "info"]
    if not info or any(item["posture"] != "info" for item in info):
        raise AssertionError(f"registry hygiene info inflated operator posture: {info}")
    gate = check_package(config, db, "npm", "drift-package", "2.0.0", max_seconds=0.1)
    if gate["sources"]["registry"]["status"] != "state-cache":
        raise AssertionError(f"pre-install gate did not reuse registry state: {gate}")
    gate_types = {item["signal_type"] for item in gate["signals"]}
    if not {"version-published-recently", "package-deprecated", "registry-install-script"}.issubset(gate_types):
        raise AssertionError(f"pre-install gate omitted cached registry warnings: {gate}")

    repeated = db.start_inventory_run(str(root), "default", "test", "")
    db.insert_inventory_packages(
        repeated,
        [record("npm", "drift-package", "2.0.0"), record("pypi", "yanked-package", "2.0.0")],
    )
    third = detect_registry_metadata_changes(config, db, str(root), [repeated])
    if third["status"] != "skipped-unchanged" or third["signals"] or third["http_stats"]["requests"] != 0:
        raise AssertionError(f"unchanged repeat did not stay silent and offline: {third}")


def write_watch_project(root: Path) -> None:
    root.mkdir(parents=True)
    (root / "package.json").write_text(json.dumps({"name": "watch", "dependencies": {"watch-package": "1.0.0"}}))
    (root / "package-lock.json").write_text(json.dumps({
        "name": "watch",
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "watch", "dependencies": {"watch-package": "1.0.0"}},
            "node_modules/watch-package": {"version": "1.0.0"},
        },
    }))


def assert_daily_watch_zero_calls(config: GuardianConfig, root: Path) -> None:
    db = Database(config.db_path)
    db.initialize()
    try:
        first = run_daily_watch(
            config,
            db,
            roots=[str(root)],
            ecosystems=["npm"],
            include_installed=False,
            include_ghsa=False,
            ghsa_max_packages=0,
            refresh_advisories=False,
            include_registry_intel=True,
        )
        second = run_daily_watch(
            config,
            db,
            roots=[str(root)],
            ecosystems=["npm"],
            include_installed=False,
            include_ghsa=False,
            ghsa_max_packages=0,
            refresh_advisories=False,
            include_registry_intel=True,
        )
    finally:
        db.close()
    if first["roots"][0]["registry_intel"]["http_stats"]["requests"] != 0:
        raise AssertionError(f"first watch baseline made registry calls: {first['roots'][0]}")
    registry = second["roots"][0]["registry_intel"]
    if second["roots_inventory_count"] != 0 or registry["status"] != "skipped-unchanged" or registry["http_stats"]["requests"] != 0:
        raise AssertionError(f"unchanged daily watch made registry calls: {second['roots'][0]}")


def main() -> int:
    modes = {name: apply_scan_mode(name) for name in ("daily", "standard", "deep")}
    if modes["daily"]["registry_intel_mode"] != "off" or modes["daily"]["include_openssf_malicious"]:
        raise AssertionError(f"daily mode enabled expensive intelligence: {modes['daily']}")
    if modes["standard"]["registry_intel_mode"] != "changed" or modes["standard"]["include_openssf_malicious"]:
        raise AssertionError(f"standard mode cost policy mismatch: {modes['standard']}")
    if modes["deep"]["registry_intel_mode"] != "deep" or not modes["deep"]["include_openssf_malicious"]:
        raise AssertionError(f"deep mode did not enable M3 intelligence: {modes['deep']}")
    with tempfile.TemporaryDirectory(prefix="guardian-registry-intel-") as raw_tmp:
        tmp = Path(raw_tmp)
        server = ThreadingHTTPServer(("127.0.0.1", 0), RegistryHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            drift_config = config_for(tmp / "drift-state", server.server_port)
            db = Database(drift_config.db_path)
            db.initialize()
            try:
                assert_version_drift(drift_config, db, tmp / "drift-project")
            finally:
                db.close()
            watch_root = tmp / "watch-project"
            write_watch_project(watch_root)
            assert_daily_watch_zero_calls(config_for(tmp / "watch-state", server.server_port), watch_root)
        finally:
            server.shutdown()
            server.server_close()
    print("registry intelligence tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
