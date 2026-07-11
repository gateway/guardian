#!/usr/bin/env python3
"""Deterministic Milestone 4 tests for lockfile hygiene, Go, and Rust."""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
PLUGIN_ROOT = REPO_ROOT / "plugins" / "guardian-security-scan"
FIXTURES = REPO_ROOT / "tests" / "fixtures"
sys.path.insert(0, str(PLUGIN_ROOT / "guardian_runtime" / "src"))

from guardian.advisories import refresh_findings  # noqa: E402
from guardian.config import GuardianConfig  # noqa: E402
from guardian.db import Database  # noqa: E402
from guardian.inventory import scan_roots  # noqa: E402
from guardian.inventory_native.engine import scan_package_records  # noqa: E402
from guardian.lockfile_hygiene import detect_lockfile_hygiene  # noqa: E402
from guardian.triage_rules import _environment_label  # noqa: E402
from guardian.util import normalize_ecosystem_for_osv  # noqa: E402
from guardian.versions import compare_versions  # noqa: E402


class OSVHandler(BaseHTTPRequestHandler):
    """Return one deterministic advisory for each new ecosystem."""

    seen_ecosystems: set[str] = set()

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(length) or b"{}")
        results = []
        for query in payload.get("queries") or []:
            package = query.get("package") or {}
            ecosystem = package.get("ecosystem")
            type(self).seen_ecosystems.add(str(ecosystem))
            advisory_id = None
            if ecosystem == "Go" and package.get("name") == "golang.org/x/text":
                advisory_id = "GO-TEST-1"
            elif ecosystem == "crates.io" and package.get("name") == "time":
                advisory_id = "RUSTSEC-TEST-1"
            results.append({"vulns": [{"id": advisory_id}]} if advisory_id else {"vulns": []})
        self._send({"results": results})

    def do_GET(self) -> None:  # noqa: N802
        advisory_id = self.path.rsplit("/", 1)[-1]
        if advisory_id == "GO-TEST-1":
            self._send(_advisory(advisory_id, "Go", "golang.org/x/text", "v0.4.0"))
            return
        if advisory_id == "RUSTSEC-TEST-1":
            self._send(_advisory(advisory_id, "crates.io", "time", "0.2.0"))
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


def _advisory(advisory_id: str, ecosystem: str, package: str, fixed: str) -> dict:
    return {
        "id": advisory_id,
        "summary": f"Fixture advisory for {package}",
        "affected": [{
            "package": {"ecosystem": ecosystem, "name": package},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fixed}]}],
        }],
        "references": [{"type": "ADVISORY", "url": f"https://osv.dev/vulnerability/{advisory_id}"}],
    }


def config_for(tmp: Path, port: int = 9) -> GuardianConfig:
    return GuardianConfig(
        development_roots=[str(tmp)],
        local_catalog_dirs=[str(tmp / "catalogs")],
        db_path=str(tmp / "guardian.db"),
        exports_dir=str(tmp / "exports"),
        reports_dir=str(tmp / "reports"),
        scans_dir=str(tmp / "scans"),
        threat_intel_sources_path=str(tmp / "sources.json"),
        threat_intel_cache_dir=str(tmp / "cache"),
        osv_api_url=f"http://127.0.0.1:{port}/querybatch",
        osv_vuln_api_url=f"http://127.0.0.1:{port}/vulns",
        api_request_min_interval_seconds=0,
        request_timeout_seconds=1,
        http_max_retries=0,
    )


def assert_ecosystem_inventory(tmp: Path) -> None:
    go_records, _ = scan_package_records(tmp / "go-module", ecosystems=["go"], include_installed=False)
    go = {(item["package_name"], item["version"], item["direct_dependency"]): item for item in go_records}
    direct = go.get(("golang.org/x/text", "v0.3.7", True))
    graph = go.get(("golang.org/x/net", "v0.0.0-20210813160813-60bc85c4be6d", False))
    if not direct or not graph:
        raise AssertionError(f"Go direct/module-graph inventory mismatch: {list(go)}")
    if (graph.get("raw_metadata") or {}).get("integrity") != "h1:net-module-checksum":
        raise AssertionError(f"Go checksum missing: {graph}")

    cargo_records, _ = scan_package_records(tmp / "cargo-lock", ecosystems=["crates.io"], include_installed=False)
    if len(cargo_records) != 1 or cargo_records[0]["package_name"] != "time":
        raise AssertionError(f"Cargo inventory mismatch: {cargo_records}")
    if cargo_records[0]["raw_metadata"].get("integrity") != "cargo-checksum-before":
        raise AssertionError(f"Cargo checksum missing: {cargo_records[0]}")

    composer_records, _ = scan_package_records(
        tmp / "composer-lock", ecosystems=["packagist"], include_installed=False
    )
    if len(composer_records) != 1 or composer_records[0]["package_name"] != "symfony/http-foundation":
        raise AssertionError(f"Composer inventory mismatch: {composer_records}")
    if composer_records[0]["version"] != "2.7.0" or not composer_records[0]["direct_dependency"]:
        raise AssertionError(f"Composer version/direct context mismatch: {composer_records[0]}")

    label = _environment_label(
        [{"source_type": "go-sum-lockfile", "direct_dependency": False}],
        {"role": "unknown"},
        {"runtime": 0, "build": 0, "test": 0},
    )
    if label != "module-graph":
        raise AssertionError(f"Go transitive evidence was not labeled module-graph: {label}")


def assert_osv_ecosystems(tmp: Path) -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), OSVHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        state = tmp / "osv-state"
        state.mkdir()
        config = config_for(state, server.server_port)
        Path(config.local_catalog_dirs[0]).mkdir()
        db = Database(config.db_path)
        db.initialize()
        scan_roots(config, db, [str(tmp / "go-module")], ecosystems=["go"])
        scan_roots(config, db, [str(tmp / "cargo-lock")], ecosystems=["crates.io"])
        refresh_findings(config, db, root_paths=[str(tmp / "go-module"), str(tmp / "cargo-lock")], enrich_live=False)
        advisory_ids = {row["advisory_id"] for row in db.open_findings()}
        if not {"GO-TEST-1", "RUSTSEC-TEST-1"}.issubset(advisory_ids):
            raise AssertionError(f"Go/Rust OSV findings missing: {advisory_ids}")
        if OSVHandler.seen_ecosystems != {"Go", "crates.io"}:
            raise AssertionError(f"OSV ecosystem mapping mismatch: {OSVHandler.seen_ecosystems}")
        db.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def assert_lockfile_hygiene(tmp: Path) -> None:
    state = tmp / "hygiene-state"
    state.mkdir()
    config = config_for(state)
    db = Database(config.db_path)
    db.initialize()
    root = str(tmp / "lockfile-hygiene")
    scan_roots(config, db, [root], ecosystems=["npm"])
    first = detect_lockfile_hygiene(config, db, root)
    rogue = [item for item in first if item["signal_type"] == "unexpected-resolved-host"]
    if len(rogue) != 1 or rogue[0]["signal_grade"] != "behavioral-high":
        raise AssertionError(f"rogue-host fixture must emit exactly one high host signal: {first}")

    scan_roots(config, db, [root], ecosystems=["npm"])
    if detect_lockfile_hygiene(config, db, root):
        raise AssertionError("unchanged lockfile hygiene scan emitted repeat signals")

    lock_path = Path(root) / "package-lock.json"
    payload = json.loads(lock_path.read_text())
    item = payload["packages"]["node_modules/safe-package"]
    item["resolved"] = "https://registry.npmjs.org/safe-package/-/safe-package-1.0.0.tgz"
    item["integrity"] = "sha512-after"
    lock_path.write_text(json.dumps(payload, indent=2) + "\n")
    scan_roots(config, db, [root], ecosystems=["npm"])
    changed = detect_lockfile_hygiene(config, db, root)
    integrity = [item for item in changed if item["signal_type"] == "integrity-changed-without-version-change"]
    if len(integrity) != 1 or integrity[0]["signal_grade"] != "behavioral-high":
        raise AssertionError(f"same-version integrity drift was not detected exactly once: {changed}")

    requirements_root = str(tmp / "requirements-hygiene")
    scan_roots(config, db, [requirements_root], ecosystems=["pypi"])
    requirement_signals = detect_lockfile_hygiene(config, db, requirements_root)
    types = {item["signal_type"] for item in requirement_signals}
    if types != {"unpinned-python-requirements", "inconsistent-python-hash-mode"}:
        raise AssertionError(f"Python hygiene summary mismatch: {requirement_signals}")

    clean_requirements = tmp / "direct-reference"
    clean_requirements.mkdir()
    requirement_path = clean_requirements / "requirements.txt"
    requirement_path.write_text("safe-package==1.0.0\n")
    direct_root = str(clean_requirements)
    scan_roots(config, db, [direct_root], ecosystems=["pypi"])
    detect_lockfile_hygiene(config, db, direct_root)
    requirement_path.write_text(
        "safe-package==1.0.0\nurl-package @ https://example.test/url-package-1.0.0.whl\n"
    )
    scan_roots(config, db, [direct_root], ecosystems=["pypi"])
    direct_signals = detect_lockfile_hygiene(config, db, direct_root)
    introduced = [item for item in direct_signals if item["signal_type"] == "direct-dependency-reference"]
    if len(introduced) != 1 or introduced[0]["signal_grade"] != "behavioral-watch":
        raise AssertionError(f"new Python direct reference was not watch-graded: {direct_signals}")
    db.close()


def assert_tolerant_lock_parsers(tmp: Path) -> None:
    """pnpm and Yarn line readers must preserve resolved URL and integrity evidence."""

    pnpm = tmp / "pnpm-hygiene"
    pnpm.mkdir()
    (pnpm / "package.json").write_text('{"dependencies":{"left-pad":"1.3.0"}}\n')
    (pnpm / "pnpm-lock.yaml").write_text(
        "lockfileVersion: '9.0'\npackages:\n  left-pad@1.3.0:\n"
        "    resolution: {integrity: sha512-pnpm, tarball: https://evil.example/left-pad.tgz}\n"
    )
    records, _ = scan_package_records(pnpm, ecosystems=["npm"], include_installed=False)
    lock_record = next((item for item in records if item["source_type"] == "pnpm-lockfile"), None)
    metadata = lock_record["raw_metadata"] if lock_record else {}
    if metadata.get("integrity") != "sha512-pnpm" or "evil.example" not in (metadata.get("resolved") or ""):
        raise AssertionError(f"pnpm hygiene fields not parsed: {records}")

    yarn = tmp / "yarn-hygiene"
    yarn.mkdir()
    (yarn / "package.json").write_text('{"dependencies":{"left-pad":"1.3.0"}}\n')
    (yarn / "yarn.lock").write_text(
        'left-pad@^1.3.0:\n  version "1.3.0"\n'
        '  resolved "https://evil.example/left-pad.tgz"\n  integrity sha512-yarn\n'
    )
    records, _ = scan_package_records(yarn, ecosystems=["npm"], include_installed=False)
    lock_record = next((item for item in records if item["source_type"] == "yarn-lockfile"), None)
    metadata = lock_record["raw_metadata"] if lock_record else {}
    if metadata.get("integrity") != "sha512-yarn" or "evil.example" not in (metadata.get("resolved") or ""):
        raise AssertionError(f"Yarn hygiene fields not parsed: {records}")


def assert_hygiene_performance(tmp: Path) -> None:
    """Keep the offline hygiene pass under the 100 ms WS6 budget at 600 packages."""

    root = tmp / "hygiene-performance"
    root.mkdir()
    packages = {"": {"dependencies": {f"p{index}": "1.0.0" for index in range(600)}}}
    packages.update({
        f"node_modules/p{index}": {
            "version": "1.0.0",
            "resolved": f"https://registry.npmjs.org/p{index}/-/p{index}-1.0.0.tgz",
            "integrity": f"sha512-{index}",
        }
        for index in range(600)
    })
    (root / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": packages}))
    state = tmp / "performance-state"
    state.mkdir()
    config = config_for(state)
    db = Database(config.db_path)
    db.initialize()
    scan_roots(config, db, [str(root)], ecosystems=["npm"])
    started = time.perf_counter()
    signals = detect_lockfile_hygiene(config, db, str(root))
    elapsed_ms = (time.perf_counter() - started) * 1000
    if signals or elapsed_ms >= 100:
        raise AssertionError(f"600-package hygiene pass exceeded budget: {elapsed_ms:.3f} ms, {signals}")
    db.close()


def assert_version_ordering() -> None:
    if compare_versions("v0.0.0-20230101000000-aaaa", "v0.0.0-20230201000000-bbbb") >= 0:
        raise AssertionError("Go pseudo-version timestamps are not ordered")
    if compare_versions("1.2.3-alpha.1", "1.2.3") >= 0:
        raise AssertionError("Rust semver prerelease should sort before stable")
    if normalize_ecosystem_for_osv("crates.io") != "crates.io":
        raise AssertionError("crates.io OSV mapping missing")


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="guardian-m4-") as raw_tmp:
        tmp = Path(raw_tmp)
        for fixture in (
            "go-module", "cargo-lock", "composer-lock",
            "lockfile-hygiene", "requirements-hygiene",
        ):
            shutil.copytree(FIXTURES / fixture, tmp / fixture)
        assert_ecosystem_inventory(tmp)
        assert_osv_ecosystems(tmp)
        assert_lockfile_hygiene(tmp)
        assert_tolerant_lock_parsers(tmp)
        assert_hygiene_performance(tmp)
        assert_version_ordering()
    print("milestone 4 tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
