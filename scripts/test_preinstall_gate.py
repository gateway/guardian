#!/usr/bin/env python3
"""Deterministic Milestone 2 tests for package checks, typo signals, and hooks."""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
PLUGIN_ROOT = REPO_ROOT / "plugins" / "guardian-security-scan"
sys.path.insert(0, str(PLUGIN_ROOT / "guardian_runtime" / "src"))

from guardian.check_package import check_package  # noqa: E402
from guardian.config import GuardianConfig  # noqa: E402
from guardian.db import Database  # noqa: E402
from guardian.install_command import extract_install_requests  # noqa: E402
from guardian.preinstall_hook import evaluate_install_command, hook_output  # noqa: E402
from guardian.typosquat import detect_new_package_typosquats, detect_typosquat  # noqa: E402
from guardian.util import normalize_package_name  # noqa: E402


class SourceHandler(BaseHTTPRequestHandler):
    """Serve fixed registry and OSV responses without external network access."""

    request_count = 0

    def do_GET(self) -> None:  # noqa: N802
        type(self).request_count += 1
        package = self.path.split("/")[2] if self.path.startswith(("/npm/", "/pypi/")) else ""
        package = package.replace("%40", "@").replace("%2F", "/")
        if self.path.startswith("/npm/"):
            payload = {"name": package, "version": "1.0.0"}
            if "scripted" in package:
                payload["scripts"] = {"postinstall": "node setup.js"}
        else:
            files = [{"packagetype": "sdist"}] if "sdist-only" in package else [{"packagetype": "bdist_wheel"}]
            payload = {
                "info": {"name": package, "version": "1.0.0"},
                "releases": {"1.0.0": files},
                "urls": files,
            }
        self._send(payload)

    def do_POST(self) -> None:  # noqa: N802
        type(self).request_count += 1
        length = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(length) or b"{}")
        results = []
        for query in payload.get("queries", []):
            name = (query.get("package") or {}).get("name")
            vulns = [{"id": "GHSA-test-vulnerable"}] if name == "vulnerable" else []
            results.append({"vulns": vulns})
        self._send({"results": results})

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
    """Build isolated source and state paths for deterministic checks."""

    catalog_dir = tmp / "catalogs"
    if not catalog_dir.exists():
        shutil.copytree(PLUGIN_ROOT / "data" / "local_catalogs", catalog_dir)
    return GuardianConfig(
        development_roots=[str(tmp)],
        local_catalog_dirs=[str(catalog_dir)],
        db_path=str(tmp / "guardian.db"),
        exports_dir=str(tmp / "exports"),
        reports_dir=str(tmp / "reports"),
        scans_dir=str(tmp / "scans"),
        threat_intel_sources_path=str(tmp / "sources.json"),
        threat_intel_cache_dir=str(tmp / "cache"),
        npm_registry_url=f"http://127.0.0.1:{port}/npm",
        pypi_registry_url=f"http://127.0.0.1:{port}/pypi",
        osv_api_url=f"http://127.0.0.1:{port}/osv",
        api_request_min_interval_seconds=0,
        request_timeout_seconds=1,
        preinstall_gate_max_seconds=2,
    )


def assert_command_parser() -> None:
    """Cover common agent-generated install forms and non-addition commands."""

    cases = {
        "npm install react@19": ("npm", "react"),
        "npm i lodash": ("npm", "lodash"),
        "npm add @types/node@22": ("npm", "@types/node"),
        "pnpm add zod": ("npm", "zod"),
        "pnpm install react": ("npm", "react"),
        "yarn add vite": ("npm", "vite"),
        "npm install --save-dev vitest": ("npm", "vitest"),
        "npm install --registry https://registry.npmjs.org react": ("npm", "react"),
        "FOO=1 npm i express": ("npm", "express"),
        "sudo npm install chalk": ("npm", "chalk"),
        "pip install requests==2.32.4": ("pypi", "requests"),
        "pip3 install flask": ("pypi", "flask"),
        "python -m pip install django": ("pypi", "django"),
        "python3 -m pip install fastapi": ("pypi", "fastapi"),
        "uv add httpx": ("pypi", "httpx"),
        "uv pip install pydantic": ("pypi", "pydantic"),
        "poetry add sqlalchemy": ("pypi", "sqlalchemy"),
        "pip install 'requests[security]==2.32.4'": ("pypi", "requests"),
        "npm i react && pip install requests": ("npm", "react"),
        "command npm i commander": ("npm", "commander"),
        "env BAR=2 yarn add eslint": ("npm", "eslint"),
        "uv add --dev pytest": ("pypi", "pytest"),
        "poetry add 'black==25.1.0'": ("pypi", "black"),
        "npm install --workspace web react": ("npm", "react"),
    }
    for command, expected in cases.items():
        requests = extract_install_requests(command)
        if not requests or (requests[0].ecosystem, requests[0].name) != expected:
            raise AssertionError(f"install parser mismatch for {command!r}: {requests}")
    for command in ("npm install", "npm ci", "yarn install", "pip install -r requirements.txt", "echo npm install react"):
        if extract_install_requests(command):
            raise AssertionError(f"non-addition command should be ignored: {command}")
    opaque = extract_install_requests("pip install git+https://github.com/example/pkg.git")
    if len(opaque) != 1 or not opaque[0].opaque_reason:
        raise AssertionError(f"VCS install should require review: {opaque}")
    chained = extract_install_requests("npm i react&&python -m pip install requests")
    if [(item.ecosystem, item.name) for item in chained] != [("npm", "react"), ("pypi", "requests")]:
        raise AssertionError(f"unspaced shell operators were not segmented: {chained}")


def assert_typosquat_state(db: Database, root: str) -> None:
    """A newly introduced typo should signal once and honor accept-name policy."""

    for ecosystem, typo, target in (
        ("npm", "lodahs", "lodash"),
        ("npm", "is-nubmer", "is-number"),
        ("pypi", "reqests", "requests"),
    ):
        started = time.perf_counter()
        signals = detect_typosquat(ecosystem, typo, db=db)
        elapsed = time.perf_counter() - started
        if not signals or signals[0]["similar_package"] != target:
            raise AssertionError(f"known typo was not detected: {ecosystem} {typo} -> {signals}")
        if elapsed >= 0.05:
            raise AssertionError(f"typo check exceeded 50ms: {ecosystem} {typo} took {elapsed:.4f}s")
    for exact in ("react", "preact"):
        if detect_typosquat("npm", exact, db=db):
            raise AssertionError(f"exact popular package should not be a typo signal: {exact}")
    record = {
        "ecosystem": "npm", "package_name": "lodahs", "normalized_name": "lodahs",
        "version": "1.0.0", "source_file": "package-lock.json", "source_type": "npm-lockfile",
    }
    first = db.start_inventory_run(root, "default", "test", "")
    db.insert_inventory_packages(first, [record])
    if len(detect_new_package_typosquats(db, root, [first])) != 1:
        raise AssertionError("first-seen package typo did not produce exactly one signal")
    second = db.start_inventory_run(root, "default", "test", "")
    db.insert_inventory_packages(second, [record])
    if detect_new_package_typosquats(db, root, [second]):
        raise AssertionError("unchanged package typo repeated after its first snapshot")


def assert_package_checks(config: GuardianConfig, db: Database) -> None:
    """Verify cold/warm, malicious, advisory, typo, policy, and offline verdicts."""

    malicious = check_package(config, db, "npm", "@beproduct/nestjs-auth", "0.1.18")
    if malicious["verdict"] != "block" or malicious["elapsed_seconds"] >= 1:
        raise AssertionError(f"local malicious match should block immediately: {malicious}")

    cold = check_package(config, db, "npm", "react", "1.0.0")
    warm_started = time.perf_counter()
    warm = check_package(config, db, "npm", "react", "1.0.0")
    if cold["verdict"] != "allow" or cold["elapsed_seconds"] >= 3 or not warm["cache_hit"] or time.perf_counter() - warm_started >= 1:
        raise AssertionError(f"clean package cache contract failed: cold={cold} warm={warm}")

    refreshed_catalog = Path(config.local_catalog_dirs[0]) / "test-refresh.json"
    refreshed_catalog.write_text(json.dumps({"entries": [{
        "id": "test-new-malicious-react", "ecosystem": "npm", "package": "react",
        "versions": ["1.0.0"], "name": "test refreshed catalog entry",
        "source_type": "malicious-package", "source": "local test",
    }]}))
    refreshed = check_package(config, db, "npm", "react", "1.0.0")
    if refreshed["verdict"] != "block" or refreshed["cache_hit"]:
        raise AssertionError(f"catalog refresh did not invalidate cached allow: {refreshed}")

    vulnerable = check_package(config, db, "npm", "vulnerable", "1.0.0")
    if vulnerable["verdict"] != "warn" or not any(s["signal_type"] == "known-vulnerability" for s in vulnerable["signals"]):
        raise AssertionError(f"OSV advisory was not surfaced: {vulnerable}")
    advisory_signal = next(s for s in vulnerable["signals"] if s["signal_type"] == "known-vulnerability")
    if advisory_signal.get("url") != "https://osv.dev/vulnerability/GHSA-test-vulnerable":
        raise AssertionError(f"OSV advisory link missing from package verdict: {advisory_signal}")

    sdist = check_package(config, db, "pypi", "sdist-only", "1.0.0")
    if not any(s["signal_type"] == "registry-install-script" for s in sdist["signals"]):
        raise AssertionError(f"PyPI version endpoint source-only release was not detected: {sdist}")

    typo = check_package(config, db, "npm", "lodahs", "1.0.0")
    if typo["verdict"] != "warn":
        raise AssertionError(f"typo package should warn: {typo}")
    db.add_policy_exception(
        ecosystem="npm", normalized_name="lodahs", version=None, advisory_source=None,
        canonical_key=None, action="accept-name", reason="test", expires_at=None, created_by="test",
    )
    db.invalidate_package_verdicts("npm", "lodahs")
    accepted = check_package(config, db, "npm", "lodahs", "1.0.0")
    if any(s["signal_type"] == "typosquat-suspected" for s in accepted["signals"]):
        raise AssertionError(f"accepted package name still emitted typo signal: {accepted}")


def assert_hook_decisions(config: GuardianConfig, db: Database) -> None:
    """Hooks should pause high-risk installs while allowing fail-open warnings."""

    blocked = evaluate_install_command(config, db, "npm i @beproduct/nestjs-auth@0.1.18")
    if blocked["decision"] != "deny" or not hook_output(blocked):
        raise AssertionError(f"malicious install was not denied: {blocked}")
    advisory = evaluate_install_command(config, db, "npm i vulnerable@1.0.0")
    if advisory["decision"] != "deny":
        raise AssertionError(f"known vulnerable install was not paused: {advisory}")
    scripted = evaluate_install_command(config, db, "npm i scripted@1.0.0")
    if scripted["decision"] != "allow" or not scripted["message"]:
        raise AssertionError(f"install-script warning should be non-blocking context: {scripted}")
    opaque = evaluate_install_command(config, db, "pip install git+https://github.com/example/pkg.git")
    if opaque["decision"] != "deny":
        raise AssertionError(f"opaque source install should pause for review: {opaque}")
    batch = evaluate_install_command(
        config,
        db,
        "npm i ordinary-package@1.0.0 @beproduct/nestjs-auth@0.1.18",
    )
    if batch["decision"] != "deny" or not any(item.get("verdict") == "block" for item in batch["requests"]):
        raise AssertionError(f"later malicious package bypassed command-wide local preflight: {batch}")
    oversized = evaluate_install_command(config, db, "npm i " + " ".join(f"package-{n}" for n in range(51)))
    if oversized["decision"] != "deny" or "Split it into batches" not in (oversized["message"] or ""):
        raise AssertionError(f"oversized install command was not bounded: {oversized}")
    config.preinstall_gate_enabled = False
    disabled = evaluate_install_command(config, db, "npm i @beproduct/nestjs-auth@0.1.18")
    config.preinstall_gate_enabled = True
    if disabled["decision"] != "allow" or disabled["requests"]:
        raise AssertionError(f"disabled hook did not bypass cleanly: {disabled}")


def assert_offline_fail_open(tmp: Path) -> None:
    """Unavailable live sources must warn without denying an ordinary package."""

    config = config_for(tmp, 1)
    config.preinstall_gate_max_seconds = 0.25
    db = Database(config.db_path)
    db.initialize()
    try:
        started = time.perf_counter()
        result = evaluate_install_command(config, db, "npm i ordinary-package@1.0.0")
        if result["decision"] != "allow" or not result["message"]:
            raise AssertionError(f"offline package check did not fail open: {result}")
        if time.perf_counter() - started >= 1:
            raise AssertionError("offline package check exceeded its bounded fail-open budget")
    finally:
        db.close()


def assert_additive_migration(tmp: Path) -> None:
    """Existing databases should gain first_seen_run_id without a rebuild."""

    path = tmp / "old.db"
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE package_state (id INTEGER PRIMARY KEY, root_path TEXT, ecosystem TEXT, "
        "normalized_name TEXT, version TEXT, present INTEGER)"
    )
    conn.commit()
    conn.close()
    db = Database(str(path))
    db.initialize()
    try:
        columns = {row[1] for row in db.conn.execute("PRAGMA table_info(package_state)")}
        if "first_seen_run_id" not in columns:
            raise AssertionError("additive migration did not add first_seen_run_id")
    finally:
        db.close()


def assert_cli_contract(tmp: Path) -> None:
    """The public command should return documented block and policy exit codes."""

    env = os.environ.copy()
    env["GUARDIAN_STATE_DIR"] = str(tmp / "cli-state")
    command = [
        str(PLUGIN_ROOT / "scripts" / "guardian"), "check-package", "npm",
        "@beproduct/nestjs-auth", "0.1.18", "--json",
    ]
    completed = subprocess.run(command, env=env, capture_output=True, text=True, check=False)
    if completed.returncode != 2 or json.loads(completed.stdout)["verdict"] != "block":
        raise AssertionError(f"public check-package block contract failed: {completed}")
    accepted = subprocess.run(
        [str(PLUGIN_ROOT / "scripts" / "guardian"), "policy", "accept-name", "npm", "lodahs", "--json"],
        env=env, capture_output=True, text=True, check=False,
    )
    if accepted.returncode != 0 or json.loads(accepted.stdout)["action"] != "accept-name":
        raise AssertionError(f"public accept-name contract failed: {accepted}")


def main() -> int:
    assert_command_parser()
    with tempfile.TemporaryDirectory(prefix="guardian-preinstall-") as raw_tmp:
        tmp = Path(raw_tmp)
        server = ThreadingHTTPServer(("127.0.0.1", 0), SourceHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            config = config_for(tmp / "live", server.server_port)
            db = Database(config.db_path)
            db.initialize()
            try:
                assert_typosquat_state(db, str(tmp / "project"))
                assert_package_checks(config, db)
                assert_hook_decisions(config, db)
            finally:
                db.close()
            assert_offline_fail_open(tmp / "offline")
            assert_additive_migration(tmp)
            assert_cli_contract(tmp)
        finally:
            server.shutdown()
            server.server_close()
    print("pre-install gate tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
