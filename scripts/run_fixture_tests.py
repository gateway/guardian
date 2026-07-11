#!/usr/bin/env python3
"""Run small end-to-end Guardian scans against safe release fixtures."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
PLUGIN_ROOT = REPO_ROOT / "plugins" / "guardian-security-scan"
GUARDIAN = PLUGIN_ROOT / "scripts" / "guardian"
FIXTURES = REPO_ROOT / "tests" / "fixtures"
sys.path.insert(0, str(PLUGIN_ROOT / "guardian_runtime" / "src"))

from guardian.upstream_context import (  # noqa: E402
    REPORT_ALREADY_TRACKED,
    REPORT_OPEN_ISSUE,
    REPORT_PRIVATE,
    REPORT_PUBLIC_PR,
    advisory_terms,
    decide_reporting_path,
    detect_repo_reporting_policy,
    _tracking_match_is_relevant,
)
from guardian.dependency_files import fingerprint_dependency_files  # noqa: E402
from guardian.inventory_native.engine import scan_package_records  # noqa: E402
from guardian.osv_matching import osv_explicit_versions_exclude_package  # noqa: E402
from guardian.repo_scout import _finding_is_high_signal  # noqa: E402
from guardian.reporting_common import advisory_details, package_evidence_context  # noqa: E402
from guardian.config import GuardianConfig  # noqa: E402
from guardian.advisories import refresh_findings  # noqa: E402
from guardian.db import Database  # noqa: E402
from guardian.http_client import GuardianHttp  # noqa: E402
from guardian.inventory import scan_roots  # noqa: E402
from guardian.sources.kev import KEVClient  # noqa: E402
from guardian.sources.osv import OSVClient  # noqa: E402
from guardian.signals import SignalGrade, grade_to_posture  # noqa: E402


def run_guardian(
    root: Path,
    state_dir: Path,
    extra_args: list[str] | None = None,
    *,
    compact: bool = True,
    mode: str = "daily",
) -> dict:
    """Run Guardian in compact mode with isolated state and return parsed JSON."""

    env = os.environ.copy()
    env["GUARDIAN_STATE_DIR"] = str(state_dir)
    env["GUARDIAN_SEED_CATALOG_DIR"] = str(PLUGIN_ROOT / "data" / "local_catalogs")
    command = [str(GUARDIAN), "scan", str(root), "--mode", mode]
    if compact:
        command.extend(["--output", "compact"])
    command.extend(extra_args or [])
    command.append("--json")
    completed = subprocess.run(
        command,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise AssertionError(
            "guardian fixture scan failed\n"
            f"root: {root}\nstdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
        )
    return json.loads(completed.stdout)


def run_guardian_command(state_dir: Path, args: list[str]) -> dict:
    """Run an arbitrary Guardian command with isolated state and parse JSON."""

    env = os.environ.copy()
    env["GUARDIAN_STATE_DIR"] = str(state_dir)
    env["GUARDIAN_SEED_CATALOG_DIR"] = str(PLUGIN_ROOT / "data" / "local_catalogs")
    completed = subprocess.run(
        [str(GUARDIAN), *args, "--json"],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise AssertionError(
            "guardian command failed\n"
            f"args: {args}\nstdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
        )
    return json.loads(completed.stdout)


def top_packages(payload: dict) -> list[dict]:
    """Return the compact operator package list regardless of payload shape."""

    return (payload.get("operator_view") or {}).get("top_packages") or payload.get("top_packages") or []


def assert_clean_fixture(tmp: Path) -> None:
    """Clean lockfile fixture should scan successfully without actionable findings."""

    payload = run_guardian(tmp / "clean-npm", tmp / "state-clean")
    packages = top_packages(payload)
    if packages:
        raise AssertionError(f"clean fixture unexpectedly produced top packages: {packages[:3]}")


def assert_local_catalog_fixture(tmp: Path) -> None:
    """Bundled malicious-package catalog should produce a critical exact-match finding."""

    payload = run_guardian(tmp / "malicious-local-catalog", tmp / "state-malicious")
    packages = top_packages(payload)
    matched = [
        item for item in packages
        if item.get("package_name") == "@beproduct/nestjs-auth" and item.get("highest_severity") == "critical"
    ]
    if not matched:
        raise AssertionError(f"malicious local catalog fixture did not produce expected critical match: {packages[:5]}")
    if "catalog-match" not in (matched[0].get("signal_grades") or []):
        raise AssertionError(f"local catalog finding did not retain its evidence grade: {matched[0]}")


def assert_vendored_fixture(tmp: Path) -> None:
    """Nested yarn.lock hits should stay visible but low-confidence and vendored."""

    payload = run_guardian(tmp / "vendored-yarn-metadata", tmp / "state-vendored", ["--include-installed"])
    packages = top_packages(payload)
    matched = [
        item for item in packages
        if item.get("package_name") == "@beproduct/nestjs-auth"
        and item.get("environment_label") == "vendored-lockfile"
    ]
    if not matched:
        raise AssertionError(f"vendored yarn fixture did not produce vendored local-catalog evidence: {packages[:5]}")


def assert_uv_lock_fixture(tmp: Path) -> None:
    """uv.lock packages should be inventoried and matched against PyPI catalogs."""

    payload = run_guardian(tmp / "uv-lock-pypi", tmp / "state-uv-lock")
    packages = top_packages(payload)
    matched = [
        item for item in packages
        if item.get("package_name") == "cryptowallet-safety"
        and item.get("highest_severity") == "critical"
    ]
    if not matched:
        raise AssertionError(f"uv.lock fixture did not produce expected PyPI exact-match finding: {packages[:5]}")


def assert_requirements_fixture(tmp: Path) -> None:
    """requirements*.txt files should be inventoried without treating ranges as exact versions."""

    root = tmp / "requirements-pypi"
    records, metrics = scan_package_records(root, ecosystems=["pypi"], include_installed=False)
    package_versions = {
        (item["normalized_name"], item["version"], item["install_scope"])
        for item in records
        if item.get("source_type") == "requirements-manifest"
    }
    expected = {
        ("critical-package", "1.2.3", "prod"),
        ("extras-package", "2.0.1", "prod"),
        ("pytest", "8.4.0", "dev"),
    }
    if package_versions != expected:
        raise AssertionError(f"requirements exact-pin inventory mismatch: {package_versions}")
    if metrics["candidate_counts_by_name"].get("requirements.txt") != 2:
        raise AssertionError(f"requirements files were not both discovered: {metrics}")
    fingerprints = fingerprint_dependency_files(root)
    requirement_files = {
        item["file_path"]: item["file_kind"]
        for item in fingerprints
        if item["file_path"].endswith("requirements.txt")
    }
    if requirement_files != {
        "requirements.txt": "python-requirements",
        "tests-unit/requirements.txt": "python-requirements",
    }:
        raise AssertionError(f"requirements fingerprints missing or misclassified: {requirement_files}")


def assert_install_script_drift(tmp: Path) -> None:
    """A newly added install script should alert once, then remain quiet."""

    root = tmp / "install-script-drift"
    state = tmp / "state-install-script"
    baseline = run_guardian(root, state)
    if baseline.get("behavioral_signals"):
        raise AssertionError(f"script-free baseline emitted behavioral signals: {baseline['behavioral_signals']}")

    lockfile = root / "package-lock.json"
    payload = json.loads(lockfile.read_text())
    dependency = payload["packages"].pop("node_modules/fixture-package")
    dependency["version"] = "1.1.0"
    dependency["hasInstallScript"] = True
    payload["packages"]["node_modules/fixture-package"] = dependency
    payload["packages"][""]["dependencies"]["fixture-package"] = "1.1.0"
    lockfile.write_text(json.dumps(payload, indent=2) + "\n")

    changed = run_guardian(root, state, ["--handoff"], compact=False, mode="standard")
    signals = changed.get("behavioral_signals") or []
    expected = [item for item in signals if item.get("signal_type") == "install-script-added"]
    if len(expected) != 1 or expected[0].get("posture") != "fix_this_week":
        raise AssertionError(f"install-script addition was not prioritized correctly: {signals}")
    operator = changed.get("operator_view") or {}
    if "behavioral: 1 fix this week" not in (operator.get("priority_headline") or ""):
        raise AssertionError(f"operator headline did not surface behavioral priority: {operator}")
    handoff_path = changed.get("handoff_path")
    handoff = Path(handoff_path).read_text() if handoff_path else ""
    if "## Behavioral Signals" not in handoff or "install-script-added" not in handoff:
        raise AssertionError(f"handoff did not render install-script evidence: {handoff_path}")

    repeated = run_guardian(root, state)
    if repeated.get("behavioral_signals"):
        raise AssertionError(f"unchanged repeat scan re-alerted: {repeated['behavioral_signals']}")


def assert_unknown_lockfile_script_state(tmp: Path) -> None:
    """pnpm lockfile evidence must remain unknown rather than guessed safe."""

    records, _metrics = scan_package_records(
        tmp / "install-script-unknown",
        ecosystems=["npm"],
        include_installed=False,
    )
    if len(records) != 1:
        raise AssertionError(f"pnpm unknown-state fixture produced unexpected records: {records}")
    metadata = records[0].get("raw_metadata") or {}
    if metadata.get("has_install_script", "missing") is not None:
        raise AssertionError(f"pnpm install-script state should be unknown: {metadata}")


def assert_signal_grades() -> None:
    """The shared grading contract must preserve operator posture mappings."""

    expected = {
        SignalGrade.CORROBORATED_MALICIOUS: "act_now",
        SignalGrade.CATALOG_MATCH: "act_now",
        SignalGrade.BEHAVIORAL_HIGH: "fix_this_week",
        SignalGrade.BEHAVIORAL_WATCH: "watch",
        SignalGrade.ADVISORY: None,
        SignalGrade.INFO: None,
    }
    actual = {grade: grade_to_posture(grade) for grade in SignalGrade}
    if actual != expected:
        raise AssertionError(f"signal-grade posture mapping drifted: {actual}")


def assert_http_client_hardening(tmp: Path) -> None:
    """Shared HTTP behavior must cache, revalidate, retry, and bound timeouts."""

    class Handler(BaseHTTPRequestHandler):
        counts = {"cached": 0, "retry": 0, "rate": 0, "timeout": 0, "osv": 0}

        def do_GET(self):  # noqa: N802 - stdlib handler API
            key = self.path.strip("/")
            type(self).counts[key] = type(self).counts.get(key, 0) + 1
            if key == "cached" and self.headers.get("If-None-Match") == '"fixture-v1"':
                self.send_response(304)
                self.end_headers()
                return
            if key == "retry" and type(self).counts[key] == 1:
                self.send_response(500)
                self.end_headers()
                return
            if key == "rate" and type(self).counts[key] == 1:
                self.send_response(429)
                self.send_header("Retry-After", "0")
                self.end_headers()
                return
            if key == "timeout":
                time.sleep(0.15)
            body = json.dumps({"vulnerabilities": [], "path": key}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("ETag", '"fixture-v1"')
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except BrokenPipeError:
                pass

        def log_message(self, _format, *_args):
            return

        def do_POST(self):  # noqa: N802 - stdlib handler API
            key = self.path.strip("/")
            type(self).counts[key] = type(self).counts.get(key, 0) + 1
            content_length = int(self.headers.get("Content-Length", "0"))
            self.rfile.read(content_length)
            if key == "osv" and type(self).counts[key] == 1:
                self.send_response(500)
                self.end_headers()
                return
            if key == "osv-fail":
                self.send_response(503)
                self.end_headers()
                return
            body = json.dumps({"results": [{}]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        cache_dir = tmp / "http-cache"
        config = GuardianConfig(
            threat_intel_cache_dir=str(cache_dir),
            api_request_min_interval_seconds=0,
            http_max_retries=2,
            http_cache_ttl_seconds=3600,
            request_timeout_seconds=1,
            kev_catalog_url=f"{base}/cached",
        )
        first_kev = KEVClient(config)
        first_kev.query_by_cve_id("CVE-2099-0001")
        first_bytes = first_kev.http.stats()["bytes_downloaded"]
        second_kev = KEVClient(config)
        second_kev.query_by_cve_id("CVE-2099-0001")
        second_stats = second_kev.http.stats()
        if first_bytes <= 0 or second_stats["bytes_downloaded"] != 0 or not second_stats["from_cache"]:
            raise AssertionError(f"KEV cache did not eliminate the second download: {first_bytes}, {second_stats}")
        if Handler.counts["cached"] != 1:
            raise AssertionError(f"fresh KEV cache unexpectedly hit the network: {Handler.counts}")

        revalidate_config = GuardianConfig(
            threat_intel_cache_dir=str(cache_dir),
            api_request_min_interval_seconds=0,
            http_max_retries=1,
            http_cache_ttl_seconds=0,
            request_timeout_seconds=1,
        )
        revalidated = GuardianHttp(revalidate_config).get(f"{base}/cached")
        if not revalidated.from_cache or not revalidated.revalidated or revalidated.bytes_downloaded != 0:
            raise AssertionError(f"conditional 304 did not serve cached bytes: {revalidated}")

        client = GuardianHttp(config)
        if client.get(f"{base}/retry", cache=False).error or Handler.counts["retry"] != 2:
            raise AssertionError(f"500 retry did not recover: {Handler.counts}")
        if client.get(f"{base}/rate", cache=False).error or Handler.counts["rate"] != 2:
            raise AssertionError(f"429 Retry-After did not recover: {Handler.counts}")

        osv_config = GuardianConfig(
            threat_intel_cache_dir=str(cache_dir),
            osv_api_url=f"{base}/osv",
            api_request_min_interval_seconds=0,
            http_max_retries=1,
            request_timeout_seconds=1,
        )
        osv_result = OSVClient(osv_config).query_batch(
            [{"ecosystem": "npm", "package_name": "fixture-package", "version": "1.0.0"}]
        )
        if osv_result != [{}] or Handler.counts["osv"] != 2:
            raise AssertionError(f"OSV batch POST did not recover from a transient 500: {osv_result}, {Handler.counts}")

        timeout_config = GuardianConfig(
            threat_intel_cache_dir=str(cache_dir),
            api_request_min_interval_seconds=0,
            http_max_retries=1,
            http_cache_ttl_seconds=0,
            request_timeout_seconds=0.03,
        )
        timed_out = GuardianHttp(timeout_config).get(f"{base}/timeout", cache=False)
        if not timed_out.error or timed_out.attempts != 2:
            raise AssertionError(f"timeout was not bounded and retried: {timed_out}")

        offline_state = tmp / "offline-source-state"
        offline_config = GuardianConfig(
            db_path=str(offline_state / "guardian.db"),
            scans_dir=str(offline_state / "scans"),
            reports_dir=str(offline_state / "reports"),
            exports_dir=str(offline_state / "exports"),
            threat_intel_cache_dir=str(offline_state / "cache"),
            local_catalog_dirs=[str(PLUGIN_ROOT / "data" / "local_catalogs")],
            osv_api_url=f"{base}/osv-fail",
            osv_vuln_api_url=f"{base}/osv-fail",
            api_request_min_interval_seconds=0,
            http_max_retries=0,
            request_timeout_seconds=0.03,
        )
        database = Database(offline_config.db_path)
        database.initialize()
        try:
            scan_roots(offline_config, database, [str(tmp / "clean-npm")])
            refresh = refresh_findings(
                offline_config,
                database,
                root_paths=[str(tmp / "clean-npm")],
                enrich_live=False,
            )
        finally:
            database.close()
        if "osv" not in refresh.get("source_errors", {}):
            raise AssertionError(f"offline OSV failure was not represented in source status: {refresh}")
    finally:
        server.shutdown()
        server.server_close()


def assert_snapshot_resolution(tmp: Path) -> None:
    """A second scan of the same root after removing the bad package should mark it resolved."""

    root = tmp / "snapshot-resolution"
    shutil.copytree(tmp / "malicious-local-catalog", root)
    state = tmp / "state-resolution"
    first = run_guardian(root, state, compact=False, mode="standard")
    if not top_packages(first):
        raise AssertionError("snapshot setup did not produce an initial finding")

    package_json = root / "package.json"
    package_lock = root / "package-lock.json"
    package_json.write_text(package_json.read_text().replace('"@beproduct/nestjs-auth": "0.1.18"', '"left-pad": "1.3.0"'))
    package_lock.write_text(
        package_lock.read_text()
        .replace('"@beproduct/nestjs-auth": "0.1.18"', '"left-pad": "1.3.0"')
        .replace('"node_modules/@beproduct/nestjs-auth"', '"node_modules/left-pad"')
        .replace('"name": "@beproduct/nestjs-auth",', '')
        .replace('"version": "0.1.18"', '"version": "1.3.0"')
        .replace('@beproduct/nestjs-auth/-/nestjs-auth-0.1.18.tgz', 'left-pad/-/left-pad-1.3.0.tgz')
    )
    second = run_guardian(root, state, compact=False, mode="standard")
    comparison = second.get("comparison") or second.get("compare") or {}
    if not comparison.get("resolved"):
        raise AssertionError(f"snapshot resolution did not mark finding resolved: {comparison}")


def assert_daily_watch_fingerprints(tmp: Path) -> None:
    """daily-watch should inventory changed roots and skip unchanged ones."""

    root = tmp / "daily-watch-clean"
    shutil.copytree(tmp / "clean-npm", root)
    state = tmp / "state-daily-watch"

    first = run_guardian_command(state, ["daily-watch", "--root", str(root)])
    if first["roots_inventory_count"] != 1 or first["roots_skipped_count"] != 0:
        raise AssertionError(f"first daily-watch should inventory baseline root: {first['roots']}")
    first_root = first["roots"][0]
    if first_root["reason"] != "dependency-files-changed":
        raise AssertionError(f"first daily-watch reason should be dependency-files-changed: {first_root}")

    second = run_guardian_command(state, ["daily-watch", "--root", str(root)])
    if second["roots_inventory_count"] != 0 or second["roots_skipped_count"] != 1:
        raise AssertionError(f"second daily-watch should skip unchanged root: {second['roots']}")
    second_root = second["roots"][0]
    if second_root["reason"] != "dependency-files-unchanged":
        raise AssertionError(f"second daily-watch reason should be dependency-files-unchanged: {second_root}")
    if second_root.get("behavioral_signals"):
        raise AssertionError(f"unchanged daily-watch root should not recompute behavioral alerts: {second_root}")

    package_json = root / "package.json"
    package_json.write_text(package_json.read_text() + "\n")
    third = run_guardian_command(state, ["daily-watch", "--root", str(root)])
    if third["roots_inventory_count"] != 1 or third["roots_skipped_count"] != 0:
        raise AssertionError(f"third daily-watch should inventory changed root: {third['roots']}")
    third_state = third["roots"][0]["file_state"]
    if "package.json" not in third_state["changed"]:
        raise AssertionError(f"third daily-watch should report package.json changed: {third_state}")


def assert_upstream_reporting_policy_helpers(tmp: Path) -> None:
    """Reporting-path helpers should classify repo policy and duplicate state deterministically."""

    private_repo = tmp / "policy-private"
    private_repo.mkdir()
    (private_repo / "SECURITY.md").write_text("Report privately via GitHub Security Advisories. Do not open public issues.")
    private_policy = detect_repo_reporting_policy(private_repo)
    if private_policy["default_decision"] != REPORT_PRIVATE:
        raise AssertionError(f"private security policy not detected: {private_policy}")

    issue_repo = tmp / "policy-issue-first"
    issue_repo.mkdir()
    (issue_repo / "CONTRIBUTING.md").write_text("Please open an issue first before submitting a pull request.")
    issue_policy = detect_repo_reporting_policy(issue_repo)
    if issue_policy["default_decision"] != REPORT_OPEN_ISSUE:
        raise AssertionError(f"issue-first policy not detected: {issue_policy}")

    public_repo = tmp / "policy-public"
    public_repo.mkdir()
    public_policy = detect_repo_reporting_policy(public_repo)
    if public_policy["default_decision"] != REPORT_PUBLIC_PR:
        raise AssertionError(f"public PR fallback not selected: {public_policy}")

    terms = advisory_terms({"advisory_links": ["https://github.com/advisories/GHSA-abcd-1234-wxyz", "CVE-2026-12345"]})
    if terms != ["CVE-2026-12345", "GHSA-abcd-1234-wxyz"]:
        raise AssertionError(f"advisory terms not normalized: {terms}")

    decision = decide_reporting_path(public_policy, {"status": "already-tracked"})
    if decision["decision"] != REPORT_ALREADY_TRACKED:
        raise AssertionError(f"already-tracked finding should suppress new reports: {decision}")

    unrelated = {"title": "WeChat media downloads broken with cryptography >= 48.0.0"}
    if _tracking_match_is_relevant(unrelated, "cryptography", "cryptography"):
        raise AssertionError("generic package bug should not count as upstream security tracking")
    relevant = {"title": "fix(deps): bump cryptography for GHSA-537c-gmf6-5ccf"}
    if not _tracking_match_is_relevant(relevant, "cryptography", "cryptography"):
        raise AssertionError("dependency security title should count as upstream tracking")


def assert_osv_explicit_version_guard() -> None:
    """OSV explicit affected-version lists should override stale open ranges."""

    vuln = {
        "affected": [
            {
                "package": {"name": "couchbase", "ecosystem": "PyPI"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
                "versions": ["4.3.5", "4.4.1", "4.5.0"],
            }
        ]
    }
    package = {"package_name": "couchbase", "ecosystem": "pypi", "version": "4.6.1"}
    if not osv_explicit_versions_exclude_package(vuln, package):
        raise AssertionError("explicit OSV affected versions should exclude newer unlisted package version")
    affected_package = {**package, "version": "4.5.0"}
    if osv_explicit_versions_exclude_package(vuln, affected_package):
        raise AssertionError("explicit OSV affected versions should not exclude listed package version")


def assert_repo_scout_high_signal_filter() -> None:
    """Repo Scout should not promote low-priority CVE noise to PR candidates."""

    low_priority = {
        "package_name": "torch",
        "highest_severity": "low",
        "risk_label": "Low Priority",
        "summary": "Potential exploit condition with low practical priority",
    }
    if _finding_is_high_signal(low_priority):
        raise AssertionError("low-priority findings should not be high-signal PR candidates")
    exploited = {
        **low_priority,
        "classification_labels": ["Known Exploited"],
    }
    if not _finding_is_high_signal(exploited):
        raise AssertionError("known-exploited findings should remain high signal")


def assert_reporting_advisory_and_evidence_helpers() -> None:
    """Reporting helpers should structure link-only advisories and evidence caveats."""

    package = {
        "package_name": "next",
        "version": "16.2.4",
        "highest_severity": "high",
        "environment_label": "runtime",
        "direct_dependency": True,
        "manifest_scope": "runtime",
        "manifest_paths": ["frontend/package.json"],
        "advisory_sources": [],
        "advisory_links": [
            "https://github.com/advisories/GHSA-8h8q-6873-q5fj",
            "https://api.first.org/data/v1/epss?cve=CVE-2026-41305",
        ],
        "occurrences": [
            {"source_type": "npm-manifest"},
            {"source_type": "npm-lockfile"},
        ],
    }
    details = advisory_details(package)
    detail_ids = [item.get("id") for item in details]
    if "GHSA-8h8q-6873-q5fj" not in detail_ids or "CVE-2026-41305" not in detail_ids:
        raise AssertionError(f"link-only advisory details were not normalized: {details}")
    context = package_evidence_context(package)
    if context["label"] != "Manifest + lockfile; installed tree not present":
        raise AssertionError(f"runtime evidence caveat was not preserved: {context}")
    if context["installed_tree_present"]:
        raise AssertionError(f"installed tree should not be marked present for lockfile-only evidence: {context}")


def main() -> int:
    """Copy fixtures to temp space and run the deterministic release assertions."""

    with tempfile.TemporaryDirectory(prefix="guardian-fixtures-") as raw_tmp:
        tmp = Path(raw_tmp)
        for fixture in (
            "clean-npm",
            "malicious-local-catalog",
            "vendored-yarn-metadata",
            "uv-lock-pypi",
            "requirements-pypi",
            "install-script-drift",
            "install-script-unknown",
        ):
            shutil.copytree(FIXTURES / fixture, tmp / fixture)
        assert_clean_fixture(tmp)
        assert_local_catalog_fixture(tmp)
        assert_vendored_fixture(tmp)
        assert_uv_lock_fixture(tmp)
        assert_requirements_fixture(tmp)
        assert_install_script_drift(tmp)
        assert_unknown_lockfile_script_state(tmp)
        assert_signal_grades()
        assert_http_client_hardening(tmp)
        assert_snapshot_resolution(tmp)
        assert_daily_watch_fingerprints(tmp)
        assert_upstream_reporting_policy_helpers(tmp)
        assert_osv_explicit_version_guard()
        assert_repo_scout_high_signal_filter()
        assert_reporting_advisory_and_evidence_helpers()
    print("fixture tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
