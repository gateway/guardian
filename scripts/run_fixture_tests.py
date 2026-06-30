#!/usr/bin/env python3
"""Run small end-to-end Guardian scans against safe release fixtures."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
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


def main() -> int:
    """Copy fixtures to temp space and run the deterministic release assertions."""

    with tempfile.TemporaryDirectory(prefix="guardian-fixtures-") as raw_tmp:
        tmp = Path(raw_tmp)
        for fixture in ("clean-npm", "malicious-local-catalog", "vendored-yarn-metadata", "uv-lock-pypi"):
            shutil.copytree(FIXTURES / fixture, tmp / fixture)
        assert_clean_fixture(tmp)
        assert_local_catalog_fixture(tmp)
        assert_vendored_fixture(tmp)
        assert_uv_lock_fixture(tmp)
        assert_snapshot_resolution(tmp)
        assert_daily_watch_fingerprints(tmp)
        assert_upstream_reporting_policy_helpers(tmp)
    print("fixture tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
