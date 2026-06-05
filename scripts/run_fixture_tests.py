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
    print("fixture tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
