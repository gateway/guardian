#!/usr/bin/env python3
"""Deterministic Milestone 5 tests for package diet and outreach safety."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
PLUGIN_ROOT = REPO_ROOT / "plugins" / "guardian-security-scan"
FIXTURES = REPO_ROOT / "tests" / "fixtures"
sys.path.insert(0, str(PLUGIN_ROOT / "guardian_runtime" / "src"))

from guardian.config import GuardianConfig  # noqa: E402
from guardian.db import Database  # noqa: E402
from guardian.outreach import preflight_outreach, record_outreach_result  # noqa: E402
from guardian.package_diet import package_diet_scan  # noqa: E402
from guardian.package_diet_rules import _is_permissive_license  # noqa: E402
from guardian.watchlist import add_vendored_package_watch  # noqa: E402


def config_for(tmp: Path, *, max_outreach: int = 5) -> GuardianConfig:
    return GuardianConfig(
        development_roots=[str(tmp)],
        local_catalog_dirs=[str(tmp / "catalogs")],
        db_path=str(tmp / "guardian.db"),
        exports_dir=str(tmp / "exports"),
        reports_dir=str(tmp / "reports"),
        scans_dir=str(tmp / "scans"),
        threat_intel_sources_path=str(tmp / "sources.json"),
        threat_intel_cache_dir=str(tmp / "cache"),
        vendored_watchlist_path=str(tmp / "vendored.json"),
        max_outreach_per_day=max_outreach,
    )


def registry_metadata(name: str, size: int, *, old: bool = False) -> dict:
    published = datetime.now(timezone.utc) - (timedelta(days=1000) if old else timedelta(days=10))
    return {
        "ecosystem": "npm",
        "package_name": name,
        "normalized_name": name,
        "version": "1.0.0",
        "published_at": published.isoformat(),
        "maintainers_hash": "fixture",
        "maintainer_count": 1 if old else 2,
        "provenance_present": False,
        "deprecated": False,
        "yanked": False,
        "repo_url": f"https://github.com/example/{name}",
        "size_bytes": size,
        "has_install_script": False,
        "license": "MIT" if name != "gpl-helper" else "GPL-3.0-only",
        "fetched_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "source": "fixture",
    }


def assert_package_diet(tmp: Path) -> None:
    state = tmp / "diet-state"
    state.mkdir()
    config = config_for(state)
    db = Database(config.db_path)
    db.initialize()
    db.upsert_registry_metadata(registry_metadata("heavy-helper", 4 * 1024 * 1024))
    db.upsert_registry_metadata(registry_metadata("tiny-helper", 10 * 1024))
    db.upsert_registry_metadata(registry_metadata("gpl-helper", 20 * 1024, old=True))
    payload = package_diet_scan(
        str(tmp / "package-diet-vendor"),
        limit=20,
        usage_limit=20,
        config=config,
        db=db,
    )
    by_name = {item["name"]: item for item in payload["packages"]}
    for name in ("heavy-helper", "tiny-helper"):
        if by_name[name]["classification"] != "Vendor Candidate":
            raise AssertionError(f"permissive micro-package was not a Vendor Candidate: {by_name[name]}")
        if not (by_name[name].get("vendor_plan") or {}).get("requires_attribution"):
            raise AssertionError(f"vendor plan omitted attribution: {by_name[name]}")
    if by_name["gpl-helper"]["classification"] != "Review":
        raise AssertionError(f"GPL package must stay Review: {by_name['gpl-helper']}")
    if not by_name["gpl-helper"]["maintenance"]["maintenance_dead"]:
        raise AssertionError(f"maintenance-death evidence missing: {by_name['gpl-helper']}")
    if _is_permissive_license("LIMITED-CUSTOM") or _is_permissive_license("MIT AND GPL-3.0"):
        raise AssertionError("license parser accepted a substring or copyleft-combined license")
    if by_name["heavy-helper"]["bloat_score"] <= by_name["tiny-helper"]["bloat_score"]:
        raise AssertionError("4 MB package did not rank above 10 KB package at equal usage")
    if by_name["heavy-helper"]["footprint"]["transitive_count"] != 1:
        raise AssertionError(f"npm transitive graph count missing: {by_name['heavy-helper']}")
    if payload["footprint_coverage"]["registry_metadata_packages"] != 3:
        raise AssertionError(f"cached registry coverage missing: {payload['footprint_coverage']}")

    offline = tmp / "diet-usage-only"
    offline.mkdir()
    (offline / "package.json").write_text('{"dependencies":{"unknown-helper":"1.0.0"}}\n')
    (offline / "index.js").write_text('import value from "unknown-helper";\n')
    offline_payload = package_diet_scan(str(offline), limit=10, usage_limit=10)
    if offline_payload["footprint_coverage"]["status"] != "usage-only":
        raise AssertionError(f"offline diet did not degrade to usage-only: {offline_payload}")
    if "unavailable" not in offline_payload["footprint_coverage"]["note"].lower():
        raise AssertionError(f"offline coverage note missing: {offline_payload['footprint_coverage']}")

    watched = add_vendored_package_watch(
        config,
        ecosystem="npm",
        name="heavy-helper",
        version="1.0.0",
        project_root=str(tmp / "package-diet-vendor"),
        license_name="MIT",
        source_url="https://github.com/example/heavy-helper",
    )
    watch_payload = json.loads(Path(watched["path"]).read_text())
    if len(watch_payload["packages"]) != 1 or watch_payload["packages"][0]["name"] != "heavy-helper":
        raise AssertionError(f"vendored upstream watch was not persisted: {watch_payload}")
    db.close()


def fake_tracking_gh(args: list[str]) -> tuple[int, str, str]:
    if args[1:3] == ["repo", "view"]:
        return 0, json.dumps({
            "isArchived": False,
            "defaultBranchRef": {"name": "main"},
            "url": "https://github.com/example/repo",
        }), ""
    if args[1:3] == ["pr", "list"] and "GHSA-TEST-1234" in args:
        return 0, json.dumps([{
            "number": 42,
            "title": "fix(deps): patch helper for GHSA-TEST-1234",
            "state": "OPEN",
            "url": "https://github.com/example/repo/pull/42",
            "updatedAt": "2026-07-11T00:00:00Z",
        }]), ""
    return 0, "[]", ""


def fake_clean_gh(args: list[str]) -> tuple[int, str, str]:
    if args[1:3] == ["repo", "view"]:
        return 0, json.dumps({
            "isArchived": False,
            "defaultBranchRef": {"name": "main"},
            "url": "https://github.com/example/repo",
        }), ""
    return 0, "[]", ""


def fake_archived_gh(args: list[str]) -> tuple[int, str, str]:
    if args[1:3] == ["repo", "view"]:
        return 0, json.dumps({
            "isArchived": True,
            "defaultBranchRef": {"name": "main"},
            "url": "https://github.com/example/archived",
        }), ""
    return 0, "[]", ""


def fake_failed_gh(_args: list[str]) -> tuple[int, str, str]:
    return 1, "", "fixture GitHub failure"


def assert_outreach_safety(tmp: Path) -> None:
    repo_dir = tmp / "outreach-repo"
    repo_dir.mkdir()
    config = config_for(tmp / "outreach-state")
    db = Database(config.db_path)
    db.initialize()
    first = preflight_outreach(
        config,
        db,
        repo="example/repo",
        repo_dir=repo_dir,
        advisory_id="GHSA-TEST-1234",
        package="helper",
        version="1.0.0",
        gh_runner=fake_tracking_gh,
    )
    if first["decision"] != "In-flight, no action" or first["status"] != "suppressed-in-flight":
        raise AssertionError(f"existing fix PR did not suppress outreach: {first}")
    if not db.outreach_entry("example/repo", "GHSA-TEST-1234", "helper"):
        raise AssertionError("suppressed outreach did not write a ledger row")
    second = preflight_outreach(
        config,
        db,
        repo="example/repo",
        repo_dir=repo_dir,
        advisory_id="GHSA-TEST-1234",
        package="helper",
        version="1.0.0",
        gh_runner=fake_tracking_gh,
    )
    if second["status"] != "blocked-ledger":
        raise AssertionError(f"ledger did not block duplicate proposal: {second}")
    archived = preflight_outreach(
        config,
        db,
        repo="example/archived",
        repo_dir=repo_dir,
        advisory_id="GHSA-ARCHIVED-1",
        package="helper",
        version="1.0.0",
        gh_runner=fake_archived_gh,
    )
    if archived["status"] != "suppressed-archived":
        raise AssertionError(f"archived repository was not suppressed: {archived}")
    unavailable = preflight_outreach(
        config,
        db,
        repo="example/unavailable",
        repo_dir=repo_dir,
        advisory_id="GHSA-UNAVAILABLE-1",
        package="helper",
        version="1.0.0",
        gh_runner=fake_failed_gh,
    )
    if unavailable["status"] != "checks-unavailable":
        raise AssertionError(f"failed GitHub check did not require manual verification: {unavailable}")
    db.close()

    eligible_repo = tmp / "eligible-repo"
    eligible_repo.mkdir()
    (eligible_repo / "package-lock.json").write_text(
        '{"packages":{"node_modules/helper":{"version":"1.0.0"}}}\n'
    )
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=eligible_repo, check=True)
    subprocess.run(["git", "add", "package-lock.json"], cwd=eligible_repo, check=True)
    subprocess.run(
        ["git", "-c", "user.name=Guardian", "-c", "user.email=guardian@example.test", "commit", "-qm", "fixture"],
        cwd=eligible_repo,
        check=True,
    )
    subprocess.run(
        ["git", "update-ref", "refs/remotes/origin/main", "HEAD"],
        cwd=eligible_repo,
        check=True,
    )
    eligible_state = tmp / "eligible-state"
    eligible_config = config_for(eligible_state)
    eligible_db = Database(eligible_config.db_path)
    eligible_db.initialize()
    eligible = preflight_outreach(
        eligible_config,
        eligible_db,
        repo="example/eligible",
        repo_dir=eligible_repo,
        advisory_id="GHSA-ELIGIBLE-1",
        package="helper",
        version="1.0.0",
        gh_runner=fake_clean_gh,
    )
    if eligible["status"] != "eligible-awaiting-confirmation":
        raise AssertionError(f"clean checked preflight should await human confirmation: {eligible}")
    recorded = record_outreach_result(
        eligible_db,
        repo="example/eligible",
        advisory_id="GHSA-ELIGIBLE-1",
        package="helper",
        action="public-pr",
        url="https://github.com/example/eligible/pull/1",
    )
    if recorded["action"] != "public-pr" or not recorded["url"]:
        raise AssertionError(f"confirmed outreach result did not update ledger: {recorded}")
    eligible_db.close()

    fixed_repo = tmp / "fixed-repo"
    fixed_repo.mkdir()
    fixed_lock = fixed_repo / "package-lock.json"
    fixed_lock.write_text('{"packages":{"node_modules/helper":{"version":"2.0.0"}}}\n')
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=fixed_repo, check=True)
    subprocess.run(["git", "add", "package-lock.json"], cwd=fixed_repo, check=True)
    subprocess.run(
        ["git", "-c", "user.name=Guardian", "-c", "user.email=guardian@example.test", "commit", "-qm", "fixture"],
        cwd=fixed_repo,
        check=True,
    )
    subprocess.run(
        ["git", "update-ref", "refs/remotes/origin/main", "HEAD"],
        cwd=fixed_repo,
        check=True,
    )
    fixed_lock.write_text('{"packages":{"node_modules/helper":{"version":"1.0.0"}}}\n')
    fixed_state = tmp / "fixed-state"
    fixed_config = config_for(fixed_state)
    fixed_db = Database(fixed_config.db_path)
    fixed_db.initialize()
    fixed = preflight_outreach(
        fixed_config,
        fixed_db,
        repo="example/fixed",
        repo_dir=fixed_repo,
        advisory_id="GHSA-FIXED-1",
        package="helper",
        version="1.0.0",
        gh_runner=fake_clean_gh,
    )
    if fixed["status"] != "suppressed-default-fixed":
        raise AssertionError(f"default-branch fix was not detected: {fixed}")
    fixed_db.close()

    cap_state = tmp / "cap-state"
    cap_config = config_for(cap_state, max_outreach=1)
    cap_db = Database(cap_config.db_path)
    cap_db.initialize()
    cap_db.record_outreach(
        repo="example/one",
        advisory_id="GHSA-CAP-0001",
        package="one",
        action="eligible-awaiting-confirmation",
        url=None,
        details={"fixture": True},
    )
    capped = preflight_outreach(
        cap_config,
        cap_db,
        repo="example/two",
        repo_dir=repo_dir,
        advisory_id="GHSA-CAP-0002",
        package="two",
        gh_runner=fake_clean_gh,
    )
    if capped["status"] != "suppressed-daily-cap":
        raise AssertionError(f"daily cap did not suppress second proposal: {capped}")
    cap_db.close()


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="guardian-m5-") as raw_tmp:
        tmp = Path(raw_tmp)
        shutil.copytree(FIXTURES / "package-diet-vendor", tmp / "package-diet-vendor")
        assert_package_diet(tmp)
        assert_outreach_safety(tmp)
    print("milestone 5 tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
