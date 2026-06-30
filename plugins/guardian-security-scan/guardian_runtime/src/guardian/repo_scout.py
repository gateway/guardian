"""Ephemeral GitHub repository scouting for community security review.

Repo Scout is intentionally separate from normal project scans. It clones
third-party repositories into a temporary workspace, scans them with temporary
Guardian state, summarizes high-signal findings, and then removes the clone and
state by default.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from .config import GuardianConfig, SEED_CATALOG_DIR, seed_local_catalogs
from .db import Database
from .dependency_files import fingerprint_dependency_files
from .ops import run_project_scan
from .scan_modes import apply_scan_mode
from .upstream_context import enrich_findings_with_upstream_context
from .util import utc_now


GITHUB_OWNER_REPO = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


def _mkdirs_for_config(config: GuardianConfig) -> None:
    """Create the isolated state tree without touching the user's default DB."""

    for path in [
        Path(config.db_path).parent,
        Path(config.exports_dir),
        Path(config.reports_dir),
        Path(config.scans_dir),
        Path(config.threat_intel_cache_dir),
        *[Path(item) for item in config.local_catalog_dirs],
    ]:
        path.mkdir(parents=True, exist_ok=True)
    if SEED_CATALOG_DIR.exists():
        seed_local_catalogs(config)


def _isolated_config(state_dir: Path, root: Path) -> GuardianConfig:
    """Build a Guardian config whose database and reports live under state_dir."""

    return GuardianConfig(
        development_roots=[str(root)],
        local_catalog_dirs=[str(state_dir / "local_catalogs")],
        db_path=str(state_dir / "guardian.db"),
        exports_dir=str(state_dir / "exports"),
        reports_dir=str(state_dir / "reports"),
        scans_dir=str(state_dir / "scans"),
        threat_intel_sources_path=str(state_dir / "threat_intel_sources.json"),
        threat_intel_cache_dir=str(state_dir / "source_cache"),
    )


def _repo_url(spec: str) -> tuple[str, str]:
    """Normalize a GitHub repo spec into a display name and clone URL."""

    raw = spec.strip().removesuffix(".git")
    if GITHUB_OWNER_REPO.match(raw):
        return raw, f"https://github.com/{raw}.git"
    for prefix in ("https://github.com/", "http://github.com/", "github.com/"):
        if raw.startswith(prefix):
            owner_repo = raw.removeprefix(prefix).strip("/")
            if GITHUB_OWNER_REPO.match(owner_repo):
                return owner_repo, f"https://github.com/{owner_repo}.git"
    raise ValueError(f"repo must be owner/name or a github.com URL: {spec}")


def _run_git_clone(repo_url: str, destination: Path, timeout_seconds: int) -> dict:
    """Shallow clone a repository with blob filtering so large repos stay bounded."""

    started = time.monotonic()
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    command = [
        "git",
        "clone",
        "--depth",
        "1",
        "--filter=blob:none",
        repo_url,
        str(destination),
    ]
    try:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            env=env,
        )
    except subprocess.TimeoutExpired:
        return {
            "status": "timeout",
            "elapsed_seconds": round(time.monotonic() - started, 4),
            "error": f"clone exceeded {timeout_seconds}s",
        }
    return {
        "status": "ok" if result.returncode == 0 else "error",
        "elapsed_seconds": round(time.monotonic() - started, 4),
        "returncode": result.returncode,
        "stderr_tail": result.stderr[-1200:] if result.returncode else "",
    }


def _finding_is_high_signal(item: dict) -> bool:
    """Keep scout output focused on findings that could justify maintainer action."""

    encoded = " ".join(
        [
            str(item.get("severity") or item.get("max_severity") or ""),
            str(item.get("priority") or item.get("action_bucket") or item.get("action") or ""),
            str(item.get("confidence") or ""),
            str(item.get("labels") or item.get("risk_labels") or ""),
            str(item.get("summary") or item.get("title") or ""),
        ]
    ).lower()
    return any(
        marker in encoded
        for marker in [
            "critical",
            "high",
            "act now",
            "fix this week",
            "known exploited",
            "malicious",
            "kev",
            "exploit",
        ]
    )


def _root_self_packages(db: Database, root: Path) -> set[tuple[str, str]]:
    """Return package/version pairs that came only from root package identity."""

    result: set[tuple[str, str]] = set()
    for row in db.current_packages_for_root(str(root)):
        try:
            raw = json.loads(row["raw_json"] or "{}")
        except Exception:
            continue
        metadata = raw.get("raw_metadata") if isinstance(raw, dict) else {}
        if isinstance(metadata, dict) and metadata.get("package_self"):
            result.add((str(row["package_name"]), str(row["version"])))
    return result


def _is_root_self_finding(item: dict, root_self_packages: set[tuple[str, str]]) -> bool:
    """Detect findings against the repo's own package identity, not a dependency."""

    name = item.get("package_name") or item.get("package") or item.get("name")
    version = item.get("version")
    return (str(name), str(version)) in root_self_packages


def _summarize_scan_payload(
    payload: dict,
    high_signal_limit: int,
    *,
    root_self_packages: set[tuple[str, str]] | None = None,
) -> dict:
    """Extract a compact, PR-review-oriented summary from a Guardian scan payload."""

    operator_view = payload.get("operator_view") or {}
    top_packages = operator_view.get("top_packages") or []
    root_self_packages = root_self_packages or set()
    root_self_findings = [item for item in top_packages if _is_root_self_finding(item, root_self_packages)]
    high_signal = [
        item
        for item in top_packages
        if _finding_is_high_signal(item) and not _is_root_self_finding(item, root_self_packages)
    ]
    if high_signal:
        scout_headline = f"{len(high_signal)} high-signal dependency PR candidate(s)"
    elif root_self_findings:
        scout_headline = (
            "No high-signal dependency PR candidates; "
            f"suppressed {len(root_self_findings)} root package self-version finding(s)"
        )
    else:
        scout_headline = "No high-signal dependency PR candidates"
    return {
        "status": payload.get("status"),
        "budget_error": payload.get("budget_error"),
        "elapsed_seconds": payload.get("elapsed_seconds"),
        "scout_headline": scout_headline,
        "priority_headline": operator_view.get("priority_headline"),
        "full_headline": operator_view.get("full_headline"),
        "compare_headline": operator_view.get("compare_headline"),
        "evidence_summary": operator_view.get("evidence_summary"),
        "top_package_count": len(top_packages),
        "high_signal_count": len(high_signal),
        "high_signal_top_packages": high_signal[:high_signal_limit],
        "suppressed_root_self_count": len(root_self_findings),
        "bottom_line": operator_view.get("bottom_line") or [],
        "source_status": payload.get("source_status"),
        "refresh": payload.get("refresh"),
        "scan_scope": payload.get("scan_scope"),
        "scan_policy": payload.get("scan_policy"),
    }


def _preflight_dependency_surface(config: GuardianConfig, root: Path, *, include_installed: bool) -> dict:
    """Count dependency files before a scan so repo-scout can choose a safe budget."""

    dependency_files = fingerprint_dependency_files(root, include_installed=include_installed)
    large_repo_mode = len(dependency_files) >= config.large_repo_dependency_file_threshold
    return {
        "dependency_file_count": len(dependency_files),
        "large_repo_mode": large_repo_mode,
        "large_repo_reason": (
            f"dependency files {len(dependency_files)} >= threshold {config.large_repo_dependency_file_threshold}"
            if large_repo_mode
            else None
        ),
    }


def run_repo_scout(
    *,
    repos: list[str],
    scan_mode: str = "standard",
    include_ghsa: bool = False,
    ghsa_max_packages: int = 40,
    include_installed: bool = False,
    include_threat_intel: bool = True,
    threat_intel_severity_floor: str = "high",
    per_repo_seconds: int = 120,
    large_repo_seconds: int | None = None,
    total_seconds: int = 900,
    clone_timeout_seconds: int = 120,
    high_signal_limit: int = 10,
    check_upstream: bool = True,
    max_repos: int | None = None,
    keep_workdir: bool = False,
    engine: str | None = None,
) -> dict:
    """Clone and scan GitHub repos with temporary state and bounded runtime."""

    started = time.monotonic()
    requested = repos[: max_repos or len(repos)]
    work_tmp = tempfile.mkdtemp(prefix="guardian-repo-scout-work-")
    state_tmp = tempfile.mkdtemp(prefix="guardian-repo-scout-state-")
    work_dir = Path(work_tmp)
    state_dir = Path(state_tmp)
    results: list[dict] = []
    cleanup = not keep_workdir

    try:
        for index, spec in enumerate(requested, start=1):
            remaining = total_seconds - (time.monotonic() - started)
            if remaining <= 0:
                results.append(
                    {
                        "repo": spec,
                        "status": "skipped-budget",
                        "message": f"total repo-scout budget exceeded before repo {index}",
                    }
                )
                break
            repo_started = time.monotonic()
            try:
                display_name, clone_url = _repo_url(spec)
            except ValueError as exc:
                results.append({"repo": spec, "status": "invalid", "error": str(exc)})
                continue

            repo_dir = work_dir / display_name.replace("/", "__")
            repo_state = state_dir / display_name.replace("/", "__")
            item: dict = {
                "repo": display_name,
                "clone_url": clone_url,
                "status": "started",
                "workdir": str(repo_dir) if keep_workdir else None,
                "state_dir": str(repo_state) if keep_workdir else None,
            }
            clone = _run_git_clone(clone_url, repo_dir, min(clone_timeout_seconds, max(1, int(remaining))))
            item["clone"] = clone
            if clone["status"] != "ok":
                item["status"] = "clone_failed"
                item["elapsed_seconds"] = round(time.monotonic() - repo_started, 4)
                results.append(item)
                continue

            config = _isolated_config(repo_state, repo_dir)
            _mkdirs_for_config(config)
            preflight = _preflight_dependency_surface(config, repo_dir, include_installed=include_installed)
            item["preflight"] = preflight
            db = Database(config.db_path)
            db.initialize()
            try:
                try:
                    mode_options = apply_scan_mode(
                        scan_mode,
                        include_installed=include_installed,
                        include_ghsa=include_ghsa,
                        include_threat_intel=include_threat_intel,
                        compact=True,
                    )
                    requested_repo_budget = per_repo_seconds
                    if preflight["large_repo_mode"]:
                        requested_repo_budget = max(
                            per_repo_seconds,
                            large_repo_seconds or config.large_repo_min_seconds,
                        )
                    scan_budget = min(
                        requested_repo_budget,
                        max(1, int(total_seconds - (time.monotonic() - started))),
                    )
                    payload = run_project_scan(
                        config,
                        db,
                        root=str(repo_dir),
                        include_installed=mode_options["include_installed"],
                        include_ghsa=mode_options["include_ghsa"],
                        ghsa_max_packages=ghsa_max_packages,
                        include_threat_intel=mode_options["include_threat_intel"],
                        threat_intel_severity_floor=threat_intel_severity_floor,
                        compact=True,
                        snapshot_full=False,
                        max_seconds=scan_budget,
                        engine=engine,
                    )
                    root_self_packages = _root_self_packages(db, repo_dir)
                except Exception as exc:
                    item.update(
                        {
                            "status": "scan_failed",
                            "error": repr(exc),
                            "elapsed_seconds": round(time.monotonic() - repo_started, 4),
                        }
                    )
                    results.append(item)
                    continue
            finally:
                db.close()

            summary = _summarize_scan_payload(
                payload,
                high_signal_limit,
                root_self_packages=root_self_packages,
            )
            if check_upstream and summary["high_signal_top_packages"]:
                # Duplicate checks are intentionally scoped to the already
                # filtered high-signal list so public-repo scouting stays
                # bounded and does not hammer GitHub search.
                upstream = enrich_findings_with_upstream_context(
                    display_name,
                    repo_dir,
                    summary["high_signal_top_packages"],
                )
                summary["repo_policy"] = upstream["repo_policy"]
                summary["reporting_path_summary"] = upstream["reporting_path_summary"]
                summary["high_signal_top_packages"] = upstream["findings"]
                tracked = upstream["reporting_path_summary"].get("Do not report, already tracked", 0)
                if tracked and tracked == summary["high_signal_count"]:
                    summary["scout_headline"] = (
                        f"{summary['high_signal_count']} high-signal finding(s), "
                        "all already tracked upstream"
                    )
            elif summary["high_signal_top_packages"]:
                summary["repo_policy"] = {
                    "default_decision": "not-checked",
                    "reason": "Upstream duplicate/policy checks were disabled.",
                    "evidence_files": [],
                    "matched_pattern": None,
                }
                summary["reporting_path_summary"] = {"not-checked": len(summary["high_signal_top_packages"])}
            item.update(summary)
            item["status"] = item.get("status") or payload.get("status") or "ok"
            item["elapsed_seconds"] = round(time.monotonic() - repo_started, 4)
            results.append(item)

        return {
            "mode": "repo-scout",
            "generated_at": utc_now(),
            "scan_mode": scan_mode,
            "repo_count_requested": len(repos),
            "repo_count_scanned": len([item for item in results if item.get("clone", {}).get("status") == "ok"]),
            "total_high_signal_count": sum(item.get("high_signal_count", 0) for item in results),
            "elapsed_seconds": round(time.monotonic() - started, 4),
            "budgets": {
                "per_repo_seconds": per_repo_seconds,
                "large_repo_seconds": large_repo_seconds,
                "total_seconds": total_seconds,
                "clone_timeout_seconds": clone_timeout_seconds,
                "ghsa_max_packages": ghsa_max_packages,
                "check_upstream": check_upstream,
            },
            "state_policy": "ephemeral-temp-state-deleted" if cleanup else "kept-for-debugging",
            "workdir_policy": "ephemeral-clones-deleted" if cleanup else "kept-for-debugging",
            "workdir": None if cleanup else str(work_dir),
            "state_dir": None if cleanup else str(state_dir),
            "results": results,
        }
    finally:
        if cleanup:
            shutil.rmtree(work_dir, ignore_errors=True)
            shutil.rmtree(state_dir, ignore_errors=True)
