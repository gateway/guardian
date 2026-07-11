"""Maintainer-safe outreach preflight, duplicate checks, and ledger enforcement."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Callable

from .config import GuardianConfig
from .db import Database
from .upstream_context import (
    REPORT_OPEN_ISSUE,
    REPORT_PRIVATE,
    REPORT_PUBLIC_PR,
    detect_repo_reporting_policy,
)


GhRunner = Callable[[list[str]], tuple[int, str, str]]


def preflight_outreach(
    config: GuardianConfig,
    db: Database,
    *,
    repo: str,
    repo_dir: Path,
    advisory_id: str,
    package: str,
    version: str | None = None,
    gh_runner: GhRunner | None = None,
) -> dict:
    """Return and persist the one safe next action before drafting upstream outreach."""

    repo = _normalize_repo(repo)
    advisory_id = advisory_id.upper().strip()
    package = package.strip()
    if not advisory_id or not package:
        raise ValueError("advisory_id and package are required")
    existing = db.outreach_entry(repo, advisory_id, package)
    if existing:
        return {
            "status": "blocked-ledger",
            "decision": "Do not report, already recorded",
            "reason": "Guardian already recorded an outreach decision for this repository/advisory/package.",
            "ledger": existing,
        }
    if db.outreach_count_today() >= max(0, config.max_outreach_per_day):
        return _record_decision(
            db, repo, advisory_id, package, "suppressed-daily-cap",
            "Do not report, daily cap reached",
            f"Guardian's daily outreach cap of {config.max_outreach_per_day} has been reached.",
            checks={"daily_cap": config.max_outreach_per_day},
        )

    runner = gh_runner or _default_gh_runner
    gh_available = gh_runner is not None or shutil.which("gh") is not None
    policy = detect_repo_reporting_policy(repo_dir)
    checks: dict = {"gh_available": gh_available, "repo_policy": policy}
    if not gh_available:
        return _record_decision(
            db, repo, advisory_id, package, "checks-unavailable",
            "Verify manually before reporting",
            "GitHub duplicate, archive, and default-branch checks are unavailable because gh is not installed.",
            checks=checks,
        )

    metadata = _repo_metadata(repo, runner)
    checks["repo_metadata"] = metadata
    if metadata.get("status") != "ok":
        return _record_decision(
            db, repo, advisory_id, package, "checks-unavailable",
            "Verify manually before reporting",
            "Guardian could not verify repository archive/default-branch metadata.",
            checks=checks,
        )
    if metadata.get("archived"):
        return _record_decision(
            db, repo, advisory_id, package, "suppressed-archived",
            "Do not report, repository archived",
            "The target repository is archived and does not accept normal contribution work.",
            checks=checks,
        )

    tracking = _tracking_checks(repo, advisory_id, package, version, runner)
    checks["upstream_tracking"] = tracking
    if tracking["matches"]:
        return _record_decision(
            db, repo, advisory_id, package, "suppressed-in-flight",
            "In-flight, no action",
            "An existing open or closed upstream PR/issue already tracks this package or advisory.",
            checks=checks,
            url=tracking["matches"][0].get("url"),
        )
    if tracking["errors"]:
        return _record_decision(
            db, repo, advisory_id, package, "checks-unavailable",
            "Verify manually before reporting",
            "One or more GitHub PR/issue duplicate searches failed.",
            checks=checks,
        )

    branch_check = _default_branch_dependency_check(
        repo_dir,
        metadata.get("default_branch"),
        package,
        version,
    )
    checks["default_branch"] = branch_check
    if branch_check.get("fixed"):
        return _record_decision(
            db, repo, advisory_id, package, "suppressed-default-fixed",
            "Do not report, default branch already fixed",
            "The scanned vulnerable package/version is not present in current default-branch dependency files.",
            checks=checks,
        )
    if branch_check.get("status") != "checked":
        return _record_decision(
            db, repo, advisory_id, package, "checks-unavailable",
            "Verify manually before reporting",
            "Guardian could not compare the scanned dependency evidence with the default branch.",
            checks=checks,
        )

    policy_decision = policy.get("default_decision") or REPORT_PUBLIC_PR
    action = {
        REPORT_PRIVATE: "private-report",
        REPORT_OPEN_ISSUE: "open-issue",
        REPORT_PUBLIC_PR: "eligible-awaiting-confirmation",
    }.get(policy_decision, "checks-unavailable")
    return _record_decision(
        db,
        repo,
        advisory_id,
        package,
        action,
        policy_decision,
        policy.get("reason") or "No stronger reporting constraint was detected.",
        checks=checks,
    )


def record_outreach_result(
    db: Database,
    *,
    repo: str,
    advisory_id: str,
    package: str,
    action: str,
    url: str | None = None,
) -> dict:
    """Update the ledger only after the human-approved outreach action completes."""

    normalized_repo = _normalize_repo(repo)
    if db.outreach_entry(normalized_repo, advisory_id, package) is None:
        raise ValueError("outreach result requires a recorded Guardian preflight")
    return db.record_outreach(
        repo=normalized_repo,
        advisory_id=advisory_id,
        package=package,
        action=action,
        url=url,
        details={"recorded_after_human_confirmation": True},
    )


def _tracking_checks(
    repo: str,
    advisory_id: str,
    package: str,
    version: str | None,
    runner: GhRunner,
) -> dict:
    terms = [advisory_id, package]
    if version:
        terms.append(f"{package} {version}")
    matches = []
    errors = []
    for kind in ("pr", "issue"):
        for term in terms:
            code, stdout, stderr = runner([
                "gh", kind, "list", "--repo", repo, "--state", "all",
                "--search", term, "--limit", "10", "--json", "number,title,state,url,updatedAt",
            ])
            if code != 0:
                errors.append({"kind": kind, "term": term, "error": stderr.strip()})
                continue
            try:
                records = json.loads(stdout or "[]")
            except json.JSONDecodeError:
                errors.append({"kind": kind, "term": term, "error": "invalid gh JSON"})
                continue
            for record in records if isinstance(records, list) else []:
                title = str(record.get("title") or "").lower()
                if advisory_id.lower() not in title and package.lower() not in title:
                    continue
                matches.append({**record, "kind": kind, "term": term})
    deduped = {}
    for item in matches:
        deduped[(item["kind"], item.get("number"), item.get("url"))] = item
    return {"matches": list(deduped.values()), "errors": errors}


def _repo_metadata(repo: str, runner: GhRunner) -> dict:
    code, stdout, stderr = runner([
        "gh", "repo", "view", repo, "--json", "isArchived,defaultBranchRef,url",
    ])
    if code != 0:
        return {"status": "unavailable", "error": stderr.strip()}
    try:
        payload = json.loads(stdout or "{}")
    except json.JSONDecodeError:
        return {"status": "unavailable", "error": "invalid gh JSON"}
    return {
        "status": "ok",
        "archived": bool(payload.get("isArchived")),
        "default_branch": (payload.get("defaultBranchRef") or {}).get("name"),
        "url": payload.get("url"),
    }


def _default_branch_dependency_check(
    repo_dir: Path,
    default_branch: str | None,
    package: str,
    version: str | None,
) -> dict:
    if not default_branch or not (repo_dir / ".git").exists() or not version:
        return {"status": "unavailable", "fixed": False}
    candidate_files = [
        path for path in repo_dir.rglob("*")
        if path.is_file()
        and path.name in {
            "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "requirements.txt",
            "uv.lock", "go.sum", "Cargo.lock", "composer.lock",
        }
        and ".git" not in path.parts
    ]
    local_evidence = []
    for path in candidate_files:
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if package in content and version in content:
            local_evidence.append(path)
    if not local_evidence:
        return {"status": "unavailable", "fixed": False, "reason": "scanned dependency evidence not located"}
    checked = []
    remote_ref = f"origin/{default_branch}"
    for path in local_evidence:
        relative = path.relative_to(repo_dir).as_posix()
        completed = subprocess.run(
            ["git", "-C", str(repo_dir), "show", f"{remote_ref}:{relative}"],
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
        if completed.returncode != 0:
            return {
                "status": "unavailable",
                "fixed": False,
                "reason": f"could not read {relative} from {remote_ref}",
                "files": checked,
            }
        checked.append(relative)
        if package in completed.stdout and version in completed.stdout:
            return {"status": "checked", "fixed": False, "files": checked}
    return {"status": "checked", "fixed": True, "files": checked}


def _record_decision(
    db: Database,
    repo: str,
    advisory_id: str,
    package: str,
    action: str,
    decision: str,
    reason: str,
    *,
    checks: dict,
    url: str | None = None,
) -> dict:
    details = {"decision": decision, "reason": reason, "checks": checks}
    ledger = db.record_outreach(
        repo=repo,
        advisory_id=advisory_id,
        package=package,
        action=action,
        url=url,
        details=details,
    )
    return {
        "status": action,
        "decision": decision,
        "reason": reason,
        "checks": checks,
        "ledger": ledger,
    }


def _default_gh_runner(args: list[str]) -> tuple[int, str, str]:
    completed = subprocess.run(args, check=False, capture_output=True, text=True, timeout=30)
    return completed.returncode, completed.stdout, completed.stderr


def _normalize_repo(value: str) -> str:
    cleaned = value.strip().removeprefix("https://github.com/").removesuffix(".git").strip("/")
    if cleaned.count("/") != 1:
        raise ValueError("repo must be owner/name or a GitHub repository URL")
    return cleaned.lower()
