"""Shared PreToolUse decision logic for Codex and Claude Code plugin hooks."""

from __future__ import annotations

import time

from .check_package import check_package, local_package_verdict
from .config import GuardianConfig
from .db import Database
from .install_command import InstallRequest, extract_install_requests
from .sources import LocalCatalogMatcher


REVIEW_SIGNAL_TYPES = {"typosquat-suspected", "known-vulnerability"}
MAX_HOOK_PACKAGES = 50


def evaluate_install_command(
    config: GuardianConfig,
    db: Database,
    command: str,
) -> dict:
    """Evaluate all dependency additions while enforcing one command-level budget."""

    requests = extract_install_requests(command)
    if not requests or not config.preinstall_gate_enabled:
        return {"decision": "allow", "requests": [], "message": None}
    if len(requests) > MAX_HOOK_PACKAGES:
        return {
            "decision": "deny",
            "requests": [],
            "message": (
                f"Guardian paused an install containing {len(requests)} package specs. "
                f"Split it into batches of at most {MAX_HOOK_PACKAGES} so every package can be checked."
            ),
        }

    started = time.perf_counter()
    results_by_index: dict[int, dict] = {}
    pending: list[tuple[int, InstallRequest, dict]] = []
    catalog_matcher = LocalCatalogMatcher(config)
    # Every package receives local checks before a slow registry request can use
    # the shared budget. This prevents later malicious specs from hiding in a batch.
    for index, request in enumerate(requests):
        if request.opaque_reason:
            results_by_index[index] = _opaque_result(request)
            continue
        local = local_package_verdict(
            config,
            db,
            request.ecosystem,
            request.name or "",
            request.version,
            catalog_matcher=catalog_matcher,
        )
        local["original_spec"] = request.original_spec
        if local["verdict"] == "block" or _requires_review(local):
            results_by_index[index] = local
        else:
            pending.append((index, request, local))

    for index, request, local in pending:
        remaining = config.preinstall_gate_max_seconds - (time.perf_counter() - started)
        if remaining <= 0.05:
            results_by_index[index] = _budget_result(request)
            continue
        try:
            result = check_package(
                config,
                db,
                request.ecosystem,
                request.name or "",
                request.version,
                max_seconds=remaining,
                local_result=local,
            )
        except (RuntimeError, ValueError) as exc:
            result = _failure_result(request, str(exc))
        result["original_spec"] = request.original_spec
        results_by_index[index] = result

    results = [results_by_index[index] for index in range(len(requests))]

    hard_blocks = [item for item in results if item.get("verdict") == "block"]
    review_required = [item for item in results if _requires_review(item)]
    warnings = [item for item in results if item.get("verdict") == "warn"]
    if hard_blocks:
        decision = "deny"
        heading = "Guardian blocked a known malicious package match."
    elif review_required:
        decision = "deny"
        heading = "Guardian paused this install for package-risk review."
    else:
        decision = "allow"
        heading = "Guardian warning (install allowed):" if warnings else None
    return {
        "decision": decision,
        "requests": results,
        "message": _message(heading, hard_blocks or review_required or warnings),
    }


def hook_output(evaluation: dict) -> dict | None:
    """Translate a Guardian decision into the cross-compatible hook JSON shape."""

    message = evaluation.get("message")
    if evaluation["decision"] == "deny":
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": message,
            }
        }
    if message:
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "additionalContext": message,
            }
        }
    return None


def _requires_review(result: dict) -> bool:
    if result.get("opaque_reason") and result.get("opaque_reason") != "local-path":
        return True
    return any(signal.get("signal_type") in REVIEW_SIGNAL_TYPES for signal in result.get("signals", []))


def _opaque_result(request: InstallRequest) -> dict:
    local_path = request.opaque_reason == "local-path"
    return {
        "verdict": "warn",
        "ecosystem": request.ecosystem,
        "name": request.name,
        "requested_version": request.version,
        "original_spec": request.original_spec,
        "opaque_reason": request.opaque_reason,
        "signals": [{
            "signal_type": "opaque-install-source",
            "signal_grade": "info" if local_path else "behavioral-high",
            "explanation": (
                "Guardian is allowing this local filesystem dependency; review local code changes separately."
                if local_path
                else f"Guardian cannot verify this {request.opaque_reason} before installation."
            ),
        }],
        "explanation": (
            "Local dependency paths are already present on disk and are not registry package fetches."
            if local_path
            else "Review the source, immutable revision, and publisher before installation."
        ),
    }


def _budget_result(request: InstallRequest) -> dict:
    return _failure_result(request, "command-level package-check budget was exhausted")


def _failure_result(request: InstallRequest, error: str) -> dict:
    return {
        "verdict": "warn",
        "ecosystem": request.ecosystem,
        "name": request.name,
        "requested_version": request.version,
        "original_spec": request.original_spec,
        "signals": [{
            "signal_type": "source-coverage-incomplete",
            "signal_grade": "info",
            "explanation": error,
        }],
        "explanation": "Live checks were incomplete; Guardian is failing open.",
    }


def _message(heading: str | None, results: list[dict]) -> str | None:
    if not heading:
        return None
    lines = [heading]
    for result in results[:5]:
        identity = result.get("original_spec") or result.get("name") or "unknown package"
        explanations = [signal.get("explanation") for signal in result.get("signals", []) if signal.get("explanation")]
        lines.append(f"- {identity}: {explanations[0] if explanations else result.get('explanation', 'review required')}")
    if len(results) > 5:
        lines.append(f"- plus {len(results) - 5} additional package warnings")
    return "\n".join(lines)
