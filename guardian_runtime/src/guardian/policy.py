from __future__ import annotations

from dataclasses import dataclass

from .config import GuardianConfig
from .db import Database
from .intel import severity_rank


@dataclass
class PolicyDecision:
    action: str
    blocked: bool
    reason: str
    matched_exception: dict | None = None


def decide_package_action(
    config: GuardianConfig,
    db: Database,
    *,
    ecosystem: str,
    normalized_name: str,
    version: str,
    findings: list[dict],
) -> PolicyDecision:
    exceptions = [dict(row) for row in db.active_policy_exceptions(
        ecosystem=ecosystem,
        normalized_name=normalized_name,
        version=version,
    )]
    for exception in exceptions:
        action = (exception["action"] or "").lower()
        if action == "allow":
            return PolicyDecision(
                action="allow",
                blocked=False,
                reason=f"policy exception allow: {exception['reason']}",
                matched_exception=exception,
            )
        if action == "block":
            return PolicyDecision(
                action="block",
                blocked=True,
                reason=f"policy exception block: {exception['reason']}",
                matched_exception=exception,
            )
        if action == "warn":
            return PolicyDecision(
                action="warn",
                blocked=False,
                reason=f"policy exception warn: {exception['reason']}",
                matched_exception=exception,
            )

    highest = max((severity_rank(item.get("severity")) for item in findings), default=0)
    blocked_threshold = max((severity_rank(item) for item in config.blocked_severities), default=0)
    if highest >= blocked_threshold and findings:
        return PolicyDecision(
            action="block",
            blocked=True,
            reason="finding severity meets or exceeds block policy",
        )
    if findings:
        return PolicyDecision(
            action="warn",
            blocked=False,
            reason="findings present but below block threshold",
        )
    return PolicyDecision(action="allow", blocked=False, reason="no findings")
