"""Maintainer-aware reporting context for ephemeral public-repo scouting.

Repo Scout finds possible upstream dependency fixes. This module adds the
second decision layer: whether the project already tracks the same issue and
which reporting path fits the target repository's published contribution and
security policies.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from collections import Counter
from pathlib import Path


REPORT_PUBLIC_PR = "Public PR OK"
REPORT_OPEN_ISSUE = "Open issue first"
REPORT_PRIVATE = "Private security advisory only"
REPORT_ALREADY_TRACKED = "Do not report, already tracked"

POLICY_FILES = [
    "SECURITY.md",
    ".github/SECURITY.md",
    "CONTRIBUTING.md",
    ".github/CONTRIBUTING.md",
    "README.md",
    ".github/pull_request_template.md",
    ".github/PULL_REQUEST_TEMPLATE.md",
]

PRIVATE_SECURITY_PATTERNS = [
    r"do not open public (?:issues|issue|pull requests|prs)",
    r"report privately",
    r"private(?:ly)? via .*security advisories",
    r"github security advisories",
    r"security@",
    r"responsible disclosure",
]

ISSUE_FIRST_PATTERNS = [
    r"open an issue first",
    r"create an issue first",
    r"file an issue first",
    r"discuss(?:ion)? .* before .*pull request",
    r"before submitting .*pull request",
    r"link(?:ed)? issue .* required",
]

ADVISORY_ID_RE = re.compile(r"\b(?:GHSA-[0-9A-Za-z-]+|CVE-\d{4}-\d{4,7})\b")
TRACKING_TITLE_TERMS = [
    "advisory",
    "audit",
    "bump",
    "cve",
    "dependabot",
    "deps",
    "ghsa",
    "security",
    "vulnerab",
]


def _read_policy_text(repo_dir: Path) -> tuple[str, list[str]]:
    """Return lower-cased policy text plus the files that contributed to it."""

    chunks: list[str] = []
    files: list[str] = []
    for relative in POLICY_FILES:
        path = repo_dir / relative
        if not path.is_file():
            continue
        try:
            text = path.read_text(errors="ignore")[:24000]
        except OSError:
            continue
        chunks.append(text)
        files.append(relative)
    return "\n".join(chunks).lower(), files


def detect_repo_reporting_policy(repo_dir: Path) -> dict:
    """Infer the safest upstream reporting path from repository policy files."""

    text, files = _read_policy_text(repo_dir)
    private_match = _first_matching_pattern(text, PRIVATE_SECURITY_PATTERNS)
    issue_match = _first_matching_pattern(text, ISSUE_FIRST_PATTERNS)
    if private_match:
        return {
            "default_decision": REPORT_PRIVATE,
            "reason": "Repository policy asks for private security reporting.",
            "evidence_files": files,
            "matched_pattern": private_match,
        }
    if issue_match:
        return {
            "default_decision": REPORT_OPEN_ISSUE,
            "reason": "Repository policy suggests discussion or issue-first contribution flow.",
            "evidence_files": files,
            "matched_pattern": issue_match,
        }
    return {
        "default_decision": REPORT_PUBLIC_PR,
        "reason": "No private security or issue-first policy was detected in common repo policy files.",
        "evidence_files": files,
        "matched_pattern": None,
    }


def _first_matching_pattern(text: str, patterns: list[str]) -> str | None:
    """Return the first regex pattern that matches the policy text."""

    for pattern in patterns:
        if re.search(pattern, text, flags=re.IGNORECASE | re.DOTALL):
            return pattern
    return None


def advisory_terms(finding: dict) -> list[str]:
    """Extract advisory identifiers from Guardian links and source fields."""

    values: list[str] = []
    for key in ("advisory_id", "issue_keys", "advisory_sources"):
        raw = finding.get(key)
        if isinstance(raw, str):
            values.append(raw)
        elif isinstance(raw, list):
            values.extend(str(item) for item in raw)
    for link in finding.get("advisory_links") or finding.get("urls") or []:
        values.append(str(link))
    found: list[str] = []
    for value in values:
        found.extend(match.group(0) for match in ADVISORY_ID_RE.finditer(value))
    return sorted(set(found))


def _package_name(finding: dict) -> str:
    """Return the display package name used by repo-scout summaries."""

    return str(
        finding.get("package_name")
        or finding.get("package")
        or finding.get("name")
        or ""
    ).strip()


def _gh_search(kind: str, repo: str, term: str, *, limit: int) -> list[dict]:
    """Search GitHub PRs or issues through gh with a small result cap."""

    if not shutil.which("gh"):
        return []
    command = [
        "gh",
        "search",
        kind,
        f"{term} repo:{repo}",
        "--limit",
        str(limit),
        "--json",
        "number,title,state,url,updatedAt",
    ]
    completed = subprocess.run(command, check=False, capture_output=True, text=True, timeout=25)
    if completed.returncode != 0:
        return []
    try:
        records = json.loads(completed.stdout or "[]")
    except json.JSONDecodeError:
        return []
    return records if isinstance(records, list) else []


def _is_advisory_term(term: str) -> bool:
    """Return true when a search term is an exact advisory identifier."""

    return bool(ADVISORY_ID_RE.fullmatch(term))


def _tracking_match_is_relevant(record: dict, term: str, package: str) -> bool:
    """Filter broad package-name GitHub search hits down to actionable tracking.

    GitHub search for common package names returns unrelated bug reports. Exact
    advisory identifiers are accepted directly. Package-name matches must look
    like dependency/security maintenance in the title.
    """

    title = str(record.get("title") or "").lower()
    if _is_advisory_term(term):
        return True
    package_lc = package.lower()
    return package_lc in title and any(marker in title for marker in TRACKING_TITLE_TERMS)


def find_upstream_tracking(repo: str, finding: dict, *, limit_per_kind: int = 5) -> dict:
    """Find existing public PRs/issues that mention the same package or advisory."""

    package = _package_name(finding)
    terms = [package] if package else []
    terms.extend(advisory_terms(finding))
    terms = [term for term in dict.fromkeys(terms) if term]
    matches: list[dict] = []
    for term in terms[:4]:
        for kind in ("prs", "issues"):
            for record in _gh_search(kind, repo, term, limit=limit_per_kind):
                if not _tracking_match_is_relevant(record, term, package):
                    continue
                matches.append(
                    {
                        "kind": "pr" if kind == "prs" else "issue",
                        "term": term,
                        "number": record.get("number"),
                        "title": record.get("title"),
                        "state": str(record.get("state") or "").lower(),
                        "url": record.get("url"),
                        "updated_at": record.get("updatedAt"),
                    }
                )
    deduped = _dedupe_tracking_matches(matches)
    open_matches = [item for item in deduped if item.get("state") == "open"]
    return {
        "status": "already-tracked" if open_matches else "none-found",
        "checked_terms": terms[:4],
        "open_count": len(open_matches),
        "match_count": len(deduped),
        "matches": open_matches[:6] or deduped[:6],
    }


def _dedupe_tracking_matches(matches: list[dict]) -> list[dict]:
    """Remove duplicate GitHub search hits across package and advisory terms."""

    seen: set[tuple[str, int | None, str | None]] = set()
    result: list[dict] = []
    for item in matches:
        key = (str(item.get("kind")), item.get("number"), item.get("url"))
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return sorted(result, key=lambda item: (item.get("state") != "open", item.get("kind"), item.get("number") or 0))


def decide_reporting_path(repo_policy: dict, upstream_tracking: dict, finding: dict | None = None) -> dict:
    """Return the operator-facing reporting path for one finding."""

    if upstream_tracking.get("status") == "already-tracked":
        return {
            "decision": REPORT_ALREADY_TRACKED,
            "reason": "A matching open upstream PR or issue already exists.",
        }
    decision = repo_policy.get("default_decision") or REPORT_PUBLIC_PR
    finding = finding or {}
    if (
        decision == REPORT_PUBLIC_PR
        and not finding.get("recommended_clean_version")
        and not finding.get("first_fixed_version")
    ):
        return {
            "decision": REPORT_OPEN_ISSUE,
            "reason": (
                "This bounded scan did not verify a fixed package target. Run focused target "
                "validation or discuss upstream status before proposing a dependency-change PR."
            ),
        }
    return {
        "decision": decision,
        "reason": repo_policy.get("reason") or "No stronger reporting constraint was detected.",
    }


def enrich_findings_with_upstream_context(repo: str, repo_dir: Path, findings: list[dict]) -> dict:
    """Attach duplicate-tracking and reporting-path decisions to scout findings."""

    repo_policy = detect_repo_reporting_policy(repo_dir)
    enriched: list[dict] = []
    for finding in findings:
        tracking = find_upstream_tracking(repo, finding)
        reporting_path = decide_reporting_path(repo_policy, tracking, finding)
        enriched.append({**finding, "upstream_tracking": tracking, "reporting_path": reporting_path})
    counts = Counter(item["reporting_path"]["decision"] for item in enriched)
    return {
        "repo_policy": repo_policy,
        "findings": enriched,
        "reporting_path_summary": dict(sorted(counts.items())),
    }
