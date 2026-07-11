"""Keyword and hygiene signal extraction used by triage scoring."""

from __future__ import annotations

import re

from .signals import SIGNAL_GRADE_ORDER, SignalGrade
from .usage import find_package_usage


HIGH_SIGNAL_KEYWORDS = {
    "rce": "remote code execution",
    "remote code execution": "remote code execution",
    "ssrf": "server-side request forgery",
    "xss": "cross-site scripting",
    "cross-site scripting": "cross-site scripting",
    "auth": "authorization or authentication bypass",
    "bypass": "authorization or authentication bypass",
    "bypassing": "authorization or authentication bypass",
    "arbitrary file write": "arbitrary file write",
    "path traversal": "path traversal",
    "command injection": "command injection",
    "deserialization": "deserialization",
    "denial of service": "denial of service",
    "dos": "denial of service",
}

CORE_RUNTIME_PACKAGES = {
    "next",
    "react",
    "react-dom",
    "fastapi",
    "starlette",
    "uvicorn",
    "django",
    "flask",
    "vite",
    "typescript",
}

HYGIENE_NAME_HINTS = {
    "@playwright/test",
    "@testing-library/react",
    "@types/node",
    "babel-jest",
    "coverage",
    "cypress",
    "eslint",
    "jest",
    "playwright",
    "postcss",
    "prettier",
    "pytest",
    "storybook",
    "tailwindcss",
    "ts-jest",
    "ts-node",
    "tsx",
    "typescript",
    "vite",
    "vitest",
    "webpack",
}

HYGIENE_NECESSITY_ORDER = {
    "candidate-for-removal": 0,
    "test-only": 1,
    "build-tooling": 2,
    "required-build": 3,
}

TEST_PATH_MARKERS = ("/tests/", "/__tests__/", "/spec/", "/specs/", ".spec.", ".test.", "test_", "conftest.py")
BUILD_PATH_MARKERS = (
    "/scripts/",
    "/ops/",
    "vite.config",
    "vitest.config",
    "next.config",
    "postcss.config",
    "tailwind",
    "webpack",
    "package.json",
    "pyproject.toml",
)


def advisory_link_sort_key(link: str) -> tuple[int, str]:
    """Prefer human-actionable advisory pages before raw scoring endpoints."""

    if "api.first.org/data/v1/epss" in link:
        return (3, link)
    if "nvd.nist.gov" in link:
        return (1, link)
    if "github.com" in link:
        return (0, link)
    return (2, link)


def signal_grade_sort_key(grade: str) -> int:
    """Keep stronger evidence grades first in compact operator output."""

    try:
        return SIGNAL_GRADE_ORDER[SignalGrade(grade)]
    except (ValueError, KeyError):
        return 99


def keyword_signals(text: str) -> list[str]:
    lowered = (text or "").lower()
    matches = []
    for needle, label in HIGH_SIGNAL_KEYWORDS.items():
        if " " in needle:
            if needle in lowered:
                matches.append(label)
            continue
        if re.search(rf"\b{re.escape(needle)}\b", lowered):
            matches.append(label)
    return sorted(set(matches))


def usage_kind(file_path: str) -> str:
    lowered = file_path.lower()
    if any(marker in lowered for marker in TEST_PATH_MARKERS):
        return "test"
    if any(marker in lowered for marker in BUILD_PATH_MARKERS):
        return "build"
    return "runtime"


def path_usage_hints(path: str) -> dict[str, int]:
    lowered = (path or "").lower()
    counts = {"runtime": 0, "build": 0, "test": 0}
    if not lowered:
        return counts
    if any(marker in lowered for marker in TEST_PATH_MARKERS):
        counts["test"] += 1
    elif any(marker in lowered for marker in BUILD_PATH_MARKERS):
        counts["build"] += 1
    else:
        counts["runtime"] += 1
    return counts


def usage_summary(occurrences: list[dict]) -> list[dict]:
    results = []
    seen_roots: set[tuple[str, str, str]] = set()
    for item in occurrences:
        key = (item["root_path"], item["ecosystem"], item["package_name"])
        if key in seen_roots:
            continue
        seen_roots.add(key)
        root_path = item["root_path"]
        usage = find_package_usage(root_path, item["ecosystem"], item["package_name"])
        by_kind = {"runtime": 0, "build": 0, "test": 0}
        for hit in usage["hits"]:
            by_kind[usage_kind(hit["file"])] += 1
        results.append(
            {
                "root_path": root_path,
                "hit_count": usage["hit_count"],
                "hits": usage["hits"],
                "by_kind": by_kind,
            }
        )
    return results


def aggregate_usage_kinds(usage_rows: list[dict]) -> dict[str, int]:
    totals = {"runtime": 0, "build": 0, "test": 0}
    for row in usage_rows:
        for kind, count in row["by_kind"].items():
            totals[kind] += count
    return totals
