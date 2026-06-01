"""Dependency-free version parsing and affected-range matching helpers."""

from __future__ import annotations

import re

try:
    from packaging.version import Version as PackagingVersion
except Exception:  # pragma: no cover - fallback path is what we test
    PackagingVersion = None


def _split_version(value: str) -> list[object]:
    parts: list[object] = []
    for token in re.findall(r"[0-9]+|[A-Za-z]+", value or ""):
        if token.isdigit():
            parts.append(int(token))
        else:
            parts.append(token.lower())
    return parts


def compare_versions(left: str, right: str) -> int:
    if PackagingVersion is not None:
        try:
            left_version = PackagingVersion(left)
            right_version = PackagingVersion(right)
            if left_version < right_version:
                return -1
            if left_version > right_version:
                return 1
            return 0
        except Exception:
            pass
    left_parts = _split_version(left)
    right_parts = _split_version(right)
    max_len = max(len(left_parts), len(right_parts))
    for index in range(max_len):
        left_value = left_parts[index] if index < len(left_parts) else 0
        right_value = right_parts[index] if index < len(right_parts) else 0
        if left_value == right_value:
            continue
        if isinstance(left_value, int) and isinstance(right_value, int):
            return -1 if left_value < right_value else 1
        return -1 if str(left_value) < str(right_value) else 1
    return 0


_RANGE_COMPARISON_RE = re.compile(r"(<=|>=|<|>|={1,2})\s*([^\s,]+)")


def version_satisfies_range(version: str, affected_range: str | None) -> bool:
    """Return whether an exact version is covered by a simple advisory range.

    GitLab/Gemnasium advisories mostly use comma-separated comparisons such as
    "<12.2.0" or ">=5.1.0,<8.1.1". This intentionally returns False for
    unsupported ranges instead of guessing.
    """
    text = (affected_range or "").strip()
    if not text:
        return False
    if text in {"*", ">=0", ">= 0"}:
        return True
    for branch in re.split(r"\s*\|\|\s*", text):
        comparisons = _parse_range_branch(branch)
        if comparisons and all(_matches_comparison(version, operator, target) for operator, target in comparisons):
            return True
    return False


def version_range_is_supported(affected_range: str | None) -> bool:
    text = (affected_range or "").strip()
    if not text:
        return False
    if text in {"*", ">=0", ">= 0"}:
        return True
    return any(_parse_range_branch(branch) for branch in re.split(r"\s*\|\|\s*", text))


def _parse_range_branch(branch: str) -> list[tuple[str, str]]:
    normalized = branch.strip()
    if not normalized or normalized.startswith("<0"):
        return []
    comparisons = _RANGE_COMPARISON_RE.findall(normalized)
    if comparisons:
        covered = _RANGE_COMPARISON_RE.sub("", normalized)
        if covered.replace(",", "").strip():
            return []
        return comparisons
    if re.fullmatch(r"[A-Za-z0-9_.!+~-]+", normalized):
        return [("==", normalized)]
    return []


def _matches_comparison(version: str, operator: str, target: str) -> bool:
    comparison = compare_versions(version, target)
    if operator in {"=", "=="}:
        return comparison == 0
    if operator == "<":
        return comparison < 0
    if operator == "<=":
        return comparison <= 0
    if operator == ">":
        return comparison > 0
    if operator == ">=":
        return comparison >= 0
    return False


def first_numeric_triplet(value: str) -> tuple[int, int, int] | None:
    numbers = [int(token) for token in re.findall(r"\d+", value or "")]
    if not numbers:
        return None
    padded = (numbers + [0, 0, 0])[:3]
    return (padded[0], padded[1], padded[2])


def classify_upgrade_jump(current_version: str, target_version: str) -> dict:
    current = first_numeric_triplet(current_version)
    target = first_numeric_triplet(target_version)
    if current is None or target is None:
        return {
            "impact": "unknown",
            "label": "unknown risk",
            "reason": "version format not recognized for safe jump classification",
        }
    if target[0] != current[0]:
        return {
            "impact": "high",
            "label": "major jump",
            "reason": f"{current_version} -> {target_version} changes the major version",
        }
    if target[1] != current[1]:
        return {
            "impact": "medium",
            "label": "minor jump",
            "reason": f"{current_version} -> {target_version} changes the minor version",
        }
    if target[2] != current[2]:
        return {
            "impact": "low",
            "label": "patch jump",
            "reason": f"{current_version} -> {target_version} changes only the patch version",
        }
    return {
        "impact": "low",
        "label": "same version",
        "reason": f"{current_version} already matches the target version",
    }
