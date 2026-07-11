"""Fast local typosquat and slopsquat detection against ranked package names."""

from __future__ import annotations

import json
import time
from collections import defaultdict
from functools import lru_cache
from pathlib import Path

from .db import Database
from .signals import SignalGrade, grade_to_posture
from .util import normalize_package_name


POPULAR_PACKAGE_DIR = Path(__file__).resolve().parents[3] / "data" / "popular_packages"


class PopularPackageIndex:
    """Precompute one-edit signatures so checks stay proportional to name length."""

    def __init__(self, ecosystem: str, payload: dict):
        self.ecosystem = ecosystem
        self.source = payload.get("source") or {}
        self.path = POPULAR_PACKAGE_DIR / f"{ecosystem}.json"
        self.ranks: dict[str, int] = {}
        self.by_length: dict[int, list[str]] = defaultdict(list)
        self.top_500: list[str] = []
        self.scoped_leaves: dict[str, set[str]] = defaultdict(set)
        for package in payload.get("packages", []):
            name = _canonical_name(ecosystem, package["name"])
            rank = int(package["rank"])
            if name in self.ranks:
                continue
            self.ranks[name] = rank
            if rank <= 500:
                self.top_500.append(name)
            self.by_length[len(name)].append(name)
            if ecosystem == "npm" and name.startswith("@") and "/" in name:
                self.scoped_leaves[name.split("/", 1)[1]].add(name)


@lru_cache(maxsize=2)
def popular_index(ecosystem: str) -> PopularPackageIndex:
    path = POPULAR_PACKAGE_DIR / f"{ecosystem}.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    return PopularPackageIndex(ecosystem, payload)


def detect_typosquat(
    ecosystem: str,
    package_name: str,
    *,
    db: Database | None = None,
) -> list[dict]:
    """Return at most one strongest similarity signal for a package name."""

    normalized_name = normalize_package_name(ecosystem, package_name)
    if db is not None and _name_is_accepted(db, ecosystem, normalized_name):
        return []
    index = popular_index(ecosystem)
    candidate = _canonical_name(ecosystem, package_name)
    if not candidate or candidate in index.ranks:
        return []

    matches: dict[str, dict] = {}
    for target in _distance_one_candidates(candidate, index):
        distance = bounded_damerau_levenshtein(candidate, target, 1)
        if distance <= 1:
            matches[target] = {
                "target": target,
                "rank": index.ranks[target],
                "distance": distance,
                "similarity_type": "edit-distance",
            }
    for target, similarity_type in _confusion_candidates(candidate, index):
        matches.setdefault(
            target,
            {
                "target": target,
                "rank": index.ranks[target],
                "distance": bounded_damerau_levenshtein(candidate, target, 2),
                "similarity_type": similarity_type,
            },
        )
    for target in index.top_500:
        if target in matches or abs(len(candidate) - len(target)) > 2:
            continue
        distance = bounded_damerau_levenshtein(candidate, target, 2)
        if distance <= 2:
            matches[target] = {
                "target": target,
                "rank": index.ranks[target],
                "distance": distance,
                "similarity_type": "edit-distance",
            }
    if not matches:
        return []

    strongest = min(matches.values(), key=_match_sort_key)
    grade = (
        SignalGrade.BEHAVIORAL_HIGH
        if strongest["rank"] <= 500 and strongest["distance"] <= 1
        else SignalGrade.BEHAVIORAL_WATCH
    )
    posture = grade_to_posture(grade)
    return [
        {
            "signal_type": "typosquat-suspected",
            "signal_grade": grade.value,
            "posture": posture,
            "posture_rank": {"act_now": 0, "fix_this_week": 1, "watch": 2}.get(posture, 9),
            "ecosystem": ecosystem,
            "package_name": package_name,
            "normalized_name": normalized_name,
            "version": None,
            "evidence_source": "popular-package-snapshot",
            "similar_package": strongest["target"],
            "similar_package_rank": strongest["rank"],
            "edit_distance": strongest["distance"],
            "similarity_type": strongest["similarity_type"],
            "source_files": [str(index.path)],
            "explanation": (
                f"Package name is unusually similar to popular {ecosystem} package "
                f"{strongest['target']!r} (rank {strongest['rank']}). Verify the spelling and publisher before installation."
            ),
            "silence_command": f"guardian policy accept-name {ecosystem} {package_name}",
        }
    ]


def detect_new_package_typosquats(
    db: Database,
    root_path: str,
    run_ids: list[int],
) -> list[dict]:
    """Check only package names introduced by the current inventory runs."""

    started = time.perf_counter()
    rows = db.new_package_names_for_runs(root_path, run_ids)
    signals = [
        signal
        for row in rows
        if row["ecosystem"] in {"npm", "pypi"}
        for signal in detect_typosquat(row["ecosystem"], row["package_name"], db=db)
    ]
    elapsed_ms = round((time.perf_counter() - started) * 1000, 3)
    for signal in signals:
        signal["detector_elapsed_ms"] = elapsed_ms
        signal["new_package_names_checked"] = len(rows)
    return sorted(signals, key=lambda item: (item["posture_rank"], item["package_name"].lower()))


def bounded_damerau_levenshtein(left: str, right: str, limit: int = 2) -> int:
    """Return optimal-string-alignment distance, stopping beyond a small bound."""

    if left == right:
        return 0
    if abs(len(left) - len(right)) > limit:
        return limit + 1
    previous_previous: list[int] | None = None
    previous = list(range(len(right) + 1))
    for left_index, left_char in enumerate(left, start=1):
        current = [left_index]
        row_minimum = left_index
        for right_index, right_char in enumerate(right, start=1):
            substitution = previous[right_index - 1] + (left_char != right_char)
            value = min(
                previous[right_index] + 1,
                current[right_index - 1] + 1,
                substitution,
            )
            if (
                previous_previous is not None
                and left_index > 1
                and right_index > 1
                and left_char == right[right_index - 2]
                and left[left_index - 2] == right_char
            ):
                value = min(value, previous_previous[right_index - 2] + 1)
            current.append(value)
            row_minimum = min(row_minimum, value)
        if row_minimum > limit:
            return limit + 1
        previous_previous, previous = previous, current
    return previous[-1] if previous[-1] <= limit else limit + 1


def _distance_one_candidates(candidate: str, index: PopularPackageIndex) -> set[str]:
    return {
        target
        for length in range(max(0, len(candidate) - 1), len(candidate) + 2)
        for target in index.by_length.get(length, [])
        if _within_one_edit_or_swap(candidate, target)
    }


def _within_one_edit_or_swap(left: str, right: str) -> bool:
    """Check insertion, deletion, substitution, or adjacent swap in linear time."""

    if abs(len(left) - len(right)) > 1 or left == right:
        return False
    if len(left) == len(right):
        mismatches = [index for index, pair in enumerate(zip(left, right)) if pair[0] != pair[1]]
        if len(mismatches) == 1:
            return True
        return (
            len(mismatches) == 2
            and mismatches[1] == mismatches[0] + 1
            and left[mismatches[0]] == right[mismatches[1]]
            and left[mismatches[1]] == right[mismatches[0]]
        )
    shorter, longer = (left, right) if len(left) < len(right) else (right, left)
    short_index = long_index = differences = 0
    while short_index < len(shorter) and long_index < len(longer):
        if shorter[short_index] == longer[long_index]:
            short_index += 1
            long_index += 1
            continue
        differences += 1
        if differences > 1:
            return False
        long_index += 1
    return True


def _confusion_candidates(candidate: str, index: PopularPackageIndex) -> set[tuple[str, str]]:
    variants: set[tuple[str, str]] = set()
    for transformed in {
        candidate.replace("_", "-"),
        candidate.replace("-", "_"),
        candidate.replace("0", "o"),
        candidate.replace("o", "0"),
        candidate.replace("1", "l"),
        candidate.replace("l", "1"),
    }:
        if transformed != candidate and transformed in index.ranks:
            variants.add((transformed, "confusion-transform"))
    affix_variants = set()
    if candidate.startswith("python3-"):
        affix_variants.add("python-" + candidate[len("python3-") :])
    if candidate.startswith("python-"):
        affix_variants.add("python3-" + candidate[len("python-") :])
    for prefix in ("py-", "python-", "python3-", "node-", "js-"):
        if candidate.startswith(prefix):
            affix_variants.add(candidate[len(prefix) :])
    for suffix in ("-py", "-python", "-python3", "-node", "-js"):
        if candidate.endswith(suffix):
            affix_variants.add(candidate[: -len(suffix)])
    for transformed in affix_variants:
        if transformed in index.ranks:
            variants.add((transformed, "affix-confusion"))
    if index.ecosystem == "npm":
        if candidate.startswith("types-"):
            transformed = "@types/" + candidate[len("types-") :]
            if transformed in index.ranks:
                variants.add((transformed, "scope-confusion"))
        for scoped in index.scoped_leaves.get(candidate, set()):
            variants.add((scoped, "scope-confusion"))
    return variants


def _canonical_name(ecosystem: str, name: str) -> str:
    lowered = name.strip().lower()
    if ecosystem == "pypi":
        return normalize_package_name(ecosystem, lowered)
    return lowered


def _name_is_accepted(db: Database, ecosystem: str, normalized_name: str) -> bool:
    return any(
        row["action"] == "accept-name"
        for row in db.active_policy_exceptions(
            ecosystem=ecosystem,
            normalized_name=normalized_name,
            version=None,
        )
    )


def _match_sort_key(match: dict) -> tuple[int, int, int, str]:
    high = match["rank"] <= 500 and match["distance"] <= 1
    return (0 if high else 1, match["distance"], match["rank"], match["target"])
