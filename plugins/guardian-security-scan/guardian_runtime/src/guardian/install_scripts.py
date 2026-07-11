"""Detect lifecycle-script drift from package evidence already read by Guardian."""

from __future__ import annotations

import json
import re
from pathlib import Path

from .db import Database
from .integrity import sha256_json
from .inventory_native.walker import PYTHON_REQUIREMENTS_PATTERN, candidate_files
from .signals import SignalGrade, grade_to_posture
from .util import normalize_package_name


def detect_install_script_changes(db: Database, root_path: str) -> list[dict]:
    """Persist current observations and return only newly actionable changes."""

    observations = _current_observations(db, root_path)
    signals: list[dict] = []
    has_baseline = db.has_prior_inventory_run(root_path)
    for observation in observations:
        exact = db.install_script_state(
            root_path,
            observation["ecosystem"],
            observation["normalized_name"],
            observation["version"],
            observation["evidence_source"],
        )
        previous = exact or db.latest_install_script_state(
            root_path,
            observation["ecosystem"],
            observation["normalized_name"],
            observation["evidence_source"],
            exclude_version=observation["version"],
        )
        signal = _compare_observation(
            observation,
            exact=exact,
            previous=previous,
            has_baseline=has_baseline,
        )
        if signal is not None:
            signals.append(signal)
        db.upsert_install_script_state(observation)
    db.commit_install_script_states()
    return sorted(signals, key=lambda item: (item["posture_rank"], item["package_name"].lower()))


def _current_observations(db: Database, root_path: str) -> list[dict]:
    """Collapse duplicate evidence rows into one honest state per package/source."""

    grouped: dict[tuple[str, str, str, str], dict] = {}
    for row in db.current_packages_for_root(root_path):
        record = json.loads(row["raw_json"])
        metadata = record.get("raw_metadata") or {}
        if "has_install_script" not in metadata:
            continue
        evidence_source = metadata.get("install_script_evidence_source") or _evidence_source(row["source_type"])
        key = (row["ecosystem"], row["normalized_name"], row["version"], evidence_source)
        current = grouped.setdefault(
            key,
            {
                "root_path": root_path,
                "ecosystem": row["ecosystem"],
                "package_name": row["package_name"],
                "normalized_name": row["normalized_name"],
                "version": row["version"],
                "has_install_script": None,
                "script_kinds": [],
                "scripts_sha256": None,
                "evidence_source": evidence_source,
                "source_files": [],
            },
        )
        state = metadata.get("has_install_script")
        if state is True or (state is False and current["has_install_script"] is None):
            current["has_install_script"] = state
        current["script_kinds"] = sorted(set(current["script_kinds"]) | set(metadata.get("install_script_kinds") or []))
        current["scripts_sha256"] = metadata.get("install_scripts_sha256") or current["scripts_sha256"]
        if row["source_file"]:
            current["source_files"].append(row["source_file"])
    for observation in _direct_url_observations(root_path):
        key = (
            observation["ecosystem"],
            observation["normalized_name"],
            observation["version"],
            observation["evidence_source"],
        )
        grouped[key] = observation
    return list(grouped.values())


def _direct_url_observations(root_path: str) -> list[dict]:
    """Capture explicit pip URL/VCS requirements without treating them as resolved packages."""

    root = Path(root_path).resolve()
    observations = []
    for path in candidate_files(root, include_installed=False):
        if not PYTHON_REQUIREMENTS_PATTERN.match(path.name):
            continue
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for line in lines:
            spec = re.sub(r"\s+#.*$", "", line.strip())
            if not spec or not ("://" in spec or spec.startswith(("git+", "hg+", "svn+", "bzr+"))):
                continue
            name_match = re.match(r"([A-Za-z0-9_.-]+)\s*@\s*", spec)
            egg_match = re.search(r"[#&]egg=([A-Za-z0-9_.-]+)", spec)
            name = name_match.group(1) if name_match else egg_match.group(1) if egg_match else None
            if not name:
                continue
            observations.append(
                {
                    "root_path": str(root),
                    "ecosystem": "pypi",
                    "package_name": name,
                    "normalized_name": normalize_package_name("pypi", name),
                    "version": _version_from_direct_reference(name, spec),
                    "has_install_script": True,
                    "script_kinds": ["direct-url"],
                    "scripts_sha256": sha256_json({"direct_reference": spec}),
                    "evidence_source": "direct-url",
                    "source_files": [str(path)],
                }
            )
    return observations


def _version_from_direct_reference(name: str, spec: str) -> str:
    archive = re.search(
        rf"{re.escape(name)}[-_]([0-9][A-Za-z0-9.!+_-]*)\.(?:tar\.gz|tar\.bz2|tar\.xz|tgz|zip|whl)(?:[?#]|$)",
        spec,
        flags=re.IGNORECASE,
    )
    return archive.group(1) if archive else "direct-reference"


def _evidence_source(source_type: str | None) -> str:
    if source_type == "npm-lockfile":
        return "package-lock"
    if source_type in {"npm-node_modules", "pnpm-node_modules"}:
        return "installed-tree"
    if source_type == "uv-lockfile":
        return "sdist-heuristic"
    if source_type == "requirements-manifest":
        return "direct-url"
    return source_type or "unknown"


def _compare_observation(observation: dict, *, exact, previous, has_baseline: bool) -> dict | None:
    current_has = observation.get("has_install_script")
    if exact is not None:
        old_has = _nullable_bool(exact["has_install_script"])
        if old_has is False and current_has is True:
            return _signal("install-script-added", SignalGrade.BEHAVIORAL_HIGH, observation, exact)
        old_hash = exact["scripts_sha256"]
        new_hash = observation.get("scripts_sha256")
        if old_hash and new_hash and old_hash != new_hash:
            return _signal("install-script-body-changed", SignalGrade.BEHAVIORAL_HIGH, observation, exact)
        return None
    if previous is not None:
        if _nullable_bool(previous["has_install_script"]) is False and current_has is True:
            return _signal("install-script-added", SignalGrade.BEHAVIORAL_HIGH, observation, previous)
        return None
    if current_has is True:
        grade = SignalGrade.BEHAVIORAL_WATCH if has_baseline else SignalGrade.INFO
        return _signal("new-dep-with-install-script", grade, observation, None)
    return None


def _nullable_bool(value: int | None) -> bool | None:
    return None if value is None else bool(value)


def _signal(signal_type: str, grade: SignalGrade, observation: dict, previous) -> dict:
    posture = grade_to_posture(grade)
    descriptions = {
        "install-script-added": "This dependency now declares install-time code where the previous observation did not.",
        "install-script-body-changed": "Install-time script content changed without a package version change; verify lockfile and installed-tree integrity.",
        "new-dep-with-install-script": "A newly observed dependency can execute code during installation; review the package source and parent chain.",
    }
    return {
        "signal_type": signal_type,
        "signal_grade": grade.value,
        "posture": posture,
        "posture_rank": {"act_now": 0, "fix_this_week": 1, "watch": 2}.get(posture, 9),
        "ecosystem": observation["ecosystem"],
        "package_name": observation["package_name"],
        "normalized_name": observation["normalized_name"],
        "version": observation["version"],
        "previous_version": previous["version"] if previous is not None else None,
        "evidence_source": observation["evidence_source"],
        "script_kinds": observation.get("script_kinds") or [],
        "source_files": sorted(set(observation.get("source_files") or [])),
        "explanation": descriptions[signal_type],
    }
