"""Offline lockfile tamper and dependency-pinning hygiene detection."""

from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import urlparse

from .config import GuardianConfig
from .db import Database
from .integrity import sha256_json
from .inventory_native.walker import PYTHON_REQUIREMENTS_PATTERN, candidate_files
from .signals import SignalGrade, grade_to_posture
from .util import normalize_package_name


def detect_lockfile_hygiene(config: GuardianConfig, db: Database, root_path: str) -> list[dict]:
    """Compare current offline evidence with the prior ledger and emit only deltas."""

    previous = db.lockfile_hygiene_state(root_path)
    observations = _package_observations(config, db, root_path)
    observations.extend(_requirements_observations(root_path))
    signals: list[dict] = []
    has_baseline = bool(previous) or db.has_prior_inventory_run(root_path)
    for observation in observations:
        prior = previous.get(observation["observation_key"])
        kind = observation["kind"]
        changed = prior is None or prior.get("evidence_hash") != observation["evidence_hash"]
        if not changed:
            continue
        if kind == "integrity" and prior is not None:
            signals.append(_signal(
                "integrity-changed-without-version-change",
                SignalGrade.BEHAVIORAL_HIGH,
                observation,
                "The recorded integrity hash changed while package name and version stayed the same.",
                previous_value=prior.get("value"),
            ))
        elif kind == "rogue-host":
            signals.append(_signal(
                "unexpected-resolved-host",
                SignalGrade.BEHAVIORAL_HIGH,
                observation,
                f"The lockfile resolves this package from unapproved host {observation['host']}.",
            ))
        elif kind == "direct-reference" and prior is None:
            grade = SignalGrade.BEHAVIORAL_WATCH if has_baseline else SignalGrade.INFO
            signals.append(_signal(
                "direct-dependency-reference",
                grade,
                observation,
                "This dependency uses a direct URL, VCS, file, or non-registry source; verify ownership and pinning.",
            ))
        elif kind == "unpinned-requirements":
            signals.append(_signal(
                "unpinned-python-requirements",
                SignalGrade.INFO,
                observation,
                f"This requirements file contains {observation['count']} unpinned dependency entries.",
            ))
        elif kind == "inconsistent-hash-mode":
            signals.append(_signal(
                "inconsistent-python-hash-mode",
                SignalGrade.INFO,
                observation,
                "Some requirements use --hash pins while others do not, so hash-checking is incomplete.",
            ))
    db.replace_lockfile_hygiene_state(root_path, observations)
    return sorted(
        signals,
        key=lambda item: (
            item["posture_rank"],
            item["package_name"].lower(),
            item["signal_type"],
        ),
    )


def _package_observations(config: GuardianConfig, db: Database, root_path: str) -> list[dict]:
    allowed_hosts = {item.lower().rstrip(".") for item in config.allowed_registry_hosts}
    observations = []
    for row in db.current_packages_for_root(root_path):
        try:
            record = json.loads(row["raw_json"])
        except (TypeError, json.JSONDecodeError):
            continue
        metadata = record.get("raw_metadata") or {}
        identity = "|".join([
            row["ecosystem"], row["normalized_name"], row["version"], row["source_file"] or "",
        ])
        common = {
            "ecosystem": row["ecosystem"],
            "package_name": row["package_name"],
            "normalized_name": row["normalized_name"],
            "version": row["version"],
            "source_files": [row["source_file"]] if row["source_file"] else [],
        }
        integrity = metadata.get("integrity")
        if integrity:
            observations.append(_observation(f"integrity|{identity}", "integrity", str(integrity), common))
        resolved = str(metadata.get("resolved") or "")
        host = _resolved_host(resolved)
        rogue_host = bool(row["ecosystem"] == "npm" and host and host not in allowed_hosts)
        if rogue_host:
            observations.append(_observation(
                f"rogue-host|{identity}",
                "rogue-host",
                resolved,
                {**common, "host": host},
            ))
        if metadata.get("direct_reference") and not rogue_host:
            observations.append(_observation(
                f"direct-reference|{identity}",
                "direct-reference",
                resolved or row["version"],
                common,
            ))
    return observations


def _requirements_observations(root_path: str) -> list[dict]:
    root = Path(root_path).resolve()
    observations = []
    for path in candidate_files(root, include_installed=False):
        if not PYTHON_REQUIREMENTS_PATTERN.match(path.name):
            continue
        entries = _requirement_entries(path)
        if not entries:
            continue
        relative = _relative_path(root, path)
        unpinned = [item for item in entries if not _is_exact_pin(item)]
        hashed = [item for item in entries if "--hash=" in item]
        common = {
            "ecosystem": "pypi",
            "package_name": relative,
            "normalized_name": normalize_package_name("pypi", relative),
            "version": None,
            "source_files": [str(path)],
        }
        if unpinned:
            observations.append(_observation(
                f"requirements-unpinned|{relative}",
                "unpinned-requirements",
                {"entries": unpinned},
                {**common, "count": len(unpinned)},
            ))
        if hashed and len(hashed) < len(entries):
            observations.append(_observation(
                f"requirements-hash-mode|{relative}",
                "inconsistent-hash-mode",
                {"hashed": len(hashed), "total": len(entries)},
                {**common, "count": len(entries) - len(hashed)},
            ))
        for index, entry in enumerate(entries, start=1):
            if _is_direct_requirement(entry):
                observations.append(_observation(
                    f"requirements-direct|{relative}|{index}",
                    "direct-reference",
                    entry,
                    {**common, "package_name": _requirement_name(entry) or relative},
                ))
    return observations


def _requirement_entries(path: Path) -> list[str]:
    """Join continuations and ignore pip options/includes before classifying entries."""

    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    joined: list[str] = []
    pending = ""
    for raw in lines:
        stripped = re.sub(r"\s+#.*$", "", raw.strip())
        if not stripped:
            continue
        pending = f"{pending} {stripped}".strip()
        if pending.endswith("\\"):
            pending = pending[:-1].strip()
            continue
        if not pending.startswith("-"):
            joined.append(pending)
        pending = ""
    if pending and not pending.startswith("-"):
        joined.append(pending)
    return joined


def _is_exact_pin(entry: str) -> bool:
    requirement = entry.split(";", 1)[0].split(" --hash=", 1)[0].strip()
    return re.match(r"^[A-Za-z0-9_.-]+(?:\[[^]]+\])?==[^=\s]+$", requirement) is not None


def _is_direct_requirement(entry: str) -> bool:
    lowered = entry.lower()
    return " @ " in lowered or lowered.startswith(("git+", "http://", "https://", "file:"))


def _requirement_name(entry: str) -> str | None:
    match = re.match(r"^([A-Za-z0-9_.-]+)(?:\[[^]]+\])?\s+@\s+", entry)
    return match.group(1) if match else None


def _resolved_host(value: str) -> str | None:
    candidate = value
    for prefix in ("registry+", "sparse+", "git+"):
        if candidate.startswith(prefix):
            candidate = candidate[len(prefix) :]
    parsed = urlparse(candidate)
    return parsed.hostname.lower().rstrip(".") if parsed.hostname else None


def _observation(key: str, kind: str, value, common: dict) -> dict:
    return {
        "observation_key": key,
        "kind": kind,
        "value": value,
        "evidence_hash": sha256_json(value),
        **common,
    }


def _signal(
    signal_type: str,
    grade: SignalGrade,
    observation: dict,
    explanation: str,
    *,
    previous_value=None,
) -> dict:
    posture = grade_to_posture(grade) or "info"
    return {
        "signal_type": signal_type,
        "signal_grade": grade.value,
        "posture": posture,
        "posture_rank": {"act_now": 0, "fix_this_week": 1, "watch": 2, "info": 3}.get(posture, 9),
        "ecosystem": observation["ecosystem"],
        "package_name": observation["package_name"],
        "normalized_name": observation["normalized_name"],
        "version": observation.get("version"),
        "previous_version": None,
        "previous_value": previous_value,
        "evidence_source": "lockfile-hygiene",
        "source_files": observation.get("source_files") or [],
        "explanation": explanation,
    }


def _relative_path(root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(root).as_posix()
    except ValueError:
        return path.resolve().as_posix()
