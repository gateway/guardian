"""Changed-package registry metadata collection and behavioral drift signals."""

from __future__ import annotations

from datetime import datetime, timezone

from .config import GuardianConfig
from .db import Database
from .registry_metadata import RegistryMetadataClient
from .signals import SignalGrade, grade_to_posture


def detect_registry_metadata_changes(
    config: GuardianConfig,
    db: Database,
    root_path: str,
    run_ids: list[int],
    *,
    include_baseline: bool = False,
) -> dict:
    """Fetch only newly observed versions and emit one-time registry drift signals."""

    candidates = [
        dict(row)
        for row in db.changed_package_versions_for_runs(
            root_path,
            run_ids,
            include_baseline=include_baseline,
        )
    ]
    candidates.sort(
        key=lambda item: (
            -int(item.get("direct_dependency") or 0),
            item["ecosystem"],
            item["normalized_name"],
            item["version"],
        )
    )
    limit = max(0, int(config.registry_intel_max_packages))
    selected = candidates[:limit] if limit else []
    client = RegistryMetadataClient(config)
    signals: list[dict] = []
    errors: list[dict] = []
    fetched = cache_hits = prior_fetched = 0

    for candidate in selected:
        current = db.registry_metadata(
            candidate["ecosystem"],
            candidate["normalized_name"],
            candidate["version"],
            ttl_seconds=config.registry_metadata_ttl_seconds,
        )
        if current is None:
            try:
                current = client.fetch(candidate["ecosystem"], candidate["package_name"], candidate["version"])
            except Exception as exc:
                errors.append({
                    "ecosystem": candidate["ecosystem"],
                    "package": candidate["package_name"],
                    "version": candidate["version"],
                    "error": str(exc),
                })
                continue
            db.upsert_registry_metadata(current)
            fetched += 1
        else:
            cache_hits += 1

        previous = None
        previous_version = None
        for prior_version in db.prior_package_versions(
            root_path,
            candidate["ecosystem"],
            candidate["normalized_name"],
            candidate["version"],
            run_ids,
        ):
            previous = db.registry_metadata(
                candidate["ecosystem"],
                candidate["normalized_name"],
                prior_version,
            )
            if previous is None:
                try:
                    previous = client.fetch(candidate["ecosystem"], candidate["package_name"], prior_version)
                except Exception as exc:
                    errors.append({
                        "ecosystem": candidate["ecosystem"],
                        "package": candidate["package_name"],
                        "version": prior_version,
                        "error": str(exc),
                        "context": "prior-version",
                    })
                    continue
                db.upsert_registry_metadata(previous)
                prior_fetched += 1
            previous_version = prior_version
            break

        signals.extend(
            _metadata_signals(
                config,
                candidate,
                current,
                previous,
                previous_version=previous_version,
            )
        )

    signals.sort(
        key=lambda item: (
            item["posture_rank"],
            item["package_name"].lower(),
            item["signal_type"],
        )
    )
    if errors and not selected:
        status = "error"
    elif errors:
        status = "partial"
    elif not candidates:
        status = "skipped-unchanged"
    else:
        status = "ok"
    return {
        "status": status,
        "candidates": len(candidates),
        "selected": len(selected),
        "truncated": max(0, len(candidates) - len(selected)),
        "metadata_fetched": fetched,
        "prior_metadata_fetched": prior_fetched,
        "metadata_cache_hits": cache_hits,
        "signals": signals,
        "errors": errors,
        "http_stats": client.http.stats(),
    }


def preinstall_registry_signals(config: GuardianConfig, metadata: dict) -> list[dict]:
    """Return current-version registry warnings suitable for the bounded install gate."""

    signals = []
    age_hours = _age_hours(metadata.get("published_at"))
    if age_hours is not None and 0 <= age_hours < config.registry_recent_release_hours:
        signals.append({
            "signal_type": "version-published-recently",
            "signal_grade": SignalGrade.BEHAVIORAL_WATCH.value,
            "source": "registry-state-cache",
            "explanation": f"This release was published about {age_hours:.1f} hours ago.",
        })
    if metadata.get("deprecated"):
        signals.append({
            "signal_type": "package-deprecated",
            "signal_grade": SignalGrade.INFO.value,
            "source": "registry-state-cache",
            "explanation": f"The registry marks this release deprecated: {metadata.get('deprecated_message') or 'no reason supplied'}.",
        })
    if metadata.get("yanked"):
        signals.append({
            "signal_type": "release-yanked",
            "signal_grade": SignalGrade.INFO.value,
            "source": "registry-state-cache",
            "explanation": f"PyPI marks this release yanked: {metadata.get('yanked_reason') or 'no reason supplied'}.",
        })
    if metadata.get("has_install_script"):
        signals.append({
            "signal_type": "registry-install-script",
            "signal_grade": SignalGrade.BEHAVIORAL_WATCH.value,
            "source": "registry-state-cache",
            "explanation": "Cached registry metadata records install-time lifecycle behavior for this version.",
        })
    return signals


def _metadata_signals(
    config: GuardianConfig,
    candidate: dict,
    current: dict,
    previous: dict | None,
    *,
    previous_version: str | None,
) -> list[dict]:
    signals = []
    age_hours = _age_hours(current.get("published_at"))
    if candidate.get("had_prior_inventory") and age_hours is not None and 0 <= age_hours < config.registry_recent_release_hours:
        signals.append(
            _signal(
                candidate,
                "version-published-recently",
                SignalGrade.BEHAVIORAL_WATCH,
                f"This newly observed version was published about {age_hours:.1f} hours ago.",
                previous_version,
                {"release_age_hours": round(age_hours, 3), "published_at": current.get("published_at")},
            )
        )
    if previous and previous.get("maintainers_hash") and current.get("maintainers_hash"):
        if previous["maintainers_hash"] != current["maintainers_hash"]:
            signals.append(
                _signal(
                    candidate,
                    "maintainer-set-changed",
                    SignalGrade.BEHAVIORAL_WATCH,
                    "The registry maintainer set differs from the previously observed package version.",
                    previous_version,
                )
            )
    if previous and previous.get("provenance_present") is True and current.get("provenance_present") is False:
        signals.append(
            _signal(
                candidate,
                "provenance-disappeared",
                SignalGrade.BEHAVIORAL_HIGH,
                "The previous npm version exposed registry attestations but this version does not.",
                previous_version,
            )
        )
    if current.get("deprecated"):
        signals.append(
            _signal(
                candidate,
                "package-deprecated",
                SignalGrade.INFO,
                f"The registry marks this release deprecated: {current.get('deprecated_message') or 'no reason supplied'}.",
                previous_version,
            )
        )
    if current.get("yanked"):
        signals.append(
            _signal(
                candidate,
                "release-yanked",
                SignalGrade.INFO,
                f"PyPI marks this release yanked: {current.get('yanked_reason') or 'no reason supplied'}.",
                previous_version,
            )
        )
    current_repo = current.get("repo_url")
    previous_repo = previous.get("repo_url") if previous else None
    if not current_repo:
        signals.append(
            _signal(
                candidate,
                "repo-url-missing-or-changed",
                SignalGrade.INFO,
                "The registry metadata does not publish a source repository URL for this version.",
                previous_version,
            )
        )
    elif previous_repo and current_repo != previous_repo:
        signals.append(
            _signal(
                candidate,
                "repo-url-missing-or-changed",
                SignalGrade.INFO,
                f"The registry repository URL changed from {previous_repo} to {current_repo}.",
                previous_version,
                {"previous_repo_url": previous_repo, "repo_url": current_repo},
            )
        )
    return signals


def _signal(
    candidate: dict,
    signal_type: str,
    grade: SignalGrade,
    explanation: str,
    previous_version: str | None,
    extra: dict | None = None,
) -> dict:
    posture = grade_to_posture(grade) or "info"
    return {
        "signal_type": signal_type,
        "signal_grade": grade.value,
        "posture": posture,
        "posture_rank": {"act_now": 0, "fix_this_week": 1, "watch": 2, "info": 3}.get(posture, 9),
        "ecosystem": candidate["ecosystem"],
        "package_name": candidate["package_name"],
        "normalized_name": candidate["normalized_name"],
        "version": candidate["version"],
        "previous_version": previous_version,
        "evidence_source": "registry-metadata",
        "source_files": [],
        "explanation": explanation,
        **(extra or {}),
    }


def _age_hours(value: str | None) -> float | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - parsed).total_seconds() / 3600
