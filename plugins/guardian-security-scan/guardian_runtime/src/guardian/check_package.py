"""Bounded pre-install package checks for CLI and agent hooks."""

from __future__ import annotations

import queue
import threading
import time

from .config import GuardianConfig
from .db import Database
from .package_local_checks import (
    blocked_by_grade,
    local_catalog_signals,
    local_package_verdict,
    package_cache_context,
)
from .package_source_checks import (
    osv_signals as query_osv_signals,
    registry_install_signals,
    registry_latest_version,
    registry_metadata,
)
from .registry_intel import preinstall_registry_signals
from .signals import SignalGrade
from .util import normalize_package_name


VERDICT_EXIT_CODES = {"allow": 0, "warn": 1, "block": 2}


def check_package(
    config: GuardianConfig,
    db: Database,
    ecosystem: str,
    name: str,
    version: str | None = None,
    *,
    max_seconds: float | None = None,
    local_result: dict | None = None,
) -> dict:
    """Return a cacheable allow/warn/block verdict within a strict time budget."""

    started = time.perf_counter()
    ecosystem = ecosystem.lower()
    if ecosystem not in {"npm", "pypi"}:
        raise ValueError(f"unsupported ecosystem: {ecosystem}")
    if not name.strip():
        raise ValueError("package name is required")
    name = name.strip()
    requested_version = (version or "").strip()
    normalized_name = normalize_package_name(ecosystem, name)
    cache_key_version = requested_version
    if not config.preinstall_gate_enabled:
        return _finalize(
            ecosystem=ecosystem,
            name=name,
            requested_version=requested_version or None,
            resolved_version=requested_version or None,
            signals=[],
            sources={},
            verdict="allow",
            explanation="Guardian pre-install gate is disabled in local configuration.",
            started=started,
            disabled=True,
            cache_context=None,
        )

    cache_context = package_cache_context(config, db, ecosystem, normalized_name, requested_version)
    cached = db.cached_package_verdict(
        ecosystem,
        normalized_name,
        cache_key_version,
        ttl_seconds=config.preinstall_gate_cache_ttl_seconds,
        cache_context=cache_context,
    )
    if cached is not None:
        cached["elapsed_seconds"] = round(time.perf_counter() - started, 4)
        return cached

    budget = float(max_seconds if max_seconds is not None else config.preinstall_gate_max_seconds)
    if budget <= 0:
        raise ValueError("max_seconds must be greater than zero")
    local = local_result or local_package_verdict(config, db, ecosystem, name, requested_version or None)
    signals = list(local["signals"])
    sources: dict[str, dict] = {
        "typosquat": {"status": "checked", "network": False},
        "local_catalog": {"status": "pending", "network": False},
        "registry": {"status": "pending", "network": True},
        "osv": {"status": "pending", "network": True},
    }
    resolved_version = local["resolved_version"]
    catalog_matches = [item for item in signals if item.get("signal_type") == "malicious-catalog-match"]
    sources["local_catalog"]["status"] = "matched" if catalog_matches else "checked"
    if blocked_by_grade(config, signals):
        payload = _finalize(
            ecosystem=ecosystem,
            name=name,
            requested_version=requested_version or None,
            resolved_version=resolved_version,
            signals=signals,
            sources=sources,
            verdict="block",
            explanation="Blocked by an exact malicious-package catalog match.",
            started=started,
            cache_context=cache_context,
        )
        db.upsert_package_verdict(ecosystem, normalized_name, cache_key_version, payload)
        return payload

    source_errors = False
    registry_payload = None
    cached_registry_metadata = (
        db.registry_metadata(
            ecosystem,
            normalized_name,
            resolved_version,
            ttl_seconds=config.registry_metadata_ttl_seconds,
        )
        if resolved_version
        else None
    )
    if cached_registry_metadata is not None:
        signals.extend(preinstall_registry_signals(config, cached_registry_metadata))
        sources["registry"] = {
            "status": "state-cache",
            "network": False,
            "fetched_at": cached_registry_metadata.get("fetched_at"),
        }
    elif _remaining(started, budget) > 0:
        registry_payload, registry_status = _bounded_source_call(
            _remaining(started, budget),
            registry_metadata,
            config,
            ecosystem,
            name,
            resolved_version,
        )
        sources["registry"] = registry_status
        if registry_payload is None:
            source_errors = True
        else:
            resolved_version = resolved_version or registry_latest_version(ecosystem, registry_payload)
            signals.extend(registry_install_signals(ecosystem, name, resolved_version, registry_payload))
    else:
        sources["registry"] = {"status": "skipped-budget", "network": True}
        source_errors = True

    if resolved_version and not catalog_matches:
        catalog_matches = local_catalog_signals(config, ecosystem, name, resolved_version)
        signals.extend(catalog_matches)
        sources["local_catalog"]["status"] = "matched" if catalog_matches else "checked"
    if blocked_by_grade(config, signals):
        payload = _finalize(
            ecosystem=ecosystem,
            name=name,
            requested_version=requested_version or None,
            resolved_version=resolved_version,
            signals=signals,
            sources=sources,
            verdict="block",
            explanation="Blocked by an exact malicious-package catalog match.",
            started=started,
            cache_context=cache_context,
        )
        db.upsert_package_verdict(ecosystem, normalized_name, cache_key_version, payload)
        return payload

    if resolved_version and _remaining(started, budget) > 0:
        osv_result, osv_status = _bounded_source_call(
            _remaining(started, budget),
            query_osv_signals,
            config,
            ecosystem,
            name,
            resolved_version,
        )
        osv_signals = osv_result or []
        signals.extend(osv_signals)
        sources["osv"] = osv_status
        source_errors = source_errors or osv_status["status"] not in {"queried", "cached"}
    else:
        sources["osv"] = {
            "status": "skipped-no-version" if not resolved_version else "skipped-budget",
            "network": True,
        }
        source_errors = True

    if source_errors:
        signals.append(
            {
                "signal_type": "source-coverage-incomplete",
                "signal_grade": SignalGrade.INFO.value,
                "source": "network",
                "explanation": "One or more live checks were unavailable; Guardian is failing open with a warning.",
            }
        )
    if blocked_by_grade(config, signals):
        verdict = "block"
        explanation = "Blocked by OSV/OpenSSF malicious-package evidence for this exact version."
    else:
        verdict = "warn" if signals else "allow"
        explanation = _explanation(verdict, signals, source_errors)
    payload = _finalize(
        ecosystem=ecosystem,
        name=name,
        requested_version=requested_version or None,
        resolved_version=resolved_version,
        signals=signals,
        sources=sources,
        verdict=verdict,
        explanation=explanation,
        started=started,
        cache_context=cache_context,
    )
    if not source_errors or verdict == "block":
        db.upsert_package_verdict(ecosystem, normalized_name, cache_key_version, payload)
    return payload


def exit_code_for_verdict(payload: dict) -> int:
    return VERDICT_EXIT_CODES[payload["verdict"]]


def _remaining(started: float, budget: float) -> float:
    reserve = min(0.05, budget * 0.1)
    return max(0.0, budget - reserve - (time.perf_counter() - started))


def _bounded_source_call(timeout: float, function, *args) -> tuple[object | None, dict]:
    """Run one live source call without allowing DNS or TLS to exceed the gate budget."""

    if timeout <= 0:
        return None, {"status": "skipped-budget", "network": True}
    results: queue.Queue = queue.Queue()

    def worker() -> None:
        try:
            results.put(("ok", function(*args)), block=False)
        except Exception as exc:  # Network/source errors become fail-open evidence.
            results.put(("error", str(exc)), block=False)

    thread = threading.Thread(target=worker, name="guardian-package-source", daemon=True)
    thread.start()
    try:
        state, value = results.get(timeout=timeout)
    except queue.Empty:
        return None, {"status": "timeout", "network": True, "error": "source check exceeded time budget"}
    if state == "error":
        return None, {"status": "error", "network": True, "error": value}
    return value


def _explanation(verdict: str, signals: list[dict], source_errors: bool) -> str:
    if verdict == "allow":
        return "No known advisory, malicious-catalog, typosquat, or install-behavior signal was found."
    if source_errors:
        return "Installation is allowed to continue, but Guardian could not complete every live check; review the warning signals."
    if any(signal.get("signal_type") == "typosquat-suspected" for signal in signals):
        return "Package name resembles a popular package. Verify spelling and publisher before installation."
    if any(signal.get("signal_type") == "known-vulnerability" for signal in signals):
        return "The requested version matches one or more published OSV advisories."
    return "Guardian found package behavior that should be reviewed before installation."


def _finalize(
    *,
    ecosystem: str,
    name: str,
    requested_version: str | None,
    resolved_version: str | None,
    signals: list[dict],
    sources: dict,
    verdict: str,
    explanation: str,
    started: float,
    disabled: bool = False,
    cache_context: str | None = None,
) -> dict:
    return {
        "verdict": verdict,
        "ecosystem": ecosystem,
        "name": name,
        "requested_version": requested_version,
        "resolved_version": resolved_version,
        "signals": signals,
        "explanation": explanation,
        "sources": sources,
        "disabled": disabled,
        "cache_context": cache_context,
        "cache_hit": False,
        "elapsed_seconds": round(time.perf_counter() - started, 4),
    }
