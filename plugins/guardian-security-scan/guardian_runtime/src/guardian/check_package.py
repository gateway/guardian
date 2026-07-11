"""Bounded pre-install package checks for CLI and agent hooks."""

from __future__ import annotations

import hashlib
import json
import queue
import re
import threading
import time
from dataclasses import replace
from pathlib import Path
from urllib.parse import quote

from .config import GuardianConfig
from .db import Database
from .http_client import GuardianHttp
from .signals import SignalGrade
from .sources import LocalCatalogMatcher, OSVClient
from .typosquat import detect_typosquat
from .util import normalize_package_name, quote_package_path


NPM_LIFECYCLE_SCRIPTS = {"preinstall", "install", "postinstall", "prepare", "preprepare", "postprepare"}
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

    cache_context = _cache_context(config)
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
    if _blocked_by_grade(config, signals):
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
    if _remaining(started, budget) > 0:
        registry_payload, registry_status = _bounded_source_call(
            _remaining(started, budget),
            _registry_metadata,
            config,
            ecosystem,
            name,
            resolved_version,
        )
        sources["registry"] = registry_status
        if registry_payload is None:
            source_errors = True
        else:
            resolved_version = resolved_version or _registry_latest_version(ecosystem, registry_payload)
            signals.extend(_registry_install_signals(ecosystem, name, resolved_version, registry_payload))
    else:
        sources["registry"] = {"status": "skipped-budget", "network": True}
        source_errors = True

    if resolved_version and not catalog_matches:
        catalog_matches = _local_catalog_signals(config, ecosystem, name, resolved_version)
        signals.extend(catalog_matches)
        sources["local_catalog"]["status"] = "matched" if catalog_matches else "checked"
    if _blocked_by_grade(config, signals):
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
            _osv_signals,
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
    if not source_errors:
        db.upsert_package_verdict(ecosystem, normalized_name, cache_key_version, payload)
    return payload


def exit_code_for_verdict(payload: dict) -> int:
    return VERDICT_EXIT_CODES[payload["verdict"]]


def local_package_verdict(
    config: GuardianConfig,
    db: Database,
    ecosystem: str,
    name: str,
    version: str | None,
    *,
    catalog_matcher: LocalCatalogMatcher | None = None,
) -> dict:
    """Evaluate all non-network package signals for command-wide hook preflight."""

    ecosystem = ecosystem.lower()
    if ecosystem not in {"npm", "pypi"}:
        raise ValueError(f"unsupported ecosystem: {ecosystem}")
    if not name.strip():
        raise ValueError("package name is required")
    requested_version = (version or "").strip()
    resolved_version = requested_version if _is_exact_version(requested_version) else None
    signals = detect_typosquat(ecosystem, name, db=db)
    signals.extend(
        _local_catalog_signals(
            config,
            ecosystem,
            name,
            resolved_version,
            catalog_matcher=catalog_matcher,
        )
    )
    if _blocked_by_grade(config, signals):
        verdict = "block"
        explanation = "Blocked by an exact malicious-package catalog match."
    elif signals:
        verdict = "warn"
        explanation = "Package name resembles a popular package; verify it before installation."
    else:
        verdict = "allow"
        explanation = "No local malicious-catalog or package-name signal was found."
    return {
        "verdict": verdict,
        "ecosystem": ecosystem,
        "name": name,
        "requested_version": requested_version or None,
        "resolved_version": resolved_version,
        "signals": signals,
        "explanation": explanation,
        "sources": {
            "typosquat": {"status": "checked", "network": False},
            "local_catalog": {
                "status": "matched" if any(item.get("signal_type") == "malicious-catalog-match" for item in signals) else "checked",
                "network": False,
            },
        },
        "cache_hit": False,
    }


def _local_catalog_signals(
    config: GuardianConfig,
    ecosystem: str,
    name: str,
    version: str | None,
    *,
    catalog_matcher: LocalCatalogMatcher | None = None,
) -> list[dict]:
    if not version:
        return []
    return [
        {
            "signal_type": "malicious-catalog-match",
            "signal_grade": SignalGrade.CATALOG_MATCH.value,
            "source": "local-catalog",
            "id": entry["id"],
            "catalog": entry.get("_catalog_file"),
            "name": entry.get("name"),
            "url": entry.get("source"),
            "explanation": f"Exact package/version match in Guardian catalog: {entry.get('name') or entry['id']}.",
        }
        for entry in (catalog_matcher or LocalCatalogMatcher(config)).match(ecosystem, name, version)
        if entry.get("source_type") != "official-advisory-db"
    ]


def _registry_metadata(
    config: GuardianConfig,
    ecosystem: str,
    name: str,
    version: str | None,
) -> tuple[dict | None, dict]:
    if ecosystem == "npm":
        selector = quote(version, safe="") if version else "latest"
        url = f"{config.npm_registry_url.rstrip('/')}/{quote_package_path(name)}/{selector}"
    else:
        suffix = f"/{quote(version, safe='')}" if version else ""
        url = f"{config.pypi_registry_url.rstrip('/')}/{quote(name, safe='')}{suffix}/json"
    request_config = replace(
        config,
        request_timeout_seconds=max(0.05, min(float(config.request_timeout_seconds), config.preinstall_gate_max_seconds)),
        http_max_retries=0,
    )
    result = GuardianHttp(request_config).get(url)
    if result.error:
        return None, {"status": "error", "network": True, "error": result.error}
    try:
        return result.json(), {
            "status": "cached" if result.from_cache else "queried",
            "network": not result.from_cache,
            "from_cache": result.from_cache,
        }
    except Exception as exc:
        return None, {"status": "error", "network": True, "error": str(exc)}


def _registry_latest_version(ecosystem: str, payload: dict) -> str | None:
    if ecosystem == "npm":
        return payload.get("version")
    return (payload.get("info") or {}).get("version")


def _registry_install_signals(
    ecosystem: str,
    name: str,
    version: str | None,
    payload: dict,
) -> list[dict]:
    install_kinds: list[str] = []
    if ecosystem == "npm":
        scripts = payload.get("scripts") if isinstance(payload.get("scripts"), dict) else {}
        install_kinds = sorted(set(scripts) & NPM_LIFECYCLE_SCRIPTS)
    elif version:
        files = (payload.get("releases") or {}).get(version) or payload.get("urls") or []
        has_wheel = any(item.get("packagetype") == "bdist_wheel" for item in files)
        has_sdist = any(item.get("packagetype") == "sdist" for item in files)
        if has_sdist and not has_wheel:
            install_kinds = ["sdist-install"]
    if not install_kinds:
        return []
    return [
        {
            "signal_type": "registry-install-script",
            "signal_grade": SignalGrade.BEHAVIORAL_WATCH.value,
            "source": "registry",
            "install_script_kinds": install_kinds,
            "explanation": f"Registry metadata for {name}@{version or 'latest'} declares install-time behavior: {', '.join(install_kinds)}.",
        }
    ]


def _osv_signals(
    config: GuardianConfig,
    ecosystem: str,
    name: str,
    version: str,
) -> tuple[list[dict], dict]:
    request_config = replace(
        config,
        request_timeout_seconds=max(0.05, min(float(config.request_timeout_seconds), config.preinstall_gate_max_seconds)),
        http_max_retries=0,
    )
    client = OSVClient(request_config)
    try:
        result = client.query_batch([{"ecosystem": ecosystem, "package_name": name, "version": version}])
    except Exception as exc:
        return [], {"status": "error", "network": True, "error": str(exc)}
    vulnerabilities = (result[0] if result else {}).get("vulns") or []
    signals = [
        {
            "signal_type": "known-vulnerability",
            "signal_grade": SignalGrade.ADVISORY.value,
            "source": "osv",
            "id": vulnerability.get("id"),
            "url": f"https://osv.dev/vulnerability/{quote(str(vulnerability.get('id') or ''), safe='')}",
            "explanation": f"OSV reports {vulnerability.get('id')} for {name}@{version}.",
        }
        for vulnerability in vulnerabilities
    ]
    return signals, {"status": "queried", "network": True, "match_count": len(signals)}


def _blocked_by_grade(config: GuardianConfig, signals: list[dict]) -> bool:
    blocked = set(config.preinstall_gate_block_grades)
    return any(signal.get("signal_grade") in blocked for signal in signals)


def _remaining(started: float, budget: float) -> float:
    reserve = min(0.05, budget * 0.1)
    return max(0.0, budget - reserve - (time.perf_counter() - started))


def _is_exact_version(value: str) -> bool:
    """Reject tags and ranges so OSV only receives concrete package versions."""

    return bool(value) and re.match(r"^v?\d", value) is not None and not re.search(r"[<>=~^*|,\s]", value)


def _cache_context(config: GuardianConfig) -> str:
    """Bind cached decisions to local malicious intelligence and block policy."""

    catalog_state = []
    for directory in sorted(config.local_catalog_dirs):
        for path in sorted(Path(directory).glob("*.json")):
            try:
                stat = path.stat()
            except OSError:
                continue
            catalog_state.append((str(path), stat.st_size, stat.st_mtime_ns))
    payload = {
        "block_grades": sorted(config.preinstall_gate_block_grades),
        "catalog_state": catalog_state,
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()


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
