"""Bounded live registry and OSV checks used by the pre-install gate."""

from __future__ import annotations

from dataclasses import replace
from urllib.parse import quote

from .config import GuardianConfig
from .http_client import GuardianHttp
from .osv_matching import osv_record_is_malicious
from .signals import SignalGrade
from .sources import OSVClient
from .util import quote_package_path


NPM_LIFECYCLE_SCRIPTS = {"preinstall", "install", "postinstall", "prepare", "preprepare", "postprepare"}


def registry_metadata(
    config: GuardianConfig,
    ecosystem: str,
    name: str,
    version: str | None,
) -> tuple[dict | None, dict]:
    """Fetch one bounded registry response for install-time inspection."""

    if ecosystem == "npm":
        selector = quote(version, safe="") if version else "latest"
        url = f"{config.npm_registry_url.rstrip('/')}/{quote_package_path(name)}/{selector}"
    else:
        suffix = f"/{quote(version, safe='')}" if version else ""
        url = f"{config.pypi_registry_url.rstrip('/')}/{quote(name, safe='')}{suffix}/json"
    request_config = replace(
        config,
        request_timeout_seconds=max(
            0.05,
            min(float(config.request_timeout_seconds), config.preinstall_gate_max_seconds),
        ),
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


def registry_latest_version(ecosystem: str, payload: dict) -> str | None:
    """Read the latest concrete version from either registry response shape."""

    if ecosystem == "npm":
        return payload.get("version")
    return (payload.get("info") or {}).get("version")


def registry_install_signals(
    ecosystem: str,
    name: str,
    version: str | None,
    payload: dict,
) -> list[dict]:
    """Describe install-time behavior visible in current registry metadata."""

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
    return [{
        "signal_type": "registry-install-script",
        "signal_grade": SignalGrade.BEHAVIORAL_WATCH.value,
        "source": "registry",
        "install_script_kinds": install_kinds,
        "explanation": (
            f"Registry metadata for {name}@{version or 'latest'} declares install-time behavior: "
            f"{', '.join(install_kinds)}."
        ),
    }]


def osv_signals(
    config: GuardianConfig,
    ecosystem: str,
    name: str,
    version: str,
) -> tuple[list[dict], dict]:
    """Query OSV for one exact version and grade malicious records separately."""

    request_config = replace(
        config,
        request_timeout_seconds=max(
            0.05,
            min(float(config.request_timeout_seconds), config.preinstall_gate_max_seconds),
        ),
        http_max_retries=0,
    )
    client = OSVClient(request_config)
    try:
        result = client.query_batch([
            {"ecosystem": ecosystem, "package_name": name, "version": version}
        ])
    except Exception as exc:
        return [], {"status": "error", "network": True, "error": str(exc)}
    vulnerabilities = (result[0] if result else {}).get("vulns") or []
    signals = []
    for vulnerability in vulnerabilities:
        malicious = osv_record_is_malicious(vulnerability)
        advisory_id = vulnerability.get("id")
        signals.append({
            "signal_type": "malicious-package-match" if malicious else "known-vulnerability",
            "signal_grade": SignalGrade.CATALOG_MATCH.value if malicious else SignalGrade.ADVISORY.value,
            "source": "osv-malicious" if malicious else "osv",
            "id": advisory_id,
            "url": f"https://osv.dev/vulnerability/{quote(str(advisory_id or ''), safe='')}",
            "explanation": (
                f"OSV/OpenSSF identifies {name}@{version} as malicious ({advisory_id})."
                if malicious
                else f"OSV reports {advisory_id} for {name}@{version}."
            ),
        })
    return signals, {"status": "queried", "network": True, "match_count": len(signals)}
