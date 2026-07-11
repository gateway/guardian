"""Registry adapters that normalize npm and PyPI metadata into one contract."""

from __future__ import annotations

import hashlib
import json
from urllib.parse import quote

from .config import GuardianConfig
from .http_client import GuardianHttp
from .util import normalize_package_name, quote_package_path, utc_now


NPM_INSTALL_SCRIPTS = {"preinstall", "install", "postinstall", "prepare", "preprepare", "postprepare"}


class RegistryMetadataClient:
    """Fetch exact-version registry records and discard unneeded source fields."""

    def __init__(self, config: GuardianConfig):
        self.config = config
        self.http = GuardianHttp(config)

    def fetch(self, ecosystem: str, package_name: str, version: str) -> dict:
        """Fetch and normalize one immutable package-version record."""

        if ecosystem == "npm":
            url = f"{self.config.npm_registry_url.rstrip('/')}/{quote_package_path(package_name)}"
        elif ecosystem == "pypi":
            url = (
                f"{self.config.pypi_registry_url.rstrip('/')}/"
                f"{quote(package_name, safe='')}/{quote(version, safe='')}/json"
            )
        else:
            raise ValueError(f"registry intelligence does not support {ecosystem}")
        result = self.http.get(url)
        if result.error:
            raise RuntimeError(result.error)
        payload = result.json()
        if ecosystem == "npm":
            return normalize_npm_metadata(package_name, version, payload)
        return normalize_pypi_metadata(package_name, version, payload)


def normalize_npm_metadata(package_name: str, version: str, payload: dict) -> dict:
    """Normalize npm's package-wide document for an exact requested version."""

    versions = payload.get("versions") or {}
    version_payload = versions.get(version)
    if not isinstance(version_payload, dict):
        raise RuntimeError(f"npm registry metadata does not contain {package_name}@{version}")
    maintainers = version_payload.get("maintainers") or payload.get("maintainers") or []
    maintainer_ids = sorted(
        {
            "|".join(
                filter(
                    None,
                    [
                        str(item.get("name") or "").strip().lower(),
                        str(item.get("email") or "").strip().lower(),
                    ],
                )
            )
            for item in maintainers
            if isinstance(item, dict) and (item.get("name") or item.get("email"))
        }
    )
    dist = version_payload.get("dist") or {}
    scripts = version_payload.get("scripts") if isinstance(version_payload.get("scripts"), dict) else {}
    return {
        "ecosystem": "npm",
        "package_name": package_name,
        "normalized_name": normalize_package_name("npm", package_name),
        "version": version,
        "latest_version": (payload.get("dist-tags") or {}).get("latest"),
        "published_at": (payload.get("time") or {}).get(version),
        "maintainers_hash": _stable_hash(maintainer_ids) if maintainer_ids else None,
        "maintainer_count": len(maintainer_ids),
        "provenance_present": bool(dist.get("attestations")),
        "deprecated": bool(version_payload.get("deprecated")),
        "deprecated_message": version_payload.get("deprecated"),
        "yanked": False,
        "repo_url": _repository_url(version_payload.get("repository") or payload.get("repository")),
        "size_bytes": _optional_int(dist.get("unpackedSize")),
        "license": _license_value(version_payload.get("license") or payload.get("license")),
        "has_install_script": bool(set(scripts) & NPM_INSTALL_SCRIPTS),
        "fetched_at": utc_now(),
        "source": "npm-registry",
    }


def normalize_pypi_metadata(package_name: str, version: str, payload: dict) -> dict:
    """Normalize PyPI's exact-release document while preserving unknown fields as null."""

    info = payload.get("info") or {}
    files = payload.get("urls") or (payload.get("releases") or {}).get(version) or []
    upload_times = sorted(
        str(item.get("upload_time_iso_8601") or item.get("upload_time"))
        for item in files
        if item.get("upload_time_iso_8601") or item.get("upload_time")
    )
    project_urls = info.get("project_urls") or {}
    repo_url = next(
        (
            project_urls.get(key)
            for key in ("Source", "Source Code", "Repository", "Homepage", "Home")
            if project_urls.get(key)
        ),
        info.get("home_page"),
    )
    return {
        "ecosystem": "pypi",
        "package_name": package_name,
        "normalized_name": normalize_package_name("pypi", package_name),
        "version": version,
        "latest_version": info.get("version"),
        "published_at": upload_times[0] if upload_times else None,
        "maintainers_hash": None,
        "maintainer_count": None,
        "provenance_present": None,
        "deprecated": False,
        "yanked": any(bool(item.get("yanked")) for item in files),
        "yanked_reason": next((item.get("yanked_reason") for item in files if item.get("yanked_reason")), None),
        "repo_url": _repository_url(repo_url),
        "size_bytes": sum(_optional_int(item.get("size")) or 0 for item in files) or None,
        "license": _license_value(info.get("license")),
        "has_install_script": None,
        "fetched_at": utc_now(),
        "source": "pypi-registry",
    }


def _repository_url(value) -> str | None:
    """Canonicalize common npm/PyPI repository URL forms for stable comparisons."""

    if isinstance(value, dict):
        value = value.get("url")
    if not isinstance(value, str) or not value.strip():
        return None
    normalized = value.strip()
    if normalized.startswith("git+"):
        normalized = normalized[4:]
    if normalized.endswith(".git"):
        normalized = normalized[:-4]
    return normalized.rstrip("/")


def _stable_hash(values: list[str]) -> str:
    return hashlib.sha256(json.dumps(values, separators=(",", ":")).encode()).hexdigest()


def _optional_int(value) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _license_value(value) -> str | None:
    if isinstance(value, str):
        return value.strip() or None
    if isinstance(value, dict):
        candidate = value.get("type")
        return str(candidate).strip() if candidate else None
    return None
