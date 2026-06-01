from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import Any, Dict, List


PROJECT_ROOT = Path(__file__).resolve().parents[2]
STATE_DIR = Path(os.getenv("GUARDIAN_STATE_DIR", str(PROJECT_ROOT / "state"))).expanduser()
SEED_CATALOG_DIR = Path(
    os.getenv("GUARDIAN_SEED_CATALOG_DIR", str(PROJECT_ROOT / "data" / "local_catalogs"))
).expanduser()
DEFAULT_CONFIG_PATH = STATE_DIR / "config.json"


def default_development_roots() -> List[str]:
    raw = os.getenv("GUARDIAN_DEVELOPMENT_ROOTS")
    if raw:
        return [item.strip() for item in raw.split(os.pathsep) if item.strip()]
    return [str(Path.cwd())]


@dataclass
class GuardianConfig:
    development_roots: List[str] = field(default_factory=default_development_roots)
    local_catalog_dirs: List[str] = field(
        default_factory=lambda: [str(STATE_DIR / "local_catalogs")]
    )
    db_path: str = str(STATE_DIR / "guardian.db")
    exports_dir: str = str(STATE_DIR / "exports")
    reports_dir: str = str(STATE_DIR / "reports")
    scans_dir: str = str(STATE_DIR / "scans")
    threat_intel_sources_path: str = str(STATE_DIR / "threat_intel_sources.json")
    threat_intel_cache_dir: str = str(STATE_DIR / "source_cache")
    inventory_engine: str = "guardian-native"
    inventory_native_supported_ecosystems: List[str] = field(
        default_factory=lambda: ["npm", "pypi"]
    )
    request_timeout_seconds: int = 20
    blocked_severities: List[str] = field(
        default_factory=lambda: ["critical", "high"]
    )
    ghsa_api_url: str = "https://api.github.com/advisories"
    osv_api_url: str = "https://api.osv.dev/v1/querybatch"
    osv_vuln_api_url: str = "https://api.osv.dev/v1/vulns"
    nvd_api_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    kev_catalog_url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    kev_human_url: str = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
    epss_api_url: str = "https://api.first.org/data/v1/epss"
    epss_high_percentile: float = 0.95
    epss_high_score: float = 0.2
    user_agent: str = "guardian/0.1.0"

    @classmethod
    def from_dict(cls, raw: Dict[str, Any]) -> "GuardianConfig":
        known = {item.name for item in fields(cls)}
        return cls(**{key: value for key, value in raw.items() if key in known})

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def ensure_state_dirs(config: GuardianConfig) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    for path in [
        config.exports_dir,
        config.reports_dir,
        config.scans_dir,
        config.threat_intel_cache_dir,
        *config.local_catalog_dirs,
    ]:
        Path(path).mkdir(parents=True, exist_ok=True)
    seed_local_catalogs(config)


def seed_local_catalogs(config: GuardianConfig) -> None:
    """Copy bundled public catalogs into user state without overwriting local edits."""

    if not SEED_CATALOG_DIR.exists() or not config.local_catalog_dirs:
        return
    destination = Path(config.local_catalog_dirs[0])
    destination.mkdir(parents=True, exist_ok=True)
    for source in SEED_CATALOG_DIR.glob("*.json"):
        target = destination / source.name
        if not target.exists():
            shutil.copyfile(source, target)


def load_config(path: Path | None = None) -> GuardianConfig:
    config_path = path or DEFAULT_CONFIG_PATH
    if not config_path.exists():
        config = GuardianConfig()
        ensure_state_dirs(config)
        save_config(config, config_path)
        return config
    data = json.loads(config_path.read_text())
    config = GuardianConfig.from_dict(data)
    ensure_state_dirs(config)
    return config


def save_config(config: GuardianConfig, path: Path | None = None) -> None:
    config_path = path or DEFAULT_CONFIG_PATH
    ensure_state_dirs(config)
    config_path.write_text(json.dumps(config.to_dict(), indent=2, sort_keys=True))


def github_token() -> str | None:
    token = os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN")
    if token:
        return token.strip()
    try:
        result = subprocess.run(
            ["gh", "auth", "token"],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (subprocess.SubprocessError, OSError):
        return None
    fallback = result.stdout.strip()
    return fallback or None
