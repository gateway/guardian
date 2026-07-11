#!/usr/bin/env python3
"""Build or verify Guardian's bundled catalog SHA-256 manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
PLUGIN_ROOT = REPO_ROOT / "plugins" / "guardian-security-scan"
CATALOG_DIR = PLUGIN_ROOT / "data" / "local_catalogs"
MANIFEST_PATH = PLUGIN_ROOT / "data" / "catalog_manifest.json"


def build_manifest() -> dict:
    version = json.loads((PLUGIN_ROOT / ".claude-plugin" / "plugin.json").read_text())["version"]
    files = []
    for path in sorted(CATALOG_DIR.glob("*.json")):
        body = path.read_bytes()
        files.append({"name": path.name, "sha256": hashlib.sha256(body).hexdigest(), "size": len(body)})
    return {
        "schema_version": "1.0",
        "plugin_version": version,
        "remote_base_url": "https://raw.githubusercontent.com/gateway/guardian/main/plugins/guardian-security-scan/data/local_catalogs",
        "files": files,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    expected = json.dumps(build_manifest(), indent=2, sort_keys=True) + "\n"
    if args.check:
        actual = MANIFEST_PATH.read_text(encoding="utf-8") if MANIFEST_PATH.exists() else ""
        if actual != expected:
            raise SystemExit("catalog manifest is stale; run scripts/build_catalog_manifest.py")
        print("catalog manifest is current")
        return 0
    MANIFEST_PATH.write_text(expected, encoding="utf-8")
    print(f"wrote {MANIFEST_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
