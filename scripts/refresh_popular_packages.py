#!/usr/bin/env python3
"""Refresh Guardian's reproducible npm and PyPI popularity snapshots."""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import tarfile
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIR = REPO_ROOT / "plugins" / "guardian-security-scan" / "data" / "popular_packages"
NPM_METADATA_URL = "https://registry.npmjs.org/download-counts/latest"
PYPI_DATA_URL = "https://hugovk.dev/top-pypi-packages/top-pypi-packages.min.json"
USER_AGENT = "guardian-popular-package-refresh/1.0"


def fetch(url: str) -> bytes:
    """Fetch one public dataset with Guardian's maintainer user agent."""

    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read()


def npm_packages(limit: int) -> dict:
    """Read ranked npm counts from the zero-dependency download-counts dataset."""

    metadata_bytes = fetch(NPM_METADATA_URL)
    metadata = json.loads(metadata_bytes)
    tarball_url = metadata["dist"]["tarball"]
    tarball = fetch(tarball_url)
    _verify_npm_integrity(tarball, metadata["dist"].get("integrity"))
    with tarfile.open(fileobj=io.BytesIO(tarball), mode="r:gz") as archive:
        member = archive.getmember("package/counts.json")
        stream = archive.extractfile(member)
        if stream is None:
            raise RuntimeError("download-counts tarball is missing package/counts.json")
        counts = json.load(stream)
    ranked = sorted(counts.items(), key=lambda item: (-int(item[1]), item[0]))[:limit]
    return _snapshot(
        ecosystem="npm",
        packages=[name for name, _count in ranked],
        source={
            "dataset": "download-counts",
            "dataset_version": metadata["version"],
            "metadata_url": NPM_METADATA_URL,
            "artifact_url": tarball_url,
            "artifact_sha256": hashlib.sha256(tarball).hexdigest(),
            "repository": "https://github.com/nice-registry/download-counts",
            "declared_license": metadata.get("license") or "not-declared",
        },
    )


def pypi_packages(limit: int) -> dict:
    """Read PyPI's public BigQuery-derived monthly popularity snapshot."""

    data = fetch(PYPI_DATA_URL)
    payload = json.loads(data)
    names = [row["project"] for row in payload.get("rows", [])[:limit]]
    return _snapshot(
        ecosystem="pypi",
        packages=names,
        source={
            "dataset": "top-pypi-packages",
            "dataset_version": payload.get("last_update"),
            "artifact_url": PYPI_DATA_URL,
            "artifact_sha256": hashlib.sha256(data).hexdigest(),
            "repository": "https://github.com/hugovk/top-pypi-packages",
            "declared_license": "not-declared",
            "upstream_source": payload.get("source"),
        },
    )


def _verify_npm_integrity(artifact: bytes, integrity: str | None) -> None:
    if not integrity or not integrity.startswith("sha512-"):
        raise RuntimeError("download-counts metadata is missing sha512 integrity")
    expected = base64.b64decode(integrity.split("-", 1)[1])
    if hashlib.sha512(artifact).digest() != expected:
        raise RuntimeError("download-counts tarball integrity mismatch")


def _snapshot(*, ecosystem: str, packages: list[str], source: dict) -> dict:
    return {
        "schema_version": "1.0",
        "ecosystem": ecosystem,
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "source": source,
        "packages": [
            {"name": name, "rank": rank}
            for rank, name in enumerate(packages, start=1)
        ],
    }


def write_snapshot(name: str, payload: dict) -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    path = OUTPUT_DIR / f"{name}.json"
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {len(payload['packages'])} packages to {path}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=5000)
    parser.add_argument("--ecosystem", choices=["npm", "pypi", "all"], default="all")
    args = parser.parse_args()
    if args.limit < 500:
        parser.error("--limit must be at least 500")
    if args.ecosystem in {"npm", "all"}:
        write_snapshot("npm", npm_packages(args.limit))
    if args.ecosystem in {"pypi", "all"}:
        write_snapshot("pypi", pypi_packages(args.limit))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
