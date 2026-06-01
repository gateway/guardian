"""Shared utility helpers for JSON, NDJSON, timestamps, package normalization, and slug formatting."""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator, List
from urllib.parse import quote


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def read_ndjson(path: Path) -> Iterator[dict]:
    decoder = json.JSONDecoder()
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            index = 0
            while index < len(line):
                while index < len(line) and line[index].isspace():
                    index += 1
                if index >= len(line):
                    break
                record, offset = decoder.raw_decode(line, index)
                yield record
                index = offset


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def print_json(payload: dict) -> None:
    sys.stdout.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")


def normalize_ecosystem_for_osv(ecosystem: str) -> str:
    mapping = {
        "npm": "npm",
        "pypi": "PyPI",
        "go": "Go",
        "rubygems": "RubyGems",
        "packagist": "Packagist",
    }
    if ecosystem not in mapping:
        raise ValueError(f"unsupported ecosystem for OSV: {ecosystem}")
    return mapping[ecosystem]


def normalize_ecosystem_for_ghsa(ecosystem: str) -> str:
    mapping = {
        "npm": "npm",
        "pypi": "pip",
        "go": "go",
        "rubygems": "rubygems",
        "packagist": "composer",
    }
    if ecosystem not in mapping:
        raise ValueError(f"unsupported ecosystem for GHSA: {ecosystem}")
    return mapping[ecosystem]


def normalize_package_name(ecosystem: str, name: str) -> str:
    if ecosystem == "pypi":
        return re.sub(r"[-_.]+", "-", name).lower()
    return name.lower()


@dataclass
class ResolvedPackageSpec:
    ecosystem: str
    name: str
    version: str
    original_spec: str


def parse_npm_spec(spec: str) -> tuple[str, str | None]:
    if spec.startswith("@"):
        slash = spec.find("/")
        at = spec.rfind("@")
        if at > slash:
            return spec[:at], spec[at + 1 :]
        return spec, None
    if "@" in spec:
        name, version = spec.rsplit("@", 1)
        if name:
            return name, version
    return spec, None


def parse_pip_spec(spec: str) -> tuple[str, str | None]:
    if "==" in spec:
        name, version = spec.split("==", 1)
        return name.strip(), version.strip()
    return spec.strip(), None


def slugify(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]+", "-", value).strip("-").lower()


def chunked(items: List[dict], size: int) -> Iterable[List[dict]]:
    for index in range(0, len(items), size):
        yield items[index : index + size]


def encode_affects(package: str, version: str) -> str:
    return f"{package}@{version}"


def quote_package_path(package: str) -> str:
    return quote(package, safe="")
