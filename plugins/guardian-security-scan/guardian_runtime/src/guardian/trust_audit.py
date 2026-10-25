"""Read-only, offline certificate inventory. Never import inspected packages."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import ssl
import stat
import sys

from .inventory_native.pypi import parse_python_metadata
from .inventory_native.walker import DEFAULT_EXCLUDES

EVIDENCE_PATH = Path(__file__).resolve().parents[3] / "data/trust_audit_emudhra.json"
MAX_BYTES = 4 * 1024 * 1024
STATUSES = ("demonstrated_failure", "review_candidate", "no_matching_findings", "unverified")
SKIP_DIRS = DEFAULT_EXCLUDES | {"node_modules", "site-packages", "dist-packages", "__pycache__", "vendor"}
LIMITATIONS = (
    "Static inventory only; no TLS probes or demonstrated acceptance failures. "
    "Keychain/browser policy, revocation, runtime overrides, embedded binaries, "
    "archives and inherited system-site-packages are unverified. "
    "No matching findings means only no match in the inspected evidence, not safe TLS."
)


def read_file(path: Path) -> bytes:
    # Nonblocking open prevents a substituted FIFO from hanging the audit.
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_BYTES:
            raise ValueError("not a regular file or exceeds 4 MiB limit")
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("exceeds 4 MiB limit")
    return data


def inspect_bundle(path: Path, evidence: dict) -> dict:
    item = {"kind": "bundle", "path": str(path), "status": "unverified", "matches": []}
    try:
        data = read_file(path).decode("ascii")
        blocks = re.findall(r"-----BEGIN CERTIFICATE-----\s*(.*?)\s*-----END CERTIFICATE-----", data, re.S)
        if not blocks or len(blocks) != data.count("-----BEGIN CERTIFICATE-----") or len(blocks) != data.count("-----END CERTIFICATE-----"):
            raise ValueError("empty or malformed PEM bundle")
        fingerprints = set()
        for block in blocks:
            der = base64.b64decode(re.sub(r"\s", "", block), validate=True)
            # Validate X.509 encoding using stdlib SSL, without default stores or I/O.
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.load_verify_locations(cadata=ssl.DER_cert_to_PEM_cert(der))
            fingerprints.add(hashlib.sha256(der).hexdigest())
        item["matches"] = [cert for cert in evidence["certificates"] if cert["sha256"] in fingerprints]
        item["certificate_count"] = len(blocks)
        item["status"] = "review_candidate" if item["matches"] else "no_matching_findings"
        item["reason"] = "Incident root present; application use and distrust policy unverified." if item["matches"] else "No incident fingerprint matched."
    except (OSError, ValueError, ssl.SSLError) as exc:
        item["reason"] = str(exc)
    return item


def _version(value: str) -> tuple | None:
    # Deliberately do not guess at local, prerelease or vendor version semantics.
    return tuple(int(part) for part in value.split(".")) if re.fullmatch(r"\d+\.\d+\.\d+", value) else None


def inspect_package(record: dict, evidence: dict) -> dict:
    name, version = record["normalized_name"], record["version"]
    item = {"kind": "package", "path": record["source_file"], "name": name,
            "version": version, "status": "unverified", "reason": "Trust configuration not inferred from package presence."}
    rule = evidence["packages"].get(name)
    if rule:
        item["fixed_version"] = rule["fixed"]
        item["recommended_version"] = rule.get("recommended", rule["fixed"])
        parsed = _version(version)
        if parsed is not None:
            affected = parsed < _version(rule["fixed"]) and (not rule.get("introduced") or parsed >= _version(rule["introduced"]))
            item["status"] = "review_candidate" if affected else "no_matching_findings"
            item["reason"] = "Version precedes published fix; backports and actual bundle use unverified." if affected else "Version outside the evidence range; runtime trust still unverified."
        else:
            item["reason"] = "Non-release version cannot be compared reliably."
    return item


def discover_environments(root: Path, items: list[dict]) -> list[Path]:
    environments = []
    def onerror(exc):
        items.append({"kind": "discovery", "path": str(exc.filename), "status": "unverified", "reason": str(exc)})
    for current, dirs, files in os.walk(root, followlinks=False, onerror=onerror):
        path = Path(current)
        if path.name in SKIP_DIRS:
            dirs[:] = []
            continue
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not d.endswith((".dist-info", ".egg-info")) and not (path / d).is_symlink())
        if "pyvenv.cfg" in files:
            cfg = path / "pyvenv.cfg"
            if cfg.is_symlink():
                items.append({"kind": "discovery", "path": str(cfg), "status": "unverified", "reason": "Symlinked environment marker skipped."})
            else:
                environments.append(path)
            # Discover nested environments without traversing this environment's libraries.
            dirs[:] = [d for d in dirs if d not in {"lib", "lib64", "bin", "include", "share"}]
    return environments


def _glob(root: Path, pattern: str) -> list[Path]:
    return sorted(root.glob(pattern))


def known_locations() -> tuple[list[Path], list[Path]]:
    bundles = [Path("/etc/ssl/cert.pem")]
    sites = []
    for prefix in (Path("/opt/homebrew"), Path("/usr/local")):
        bundles.extend(prefix / suffix for suffix in (
            "etc/ca-certificates/cert.pem", "etc/openssl@3/cert.pem", "etc/openssl@1.1/cert.pem"))
        sites.extend(_glob(prefix, "lib/python*/site-packages"))
    for framework in ("Python", "PythonT"):
        versions = Path(f"/Library/Frameworks/{framework}.framework/Versions")
        sites.extend(_glob(versions, "*/lib/python*/site-packages"))
        bundles.extend(_glob(versions, "*/etc/openssl/cert.pem"))
    sites.extend(_glob(Path.home() / "Library/Python", "*/lib/python/site-packages"))
    return bundles, sites


def audit(root: str | None = None) -> dict:
    evidence = json.loads(read_file(EVIDENCE_PATH))
    items, environments = [], []
    bundles, sites = known_locations() if sys.platform == "darwin" else ([], [])
    if sys.platform != "darwin":
        items.append({"kind": "platform", "path": sys.platform, "status": "unverified", "reason": "Known macOS locations not inspected on this platform."})
    else:
        items.append({"kind": "configuration", "path": "macOS Keychain and runtime policy", "status": "unverified", "reason": "PEM inventory does not establish effective system or application trust."})
    if root is not None:
        root_path = Path(root).expanduser().resolve()
        if not root_path.is_dir():
            raise ValueError("--root must be an existing directory")
        environments = discover_environments(root_path, items)
        for environment in environments:
            found = []
            for pattern in ("lib/python*/site-packages", "lib64/python*/site-packages"):
                found.extend(p for p in _glob(environment, pattern) if not any(part.is_symlink() for part in (p, p.parent, p.parent.parent)))
            sites.extend(found)
            if not found:
                items.append({"kind": "environment", "path": str(environment), "status": "unverified", "reason": "No supported site-packages layout found."})
    relevant = set(evidence["packages"]) | {"requests", "urllib3", "truststore", "pip-system-certs", "python-certifi-win32"}
    for site in sorted(set(p.resolve() for p in sites)):
        try:
            entries = sorted(site.iterdir())
        except OSError as exc:
            items.append({"kind": "discovery", "path": str(site), "status": "unverified", "reason": str(exc)})
            continue
        installed = set()
        for entry in entries:
            if not entry.name.endswith((".dist-info", ".egg-info")):
                continue
            metadata = entry / ("METADATA" if entry.name.endswith(".dist-info") else "PKG-INFO")
            try:
                if entry.is_symlink():
                    raise ValueError("Symlinked metadata directory skipped")
                # The existing parser also reads these siblings. Bound them first.
                for path in (metadata, entry / "INSTALLER", entry / "direct_url.json"):
                    if path.is_symlink():
                        raise ValueError("Symlinked metadata skipped")
                    if path == metadata or path.exists():
                        read_file(path)
                records = parse_python_metadata(metadata, site)
                if not records:
                    raise ValueError("Missing or malformed package name/version")
                for record in records:
                    installed.add(record["normalized_name"])
                    if record["normalized_name"] in relevant:
                        items.append(inspect_package(record, evidence))
            except (OSError, ValueError) as exc:
                items.append({"kind": "metadata", "path": str(metadata), "status": "unverified", "reason": str(exc)})
        for relative in ("certifi/cacert.pem", "pip/_vendor/certifi/cacert.pem"):
            path = site / relative
            owner = "pip" if relative.startswith("pip/") else "certifi"
            if path.exists() or path.is_symlink() or owner in installed:
                bundles.append(path)
    seen = set()
    for bundle in sorted(bundles):
        # Known system bundle symlinks are common; inspect the resolved regular file.
        try:
            resolved = bundle.resolve()
        except (OSError, RuntimeError):
            resolved = bundle
        if resolved in seen:
            continue
        seen.add(resolved)
        items.append(inspect_bundle(bundle, evidence))
    counts = {status: sum(item["status"] == status for item in items) for status in STATUSES}
    status = "review_candidate" if counts["review_candidate"] else "unverified" if counts["unverified"] or not items else "no_matching_findings"
    return {"schema_version": 1, "status": status, "offline": True, "evidence": evidence,
            "root": root, "environments": [str(p) for p in environments], "counts": counts,
            "items": items, "limitations": LIMITATIONS}


def _safe(value: object) -> str:
    return str(value).encode("unicode_escape").decode("ascii")


def render_report(report: dict, *, markdown: bool = False) -> str:
    lines = [("# " if markdown else "") + "Guardian Trust Audit (offline)",
             ", ".join(f"{key.replace('_', ' ')}: {value}" for key, value in report["counts"].items()),
             f"Python environments: {len(report['environments'])}; evidence verified: {report['evidence']['verified_on']}"]
    visible = [item for item in report["items"] if markdown or item["status"] in {"review_candidate", "unverified"}]
    for item in visible if markdown else visible[:20]:
        lines.append(f"- {item['status']}: {_safe(item['path'])}: {_safe(item['reason'])}")
        if item.get("fixed_version"):
            lines.append(f"  Recommended {item['name']}: {item['recommended_version']} or later.")
    if not markdown and len(visible) > 20:
        lines.append(f"... {len(visible) - 20} more entries; use --json or --output for details.")
    lines.extend(["", report["limitations"], report["evidence"]["guidance"], "Official guidance:"])
    lines.extend(report["evidence"]["sources"])
    return "\n".join(lines) + "\n"


def run_cli(args) -> int:
    try:
        report = audit(args.root)
        if args.output:
            # Explicit output is the only write. Never overwrite input or existing reports.
            with Path(args.output).expanduser().open("x", encoding="utf-8") as stream:
                stream.write(render_report(report, markdown=True))
        print(json.dumps(report, indent=2) if args.json else render_report(report), end="\n" if args.json else "")
        return 0
    except (OSError, ValueError) as exc:
        if args.json:
            print(json.dumps({"status": "error", "error": str(exc)}))
        else:
            print(f"trust-audit: {_safe(exc)}", file=sys.stderr)
        return 2
