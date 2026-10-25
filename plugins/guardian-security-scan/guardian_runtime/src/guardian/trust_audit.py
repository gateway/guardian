"""Read-only, offline certificate inventory. Never import inspected packages."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import ssl
import sys

from .inventory_native.pypi import parse_python_metadata
from .inventory_native.walker import DEFAULT_EXCLUDES
from .trust_audit_io import read_file
from .trust_audit_node import inspect_node, known_node_locations

EVIDENCE_PATH = Path(__file__).resolve().parents[3] / "data/trust_audit_emudhra.json"
STATUSES = (
    "demonstrated_failure",
    "review_candidate",
    "no_matching_findings",
    "unverified",
)
SKIP_DIRS = DEFAULT_EXCLUDES | {
    "node_modules",
    "site-packages",
    "dist-packages",
    "__pycache__",
    "vendor",
}
MAX_DISCOVERY_DIRECTORIES = 10000
LIMITATIONS = (
    "Static inventory only; no TLS probes or demonstrated acceptance failures. "
    "Keychain/browser policy, revocation, runtime overrides, uninspected embedded binaries, "
    "archives and inherited system-site-packages are unverified. "
    "No matching findings means only no match in the inspected evidence, not safe TLS. "
    "This audit does not determine whether a device is compromised."
)


def inspect_bundle(path: Path, evidence: dict) -> dict:
    item = {
        "kind": "bundle",
        "path": str(path),
        "status": "unverified",
        "matches": [],
        "inspection_errors": [],
    }
    fingerprints = set()
    try:
        raw = read_file(path)
        data = raw.decode("ascii", errors="replace")
        if not raw.isascii():
            item["inspection_errors"].append("Non-ASCII bytes in PEM bundle")
        # Do not let an unterminated block consume the next valid certificate.
        blocks = re.findall(
            r"-----BEGIN CERTIFICATE-----\s*([^-]*?)\s*-----END CERTIFICATE-----",
            data,
            re.S,
        )
        if (
            not blocks
            or len(blocks) != data.count("-----BEGIN CERTIFICATE-----")
            or len(blocks) != data.count("-----END CERTIFICATE-----")
        ):
            item["inspection_errors"].append("Empty or malformed PEM bundle")
        for block in blocks:
            try:
                der = base64.b64decode(re.sub(r"\s", "", block), validate=True)
                # Validate X.509 encoding using stdlib SSL, without default stores or I/O.
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.load_verify_locations(cadata=ssl.DER_cert_to_PEM_cert(der))
                fingerprints.add(hashlib.sha256(der).hexdigest())
            except (ValueError, ssl.SSLError) as exc:
                item["inspection_errors"].append(str(exc))
    except (OSError, ValueError, ssl.SSLError) as exc:
        item["inspection_errors"].append(str(exc))
    item["matches"] = [
        cert for cert in evidence["certificates"] if cert["sha256"] in fingerprints
    ]
    item["certificate_count"] = len(fingerprints)
    item["status"] = (
        "review_candidate"
        if item["matches"]
        else "unverified"
        if item["inspection_errors"]
        else "no_matching_findings"
    )
    item["reason"] = (
        "Incident certificate present; application use and distrust policy unverified."
        if item["matches"]
        else "Bundle inspection incomplete."
        if item["inspection_errors"]
        else "No incident fingerprint matched."
    )
    if item["inspection_errors"]:
        item["reason"] += " " + "; ".join(item["inspection_errors"][:3])
    return item


def _version(value: str) -> tuple | None:
    # Deliberately do not guess at local, prerelease or vendor version semantics.
    if len(value) > 64 or not re.fullmatch(r"\d+(?:\.\d+){1,3}", value):
        return None
    parts = tuple(int(part) for part in value.split("."))
    return parts + (0,) * max(0, 3 - len(parts))


def inspect_package(
    record: dict, evidence: dict, python_version: str | None = None
) -> dict:
    name, version = record["normalized_name"], record["version"]
    item = {
        "kind": "package",
        "path": record["source_file"],
        "name": name,
        "version": version,
        "status": "unverified",
        "reason": "Trust configuration not inferred from package presence.",
    }
    rule = evidence["packages"].get(name)
    if rule:
        item["fixed_version"] = rule["fixed"]
        item["recommended_version"] = rule.get("recommended", rule["fixed"])
        parsed = _version(version)
        if parsed is not None:
            affected = parsed < _version(rule["fixed"]) and (
                not rule.get("introduced") or parsed >= _version(rule["introduced"])
            )
            item["status"] = "review_candidate" if affected else "no_matching_findings"
            item["reason"] = (
                "Version precedes published fix; backports and actual bundle use unverified."
                if affected
                else "Version outside the evidence range; runtime trust still unverified."
            )
        else:
            item["reason"] = "Non-release version cannot be compared reliably."
        if rule.get("minimum_python"):
            item["minimum_python"] = rule["minimum_python"]
            item["python_version"] = python_version
            parsed_python = _version(python_version or "")
            item["recommendation_compatibility"] = (
                "unknown"
                if parsed_python is None
                else "incompatible"
                if parsed_python < _version(rule["minimum_python"])
                else "compatible"
            )
            if item["recommendation_compatibility"] == "incompatible":
                item["reason"] += (
                    f" Recommended {name} requires Python >= {rule['minimum_python']}; "
                    f"this environment reports {python_version}. Plan a supported interpreter migration or a verified compatible fix; do not apply this recommendation directly."
                )
    return item


def discover_environments(
    root: Path,
    items: list[dict],
    *,
    excludes=(),
    nodes=None,
    summary=None,
    max_directories=MAX_DISCOVERY_DIRECTORIES,
) -> list[Path]:
    environments = []
    skip_dirs = SKIP_DIRS | set(excludes)
    if summary is None:
        summary = {"visited_directories": 0, "skipped_directories": 0}
    summary["complete"] = True

    def onerror(exc):
        summary["complete"] = False
        items.append(
            {
                "kind": "discovery",
                "path": str(exc.filename),
                "status": "unverified",
                "reason": str(exc),
            }
        )

    for current, dirs, files in os.walk(root, followlinks=False, onerror=onerror):
        path = Path(current)
        if summary["visited_directories"] >= max_directories:
            summary["complete"] = False
            items.append(
                {
                    "kind": "discovery",
                    "path": str(root),
                    "status": "unverified",
                    "reason": f"Discovery stopped at {max_directories} directories; choose narrower roots or raise --max-directories.",
                }
            )
            break
        summary["visited_directories"] += 1
        if path.name in skip_dirs:
            summary["skipped_directories"] += 1
            dirs[:] = []
            continue
        kept = sorted(
            d
            for d in dirs
            if d not in skip_dirs
            and not d.endswith((".dist-info", ".egg-info"))
            and not (path / d).is_symlink()
        )
        summary["skipped_directories"] += len(dirs) - len(kept)
        dirs[:] = kept
        if nodes is not None and path.name == "bin" and "node" in files:
            nodes.append(path / "node")
        if "pyvenv.cfg" in files:
            cfg = path / "pyvenv.cfg"
            if cfg.is_symlink():
                items.append(
                    {
                        "kind": "discovery",
                        "path": str(cfg),
                        "status": "unverified",
                        "reason": "Symlinked environment marker skipped.",
                    }
                )
            else:
                environments.append(path)
            # Discover nested environments without traversing this environment's libraries.
            kept = [
                d for d in dirs if d not in {"lib", "lib64", "bin", "include", "share"}
            ]
            summary["skipped_directories"] += len(dirs) - len(kept)
            dirs[:] = kept
    return environments


def environment_details(environment: Path) -> dict:
    detail = {
        "path": str(environment),
        "python_version": None,
        "include_system_site_packages": None,
    }
    try:
        text = read_file(environment / "pyvenv.cfg").decode("utf-8")
        fields = dict(line.split("=", 1) for line in text.splitlines() if "=" in line)
        fields = {k.strip(): v.strip() for k, v in fields.items()}
        version = fields.get("version", fields.get("version_info", ""))
        if _version(version) is not None:
            detail["python_version"] = version
        detail["include_system_site_packages"] = fields.get(
            "include-system-site-packages"
        )
    except (OSError, ValueError) as exc:
        detail["error"] = str(exc)
    return detail


def _glob(root: Path, pattern: str) -> list[Path]:
    return sorted(root.glob(pattern))


def known_locations() -> tuple[list[Path], list[Path]]:
    bundles = [Path("/etc/ssl/cert.pem")]
    sites = []
    for prefix in (Path("/opt/homebrew"), Path("/usr/local")):
        bundles.extend(
            prefix / suffix
            for suffix in (
                "etc/ca-certificates/cert.pem",
                "etc/openssl@3/cert.pem",
                "etc/openssl@1.1/cert.pem",
            )
        )
        sites.extend(_glob(prefix, "lib/python*/site-packages"))
    for framework in ("Python", "PythonT"):
        versions = Path(f"/Library/Frameworks/{framework}.framework/Versions")
        sites.extend(_glob(versions, "*/lib/python*/site-packages"))
        bundles.extend(_glob(versions, "*/etc/openssl/cert.pem"))
    sites.extend(_glob(Path.home() / "Library/Python", "*/lib/python/site-packages"))
    return bundles, sites


def collect_environment_sites(environments, environment_roots, sites, items):
    """Read environment metadata and associate supported library layouts."""
    details, site_environments = [], {}
    for environment in environments:
        detail = environment_details(environment)
        detail["roots"] = environment_roots[environment]
        details.append(detail)
        if detail.get("error"):
            items.append(
                {
                    "kind": "environment",
                    "path": str(environment),
                    "status": "unverified",
                    "reason": detail["error"],
                }
            )
        found = []
        for pattern in ("lib/python*/site-packages", "lib64/python*/site-packages"):
            found.extend(
                p
                for p in _glob(environment, pattern)
                if not any(part.is_symlink() for part in (p, p.parent, p.parent.parent))
            )
        sites.extend(found)
        for site in found:
            site_environments[site.resolve()] = detail
        if not found:
            items.append(
                {
                    "kind": "environment",
                    "path": str(environment),
                    "status": "unverified",
                    "reason": "No supported site-packages layout found.",
                }
            )
    return details, site_environments


def collect_packages(sites, site_environments, evidence, items, bundles):
    """Inspect installed metadata snapshots and locate each independent CA bundle."""
    relevant = set(evidence["packages"]) | {
        "requests",
        "urllib3",
        "httpx",
        "httpcore",
        "truststore",
        "pip-system-certs",
        "python-certifi-win32",
    }
    for site in sorted(set(p.resolve() for p in sites)):
        try:
            entries = sorted(site.iterdir())
        except OSError as exc:
            items.append(
                {
                    "kind": "discovery",
                    "path": str(site),
                    "status": "unverified",
                    "reason": str(exc),
                }
            )
            continue
        installed = set()
        for entry in entries:
            if not entry.name.endswith((".dist-info", ".egg-info")):
                continue
            metadata = entry / (
                "METADATA" if entry.name.endswith(".dist-info") else "PKG-INFO"
            )
            try:
                if entry.is_symlink():
                    raise ValueError("Symlinked metadata directory skipped")
                # The existing parser also reads these siblings. Bound them first.
                contents = {}
                for path in (metadata, entry / "INSTALLER", entry / "direct_url.json"):
                    if path.is_symlink():
                        raise ValueError("Symlinked metadata skipped")
                    if path == metadata or path.exists():
                        data = read_file(path)
                        contents[path.name] = data
                        if path.name == "direct_url.json":
                            direct = json.loads(data)
                            if not isinstance(direct, dict) or not isinstance(
                                direct.get("url", ""), str
                            ):
                                raise ValueError(
                                    "Malformed direct_url.json: expected an object with a string URL"
                                )
                records = parse_python_metadata(metadata, site, contents=contents)
                if not records:
                    raise ValueError("Missing or malformed package name/version")
                for record in records:
                    installed.add(record["normalized_name"])
                    if record["normalized_name"] in relevant:
                        detail = site_environments.get(site, {})
                        package = inspect_package(
                            record, evidence, detail.get("python_version")
                        )
                        if detail:
                            package["environment"] = detail["path"]
                        items.append(package)
            except (OSError, ValueError) as exc:
                items.append(
                    {
                        "kind": "metadata",
                        "path": str(metadata),
                        "status": "unverified",
                        "reason": str(exc),
                    }
                )
        for relative in ("certifi/cacert.pem", "pip/_vendor/certifi/cacert.pem"):
            path = site / relative
            owner = "pip" if relative.startswith("pip/") else "certifi"
            if path.exists() or path.is_symlink() or owner in installed:
                bundles.append(path)


def inspect_unique_paths(paths, inspector, evidence):
    """Inspect each resolved store once, preserving errors for unresolved links."""
    items, seen = [], set()
    for path in sorted(paths):
        try:
            resolved = path.resolve()
        except (OSError, RuntimeError):
            resolved = path
        if resolved not in seen:
            seen.add(resolved)
            items.append(inspector(path, evidence))
    return items


def audit(
    root: str | list[str] | None = None,
    *,
    node_paths=None,
    bundle_paths=None,
    excludes=(),
    max_directories=MAX_DISCOVERY_DIRECTORIES,
) -> dict:
    if max_directories < 1:
        raise ValueError("--max-directories must be positive")
    evidence = json.loads(read_file(EVIDENCE_PATH))
    items, environments = [], []
    bundles, sites = known_locations() if sys.platform == "darwin" else ([], [])
    absent_locations = [
        str(p) for p in bundles if not p.exists() and not p.is_symlink()
    ]
    bundles = [p for p in bundles if p.exists() or p.is_symlink()]
    bundles.extend(Path(p).expanduser().absolute() for p in (bundle_paths or []))
    nodes = known_node_locations() if sys.platform == "darwin" else []
    nodes.extend(Path(p).expanduser() for p in (node_paths or []))
    if any(
        not name or name in {".", ".."} or "/" in name or "\\" in name
        for name in excludes
    ):
        raise ValueError("--exclude must be a directory basename")
    requested = [root] if isinstance(root, str) else list(root or [])
    roots = list(dict.fromkeys(Path(p).expanduser().resolve() for p in requested))
    discovery, environment_roots = [], {}
    if sys.platform != "darwin":
        items.append(
            {
                "kind": "platform",
                "path": sys.platform,
                "status": "unverified",
                "reason": "Known macOS locations not inspected on this platform.",
            }
        )
    else:
        items.append(
            {
                "kind": "configuration",
                "path": "macOS Keychain and runtime policy",
                "status": "unverified",
                "reason": "PEM inventory does not establish effective system or application trust.",
            }
        )
    for root_path in roots:
        if not root_path.is_dir():
            raise ValueError("--root must be an existing directory")
        summary = {
            "path": str(root_path),
            "visited_directories": 0,
            "skipped_directories": 0,
        }
        discovery.append(summary)
        found_environments = discover_environments(
            root_path,
            items,
            excludes=excludes,
            nodes=nodes,
            summary=summary,
            max_directories=max_directories,
        )
        environments.extend(found_environments)
        for environment in found_environments:
            environment_roots.setdefault(environment, []).append(str(root_path))
    environments = sorted(set(environments))
    details, site_environments = collect_environment_sites(
        environments, environment_roots, sites, items
    )
    collect_packages(sites, site_environments, evidence, items, bundles)
    items.extend(inspect_unique_paths(bundles, inspect_bundle, evidence))
    items.extend(inspect_unique_paths(nodes, inspect_node, evidence))
    counts = {
        status: sum(item["status"] == status for item in items) for status in STATUSES
    }
    status = (
        "review_candidate"
        if counts["review_candidate"]
        else "unverified"
        if counts["unverified"] or not items
        else "no_matching_findings"
    )
    report = {
        "schema_version": 2,
        "status": status,
        "offline": True,
        "evidence": evidence,
        "root": requested[0] if len(requested) == 1 else None,
        "roots": [str(p) for p in roots],
        "discovery": discovery,
        "excluded_directory_names": sorted(SKIP_DIRS | set(excludes)),
        "absent_optional_locations": absent_locations,
        "environment_details": details,
        "environments": [str(p) for p in environments],
        "counts": counts,
        "items": items,
        "limitations": LIMITATIONS,
        "max_directories_per_root": max_directories,
    }
    report["overview"] = build_overview(report)
    return report


def build_overview(report: dict) -> dict:
    """Describe inspected development scope, never a whole-device security score."""

    def within(item, root):
        path = Path(item.get("resolved_path", item["path"]))
        return path == root or root in path.parents

    roots = [Path(p) for p in report["roots"]]
    scoped = []
    for root in roots:
        members = [i for i in report["items"] if within(i, root)]
        components = sum(
            i["kind"] in {"package", "bundle", "node_runtime"} for i in members
        )
        scoped.append(
            {
                "path": str(root),
                "evidence_entries": len(members),
                "inspected_components": components,
                "coverage": "inventory_only"
                if components
                else "no_supported_component_evidence",
                "review_candidates": sum(
                    i["status"] == "review_candidate" for i in members
                ),
                "unverified": sum(i["status"] == "unverified" for i in members),
                "python_environments": [
                    d["path"]
                    for d in report["environment_details"]
                    if str(root) in d["roots"]
                ],
            }
        )
    shared = [
        i
        for i in report["items"]
        if i["kind"] in {"package", "bundle", "node_runtime"}
        and not any(within(i, root) for root in roots)
    ]
    return {
        "assessment": "review_needed"
        if report["counts"]["review_candidate"]
        else "limited_inventory",
        "compromise_assessed": False,
        "tls_acceptance_tested": False,
        "discovery_complete": all(d["complete"] for d in report["discovery"]),
        "development_roots": scoped,
        "inspected_components": {
            kind: sum(i["kind"] == kind for i in report["items"])
            for kind in ("package", "bundle", "node_runtime")
        },
        "shared_tooling_review_candidates": sum(
            i["status"] == "review_candidate" for i in shared
        ),
        "note": "Evidence counts can overlap. Selected roots and known tooling only; no whole-device health or compromise verdict.",
    }


def _safe(value: object, *, markdown: bool = False) -> str:
    text = str(value).encode("unicode_escape").decode("ascii")
    if markdown:
        # Escape markup after terminal controls so inspected text stays literal.
        text = re.sub(r"([\\`*_{}\[\]()<>!#+.\-|&])", r"\\\1", text)
    return text


def render_report(report: dict, *, markdown: bool = False) -> str:
    def safe(value):
        return _safe(value, markdown=markdown)

    lines = [
        ("# " if markdown else "") + "Guardian Trust Audit (offline)",
        ", ".join(
            f"{key.replace('_', ' ')}: {value}"
            for key, value in report["counts"].items()
        ),
        f"Python environments: {len(report['environments'])}; evidence verified: {report['evidence']['verified_on']}",
    ]
    overview = report["overview"]
    lines.extend(
        [
            "",
            "Developer trust overview: " + overview["assessment"].replace("_", " "),
            "Compromise assessment: not performed. TLS acceptance: not tested.",
            "Discovery complete within configured scope: "
            + str(overview["discovery_complete"]).lower(),
            f"Shared tooling review entries: {overview['shared_tooling_review_candidates']}",
        ]
    )
    for root in overview["development_roots"]:
        lines.append(
            f"Development root: {safe(root['path'])}: {root['inspected_components']} inspected components, {root['review_candidates']} review entries, {root['unverified']} unverified entries"
        )
        if not root["inspected_components"]:
            lines.append(
                "  No supported component evidence found here; use guardian scan separately for project dependency advisories."
            )
    for detail in report.get("environment_details", []):
        lines.append(
            f"Environment: {safe(detail['path'])}; Python {safe(detail['python_version'] or 'unknown')}"
        )
    for discovery in report.get("discovery", []):
        lines.append(
            f"Root: {safe(discovery['path'])}; visited {discovery['visited_directories']} directories, skipped {discovery['skipped_directories']}"
        )
    if report.get("absent_optional_locations"):
        lines.append(
            f"Optional locations not installed: {len(report['absent_optional_locations'])} (not counted as unverified)"
        )
    visible = [
        item
        for item in report["items"]
        if markdown or item["status"] in {"review_candidate", "unverified"}
    ]
    for item in visible if markdown else visible[:20]:
        lines.append(
            f"- {item['status']}: {safe(item['path'])}: {safe(item['reason'])}"
        )
        if item.get("fixed_version"):
            name = item.get("name", "Node within this release line")
            lines.append(
                f"  Published fix for {name}: {safe(item['recommended_version'])} or later."
            )
            if item.get("minimum_python"):
                lines.append(
                    f"  Requires Python >= {item['minimum_python']}; compatibility: {item['recommendation_compatibility']}."
                )
    if not markdown and len(visible) > 20:
        lines.append(
            f"... {len(visible) - 20} more entries; use --json or --output for details."
        )
    lines.extend(
        [
            "",
            report["limitations"],
            report["evidence"]["guidance"],
            "Official guidance:",
        ]
    )
    lines.extend(report["evidence"]["sources"])
    return "\n".join(lines) + "\n"


def run_cli(args) -> int:
    try:
        report = audit(
            args.root,
            node_paths=args.node,
            bundle_paths=args.bundle,
            excludes=args.exclude,
            max_directories=args.max_directories,
        )
        if args.output:
            # Explicit output is the only write. Never overwrite input or existing reports.
            with Path(args.output).expanduser().open("x", encoding="utf-8") as stream:
                stream.write(render_report(report, markdown=True))
        print(
            json.dumps(report, indent=2) if args.json else render_report(report),
            end="\n" if args.json else "",
        )
        return 0
    except (OSError, ValueError, RuntimeError) as exc:
        if args.json:
            print(json.dumps({"status": "error", "error": str(exc)}))
        else:
            print(f"trust-audit: {_safe(exc)}", file=sys.stderr)
        return 2
