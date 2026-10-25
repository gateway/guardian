"""Static Node installation inventory, including Homebrew's separate libnode.

Headers are installation metadata, not proof of the running executable's version.
Embedded PEM matches prove presence only; absence cannot prove effective trust.
"""

import base64
import hashlib
import os
from pathlib import Path
import re
import ssl

from .trust_audit_io import read_file

MAX_NODE_BYTES = 128 * 1024 * 1024
PEM = re.compile(rb"-----BEGIN CERTIFICATE-----\s*([A-Za-z0-9+/=\r\n]+?)\s*-----END CERTIFICATE-----")


def known_node_locations() -> list[Path]:
    paths = [Path("/opt/homebrew/bin/node"), Path("/usr/local/bin/node")]
    for prefix in (Path("/opt/homebrew"), Path("/usr/local")):
        paths.extend(prefix.glob("Cellar/node*/*/bin/node"))
    for pattern in (".nvm/versions/node/*/bin/node", ".volta/tools/image/node/*/bin/node",
                    ".asdf/installs/nodejs/*/bin/node", ".local/share/fnm/node-versions/*/installation/bin/node",
                    "Library/Application Support/fnm/node-versions/*/installation/bin/node"):
        paths.extend(Path.home().glob(pattern))
    # Read candidates only. Never launch PATH entries or version-manager shims.
    for directory in os.get_exec_path():
        if Path(directory).is_absolute():
            paths.append(Path(directory) / "node")
    return [p for p in paths if p.exists() or p.is_symlink()]


def inspect_node(path: Path, evidence: dict) -> dict:
    item = {"kind": "node_runtime", "path": str(path), "status": "unverified", "version_status": "unverified",
            "matches": [], "reason": "Node installation metadata and embedded PEM only; effective runtime trust unverified.",
            "inspection_errors": [], "inspected_files": []}
    binary, prefix = path, path.parent
    try:
        binary = path.resolve()
        prefix = binary.parent.parent if binary.parent.name == "bin" else binary.parent
        item["resolved_path"] = str(binary)
        header = prefix / "include/node/node_version.h"
        if header.exists():
            text = read_file(header).decode("ascii")
            parts = [re.search(rf"^#define NODE_{part}_VERSION\s+(\d{{1,6}})\s*$", text, re.M)
                     for part in ("MAJOR", "MINOR", "PATCH")]
            if all(parts):
                version = tuple(int(p.group(1)) for p in parts)
                item["version"] = ".".join(map(str, version))
                item["version_source"] = str(header)
                rule = evidence.get("node", {}).get("fixed_by_major", {}).get(str(version[0]))
                if rule:
                    item["fixed_version"] = rule
                    item["recommended_version"] = rule
                    item["version_status"] = "review_candidate" if version < tuple(map(int, rule.split("."))) else "no_matching_findings"
                    item["status"] = "review_candidate" if item["version_status"] == "review_candidate" else "unverified"
                    item["reason"] = ("Installation header version precedes this Node release line's certificate fix."
                                      if item["status"] == "review_candidate" else
                                      "Installation header version meets this Node release line's certificate fix; binary provenance and runtime trust unverified.")
                else:
                    item["reason"] = "No verified fixed version for this Node major in the evidence snapshot; review a supported release line."
            else:
                item["inspection_errors"].append("Malformed Node version header")
    except (OSError, ValueError, RuntimeError) as exc:
        item["inspection_errors"].append(str(exc))
        # Still inspect the resolved binary/library if its header was malformed.
    files = [binary]
    # Homebrew links a small launcher to a separate library containing the roots.
    files.extend(sorted((prefix / "lib").glob("libnode*.dylib")))
    fingerprints = set()
    for file in dict.fromkeys(files):
        try:
            data = read_file(file, MAX_NODE_BYTES)
            item["inspected_files"].append(str(file))
            for block in PEM.findall(data):
                try:
                    der = base64.b64decode(re.sub(rb"\s", b"", block), validate=True)
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    context.load_verify_locations(cadata=ssl.DER_cert_to_PEM_cert(der))
                    fingerprints.add(hashlib.sha256(der).hexdigest())
                except (ValueError, ssl.SSLError):
                    item["inspection_errors"].append(f"{file}: malformed embedded certificate")
        except (OSError, ValueError) as exc:
            item["inspection_errors"].append(f"{file}: {exc}")
    item["embedded_certificate_count"] = len(fingerprints)
    item["matches"] = [c for c in evidence["certificates"] if c["sha256"] in fingerprints]
    if item["matches"]:
        item["status"] = "review_candidate"
        item["reason"] = "Incident certificate embedded in Node installation files; active binary, store selection and distrust policy unverified."
        if item.get("version") and not item.get("fixed_version"):
            item["reason"] += " No verified fixed version for this major in the snapshot; review a supported release line."
    elif item["inspection_errors"]:
        # Never turn an incomplete inspection into a clean result.
        if item["status"] != "review_candidate":
            item["status"] = "unverified"
        item["reason"] += " Some installation files could not be inspected."
    item["embedded_pem_status"] = "review_candidate" if item["matches"] else "unverified"
    if not item["matches"]:
        item["reason"] += " No incident fingerprint was found in extracted PEM; this does not verify the complete runtime trust store."
    return item
