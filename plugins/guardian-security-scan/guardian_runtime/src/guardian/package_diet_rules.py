"""Package-diet classification and scoring with conservative replacement guardrails."""

from __future__ import annotations

import re


DO_NOT_REIMPLEMENT = {
    "bcrypt",
    "better-sqlite3",
    "electron",
    "electron-builder",
    "express",
    "fastapi",
    "jsonwebtoken",
    "next",
    "pg",
    "playwright",
    "react",
    "sharp",
    "stripe",
    "typescript",
    "vite",
    "vitest",
    "yaml",
    "zod",
}

REPLACEMENT_RECIPES = {
    "left-pad": {
        "confidence": "high",
        "example": "String(value).padStart(width, fill)",
        "note": "Native `String.padStart` usually replaces this safely for simple string padding.",
    },
    "is-number": {
        "confidence": "high",
        "example": "typeof value === 'number' && Number.isFinite(value)",
        "note": "Use native number checks unless string-coercion behavior is required.",
    },
    "is-odd": {
        "confidence": "high",
        "example": "Number.isInteger(value) && Math.abs(value % 2) === 1",
        "note": "Small numeric predicate; local code is usually clearer.",
    },
    "clsx": {
        "confidence": "medium",
        "example": "const cx = (...items) => items.flat().filter(Boolean).join(' ');",
        "note": "A tiny helper can work for simple cases; keep the package if object/array edge cases matter broadly.",
    },
    "classnames": {
        "confidence": "medium",
        "example": "const cx = (...items) => items.flat().filter(Boolean).join(' ');",
        "note": "A tiny helper can work for simple cases; keep the package if object/array edge cases matter broadly.",
    },
    "lodash": {
        "confidence": "medium",
        "example": "uniq: Array.from(new Set(items)); compact: items.filter(Boolean)",
        "note": "Only replace specific simple helpers. Do not rewrite complex lodash behavior without tests.",
    },
    "axios": {
        "confidence": "medium",
        "example": "const res = await fetch(url, options); if (!res.ok) throw new Error(`HTTP ${res.status}`);",
        "note": "Native `fetch` can replace simple calls, but interceptors, retries, upload progress, and defaults may justify keeping axios.",
    },
}

PERMISSIVE_LICENSE_PATTERNS = (
    r"(?:^|[^A-Z0-9])MIT(?:$|[^A-Z0-9])",
    r"(?:^|[^A-Z0-9])ISC(?:$|[^A-Z0-9])",
    r"(?:^|[^A-Z0-9])BSD(?:-[0-9A-Z.-]+)?(?:$|[^A-Z0-9])",
    r"(?:^|[^A-Z0-9])APACHE(?:-| )?2(?:\.0)?(?:$|[^A-Z0-9])",
)
COPYLEFT_LICENSE_MARKERS = ("GPL", "AGPL", "LGPL", "MPL", "EPL", "CDDL")


def assess_package(package: dict, usage: dict, symbols: list[str]) -> dict:
    del symbols
    name = package["normalized_name"]
    usage_count = int(usage.get("hit_count") or 0)
    if package.get("specifier", "").startswith("workspace:"):
        return _assessment(
            "Keep",
            "High",
            "high",
            "Workspace dependency; it may provide local bins, build graph wiring, or package-manager linking even without direct imports.",
            "Keep unless repo maintainers confirm the workspace package is no longer part of the build or release graph.",
        )
    if name.startswith("@types/"):
        return _assessment(
            "Keep",
            "High",
            "high",
            "Type declaration package; usage may be compiler-driven rather than direct source imports.",
            "Keep unless TypeScript reports it is unnecessary after a clean install and typecheck.",
        )
    if name in DO_NOT_REIMPLEMENT:
        return _assessment(
            "Keep",
            "High",
            "high",
            "Package does framework, binary, parsing, security, or tooling work that should not be casually reimplemented.",
            "Keep the package unless there is a separate security or maintenance reason to replace it.",
        )
    if usage_count == 0:
        if package["scope"] != "runtime":
            return _assessment(
                "Review",
                "Low",
                "medium",
                "No direct imports were found, but this is not a runtime dependency and may be used through scripts, config, CLIs, peer wiring, or package-manager behavior.",
                "Check package scripts, config files, and CI before removing. Do not remove from import search alone.",
            )
        return _assessment(
            "Unused Candidate",
            "Medium",
            "low",
            "Declared in a manifest but no direct imports were found outside ignored/generated directories.",
            "Verify scripts/config dynamic usage, then remove the dependency if no usage exists.",
        )
    recipe = REPLACEMENT_RECIPES.get(name)
    if recipe and usage_count <= 3:
        return _assessment(
            "Replace Candidate",
            recipe["confidence"].title(),
            "low" if recipe["confidence"] == "high" else "medium",
            f"Only {usage_count} direct usage location(s) found and the package has a small local-code replacement pattern.",
            recipe["note"],
            recipe["example"],
        )
    if _is_vendor_candidate(package, usage_count):
        version = package.get("resolved_version") or package.get("specifier") or "unknown"
        license_name = package.get("license") or "permissive license"
        assessment = _assessment(
            "Vendor Candidate",
            "Medium",
            "medium",
            (
                f"Only {usage_count} direct usage location(s) were found; the locked package is pure source "
                f"under {license_name}, but Guardian has no safe native replacement recipe."
            ),
            (
                f"Write characterization tests first, then extract only the used functions into "
                f"`vendor/{_vendor_path(name)}/` with the {license_name} attribution, an upstream "
                f"version `{version}` comment, and an upstream advisory watch entry."
            ),
        )
        assessment["vendor_plan"] = {
            "path": f"vendor/{_vendor_path(name)}/",
            "license": license_name,
            "upstream_version": version,
            "requires_attribution": True,
            "tests_before_swap": True,
        }
        return assessment
    if usage_count <= 2:
        return _assessment(
            "Review",
            "Medium",
            "medium",
            f"Only {usage_count} direct usage location(s) found, but Guardian does not have a safe replacement recipe for this package.",
            "Review usage manually. Prefer keeping the package unless replacement is simple and covered by tests.",
        )
    return _assessment(
        "Keep",
        "Medium",
        "medium",
        f"{usage_count} usage locations found; broad usage usually makes replacement higher risk.",
        "Keep unless there is a separate security, size, or maintenance reason to refactor.",
    )


def dynamic_reference_assessment() -> dict:
    return _assessment(
        "Review",
        "Medium",
        "medium",
        (
            "No static imports were found, but source code references the package name as a string. "
            "This often means dynamic import, require.resolve, package-root lookup, or runtime plugin loading."
        ),
        (
            "Review the dynamic reference before removing. Treat as used unless maintainers confirm "
            "the runtime loading path is obsolete."
        ),
    )


def usage_unavailable_assessment() -> dict:
    return _assessment(
        "Review",
        "Low",
        "high",
        (
            "Usage analysis was unavailable because ripgrep (rg) is not installed, "
            "so Guardian cannot tell whether this package is used."
        ),
        (
            "Install ripgrep and rerun the package-diet scan before removing, "
            "replacing, or vendoring this dependency."
        ),
    )


def apply_fanout_adjustment(package: dict) -> None:
    fanout = package.get("wrapper_fanout") or {}
    if int(fanout.get("max_hit_count") or 0) < 10:
        return
    if package["classification"] not in {"Replace Candidate", "Vendor Candidate", "Review"}:
        return
    package["classification"] = "Review"
    package["confidence"] = "Medium"
    package["replacement_risk"] = "high"
    package["reason"] = (
        f"{package['reason']} However, the import appears to feed `{fanout['top_symbol']}`, "
        f"which has {fanout['max_hit_count']} repo usage locations."
    )
    package["suggestion"] = (
        "Treat this as wrapper-backed usage, not a simple one-import dependency. "
        "Only remove it after reviewing the helper/component fanout and adding targeted tests."
    )
    package["local_example"] = None


def apply_maintenance_adjustment(package: dict) -> None:
    """Nudge non-exempt dead packages toward review without overriding safety guards."""

    maintenance = package.get("maintenance") or {}
    if not maintenance.get("maintenance_dead"):
        return
    if package["normalized_name"] in DO_NOT_REIMPLEMENT:
        return
    if package.get("specifier", "").startswith("workspace:") or package["normalized_name"].startswith("@types/"):
        return
    if package["classification"] == "Keep":
        package["classification"] = "Review"
        package["replacement_risk"] = "medium"
        package["suggestion"] = (
            "Review maintained alternatives or a tested local extraction; do not remove solely because publishing slowed."
        )
    package["reason"] = f"{package['reason']} {maintenance['reason']}"


def bloat_score(package: dict) -> int:
    score = 0
    usage_count = int((package.get("usage") or {}).get("hit_count") or 0)
    if package["classification"] == "Unused Candidate":
        score += 55
    elif package["classification"] == "Replace Candidate":
        score += 45
    elif package["classification"] == "Vendor Candidate":
        score += 38
    elif package["classification"] == "Review":
        score += 25
    if package["scope"] == "runtime":
        score += 20
    elif package["scope"] in {"optional", "peer"}:
        score += 10
    if usage_count == 0:
        score += 20
    elif usage_count <= 2:
        score += 10
    if package.get("local_example"):
        score += 15
    footprint = package.get("footprint") or {}
    size_bytes = footprint.get("size_bytes")
    transitive_count = footprint.get("transitive_count")
    if usage_count <= 2 and isinstance(size_bytes, int):
        if size_bytes >= 4 * 1024 * 1024:
            score += 22
        elif size_bytes >= 1024 * 1024:
            score += 14
        elif size_bytes >= 256 * 1024:
            score += 7
    if usage_count <= 3 and isinstance(transitive_count, int):
        if transitive_count >= 20:
            score += 16
        elif transitive_count >= 5:
            score += 9
        elif transitive_count == 0:
            score += 5
    if (package.get("maintenance") or {}).get("maintenance_dead"):
        score += 10
    if int((package.get("wrapper_fanout") or {}).get("max_hit_count") or 0) >= 10:
        score -= 35
    if package["replacement_risk"] == "high":
        score -= 25
    elif package["replacement_risk"] == "medium":
        score -= 5
    if package["confidence"] == "Low":
        score -= 10
    return max(0, min(100, score))


def buckets(packages: list[dict]) -> dict[str, list[dict]]:
    grouped = {
        "remove_candidates": [],
        "replace_with_native": [],
        "vendor_candidates": [],
        "review": [],
        "keep_do_not_reimplement": [],
    }
    for package in packages:
        if package["classification"] == "Unused Candidate":
            grouped["remove_candidates"].append(package)
        elif package["classification"] == "Replace Candidate":
            grouped["replace_with_native"].append(package)
        elif package["classification"] == "Vendor Candidate":
            grouped["vendor_candidates"].append(package)
        elif package["classification"] == "Review":
            grouped["review"].append(package)
        elif _is_high_risk_keep(package):
            grouped["keep_do_not_reimplement"].append(package)
    for items in grouped.values():
        items.sort(key=lambda item: (-item["bloat_score"], item["name"]))
    return grouped


def summary(packages: list[dict]) -> dict:
    counts: dict[str, int] = {}
    for package in packages:
        counts[package["classification"]] = counts.get(package["classification"], 0) + 1
    return counts


def priority_rank(classification: str) -> int:
    return {
        "Unused Candidate": 0,
        "Replace Candidate": 1,
        "Vendor Candidate": 2,
        "Review": 3,
        "Keep": 4,
    }.get(classification, 9)


def _assessment(
    classification: str,
    confidence: str,
    replacement_risk: str,
    reason: str,
    suggestion: str,
    local_example: str | None = None,
) -> dict:
    return {
        "classification": classification,
        "confidence": confidence,
        "replacement_risk": replacement_risk,
        "reason": reason,
        "suggestion": suggestion,
        "local_example": local_example,
    }


def _is_high_risk_keep(package: dict) -> bool:
    return (
        package["classification"] == "Keep"
        and package["replacement_risk"] == "high"
        and not package.get("specifier", "").startswith("workspace:")
        and not package["normalized_name"].startswith("@types/")
    )


def _is_vendor_candidate(package: dict, usage_count: int) -> bool:
    if not 1 <= usage_count <= 3:
        return False
    if package["normalized_name"] in REPLACEMENT_RECIPES or package["normalized_name"] in DO_NOT_REIMPLEMENT:
        return False
    if package.get("pure_source") is not True or not package.get("resolved_version"):
        return False
    return _is_permissive_license(package.get("license"))


def _is_permissive_license(value: str | None) -> bool:
    normalized = (value or "").upper().replace("_", "-")
    if any(marker in normalized for marker in COPYLEFT_LICENSE_MARKERS):
        return False
    return any(re.search(pattern, normalized) for pattern in PERMISSIVE_LICENSE_PATTERNS)


def _vendor_path(package_name: str) -> str:
    return package_name.lstrip("@").replace("/", "__")
