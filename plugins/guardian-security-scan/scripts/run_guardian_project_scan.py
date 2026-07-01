#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
GUARDIAN = PLUGIN_ROOT / "scripts" / "guardian"


def detect_repo_root(start: Path) -> Path:
    """Resolve the Git repo root when possible, otherwise keep the current path."""

    try:
        completed = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=str(start),
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return start
    if completed.returncode == 0 and completed.stdout.strip():
        return Path(completed.stdout.strip())
    return start


def run_guardian(args: list[str]) -> dict:
    """Run the bundled Guardian CLI and parse its JSON output."""

    completed = subprocess.run(
        [str(GUARDIAN), *args, "--json"],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            "guardian command failed\n"
            f"command: {GUARDIAN} {' '.join(args)}\n"
            f"stdout:\n{completed.stdout}\n"
            f"stderr:\n{completed.stderr}"
        )
    return json.loads(completed.stdout)


def compact_package(item: dict) -> dict:
    """Reduce a package action to the fields useful in skill responses."""

    confidence = item.get("confidence")
    confidence_label = confidence.get("label") if isinstance(confidence, dict) else confidence
    low_action = item.get("environment_label") == "vendored-lockfile" and confidence_label == "Low Confidence"
    return {
        "package": item.get("package_name"),
        "version": item.get("version"),
        "risk": item.get("risk_label"),
        "severity": item.get("highest_severity"),
        "confidence": confidence_label,
        "environment": item.get("environment_label"),
        "role": item.get("role_label"),
        "reason": item.get("reason") or (item.get("issue_summaries") or [None])[0],
        "target": None if low_action else (item.get("recommended_clean_version") or item.get("first_fixed_version")),
        "recommended_action": (
            "Review parent chain / no direct app action."
            if low_action
            else item.get("recommended_action") or (item.get("notes") or [None])[0]
        ),
        "advisories": item.get("advisory_sources", [])[:4],
        "links": item.get("advisory_links", [])[:4],
        "advisory_details": item.get("advisory_details", [])[:4],
        "evidence_context": item.get("evidence_context"),
    }


def is_low_action(item: dict) -> bool:
    """Return True when a package should be framed as non-actionable metadata."""

    return item.get("environment") == "vendored-lockfile" and item.get("confidence") == "Low Confidence"


def advisory_note(top_packages: list[dict]) -> str | None:
    """Add an operator warning when the priority list is mostly vendored noise."""

    vendored = [item for item in top_packages if item.get("environment") == "vendored-lockfile"]
    if top_packages and len(vendored) >= max(3, len(top_packages) // 2):
        return (
            "Most top packages are vendored nested lockfile findings. Do not change app dependencies unless the same versions "
            "also appear in real lockfiles, installed runtime packages, or code usage."
        )
    return None


def print_human_summary(payload: dict) -> None:
    """Print a short operator summary for non-JSON skill runner usage."""

    print(f"root: {payload['root']}")
    print(f"priority: {payload['triage_headline']}")
    print(f"compare: {payload['compare_headline']}")
    print(f"operator report: {payload.get('operator_report_path')}")
    if payload.get("handoff_path"):
        print(f"handoff: {payload['handoff_path']}")
    if payload.get("advisory_note"):
        print(f"note: {payload['advisory_note']}")
    if payload["top_packages"]:
        heading = "top packages"
        if all(is_low_action(item) for item in payload["top_packages"]):
            heading = "top packages (low-confidence vendored metadata)"
        print(f"{heading}:")
        for item in payload["top_packages"]:
            print(
                f"  {item['risk']} {item['package']}@{item['version']} "
                f"confidence={item.get('confidence') or 'unknown'} env={item['environment']} severity={item['severity']}"
            )
            if item.get("recommended_action"):
                print(f"    action: {item['recommended_action']}")
            evidence_context = item.get("evidence_context") or {}
            if evidence_context.get("label"):
                print(f"    evidence: {evidence_context['label']}")
            if item.get("links"):
                print(f"    link: {item['links'][0]}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root")
    parser.add_argument("--mode", choices=["daily", "standard", "deep", "handoff"], default="daily")
    parser.add_argument("--include-ghsa", action="store_true")
    parser.add_argument("--include-threat-intel", action="store_true")
    parser.add_argument("--threat-intel-severity-floor", default="high", choices=["unknown", "low", "medium", "high", "critical"])
    parser.add_argument("--handoff", action="store_true")
    parser.add_argument("--include-installed", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    working_root = Path(os.path.abspath(args.root)) if args.root else detect_repo_root(Path.cwd()).resolve()
    scan_args = ["scan", str(working_root), "--mode", args.mode, "--output", "compact"]
    if args.include_installed:
        scan_args.append("--include-installed")
    if args.include_ghsa:
        scan_args.append("--include-ghsa")
    if args.include_threat_intel:
        scan_args.extend(["--include-threat-intel", "--threat-intel-severity-floor", args.threat_intel_severity_floor])
    if args.handoff:
        scan_args.append("--handoff")

    scan = run_guardian(scan_args)
    operator_view = scan.get("operator_view") or {}
    compare = scan.get("comparison") or {}
    top_packages = [compact_package(item) for item in operator_view.get("top_packages", scan.get("top_packages", []))[:8]]
    payload = {
        "root": str(working_root),
        "status": scan.get("status"),
        "elapsed_seconds": scan.get("elapsed_seconds"),
        "triage_headline": operator_view.get("priority_headline") or scan.get("priority_headline"),
        "current_headline": operator_view.get("full_headline") or scan.get("priority_headline"),
        "operator_report_path": scan.get("operator_report_path"),
        "daily_report_path": scan.get("report_path") or scan.get("project_report_path"),
        "handoff_path": scan.get("handoff_path"),
        "compare_status": compare.get("status"),
        "compare_headline": compare.get("headline") or compare.get("message") or scan.get("compare_headline"),
        "compare": {
            "new_open_count": len(compare.get("new_open", [])),
            "resolved_count": len(compare.get("resolved", [])),
            "evidence_changed_count": len(compare.get("evidence_changed", [])),
            "classification_changed_count": len(compare.get("classification_changed", [])),
            "changed_count": len(compare.get("changed", [])),
            "unchanged_count": compare.get("unchanged_count"),
        },
        "operator_summary": {
            "bottom_line": operator_view.get("bottom_line", scan.get("bottom_line", []))[:3],
            "perspective": operator_view.get("perspective"),
            "corroboration": operator_view.get("corroboration"),
            "evidence_summary": operator_view.get("evidence_summary") or scan.get("package_evidence"),
        },
        "top_packages": top_packages,
    }
    payload["advisory_note"] = advisory_note(top_packages)
    if args.json:
        json.dump(payload, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    else:
        print_human_summary(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
