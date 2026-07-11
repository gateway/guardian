"""Watchlist runner for repeatedly checking selected package/version sets."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .check_package import check_package
from .config import GuardianConfig, STATE_DIR
from .db import Database
from .ops import run_daily
from .remediation import remediation_status
from .util import utc_now, write_json, write_text


DEFAULT_WATCHLIST_PATH = STATE_DIR / "watchlist.json"


def run_watchlist(
    config: GuardianConfig,
    db: Database,
    *,
    watchlist_path: Path | None = None,
    limit: int | None = None,
    include_ghsa_override: bool | None = None,
) -> dict:
    path = watchlist_path or DEFAULT_WATCHLIST_PATH
    watchlist = _load_watchlist(path)
    projects = watchlist.get("projects", [])
    if limit is not None:
        projects = projects[:limit]
    results = []
    for project in projects:
        root = project["root"]
        include_ghsa = bool(project.get("include_ghsa", True))
        if include_ghsa_override is not None:
            include_ghsa = include_ghsa_override
        try:
            daily = run_daily(
                config,
                db,
                roots=[root],
                ecosystems=list(project.get("ecosystems") or ["npm", "pypi", "go", "crates.io", "packagist"]),
                include_installed=bool(project.get("include_installed", True)),
                include_ghsa=include_ghsa,
                ghsa_max_packages=int(project.get("ghsa_max_packages") or 75),
                engine=project.get("engine") or "guardian-native",
            )
            remediation = remediation_status(db, root_filter=root, limit=25)
            results.append(_project_result(project, daily, remediation))
        except Exception as exc:
            results.append(
                {
                    "name": project.get("name") or Path(root).name,
                    "root": root,
                    "status": "failed",
                    "error": str(exc),
                }
            )
    vendored_results = _run_vendored_package_watch(config, db)
    payload = {
        "status": (
            "pass"
            if all(item.get("status") == "ok" for item in results)
            and all(item.get("verdict") == "allow" for item in vendored_results)
            else "attention"
        ),
        "generated_at": utc_now(),
        "watchlist_path": str(path),
        "project_count": len(results),
        "results": results,
        "vendored_package_count": len(vendored_results),
        "vendored_packages": vendored_results,
    }
    output_stem = f"watchlist-{utc_now().replace(':', '-')}"
    json_path = Path(config.reports_dir) / f"{output_stem}.json"
    markdown_path = Path(config.reports_dir) / f"{output_stem}.md"
    write_json(json_path, payload)
    write_text(markdown_path, build_watchlist_markdown(payload))
    payload["report_path"] = str(json_path)
    payload["markdown_path"] = str(markdown_path)
    return payload


def build_watchlist_markdown(payload: dict) -> str:
    lines = [
        "# Guardian Watchlist Report",
        "",
        f"- Status: `{payload['status']}`",
        f"- Generated at: `{payload['generated_at']}`",
        f"- Projects scanned: `{payload['project_count']}`",
        f"- Vendored upstream packages checked: `{payload.get('vendored_package_count', 0)}`",
        f"- Watchlist: `{payload['watchlist_path']}`",
        "",
        "## Project Results",
        "",
    ]
    for item in payload["results"]:
        lines.append(f"### {item['name']}")
        lines.append("")
        lines.append(f"- Root: `{item['root']}`")
        lines.append(f"- Status: `{item['status']}`")
        if item.get("error"):
            lines.append(f"- Error: `{item['error']}`")
            lines.append("")
            continue
        lines.append(f"- Current posture: {item['headline']}")
        lines.append(f"- Snapshot compare: {item['compare_headline']}")
        lines.append(f"- Remediation counts: `{item['remediation_counts']}`")
        lines.append(f"- Daily report: `{item['daily_report_path']}`")
        if item.get("operator_report_path"):
            lines.append(f"- Operator report: `{item['operator_report_path']}`")
        for package in item.get("top_packages", [])[:5]:
            lines.append(
                f"- {package['risk_label']}: `{package['package_name']}@{package['version']}` "
                f"severity `{package.get('highest_severity')}` env `{package.get('environment_label')}`"
            )
            if package.get("advisory_links"):
                lines.append(f"  Advisory: {package['advisory_links'][0]}")
        lines.append("")
    if payload.get("vendored_packages"):
        lines.extend(["## Vendored Upstream Packages", ""])
        for item in payload["vendored_packages"]:
            lines.append(
                f"- `{item.get('ecosystem', 'unknown')}:{item.get('name', 'invalid-entry')}@"
                f"{item.get('version', 'unknown')}`: `{item.get('verdict', 'warn')}` - "
                f"{item.get('explanation', 'Vendored watch entry could not be evaluated.')}"
            )
        lines.append("")
    lines.append("## How To Read This")
    lines.append("")
    lines.append("- `new evidence` usually means a package or advisory match appeared since the previous run.")
    lines.append("- `resolved evidence` means Guardian no longer sees the package/advisory match.")
    lines.append("- `classification changed` means prioritization changed without necessarily changing package evidence.")
    lines.append("- Remediation counts persist lifecycle state across runs: open, resolved, and reintroduced.")
    return "\n".join(lines) + "\n"


def _project_result(project: dict, daily: dict, remediation: dict) -> dict:
    comparison = (daily.get("comparisons") or [{}])[0]
    triage = daily.get("triage") or {}
    return {
        "name": project.get("name") or Path(project["root"]).name,
        "root": project["root"],
        "status": "ok",
        "headline": triage.get("headline"),
        "compare_status": comparison.get("status"),
        "compare_headline": comparison.get("headline") or comparison.get("message"),
        "daily_report_path": daily.get("report_path"),
        "operator_report_path": daily.get("operator_report_path"),
        "remediation_counts": remediation.get("counts", {}),
        "top_packages": _compact_top_packages(triage.get("package_actions", [])),
    }


def _compact_top_packages(packages: list[dict]) -> list[dict]:
    results = []
    for package in packages[:8]:
        results.append(
            {
                "package_name": package.get("package_name"),
                "version": package.get("version"),
                "risk_label": package.get("risk_label"),
                "highest_severity": package.get("highest_severity"),
                "environment_label": package.get("environment_label"),
                "confidence": (package.get("confidence") or {}).get("label"),
                "advisory_links": package.get("advisory_links", [])[:2],
            }
        )
    return results


def _load_watchlist(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"projects": []}
    payload = json.loads(path.read_text(encoding="utf-8"))
    projects = payload.get("projects")
    if not isinstance(projects, list):
        raise ValueError("watchlist must contain a projects list")
    for project in projects:
        if not isinstance(project, dict) or not project.get("root"):
            raise ValueError("each watchlist project must contain a root")
    return payload


def add_vendored_package_watch(
    config: GuardianConfig,
    *,
    ecosystem: str,
    name: str,
    version: str,
    project_root: str,
    license_name: str | None = None,
    source_url: str | None = None,
) -> dict:
    """Persist the upstream identity retained by a local vendored extraction."""

    path = Path(config.vendored_watchlist_path)
    if path.exists():
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid vendored package watchlist: {exc}") from exc
    else:
        payload = {"schema_version": "1.0", "packages": []}
    packages = payload.get("packages")
    if not isinstance(packages, list):
        raise ValueError("vendored package watchlist must contain a packages list")
    identity = (ecosystem.lower(), name.lower(), version, str(Path(project_root).resolve()))
    entry = {
        "ecosystem": ecosystem.lower(),
        "name": name,
        "version": version,
        "project_root": identity[3],
        "license": license_name,
        "source_url": source_url,
        "added_at": utc_now(),
    }
    replaced = False
    for index, current in enumerate(packages):
        current_identity = (
            str(current.get("ecosystem") or "").lower(),
            str(current.get("name") or "").lower(),
            str(current.get("version") or ""),
            str(current.get("project_root") or ""),
        )
        if current_identity == identity:
            entry["added_at"] = current.get("added_at") or entry["added_at"]
            packages[index] = entry
            replaced = True
            break
    if not replaced:
        packages.append(entry)
    packages.sort(key=lambda item: (item["ecosystem"], item["name"].lower(), item["version"], item["project_root"]))
    payload["packages"] = packages
    write_json(path, payload)
    return {"status": "updated" if replaced else "added", "path": str(path), "entry": entry}


def _run_vendored_package_watch(config: GuardianConfig, db: Database) -> list[dict]:
    path = Path(config.vendored_watchlist_path)
    if not path.exists():
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return [{"status": "error", "verdict": "warn", "explanation": str(exc)}]
    results = []
    for package in payload.get("packages") or []:
        ecosystem = str(package.get("ecosystem") or "")
        name = str(package.get("name") or "")
        version = str(package.get("version") or "")
        if ecosystem not in {"npm", "pypi"} or not name or not version:
            continue
        verdict = check_package(config, db, ecosystem, name, version)
        results.append({
            **package,
            "verdict": verdict["verdict"],
            "explanation": verdict["explanation"],
            "signals": verdict.get("signals") or [],
        })
    return results
