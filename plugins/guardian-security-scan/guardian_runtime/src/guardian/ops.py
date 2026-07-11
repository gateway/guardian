"""High-level project scan orchestration, including budgets, optional live-source enrichment, reports, and snapshots."""

from __future__ import annotations

import signal
import time
from collections import Counter
from pathlib import Path

from .advisories import refresh_findings
from .config import GuardianConfig
from .db import Database
from .dependency_files import fingerprint_dependency_files
from .intel import severity_rank
from .install_scripts import detect_install_script_changes
from .inventory import DEFAULT_ECOSYSTEMS, scan_roots
from .reporting import (
    build_operator_view,
    compare_triage_snapshots,
    create_triage_snapshot,
    summary,
    triage_report,
    write_handoff_report,
    write_operator_report,
)
from .remediation import sync_remediation_lifecycle
from .scan_summary import build_compact_operator_view
from .source_contract import live_source_contract, threat_intel_source_contract
from .threat_intel import ensure_default_threat_intel_sources, ingest_threat_intel
from .typosquat import detect_new_package_typosquats
from .util import utc_now, write_json


class ScanBudgetExceeded(RuntimeError):
    """Raised when a project scan exceeds its configured wall-clock budget."""

    pass


def run_project_scan(
    config: GuardianConfig,
    db: Database,
    *,
    root: str,
    ecosystems: list[str] | None = None,
    include_installed: bool = False,
    include_ghsa: bool = False,
    ghsa_max_packages: int = 50,
    include_threat_intel: bool = False,
    threat_intel_severity_floor: str | None = "high",
    write_handoff: bool = False,
    compact: bool = False,
    snapshot_full: bool = True,
    max_seconds: int | None = None,
    engine: str | None = None,
) -> dict:
    """Run the complete read-only project scan pipeline for one repository root.

    The pipeline is deliberately phase-based so Guardian can report partial
    progress, enforce scan budgets, and keep optional expensive work isolated
    from the core inventory/advisory/triage path.
    """

    selected_ecosystems = ecosystems or list(DEFAULT_ECOSYSTEMS)
    phases: list[dict] = []
    started_at = utc_now()
    run_started = time.monotonic()
    effective_max_seconds = max_seconds

    def remaining_seconds() -> float | None:
        """Return the remaining scan budget, or None for unbounded scans."""

        if effective_max_seconds is None:
            return None
        return effective_max_seconds - (time.monotonic() - run_started)

    def run_phase(name: str, callback, *, required: bool = True):
        """Execute one named phase and record timing/status for operator output."""

        phase_started = time.monotonic()
        remaining = remaining_seconds()
        if remaining is not None and remaining <= 0:
            phases.append({"name": name, "status": "skipped-budget", "elapsed_seconds": 0})
            raise ScanBudgetExceeded(f"scan budget exceeded before {name}")
        old_handler = None
        if remaining is not None and hasattr(signal, "SIGALRM"):
            def _timeout_handler(signum, frame):
                del signum, frame
                raise ScanBudgetExceeded(f"scan budget exceeded during {name}")
            try:
                old_handler = signal.signal(signal.SIGALRM, _timeout_handler)
                signal.alarm(max(1, int(remaining)))
            except ValueError:
                old_handler = None
        try:
            result = callback()
        except ScanBudgetExceeded as exc:
            phases.append(
                {
                    "name": name,
                    "status": "timeout",
                    "elapsed_seconds": round(time.monotonic() - phase_started, 4),
                    "error": str(exc),
                }
            )
            raise
        except Exception as exc:
            phases.append(
                {
                    "name": name,
                    "status": "error",
                    "elapsed_seconds": round(time.monotonic() - phase_started, 4),
                    "error": str(exc),
                }
            )
            if required:
                raise
            return None
        finally:
            if remaining is not None and old_handler is not None and hasattr(signal, "SIGALRM"):
                signal.alarm(0)
                signal.signal(signal.SIGALRM, old_handler)
        phases.append(
            {
                "name": name,
                "status": "ok",
                "elapsed_seconds": round(time.monotonic() - phase_started, 4),
            }
        )
        return result

    inventory_runs = []
    threat_intel = None
    behavioral_signals: list[dict] = []
    refresh = {}
    triage = None
    snapshot = None
    comparison = {}
    remediation = {}
    operator_view = None
    operator_report_path = None
    handoff_path = None
    scan_scope: dict = {}
    scan_policy: dict = {
        "large_repo_mode": False,
        "large_repo_reason": None,
        "requested_max_seconds": max_seconds,
        "effective_max_seconds": effective_max_seconds,
        "requested_ghsa_max_packages": ghsa_max_packages,
        "effective_ghsa_max_packages": ghsa_max_packages,
        "api_policy": {
            "ghsa_max_workers": config.ghsa_max_workers,
            "api_request_min_interval_seconds": config.api_request_min_interval_seconds,
            "osv_batch_delay_seconds": config.osv_batch_delay_seconds,
        },
    }
    status = "ok"
    budget_error = None
    try:
        # Phase order matters: inventory establishes the exact package universe;
        # optional intel enrichment can add local exact-match catalog entries;
        # advisory refresh records findings; triage turns those rows into
        # operator decisions; snapshots make later fix verification possible.
        inventory_runs = run_phase(
        "inventory",
        lambda: scan_roots(
            config=config,
            db=db,
            roots=[root],
            ecosystems=selected_ecosystems,
            include_installed=include_installed,
            excludes=[],
            engine=engine,
        ),
        )
        scan_scope = _scan_scope(db, root, include_installed=include_installed)
        behavioral_signals = run_phase(
            "behavioral-signals",
            lambda: _behavioral_signals_for_runs(
                db,
                root,
                [item["run_id"] for item in inventory_runs if item.get("run_id") is not None],
            ),
        )
        large_reasons = _large_repo_reasons(config, scan_scope)
        if large_reasons:
            scan_policy["large_repo_mode"] = True
            scan_policy["large_repo_reason"] = "; ".join(large_reasons)
            if effective_max_seconds is not None and effective_max_seconds < config.large_repo_min_seconds:
                effective_max_seconds = config.large_repo_min_seconds
            if include_ghsa and ghsa_max_packages > config.large_repo_ghsa_package_cap:
                ghsa_max_packages = config.large_repo_ghsa_package_cap
            scan_policy["effective_max_seconds"] = effective_max_seconds
            scan_policy["effective_ghsa_max_packages"] = ghsa_max_packages
        if include_threat_intel:
            run_phase("threat-intel-sources-init", lambda: ensure_default_threat_intel_sources(config))
            threat_intel = run_phase(
                "threat-intel-ingest",
                lambda: ingest_threat_intel(
                    config,
                    db,
                    root_paths=[root],
                    ecosystems=selected_ecosystems,
                    severity_floor=threat_intel_severity_floor,
                ),
                required=False,
            )
        refresh = run_phase(
            "assess-refresh",
            lambda: refresh_findings(
                config=config,
                db=db,
                include_ghsa=include_ghsa,
                ghsa_max_packages=ghsa_max_packages,
                root_paths=[root],
            ),
        )
        if not compact:
            operator_view = run_phase(
                "operator-view",
                lambda: build_operator_view(
                    config,
                    db,
                    root_filter=root,
                    behavioral_signals=behavioral_signals,
                ),
            )
            operator_report_path = run_phase(
                "operator-report",
                lambda: str(write_operator_report(config, db, root_filter=root, payload=operator_view)),
            )
        triage_limit = None if snapshot_full else 12
        triage = run_phase("triage", lambda: triage_report(config, db, root_filter=root, package_limit=triage_limit))
        snapshot = run_phase(
            "snapshot",
            lambda: create_triage_snapshot(
                config,
                db,
                root_filter=root,
                triage=triage,
                inventory_run_ids=[item["run_id"] for item in inventory_runs if item.get("run_id") is not None],
            ),
        )
        comparison = run_phase(
            "compare",
            lambda: compare_triage_snapshots(db, root_filter=root, current_snapshot_id=snapshot["snapshot_id"]),
        )
        remediation = run_phase(
            "remediation-sync",
            lambda: sync_remediation_lifecycle(db, root_filter=root, current_snapshot_id=snapshot["snapshot_id"]),
        )
        if compact:
            operator_view = run_phase(
                "compact-operator-view",
                lambda: build_compact_operator_view(config, db, root_filter=root, triage=triage, comparison=comparison),
            )
            operator_view["behavioral_signals"] = behavioral_signals
            operator_view["behavioral_signal_counts"] = {
                "fix_this_week": sum(1 for item in behavioral_signals if item.get("posture") == "fix_this_week"),
                "watch": sum(1 for item in behavioral_signals if item.get("posture") == "watch"),
            }
            if behavioral_signals:
                counts = operator_view["behavioral_signal_counts"]
                operator_view["priority_headline"] += (
                    f"; behavioral: {counts['fix_this_week']} fix this week, {counts['watch']} watch"
                )
            operator_report_path = run_phase(
                "compact-operator-report",
                lambda: str(_write_project_json_report(config, root, "operator", operator_view)),
            )
        if write_handoff:
            handoff_path = run_phase(
                "handoff",
                lambda: str(
                    write_handoff_report(
                        config,
                        db,
                        root_filter=root,
                        behavioral_signals=behavioral_signals,
                    )
                ),
            )
    except ScanBudgetExceeded as exc:
        status = "partial"
        budget_error = str(exc)
        if triage is not None and operator_view is None:
            operator_view = build_compact_operator_view(config, db, root_filter=root, triage=triage, comparison=comparison)
    if operator_view is None:
        operator_view = {
            "root_path": root,
            "generated_at": utc_now(),
            "priority_headline": "Scan incomplete before triage completed",
            "full_headline": "Scan incomplete before triage completed",
            "compare_headline": None,
            "compare": {},
            "evidence_summary": None,
            "top_packages": [],
            "bottom_line": ["Guardian returned partial results because the scan did not complete."],
        }

    payload = {
        "status": status,
        "budget_error": budget_error,
        "max_seconds": max_seconds,
        "effective_max_seconds": effective_max_seconds,
        "started_at": started_at,
        "completed_at": utc_now(),
        "elapsed_seconds": round(time.monotonic() - run_started, 4),
        "root_path": root,
        "ecosystems": selected_ecosystems,
        "compact": compact,
        "inventory_runs": inventory_runs,
        "scan_scope": scan_scope,
        "scan_policy": scan_policy,
        "threat_intel": threat_intel,
        "refresh": refresh,
        "behavioral_signals": behavioral_signals,
        "operator_view": operator_view,
        "source_status": {
            "osv": {
                **live_source_contract(
                    source_id="osv",
                    status="error" if (refresh.get("source_errors") or {}).get("osv") else "queried" if refresh else "not-run",
                    records_read=refresh.get("packages_checked") if refresh else None,
                    error=(refresh.get("source_errors") or {}).get("osv") if refresh else None,
                    http_stats=(refresh.get("http_stats") or {}).get("osv") if refresh else None,
                ),
            },
            "ghsa": {
                **live_source_contract(
                    source_id="ghsa",
                    status="error" if refresh.get("ghsa_error") else "queried" if refresh.get("ghsa_included") else "not-requested-or-skipped",
                    records_read=refresh.get("ghsa_target_count"),
                    error=refresh.get("ghsa_error"),
                    skipped_reason=refresh.get("ghsa_skipped_reason"),
                    http_stats=(refresh.get("http_stats") or {}).get("ghsa"),
                ),
            },
            "kev": live_source_contract(
                source_id="kev",
                status="error" if (refresh.get("source_errors") or {}).get("kev") else "queried" if ((refresh.get("http_stats") or {}).get("kev") or {}).get("requests") else "not-needed",
                error=(refresh.get("source_errors") or {}).get("kev"),
                http_stats=(refresh.get("http_stats") or {}).get("kev"),
            ),
            "epss": live_source_contract(
                source_id="epss",
                status="error" if (refresh.get("source_errors") or {}).get("epss") else "queried" if ((refresh.get("http_stats") or {}).get("epss") or {}).get("requests") else "not-needed",
                error=(refresh.get("source_errors") or {}).get("epss"),
                http_stats=(refresh.get("http_stats") or {}).get("epss"),
            ),
            "nvd": live_source_contract(
                source_id="nvd",
                status="error" if (refresh.get("source_errors") or {}).get("nvd") else "queried" if ((refresh.get("http_stats") or {}).get("nvd") or {}).get("requests") else "not-needed",
                error=(refresh.get("source_errors") or {}).get("nvd"),
                http_stats=(refresh.get("http_stats") or {}).get("nvd"),
            ),
            "threat_intel": [
                threat_intel_source_contract(source)
                for source in (threat_intel or {}).get("source_reports", [])
            ],
        },
        "operator_report_path": operator_report_path,
        "handoff_path": handoff_path,
        "snapshot": snapshot,
        "comparison": comparison,
        "remediation": remediation,
        "phases": phases,
    }
    path = Path(config.reports_dir) / f"project-scan-{Path(root).name}-{utc_now().replace(':', '-')}.json"
    write_json(path, payload)
    payload["report_path"] = str(path)
    return payload


def _scan_scope(db: Database, root: str, *, include_installed: bool) -> dict:
    """Summarize dependency-surface size for budgets and operator evidence."""

    rows = [dict(row) for row in db.current_packages_for_root(root)]
    unique_versions = {
        (row["ecosystem"], row["normalized_name"], row["version"])
        for row in rows
    }
    source_files = {
        row["source_file"]
        for row in rows
        if row.get("source_file")
    }
    by_ecosystem = Counter(row["ecosystem"] for row in rows)
    by_source_type = Counter(row.get("source_type") or "unknown" for row in rows)
    dependency_files = fingerprint_dependency_files(root, include_installed=include_installed)
    file_kinds = Counter(item["file_kind"] for item in dependency_files)
    return {
        "package_rows": len(rows),
        "unique_package_versions": len(unique_versions),
        "source_file_count": len(source_files),
        "dependency_file_count": len(dependency_files),
        "dependency_file_kinds": dict(sorted(file_kinds.items())),
        "ecosystems": dict(sorted(by_ecosystem.items())),
        "source_types": dict(sorted(by_source_type.items())),
    }


def _large_repo_reasons(config: GuardianConfig, scan_scope: dict) -> list[str]:
    """Return the policy reasons that make a repo need large-surface handling."""

    reasons = []
    unique_versions = scan_scope.get("unique_package_versions", 0)
    dependency_files = scan_scope.get("dependency_file_count", 0)
    if unique_versions >= config.large_repo_package_threshold:
        reasons.append(
            f"unique package versions {unique_versions} >= threshold {config.large_repo_package_threshold}"
        )
    if dependency_files >= config.large_repo_dependency_file_threshold:
        reasons.append(
            f"dependency files {dependency_files} >= threshold {config.large_repo_dependency_file_threshold}"
        )
    return reasons


def _write_project_json_report(config: GuardianConfig, root: str, prefix: str, payload: dict) -> Path:
    path = Path(config.reports_dir) / f"{prefix}-{Path(root).name}-{utc_now().replace(':', '-')}.json"
    write_json(path, payload)
    return path


def _risk_label_for_severity(severity: str | None) -> str:
    rank = severity_rank(severity)
    if rank >= severity_rank("high"):
        return "Act Now"
    if rank == severity_rank("medium"):
        return "Fix This Week"
    return "Watch"


def _compact_daily_watch_triage(db: Database, root: str) -> dict:
    """Build a finding-only triage payload without code-usage enrichment."""

    rows = db.conn.execute(
        """
        WITH repo_packages AS (
          SELECT DISTINCT
            root_path, ecosystem, package_name, normalized_name, version,
            source_type, root_kind, confidence, direct_dependency, install_scope
          FROM package_state
          WHERE present = 1 AND root_path = ?
        )
        SELECT
          rp.ecosystem,
          rp.package_name,
          rp.normalized_name,
          rp.version,
          rp.source_type,
          rp.root_kind,
          rp.confidence,
          rp.direct_dependency,
          rp.install_scope,
          f.advisory_source,
          f.advisory_id,
          f.severity
        FROM repo_packages rp
        JOIN findings f
          ON f.ecosystem = rp.ecosystem
         AND f.normalized_name = rp.normalized_name
         AND f.version = rp.version
        WHERE f.status = 'open'
        ORDER BY rp.ecosystem, rp.normalized_name, rp.version, f.advisory_source, f.advisory_id
        """,
        (root,),
    ).fetchall()

    grouped: dict[tuple[str, str, str], dict] = {}
    for row in rows:
        key = (row["ecosystem"], row["normalized_name"], row["version"])
        package = grouped.setdefault(
            key,
            {
                "ecosystem": row["ecosystem"],
                "package_name": row["package_name"],
                "normalized_name": row["normalized_name"],
                "version": row["version"],
                "highest_severity": None,
                "advisory_count": 0,
                "issue_keys": [],
                "classification_labels": ["Daily Watch"],
                "notes": [
                    "Compact daily-watch snapshot: run a full Guardian scan for code usage, root cause, and upgrade-risk details."
                ],
                "role_label": _compact_role_label(row),
                "environment_label": _compact_environment_label(row),
                "recommended_clean_version": None,
                "first_fixed_version": None,
            },
        )
        package["advisory_count"] += 1
        package["issue_keys"].append(f"{row['advisory_source']}:{row['advisory_id']}")
        if severity_rank(row["severity"]) > severity_rank(package["highest_severity"]):
            package["highest_severity"] = row["severity"]

    packages = list(grouped.values())
    for package in packages:
        package["issue_keys"] = sorted(set(package["issue_keys"]))
        package["risk_label"] = _risk_label_for_severity(package["highest_severity"])
    risk_order = {"Act Now": 0, "Fix This Week": 1, "Watch": 2}
    packages.sort(
        key=lambda item: (
            risk_order.get(item["risk_label"], 9),
            -severity_rank(item["highest_severity"]),
            item["package_name"].lower(),
            item["version"],
        )
    )
    by_risk: dict[str, int] = {}
    for package in packages:
        by_risk[package["risk_label"]] = by_risk.get(package["risk_label"], 0) + 1
    headline = (
        f"{by_risk.get('Act Now', 0)} packages act now, "
        f"{by_risk.get('Fix This Week', 0)} fix this week, "
        f"{by_risk.get('Watch', 0)} watch"
        if packages
        else "No open package findings"
    )
    return {
        "headline": headline,
        "by_risk_label": by_risk,
        "issue_by_risk_label": by_risk,
        "top_actions": [
            {
                "package": f"{item['package_name']}@{item['version']}",
                "risk_label": item["risk_label"],
                "highest_severity": item["highest_severity"],
                "issue_keys": item["issue_keys"][:3],
            }
            for item in packages[:10]
        ],
        "package_actions": packages,
        "issues": [],
        "snapshot_kind": "daily-watch-compact",
    }


def _compact_role_label(row) -> str:
    if row["direct_dependency"]:
        return "Runtime" if (row["install_scope"] or "").lower() not in {"dev", "test"} else "Tooling/Test"
    return "Transitive Only"


def _compact_environment_label(row) -> str:
    source_type = row["source_type"] or ""
    if "vendored" in source_type:
        return "vendored-lockfile"
    if row["root_kind"]:
        return row["root_kind"]
    return source_type or "unknown"


def run_daily(
    config: GuardianConfig,
    db: Database,
    *,
    roots: list[str],
    ecosystems: list[str],
    include_installed: bool,
    include_ghsa: bool,
    ghsa_max_packages: int,
    include_threat_intel: bool = False,
    threat_intel_severity_floor: str | None = None,
    engine: str | None = None,
) -> dict:
    root_filter = roots[0] if len(roots) == 1 else None
    inventory_runs = scan_roots(
        config=config,
        db=db,
        roots=roots,
        ecosystems=ecosystems,
        include_installed=include_installed,
        excludes=[],
        engine=engine,
    )
    run_ids_by_root = {
        item["root"]: [item["run_id"]]
        for item in inventory_runs
        if item.get("run_id") is not None
    }
    behavioral_signals_by_root = {
        root: _behavioral_signals_for_runs(db, root, run_ids_by_root.get(root, []))
        for root in roots
    }
    threat_intel = None
    if include_threat_intel:
        ensure_default_threat_intel_sources(config)
        threat_intel = ingest_threat_intel(
            config,
            db,
            root_paths=roots,
            ecosystems=ecosystems,
            severity_floor=threat_intel_severity_floor,
        )
    refresh = refresh_findings(
        config=config,
        db=db,
        include_ghsa=include_ghsa,
        ghsa_max_packages=ghsa_max_packages,
        root_paths=roots,
    )
    report = summary(db)
    triage = triage_report(config, db, root_filter=root_filter)
    operator_view = (
        build_operator_view(
            config,
            db,
            root_filter=root_filter,
            behavioral_signals=behavioral_signals_by_root.get(root_filter, []),
        )
        if root_filter
        else None
    )
    operator_report_path = (
        str(write_operator_report(config, db, root_filter=root_filter, payload=operator_view))
        if root_filter
        else None
    )
    snapshots = []
    comparisons = []
    remediation_updates = []
    roots_to_snapshot = roots if roots else ([root_filter] if root_filter else [])
    for root in roots_to_snapshot:
        root_triage = triage_report(config, db, root_filter=root, package_limit=None)
        snapshot = create_triage_snapshot(
            config,
            db,
            root_filter=root,
            triage=root_triage,
            inventory_run_ids=run_ids_by_root.get(root, []),
        )
        snapshots.append(snapshot)
        comparison = compare_triage_snapshots(
            db,
            root_filter=root,
            current_snapshot_id=snapshot["snapshot_id"],
        )
        comparisons.append(comparison)
        remediation_updates.append(
            sync_remediation_lifecycle(
                db,
                root_filter=root,
                current_snapshot_id=snapshot["snapshot_id"],
            )
        )
    payload = {
        "ran_at": utc_now(),
        "inventory_runs": inventory_runs,
        "threat_intel": threat_intel,
        "refresh": refresh,
        "summary": report,
        "triage": triage,
        "operator_view": operator_view,
        "behavioral_signals_by_root": behavioral_signals_by_root,
        "operator_report_path": operator_report_path,
        "snapshots": snapshots,
        "comparisons": comparisons,
        "remediation_updates": remediation_updates,
    }
    path = Path(config.reports_dir) / f"daily-{utc_now().replace(':', '-')}.json"
    write_json(path, payload)
    payload["report_path"] = str(path)
    return payload


def run_daily_watch(
    config: GuardianConfig,
    db: Database,
    *,
    roots: list[str],
    ecosystems: list[str],
    include_installed: bool,
    include_ghsa: bool,
    ghsa_max_packages: int,
    refresh_advisories: bool = False,
    include_threat_intel: bool = False,
    threat_intel_severity_floor: str | None = None,
    live_enrichment: bool = False,
    engine: str | None = None,
) -> dict:
    """Run a lightweight morning watch pass over known roots.

    The watch pass fingerprints dependency manifests and lockfiles first. Repos
    with unchanged dependency files reuse existing package_state rows, while
    changed or previously unseen roots are inventoried before advisory refresh.
    Advisory matching still runs for every watched root so newly published
    vulnerabilities can surface even when the local code did not change.
    """

    normalized_roots = [str(Path(root).resolve()) for root in roots]
    selected_ecosystems = ecosystems or list(DEFAULT_ECOSYSTEMS)
    root_statuses = []
    roots_to_inventory = []

    for root in normalized_roots:
        fingerprints = fingerprint_dependency_files(root, include_installed=include_installed)
        file_state = db.record_dependency_file_state(root, fingerprints)
        package_count = len(db.current_packages_for_root(root))
        needs_inventory = file_state["has_changes"] or (file_state["current_count"] > 0 and package_count == 0)
        if needs_inventory:
            if file_state["has_changes"]:
                reason = "dependency-files-changed"
            else:
                reason = "no-current-package-state"
            roots_to_inventory.append(root)
            action = "inventory"
        else:
            reason = "dependency-files-unchanged" if file_state["current_count"] else "no-dependency-files"
            action = "skip-inventory"
        root_statuses.append(
            {
                "root_path": root,
                "action": action,
                "reason": reason,
                "package_count_before": package_count,
                "file_state": file_state,
                "behavioral_signals": [],
            }
        )

    inventory_runs = []
    behavioral_signals_by_root: dict[str, list[dict]] = {}
    if roots_to_inventory:
        inventory_runs = scan_roots(
            config=config,
            db=db,
            roots=roots_to_inventory,
            ecosystems=selected_ecosystems,
            include_installed=include_installed,
            excludes=[],
            engine=engine,
        )
        run_ids_by_root = {
            item["root"]: [item["run_id"]]
            for item in inventory_runs
            if item.get("run_id") is not None
        }
        behavioral_signals_by_root = {
            root: _behavioral_signals_for_runs(db, root, run_ids_by_root.get(root, []))
            for root in roots_to_inventory
        }
        for root_status in root_statuses:
            root_status["behavioral_signals"] = behavioral_signals_by_root.get(root_status["root_path"], [])

    threat_intel = None
    if include_threat_intel:
        ensure_default_threat_intel_sources(config)
        threat_intel = ingest_threat_intel(
            config,
            db,
            root_paths=normalized_roots,
            ecosystems=selected_ecosystems,
            severity_floor=threat_intel_severity_floor,
        )

    if refresh_advisories:
        refresh = refresh_findings(
            config=config,
            db=db,
            include_ghsa=include_ghsa,
            ghsa_max_packages=ghsa_max_packages,
            root_paths=normalized_roots,
            enrich_live=live_enrichment,
        )
    else:
        package_rows = [
            dict(row)
            for root in normalized_roots
            for row in db.current_packages_for_root(root)
            if row["ecosystem"] in {"npm", "pypi", "go", "rubygems", "packagist"}
        ]
        unique_versions = {
            (row["ecosystem"], row["normalized_name"], row["version"])
            for row in package_rows
        }
        refresh = {
            "status": "skipped",
            "skipped_reason": "daily-watch default uses cached findings; pass --refresh-advisories for live OSV/local-catalog refresh",
            "packages_checked": 0,
            "package_rows_considered": len(package_rows),
            "unique_versions_available": len(unique_versions),
            "findings_refreshed": 0,
            "ghsa_included": False,
            "ghsa_target_count": 0,
            "ghsa_error": None,
            "ghsa_skipped_reason": None,
            "live_enrichment": False,
        }
    report = summary(db)

    run_ids_by_root = {
        item["root"]: [item["run_id"]]
        for item in inventory_runs
        if item.get("run_id") is not None
    }
    snapshots = []
    comparisons = []
    remediation_updates = []
    for root in normalized_roots:
        root_triage = _compact_daily_watch_triage(db, root)
        snapshot = create_triage_snapshot(
            config,
            db,
            root_filter=root,
            triage=root_triage,
            inventory_run_ids=run_ids_by_root.get(root, []),
        )
        snapshots.append(snapshot)
        comparison = compare_triage_snapshots(
            db,
            root_filter=root,
            current_snapshot_id=snapshot["snapshot_id"],
        )
        comparisons.append(comparison)
        remediation_updates.append(
            sync_remediation_lifecycle(
                db,
                root_filter=root,
                current_snapshot_id=snapshot["snapshot_id"],
            )
        )

    payload = {
        "ran_at": utc_now(),
        "mode": "daily-watch",
        "roots": root_statuses,
        "roots_inventory_count": len(roots_to_inventory),
        "roots_skipped_count": len(normalized_roots) - len(roots_to_inventory),
        "inventory_runs": inventory_runs,
        "behavioral_signals_by_root": behavioral_signals_by_root,
        "threat_intel": threat_intel,
        "refresh": refresh,
        "refresh_advisories": refresh_advisories,
        "live_enrichment": live_enrichment,
        "summary": report,
        "snapshots": snapshots,
        "comparisons": comparisons,
        "remediation_updates": remediation_updates,
    }
    path = Path(config.reports_dir) / f"daily-watch-{utc_now().replace(':', '-')}.json"
    write_json(path, payload)
    payload["report_path"] = str(path)
    return payload


def _behavioral_signals_for_runs(db: Database, root: str, run_ids: list[int]) -> list[dict]:
    """Combine offline behavioral detectors while preserving one priority order."""

    signals = detect_install_script_changes(db, root)
    signals.extend(detect_new_package_typosquats(db, root, run_ids))
    return sorted(
        signals,
        key=lambda item: (
            item.get("posture_rank", 9),
            (item.get("package_name") or "").lower(),
            item.get("signal_type") or "",
        ),
    )
