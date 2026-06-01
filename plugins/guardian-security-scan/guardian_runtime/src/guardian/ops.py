from __future__ import annotations

import signal
import time
from pathlib import Path

from .advisories import refresh_findings
from .config import GuardianConfig
from .db import Database
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
from .util import utc_now, write_json


class ScanBudgetExceeded(RuntimeError):
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
    selected_ecosystems = ecosystems or list(DEFAULT_ECOSYSTEMS)
    phases: list[dict] = []
    started_at = utc_now()
    run_started = time.monotonic()

    def remaining_seconds() -> float | None:
        if max_seconds is None:
            return None
        return max_seconds - (time.monotonic() - run_started)

    def run_phase(name: str, callback, *, required: bool = True):
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
    refresh = {}
    triage = None
    snapshot = None
    comparison = {}
    remediation = {}
    operator_view = None
    operator_report_path = None
    handoff_path = None
    status = "ok"
    budget_error = None
    try:
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
            operator_view = run_phase("operator-view", lambda: build_operator_view(config, db, root_filter=root))
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
            operator_report_path = run_phase(
                "compact-operator-report",
                lambda: str(_write_project_json_report(config, root, "operator", operator_view)),
            )
        if write_handoff:
            handoff_path = run_phase("handoff", lambda: str(write_handoff_report(config, db, root_filter=root)))
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
        "started_at": started_at,
        "completed_at": utc_now(),
        "elapsed_seconds": round(time.monotonic() - run_started, 4),
        "root_path": root,
        "ecosystems": selected_ecosystems,
        "compact": compact,
        "inventory_runs": inventory_runs,
        "threat_intel": threat_intel,
        "refresh": refresh,
        "operator_view": operator_view,
        "source_status": {
            "osv": {
                **live_source_contract(
                    source_id="osv",
                    status="queried" if refresh else "not-run",
                    records_read=refresh.get("packages_checked") if refresh else None,
                ),
            },
            "ghsa": {
                **live_source_contract(
                    source_id="ghsa",
                    status="queried" if refresh.get("ghsa_included") else "not-requested-or-skipped",
                    records_read=refresh.get("ghsa_target_count"),
                    error=refresh.get("ghsa_error"),
                    skipped_reason=refresh.get("ghsa_skipped_reason"),
                ),
            },
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


def _write_project_json_report(config: GuardianConfig, root: str, prefix: str, payload: dict) -> Path:
    path = Path(config.reports_dir) / f"{prefix}-{Path(root).name}-{utc_now().replace(':', '-')}.json"
    write_json(path, payload)
    return path


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
    operator_view = build_operator_view(config, db, root_filter=root_filter) if root_filter else None
    operator_report_path = str(write_operator_report(config, db, root_filter=root_filter)) if root_filter else None
    snapshots = []
    comparisons = []
    remediation_updates = []
    roots_to_snapshot = roots if roots else ([root_filter] if root_filter else [])
    run_ids_by_root = {
        item["root"]: [item["run_id"]]
        for item in inventory_runs
        if item.get("run_id") is not None
    }
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
        "operator_report_path": operator_report_path,
        "snapshots": snapshots,
        "comparisons": comparisons,
        "remediation_updates": remediation_updates,
    }
    path = Path(config.reports_dir) / f"daily-{utc_now().replace(':', '-')}.json"
    write_json(path, payload)
    payload["report_path"] = str(path)
    return payload
