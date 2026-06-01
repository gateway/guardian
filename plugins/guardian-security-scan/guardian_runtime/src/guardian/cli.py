"""Command-line dispatcher for Guardian scans, inventory import, gates, reporting, and release validation."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from .advisories import refresh_findings
from .catalog import export_exact_match_catalog
from .config import DEFAULT_CONFIG_PATH, load_config, save_config
from .cli_output import print_diet_scan, print_gate_check, print_gate_install, print_project_scan_summary
from .cli_parser import build_parser
from .db import Database
from .gates import check_package, gate_install
from .inventory import DEFAULT_ECOSYSTEMS, import_ndjson, scan_roots
from .ops import run_daily, run_project_scan
from .package_diet import package_diet_scan
from .reporting import (
    build_operator_view,
    compare_triage_snapshots,
    create_triage_snapshot,
    grouped_issues,
    hygiene_report,
    open_findings,
    summary,
    triage_report,
    write_handoff_report,
)
from .remediation import remediation_status, sync_remediation_lifecycle
from .release_checks import plugin_release_checks
from .scan_modes import apply_scan_mode
from .scan_summary import compact_project_scan_payload
from .threat_intel import audit_advisory_yaml_corpus, ensure_default_threat_intel_sources, ingest_threat_intel
from .util import normalize_package_name, print_json
from .watchlist import run_watchlist


def _severity_sort_key(value: str | None) -> int:
    """Convert advisory severity labels into a stable ordering for summaries."""

    order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    return order.get((value or "").lower(), 0)


def _dedupe_gate_findings(findings: list[dict]) -> list[dict]:
    """Collapse duplicate gate findings while preserving the strongest severity."""

    grouped: dict[str, dict] = {}
    for item in findings:
        key = item["id"]
        current = grouped.get(key)
        if current is None:
            grouped[key] = dict(item)
            continue
        if _severity_sort_key(item.get("severity")) > _severity_sort_key(current.get("severity")):
            grouped[key]["severity"] = item.get("severity")
        if not grouped[key].get("summary") and item.get("summary"):
            grouped[key]["summary"] = item["summary"]
        if grouped[key].get("source") != item.get("source"):
            grouped[key]["source"] = "multiple"
    return sorted(
        grouped.values(),
        key=lambda item: (-_severity_sort_key(item.get("severity")), item["id"]),
    )


def main(argv: list[str] | None = None) -> int:
    """Parse CLI arguments and route each subcommand to the matching workflow.

    The CLI intentionally stays thin: heavy behavior lives in focused modules so
    skills, release checks, and direct CLI usage all exercise the same codepath.
    """

    parser = build_parser()
    args = parser.parse_args(argv)
    config = load_config()
    db = Database(config.db_path)
    db.initialize()

    try:
        if args.command == "init":
            save_config(config)
            payload = {"config_path": str(DEFAULT_CONFIG_PATH), "db_path": config.db_path}
            print_json(payload)
            return 0

        if args.command == "scan":
            # Project scans are the primary public workflow. Scan modes decide
            # which expensive checks run so daily automation stays lightweight.
            root = os.path.abspath(args.root)
            mode_options = apply_scan_mode(
                args.mode,
                include_installed=args.include_installed,
                include_ghsa=args.include_ghsa,
                include_threat_intel=args.include_threat_intel,
                write_handoff=args.handoff,
                compact=None if args.output == "auto" else args.output == "compact",
            )
            payload = run_project_scan(
                config,
                db,
                root=root,
                ecosystems=args.ecosystem or None,
                include_installed=mode_options["include_installed"],
                include_ghsa=mode_options["include_ghsa"],
                ghsa_max_packages=args.ghsa_max_packages,
                include_threat_intel=mode_options["include_threat_intel"],
                threat_intel_severity_floor=args.threat_intel_severity_floor,
                write_handoff=mode_options["write_handoff"],
                compact=mode_options["compact"],
                snapshot_full=mode_options["snapshot_full"],
                max_seconds=args.max_seconds if args.max_seconds is not None else mode_options["max_seconds"],
                engine=args.engine,
            )
            if args.json:
                print_json(compact_project_scan_payload(payload) if mode_options["compact"] else payload)
            else:
                print_project_scan_summary(payload)
            return 0

        if args.command == "intel":
            # Threat-intel commands manage optional advisory corpus ingestion.
            # They are separated from normal scans to avoid unexpected network
            # or filesystem work during routine project review.
            if args.intel_command == "sources-init":
                payload = ensure_default_threat_intel_sources(config)
                payload["path"] = config.threat_intel_sources_path
                if args.json:
                    print_json(payload)
                else:
                    print(f"threat-intel sources: {config.threat_intel_sources_path}")
                    for source in payload["sources"]:
                        print(f"  {source['id']}: {source['type']} enabled={source.get('enabled', True)}")
                return 0
            if args.intel_command == "ingest":
                payload = ingest_threat_intel(
                    config,
                    db,
                    source_config_path=Path(args.source_config) if args.source_config else None,
                    root_paths=args.root or None,
                    ecosystems=args.ecosystem or None,
                    severity_floor=args.severity_floor,
                )
                if args.json:
                    print_json(payload)
                else:
                    print(f"threat-intel ingest: {payload['entries_written']} entries")
                    print(f"catalog: {payload['catalog_path']}")
                    print(f"report: {payload['markdown_path']}")
                    for source in payload["source_reports"]:
                        print(
                            f"  {source['id']}: {source.get('entries_written', 0)} entries "
                            f"from {source.get('yaml_files_read', 0)} advisory files"
                        )
                return 0
            if args.intel_command == "audit-parser":
                payload = audit_advisory_yaml_corpus(Path(args.source_dir))
                if args.json:
                    print_json(payload)
                else:
                    print(f"advisories read: {payload['advisories_read']}")
                    print(f"missing required fields: {payload['missing_required_count']}")
                    print(f"unsupported ranges: {payload['unsupported_range_count']}")
                    print(f"fixed versions matching affected ranges: {payload['fixed_version_range_match_count']}")
                    print(f"multiline affected ranges: {payload['multiline_affected_range_count']}")
                    print(f"multiline titles: {payload['multiline_title_count']}")
                return 0 if payload.get("status") == "pass" else 1

        if args.command == "validate":
            if args.validate_command == "plugin-release":
                payload = plugin_release_checks(Path(args.source_dir) if args.source_dir else None)
                if args.json:
                    print_json(payload)
                else:
                    print(f"plugin release checks: {payload['status']}")
                    for name, check in payload["checks"].items():
                        print(f"  {name}: {check['status']}")
                return 0 if payload["status"] == "pass" else 1

        if args.command == "inventory":
            # Inventory commands expose the native scanner directly for debugging
            # parser behavior without running advisory enrichment or triage.
            if args.inventory_command == "scan":
                roots = args.root or config.development_roots
                payload = scan_roots(
                    config=config,
                    db=db,
                    roots=roots,
                    ecosystems=args.ecosystem or DEFAULT_ECOSYSTEMS,
                    include_installed=args.include_installed,
                    excludes=args.exclude,
                    engine=args.engine,
                )
                if args.json:
                    print_json({"runs": payload})
                else:
                    for item in payload:
                        print(f"{item['root']}: imported {item['packages']} package records via {item['engine']}")
                return 0
            if args.inventory_command == "import":
                payload = import_ndjson(db, args.root, Path(args.ndjson))
                if args.json:
                    print_json(payload)
                else:
                    print(f"{payload['root']}: imported {payload['packages']} package records from {payload['ndjson_path']}")
                return 0

        if args.command == "diet":
            if args.diet_command == "scan":
                payload = package_diet_scan(args.root, limit=args.limit, usage_limit=args.usage_limit)
                if args.json:
                    print_json(payload)
                else:
                    print_diet_scan(payload, args.limit)
                return 0

        if args.command == "watchlist":
            if args.watchlist_command == "run":
                include_ghsa_override = None
                if args.include_ghsa:
                    include_ghsa_override = True
                if args.no_ghsa:
                    include_ghsa_override = False
                payload = run_watchlist(
                    config,
                    db,
                    watchlist_path=Path(args.path) if args.path else None,
                    limit=args.limit,
                    include_ghsa_override=include_ghsa_override,
                )
                if args.json:
                    print_json(payload)
                else:
                    print(f"watchlist: {payload['status']}")
                    print(f"report: {payload['markdown_path']}")
                    for item in payload["results"]:
                        print(f"{item['name']}: {item['status']} {item.get('headline') or item.get('error')}")
                return 0 if payload["status"] == "pass" else 1

        if args.command == "assess" and args.assess_command == "refresh":
            payload = refresh_findings(
                config,
                db,
                include_ghsa=args.include_ghsa,
                ghsa_max_packages=args.ghsa_max_packages,
                root_paths=args.root or None,
            )
            if args.json:
                print_json(payload)
            else:
                print(f"checked {payload['packages_checked']} packages, refreshed {payload['findings_refreshed']} findings")
                if payload["ghsa_skipped_reason"]:
                    print(f"ghsa skipped: {payload['ghsa_skipped_reason']}")
            return 0
        if args.command == "assess" and args.assess_command == "run-daily":
            roots = args.root or config.development_roots
            payload = run_daily(
                config,
                db,
                roots=roots,
                ecosystems=args.ecosystem or DEFAULT_ECOSYSTEMS,
                include_installed=args.include_installed,
                include_ghsa=args.include_ghsa,
                ghsa_max_packages=args.ghsa_max_packages,
                include_threat_intel=args.include_threat_intel,
                threat_intel_severity_floor=args.threat_intel_severity_floor,
                engine=args.engine,
            )
            if args.json:
                print_json(payload)
            else:
                print(f"daily run complete: {payload['report_path']}")
                print(f"roots scanned: {len(payload['inventory_runs'])}")
                if payload.get("threat_intel"):
                    print(f"threat-intel entries: {payload['threat_intel']['entries_written']}")
                print(f"packages checked: {payload['refresh']['packages_checked']}")
                for comparison in payload.get("comparisons", []):
                    print(f"compare {comparison['root_path']}: {comparison.get('headline') or comparison.get('message')}")
            return 0

        if args.command == "report":
            if args.report_command == "summary":
                payload = summary(db)
                if args.json:
                    print_json(payload)
                else:
                    print(f"current packages: {payload['current_packages']}")
                    for ecosystem, count in sorted(payload["packages_by_ecosystem"].items()):
                        print(f"  {ecosystem}: {count}")
                    if payload["open_findings_by_severity"]:
                        print("open findings:")
                        for severity, count in payload["open_findings_by_severity"].items():
                            print(f"  {severity}: {count}")
                    else:
                        print("open findings: none")
                return 0
            if args.report_command == "findings":
                payload = open_findings(db)
                if args.json:
                    print_json({"findings": payload})
                else:
                    if not payload:
                        print("no open findings")
                    for finding in payload:
                        print(
                            f"{finding['severity'] or 'unknown'} {finding['ecosystem']} "
                            f"{finding['package_name']}@{finding['version']} "
                            f"{finding['advisory_source']}:{finding['advisory_id']}"
                        )
                return 0
            if args.report_command == "issues":
                payload = grouped_issues(db)
                if args.json:
                    print_json({"issues": payload})
                else:
                    if not payload:
                        print("no grouped issues")
                    for issue in payload:
                        print(f"{issue['severity']} {issue['canonical_key']}")
                        print(f"  packages: {len(issue['packages'])}")
                        print(f"  sources: {', '.join(issue['sources'])}")
                return 0
            if args.report_command == "triage":
                payload = triage_report(config, db, root_filter=args.root)
                if args.json:
                    print_json(payload)
                else:
                    print(payload["headline"])
                    if payload["by_risk_label"]:
                        print("risk buckets:")
                        for label, count in payload["by_risk_label"].items():
                            print(f"  {label}: {count}")
                    if payload["package_actions"]:
                        print("priority packages:")
                        for package in payload["package_actions"][:5]:
                            print(
                                f"  {package['risk_label']} {package['package_name']}@{package['version']} "
                                f"severity={package['highest_severity']} findings={package['advisory_count']}"
                            )
                            if package.get("classification_labels"):
                                print(f"    labels: {', '.join(package['classification_labels'])}")
                            if package["issue_summaries"]:
                                print(f"    {package['issue_summaries'][0]}")
                            if package.get("recommended_clean_version"):
                                print(
                                    f"    clean target: {package['recommended_clean_version']} "
                                    f"({package['upgrade_risk']['label']})"
                                )
                            elif package.get("first_fixed_version"):
                                print(
                                    f"    first fixed version: {package['first_fixed_version']} "
                                    f"({package['upgrade_risk']['label']})"
                                )
                            else:
                                print("    clean target: manual review required")
                            print(
                                f"    role: {package['role_label']} | "
                                f"environment={package['environment_label']} | "
                                f"usage runtime/build/test="
                                f"{package['usage_by_kind']['runtime']}/"
                                f"{package['usage_by_kind']['build']}/"
                                f"{package['usage_by_kind']['test']}"
                            )
                            if package.get("root_cause"):
                                print(f"    via: {package['root_cause']['summary']}")
                            if package.get("usage") and package["usage"][0]["hits"]:
                                for hit in package["usage"][0]["hits"][:2]:
                                    print(f"    used at: {hit['file']}:{hit['line']}")
                            for note in package.get("notes", [])[:2]:
                                print(f"    note: {note}")
                            for suggestion in package.get("suggestions", [])[:1]:
                                print(f"    suggestion: {suggestion}")
                return 0
            if args.report_command == "hygiene":
                payload = hygiene_report(config, db, root_filter=args.root)
                if args.json:
                    print_json(payload)
                else:
                    print(payload["headline"])
                    for package in payload["packages"][:20]:
                        print(
                            f"  {package['role_label']} {package['package_name']}@{package['version']} "
                            f"roots={len(package['root_paths'])}"
                        )
                        print(f"    environment={package['environment_label']}")
                        if package.get("root_cause"):
                            print(f"    via: {package['root_cause']['summary']}")
                        if package["usage_by_kind"]:
                            print(
                                f"    usage runtime/build/test="
                                f"{package['usage_by_kind']['runtime']}/"
                                f"{package['usage_by_kind']['build']}/"
                                f"{package['usage_by_kind']['test']}"
                            )
                        for suggestion in package.get("suggestions", [])[:2]:
                            print(f"    {suggestion}")
                return 0
            if args.report_command == "handoff":
                path = write_handoff_report(config, db, root_filter=args.root)
                payload = {"path": str(path)}
                if args.json:
                    print_json(payload)
                else:
                    print(str(path))
                return 0
            if args.report_command == "operator":
                payload = build_operator_view(config, db, root_filter=args.root)
                if args.json:
                    print_json(payload)
                else:
                    print(payload["priority_headline"])
                    print(payload["compare_headline"])
                return 0
            if args.report_command == "snapshot":
                triage = triage_report(config, db, root_filter=args.root, package_limit=None)
                payload = create_triage_snapshot(config, db, root_filter=args.root, triage=triage)
                payload["remediation"] = sync_remediation_lifecycle(
                    db,
                    root_filter=args.root,
                    current_snapshot_id=payload["snapshot_id"],
                )
                if args.json:
                    print_json(payload)
                else:
                    print(f"snapshot {payload['snapshot_id']} for {payload['root_path']}: {payload['headline']}")
                return 0
            if args.report_command == "compare":
                payload = compare_triage_snapshots(
                    db,
                    root_filter=args.root,
                    current_snapshot_id=args.current_snapshot_id,
                    previous_snapshot_id=args.previous_snapshot_id,
                )
                if args.json:
                    print_json(payload)
                else:
                    print(payload.get("headline") or payload.get("message"))
                    if payload.get("status") != "ok":
                        return 0
                    print(
                        f"current snapshot: {payload['current_snapshot']['id']} "
                        f"at {payload['current_snapshot']['created_at']}"
                    )
                    print(
                        f"previous snapshot: {payload['previous_snapshot']['id']} "
                        f"at {payload['previous_snapshot']['created_at']}"
                    )
                    if payload["resolved"]:
                        print("resolved:")
                        for item in payload["resolved"][:10]:
                            print(f"  {item['package_name']}@{item['version']} ({item.get('risk_label') or 'unknown'})")
                    if payload["new_open"]:
                        print("new open:")
                        for item in payload["new_open"][:10]:
                            print(f"  {item['package_name']}@{item['version']} ({item.get('risk_label') or 'unknown'})")
                    if payload["changed"]:
                        print("changed:")
                        for item in payload["changed"][:10]:
                            evidence_fields = ", ".join(sorted((item.get("evidence_changes") or {}).keys()))
                            classification_fields = ", ".join(sorted((item.get("classification_changes") or {}).keys()))
                            field_parts = []
                            if evidence_fields:
                                field_parts.append(f"evidence={evidence_fields}")
                            if classification_fields:
                                field_parts.append(f"classification={classification_fields}")
                            print(f"  {item['package_name']}@{item['version']} changed: {', '.join(field_parts)}")
                    if payload.get("evidence_changed"):
                        print(f"evidence-changed packages: {len(payload['evidence_changed'])}")
                    if payload.get("classification_changed"):
                        print(f"classification-changed packages: {len(payload['classification_changed'])}")
                    print(f"unchanged open packages: {payload['unchanged_count']}")
                return 0
            if args.report_command == "remediation":
                payload = remediation_status(db, root_filter=args.root, limit=args.limit)
                if args.json:
                    print_json(payload)
                else:
                    print(f"remediation status for {payload['root_path']}")
                    for status, count in sorted(payload["counts"].items()):
                        print(f"  {status}: {count}")
                    for item in payload["items"][:10]:
                        print(
                            f"  {item['status']}: {item['package_name']}@{item['version']} "
                            f"{item['issue_key']} ({item.get('risk_label') or 'unknown risk'})"
                        )
                return 0

        if args.command == "export" and args.export_command == "exact-match-catalog":
            path = export_exact_match_catalog(config, db)
            payload = {"path": str(path)}
            if args.json:
                print_json(payload)
            else:
                print(str(path))
            return 0

        if args.command == "gate":
            if args.gate_command == "check-package":
                payload = check_package(config, db, args.ecosystem, args.name, args.version)
                if args.json:
                    print_json(payload)
                else:
                    payload["deduped_findings"] = _dedupe_gate_findings(payload["findings"])
                    print_gate_check(payload)
                return 1 if payload["blocked"] else 0
            if args.gate_command == "install":
                payload = gate_install(config, db, args.package_manager, args.specs, execute=args.execute)
                if args.json:
                    print_json(payload)
                else:
                    for package in payload["packages"]:
                        package["deduped_findings"] = _dedupe_gate_findings(package["findings"])
                    print_gate_install(payload, execute=args.execute, package_manager=args.package_manager)
                return 1 if payload["blocked"] else int(payload.get("returncode", 0))

        if args.command == "policy":
            if args.policy_command == "add-exception":
                db.add_policy_exception(
                    ecosystem=args.ecosystem,
                    normalized_name=normalize_package_name(args.ecosystem, args.name),
                    version=args.version,
                    advisory_source=None,
                    canonical_key=None,
                    action=args.action,
                    reason=args.reason,
                    expires_at=args.expires_at,
                    created_by=args.created_by,
                )
                payload = {"status": "ok"}
                if args.json:
                    print_json(payload)
                else:
                    print("policy exception added")
                return 0
            if args.policy_command == "list-exceptions":
                payload = [dict(row) for row in db.list_policy_exceptions()]
                if args.json:
                    print_json({"exceptions": payload})
                else:
                    if not payload:
                        print("no active policy exceptions")
                    for item in payload:
                        print(
                            f"{item['action']} {item['ecosystem']} {item['normalized_name']}"
                            + (f"@{item['version']}" if item["version"] else "")
                            + f" reason={item['reason']}"
                        )
                return 0

    except (RuntimeError, ValueError) as exc:
        if getattr(args, "json", False):
            print_json({"status": "error", "error": str(exc)})
        else:
            print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        db.close()

    parser.error("unhandled command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
