"""Human-readable terminal rendering for Guardian CLI commands."""

from __future__ import annotations


def print_project_scan_summary(payload: dict) -> None:
    operator = payload["operator_view"]
    print(operator["priority_headline"])
    print(f"root: {payload['root_path']}")
    print(f"elapsed: {payload['elapsed_seconds']}s")
    print(f"packages checked: {payload['refresh']['packages_checked']}")
    for item in payload.get("behavioral_signals", []):
        identity = item["package_name"] + (f"@{item['version']}" if item.get("version") else "")
        print(
            f"behavioral {item['posture'].replace('_', ' ')}: "
            f"{identity} ({item['signal_type']})"
        )
    scan_policy = payload.get("scan_policy") or {}
    if scan_policy.get("large_repo_mode"):
        print(f"large-repo mode: {scan_policy.get('large_repo_reason')}")
        print(
            "effective budget: "
            f"{scan_policy.get('effective_max_seconds')}s | "
            f"GHSA cap: {scan_policy.get('effective_ghsa_max_packages')}"
        )
    if payload.get("threat_intel"):
        print(f"threat-intel entries: {payload['threat_intel']['entries_written']}")
        for source in payload["threat_intel"]["source_reports"]:
            health = source.get("source_health") or {}
            print(
                f"source {source['id']}: status={source['status']} "
                f"stale={health.get('stale')} revision={source.get('revision') or 'unknown'}"
            )
    print(f"operator report: {payload['operator_report_path']}")
    if payload.get("handoff_path"):
        print(f"handoff: {payload['handoff_path']}")
    print(payload["comparison"].get("headline") or payload["comparison"].get("message"))


def print_diet_scan(payload: dict, limit: int) -> None:
    print(f"Package diet scan: {payload['package_count']} declared npm packages")
    print(f"Summary: {payload['summary']}")
    for bucket_name, bucket_items in payload.get("top_candidates", {}).items():
        if bucket_items:
            print(f"{bucket_name.replace('_', ' ').title()}:")
            for item in bucket_items[:3]:
                print(
                    f"  {item['name']} score={item['bloat_score']} "
                    f"usage={item['usage_density']['label']} "
                    f"class={item['classification']}"
                )
    for package in payload["packages"][:limit]:
        print(
            f"  {package['classification']} {package['name']} "
            f"scope={package['scope']} usage={package['usage']['hit_count']} "
            f"risk={package['replacement_risk']} score={package['bloat_score']}"
        )
        print(f"    manifest: {package['manifest_relative_path']}")
        print(f"    usage density: {package['usage_density']['label']}")
        print(f"    reason: {package['reason']}")
        if package.get("usage_symbols"):
            print(f"    symbols: {', '.join(package['usage_symbols'])}")
        fanout = package.get("wrapper_fanout") or {}
        if fanout.get("top_symbol"):
            print(f"    wrapper fanout: {fanout['top_symbol']} has {fanout['max_hit_count']} repo usage hits")
        for hit in package["usage"]["hits"][:2]:
            print(f"    used at: {hit['file']}:{hit['line']}")
        if package.get("local_example"):
            print(f"    local example: {package['local_example']}")


def print_gate_check(payload: dict) -> None:
    print(f"{payload['ecosystem']} {payload['name']}@{payload['version']}: {payload['risk_label']}")
    print("labels: Known Vulnerable")
    print(f"decision: {payload['action']} ({payload['decision_reason']})")
    print_gate_recommendation(payload)
    for finding in payload.get("deduped_findings", []):
        print_gate_finding(finding, indent="  ")


def print_package_verdict(payload: dict) -> None:
    """Render the bounded pre-install verdict without legacy remediation noise."""

    version = payload.get("resolved_version") or payload.get("requested_version") or "latest"
    print(f"Guardian {payload['verdict'].upper()}: {payload['ecosystem']} {payload['name']}@{version}")
    print(payload["explanation"])
    for signal in payload.get("signals", []):
        reference = f" {signal['id']}" if signal.get("id") else ""
        print(f"  {signal['signal_grade']} {signal['signal_type']}{reference}: {signal['explanation']}")
    print(f"cache: {'hit' if payload.get('cache_hit') else 'miss'} | elapsed: {payload['elapsed_seconds']}s")


def print_gate_install(payload: dict, *, execute: bool, package_manager: str) -> None:
    print(f"{package_manager} install gate: {'BLOCK' if payload['blocked'] else 'ALLOW'}")
    for package in payload["packages"]:
        print(f"  {package['ecosystem']} {package['name']}@{package['version']}: {package['risk_label']}")
        print_gate_recommendation(package, indent="    ")
        for finding in package.get("deduped_findings", []):
            print_gate_finding(finding, indent="    ")
        print(f"    decision: {package['action']} ({package['decision_reason']})")
    if not payload["blocked"] and not execute:
        print("install not executed; pass --execute to run it after checks")


def print_gate_recommendation(package: dict, *, indent: str = "") -> None:
    if package.get("recommended_version"):
        print(f"{indent}recommended version: {package['recommended_version']} ({package['upgrade_risk']['label']})")
    if package["upgrade_risk"].get("reason"):
        print(f"{indent}upgrade risk: {package['upgrade_risk']['reason']}")
    if package.get("recommended_version"):
        if package.get("recommended_version_is_clean"):
            print(f"{indent}clean target status: no known current matches in Guardian sources for the recommended version")
        else:
            print(f"{indent}clean target status: this is the first fixed version, but Guardian could not prove it fully clean from current sources")


def print_gate_finding(finding: dict, *, indent: str) -> None:
    print(
        f"{indent}{finding['source']} {finding['id']} "
        f"{finding.get('severity') or 'unknown'} {finding.get('summary') or ''}"
    )
