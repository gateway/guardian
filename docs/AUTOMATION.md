# Guardian Automation

Guardian can be used as a lightweight daily or scheduled dependency-risk check across local projects.

## Recommended Daily Flow

Use `guardian-daily-watch` for morning checks. It is cheaper than running full deep scans across every repo because it hashes dependency files first.

```text
Use Guardian daily watch to check my known local repos and summarize what changed.
```

The daily watch workflow is designed to answer:

- Did dependency files change since the last run?
- Did a repo need fresh inventory?
- Did new advisory evidence appear for known packages?
- Did a previous finding resolve?
- Did only interpretation/metadata change while package evidence stayed the same?

## Local Scan State

Guardian keeps runtime state outside the plugin by default:

```text
~/.guardian-security-scan/guardian.db
```

The SQLite database stores package inventory rows, dependency-file fingerprints, advisory records, findings, triage snapshots, policy exceptions, remediation lifecycle data, registry observations, pre-install verdicts, lockfile-hygiene observations, and the outreach ledger.

Set `GUARDIAN_STATE_DIR` when you want isolated state for a workflow:

```bash
export GUARDIAN_STATE_DIR=/path/to/guardian-state
```

## Freshness

Guardian does not rely only on a static bundled database. A normal project scan re-inventories visible package evidence, checks local exact-match catalogs, queries OSV for visible package versions, and enriches matching CVEs when configured source data is available.

Use these options when you want stronger daily freshness:

```bash
guardian daily-watch --root /path/to/repo --refresh-advisories --json
```

Add live enrichment only when you need slower CVE context such as KEV, EPSS, or NVD detail:

```bash
guardian daily-watch --root /path/to/repo --refresh-advisories --live-enrichment --json
```

Add changed-package registry intelligence without enabling broader live enrichment:

```bash
guardian daily-watch --root /path/to/repo --include-registry-intel --json
```

OpenSSF malicious-package ingest is intentionally heavier because its first sparse git checkout can carry substantial tree metadata. Enable it only for a deliberate deep refresh:

```bash
guardian daily-watch --root /path/to/repo --include-threat-intel --include-openssf-malicious --json
```

## Efficiency Notes

- Unchanged dependency files can be skipped before full inventory.
- Unchanged roots make zero registry-intelligence calls, even when the option is enabled.
- Standard scans inspect registry metadata only after a version is introduced beyond an existing baseline.
- Advisory refresh for known packages is cheaper than broad repo rescans.
- Snapshot comparison keeps unchanged findings from being treated as new.
- Operator JSON is compact enough for agents and dashboards.
- Deep scans should be reserved for release candidates, suspicious changes, or confirmed findings.

## Automation Safety

For scheduled scans:

- Prefer compact operator output.
- Keep report and database paths outside project repos.
- Do not commit generated reports containing private file paths.
- Use environment variables for optional GitHub tokens.
- Avoid deep installed-tree scans on every repo unless you have a specific reason.
