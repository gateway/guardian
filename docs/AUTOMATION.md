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

## Schedule A Morning Watch

Claude Code and Codex both support scheduled or recurring tasks (for example Claude Code's `/schedule` routines, or your harness's equivalent automation feature). Guardian's daily watch is designed to be the thing you put in one: the scan work happens locally in the Guardian runtime, and the model only reads a compact JSON summary — so a scheduled morning run is cheap in tokens and fine on a small, fast model at low effort.

Schedule this prompt (adjust roots and cadence to taste):

Claude Code:

> /guardian-security-scan:guardian-daily-watch Run Guardian's daily watch across my development roots. Skip unchanged repos, refresh advisory data for known packages, and report only what changed since yesterday: new or resolved findings, dependency-file changes, new behavioral signals (install scripts, lockfile drift, suspicious new versions), and anything rated act-now or fix-this-week. If a repo shows a high-priority change, run a full guardian-project-scan on that repo only and include the evidence. If nothing changed, say so in one line.

Codex:

> $guardian-security-scan:guardian-daily-watch Run Guardian's daily watch across my development roots. Skip unchanged repos, refresh advisory data for known packages, and report only what changed since yesterday: new or resolved findings, dependency-file changes, new behavioral signals (install scripts, lockfile drift, suspicious new versions), and anything rated act-now or fix-this-week. If a repo shows a high-priority change, run a full guardian-project-scan on that repo only and include the evidence. If nothing changed, say so in one line.

Why this stays cheap:

- Dependency manifests and lockfiles are hashed first; unchanged repos are skipped before any inventory or network work.
- Unchanged roots make zero registry-intelligence calls.
- Snapshot comparison means the model summarizes deltas, not the full finding list, every morning.
- The escalation clause means expensive deep scans only run when the watch actually found something.

If you prefer running outside an agent entirely, the same check works headless from cron or launchd, since the runtime is standard-library Python with no environment to activate:

```bash
# crontab: weekday mornings at 7:30
30 7 * * 1-5 /path/to/guardian-plugin/scripts/guardian daily-watch --root "$HOME/dev/repo1" --root "$HOME/dev/repo2" --json >> "$HOME/.guardian-security-scan/daily-watch.log" 2>&1
```

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

Advisory refresh is on by default: every daily watch re-checks OSV and local catalogs for the packages already in your inventory, so a CVE or malicious-package record published overnight against an unchanged dependency still surfaces the next morning. Guardian has no background daemon — a scan only knows what was published as of the moment it runs, which is exactly why the daily watch exists.

For the cheapest cached-findings-only pass (for example offline), disable the refresh explicitly:

```bash
guardian daily-watch --root /path/to/repo --no-refresh-advisories --json
```

Add live enrichment only when you need slower CVE context such as KEV, EPSS, or NVD detail:

```bash
guardian daily-watch --root /path/to/repo --live-enrichment --json
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
