# Guardian

Guardian is a local-first security plugin for AI coding agents. It helps Codex and Claude Code scan npm and Python projects for known package risk, explain what matters, and avoid unnecessary dependency churn.

Use Guardian when you want your agent to answer: "Is this project carrying known dependency risk, what changed since the last scan, and what should we do next?"

Guardian is built for modern AI-assisted development, where projects can accumulate dependencies quickly and not every scary advisory is a real production issue.

## What Guardian Does

- Inventories npm and Python dependency evidence from manifests, lockfiles, and optional installed metadata.
- Matches exact package versions against vulnerability, exploit-intelligence, and malicious-package sources.
- Separates direct runtime risk from transitive, vendored metadata, test-only, tooling-only, and isolated-environment noise.
- Tracks scans over time so you can see new, resolved, changed, and unchanged findings.
- Produces compact operator JSON and optional Markdown handoff reports for agents, maintainers, and reviewers.
- Includes a package-diet workflow for unused or replaceable dependencies.
- Helps prepare maintainer-friendly advisory PRs only when the evidence supports a real fix.

Guardian does not edit dependency files, install project dependencies, or execute arbitrary project code during normal scans.

## How Guardian Works

```text
Project evidence
  -> read-only inventory
  -> normalized package versions
  -> advisory and exploit-intelligence matching
  -> project-context corroboration
  -> prioritized findings
  -> operator summary, handoff report, and snapshot comparison
```

Guardian is evidence-first. It should not tell an agent to upgrade a package unless the package version, advisory match, dependency context, and project evidence support that recommendation.

## Install In Codex

```bash
codex plugin marketplace add gateway/guardian --ref main
codex plugin add guardian-security-scan@guardian
```

Start a new Codex thread after installing so the Guardian skills are loaded.

For local development from a checkout:

```bash
git clone https://github.com/gateway/guardian.git
codex plugin marketplace add ./guardian
codex plugin add guardian-security-scan@guardian
```

## Install In Claude Code

```bash
claude plugin marketplace add gateway/guardian
claude plugin install guardian-security-scan@guardian
```

Guardian's Claude skills are namespaced:

```text
/guardian-security-scan:guardian-project-scan
/guardian-security-scan:guardian-daily-watch
/guardian-security-scan:guardian-repo-scout
/guardian-security-scan:guardian-package-diet
/guardian-security-scan:guardian-advisory-pr
```

For Claude-specific install and validation notes, see [`docs/CLAUDE_CODE.md`](docs/CLAUDE_CODE.md).

## Quick Test

After installing in Claude Code, verify the cached plugin can run:

```bash
GUARDIAN_PLUGIN_BIN="$(find "$HOME/.claude/plugins/cache/guardian/guardian-security-scan" -path '*/scripts/guardian' -type f -print | sort | tail -n 1)"
GUARDIAN_SMOKE_STATE="$(mktemp -d "${TMPDIR:-/tmp}/guardian-smoke.XXXXXX")"
GUARDIAN_STATE_DIR="$GUARDIAN_SMOKE_STATE" "$GUARDIAN_PLUGIN_BIN" report summary --json
```

From a local checkout:

```bash
./plugins/guardian-security-scan/scripts/guardian report summary --json
```

From an agent session after install:

```text
Use Guardian to scan this project read-only and give me the operator summary.
```

Use Sonnet with low or normal effort for smoke scans. Guardian does the dependency scan locally; higher-reasoning models are usually unnecessary for install verification.

## Skills And When To Use Them

### `guardian-project-scan`

Use this for normal project security scans, repeat scans, fix verification, and handoff reports.

```text
Use Guardian to scan this project read-only and summarize actionable package risk.
```

```text
Run Guardian again and compare this scan with the previous scan so I can see what is new, fixed, changed, or unchanged.
```

### `guardian-daily-watch`

Use this for lightweight morning automation across known local repos. It fingerprints dependency files, skips unchanged inventory, and can refresh advisory data for known package inventories.

```text
Use Guardian daily watch to check my known local repos and summarize what changed.
```

See [`docs/AUTOMATION.md`](docs/AUTOMATION.md) for scheduled scan strategy.

### `guardian-repo-scout`

Use this for temporary scans of public GitHub repos you do not own. Repo Scout uses disposable clones and temporary Guardian state by default, then reports high-signal findings and the recommended reporting path.

```text
Use Guardian repo scout to scan owner/name with temporary state and show only high-signal findings.
```

See [`docs/REPO_SCOUT.md`](docs/REPO_SCOUT.md) for the public-repo scouting workflow.

### `guardian-package-diet`

Use this for dependency bloat, unused packages, and "could simple local code replace this dependency?" review. This is separate from vulnerability scanning.

```text
Use Guardian package diet to find unused packages and simple replace-with-code candidates.
```

### `guardian-advisory-pr`

Use this after Guardian confirms an actionable finding and you want a maintainer-friendly PR with advisory links, dependency evidence, fix rationale, and validation notes.

```text
Use Guardian Advisory PR to prepare a maintainer-friendly security PR for this confirmed finding.
```

## Automation

Guardian stores local scan state in SQLite outside the plugin by default:

```text
~/.guardian-security-scan/guardian.db
```

That state lets Guardian compare scans across time and answer practical questions:

- Did a new advisory affect a package we already had?
- Did a dependency change introduce a new finding?
- Did a fix actually resolve the previous issue?
- Is this unchanged metadata noise that should not be re-explained every morning?

For morning checks, use `guardian-daily-watch`. It keeps scans cheap by hashing dependency manifests and lockfiles first, then only re-inventories repos whose dependency files changed. Add live advisory refresh when you want to check known packages against newly published data.

## Intelligence Sources

Guardian uses multiple sources because no single feed is complete:

- OSV
- GitHub Security Advisories
- CISA Known Exploited Vulnerabilities
- FIRST EPSS
- NVD enrichment
- GitLab Advisory Database ingest
- Bundled exact-match public malicious-package campaign catalogs

Guardian reports what configured sources currently know about package versions it can see. It cannot prove a project is safe from unknown zero-days.

For source behavior, trust boundaries, and known limits, see [`docs/TRUST_MODEL.md`](docs/TRUST_MODEL.md).

## Efficient By Default

Guardian is designed to be lightweight for local agent workflows and scheduled scans:

- The scanner runtime uses the Python standard library only.
- Normal reports are compact so agents read summaries instead of raw lockfiles.
- Daily watch skips unchanged dependency inventories.
- Live advisory refresh and installed-tree corroboration are explicit options.
- Repo Scout uses bounded, paced scans for large public repos.
- Snapshot comparison prevents repeated scans from re-explaining unchanged findings.
- Package-diet review is separate so bloat analysis does not inflate security output.

Default scans are intentionally conservative. Deeper live-source checks, installed-tree corroboration, and package usage scans are available when the situation justifies them.

## More Documentation

- [`docs/AUTOMATION.md`](docs/AUTOMATION.md): daily watch, freshness, and scan-state behavior.
- [`docs/CLI.md`](docs/CLI.md): direct CLI usage, scan modes, tokens, and local state.
- [`docs/CLAUDE_CODE.md`](docs/CLAUDE_CODE.md): Claude Code install, validation, and smoke tests.
- [`docs/REPO_SCOUT.md`](docs/REPO_SCOUT.md): temporary public GitHub repo scouting.
- [`docs/TRUST_MODEL.md`](docs/TRUST_MODEL.md): security boundary, source model, and known limits.
- [`SECURITY.md`](SECURITY.md): vulnerability reporting and secret-handling guidance.

## What Guardian Does Not Do

- It does not prove a project has no unknown zero-days.
- It does not execute arbitrary project code during normal scans.
- It does not automatically edit or upgrade dependencies.
- It does not treat every transitive or vendored metadata finding as a production incident.
- It does not replace human review for high-impact security fixes.
