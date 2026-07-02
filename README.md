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

### Codex Desktop

Open **Plugins** in the Codex app. If your app exposes an add-marketplace or add-repository flow, add Guardian with:

- Marketplace or GitHub repo: `gateway/guardian`
- Plugin to install: `guardian-security-scan`

If the app does not expose that source flow, use the Codex CLI commands below once from Terminal, then restart Codex or start a new thread so the Guardian skills are loaded.

### Codex CLI

Run these commands in Terminal. The install is two steps because Codex first adds the Guardian marketplace source, then installs the plugin from that marketplace.

`gateway/guardian` is GitHub shorthand for `https://github.com/gateway/guardian`. Codex reads this repo's `.agents/plugins/marketplace.json`; that file names the marketplace `guardian` and points the `guardian-security-scan` plugin at `./plugins/guardian-security-scan`.

1. Add the Guardian marketplace:

```bash
codex plugin marketplace add gateway/guardian --ref main
```

2. Install the Guardian plugin:

```bash
codex plugin add guardian-security-scan@guardian
```

For local development from a checkout, use the local path instead of the GitHub marketplace:

```bash
git clone https://github.com/gateway/guardian.git
codex plugin marketplace add ./guardian
codex plugin add guardian-security-scan@guardian
```

## Install In Claude Code

### Claude Desktop / Claude Code UI

In Claude Code, type `/plugin` in the prompt box to open the plugin manager. Go to **Marketplaces**, add Guardian, then install the plugin:

- Plugin source or GitHub repo: `https://github.com/gateway/guardian`
- Plugin to install: `guardian-security-scan`

Claude skills are namespaced after install, for example `guardian-security-scan:guardian-project-scan`.

### Claude Code Prompt Commands

These are Claude Code slash commands. Paste them into a Claude Code prompt, not your shell. The install is two steps: add the Guardian marketplace, then install the plugin.

`gateway/guardian` is GitHub shorthand for `https://github.com/gateway/guardian`. Claude Code reads this repo's `.claude-plugin/marketplace.json`; that file names the marketplace `guardian` and points the `guardian-security-scan` plugin at `./plugins/guardian-security-scan`.

1. Add the Guardian marketplace:

```text
/plugin marketplace add gateway/guardian
```

2. Install the Guardian plugin:

```text
/plugin install guardian-security-scan@guardian
```

Run `/reload-plugins` or start a new Claude Code session after installing.

Guardian's Claude skills are namespaced:

- `guardian-security-scan:guardian-project-scan`
- `guardian-security-scan:guardian-daily-watch`
- `guardian-security-scan:guardian-repo-scout`
- `guardian-security-scan:guardian-package-diet`
- `guardian-security-scan:guardian-advisory-pr`

For Claude-specific install and validation notes, see [`docs/CLAUDE_CODE.md`](docs/CLAUDE_CODE.md).

## Test Your First Repo

After installing, open Codex or Claude in a project you want to scan and use one of these prompts:

Codex:

> $guardian-security-scan:guardian-project-scan Scan this project read-only. Do not edit files, install dependencies, or run project code. Give me the operator summary, top findings, and any suggested next steps.

Claude Code:

> /guardian-security-scan:guardian-project-scan Scan this project read-only. Do not edit files, install dependencies, or run project code. Give me the operator summary, top findings, and any suggested next steps.

A good first scan should report:

- Current posture, such as `0 act now`, `1 fix this week`, or `watch`.
- Whether findings are runtime-linked, transitive, vendored metadata, test-only, or isolated.
- Advisory links and severity when a package matches a known issue.
- What changed compared with the previous scan if this repo has been scanned before.
- Paths to any operator JSON or Markdown handoff artifacts.

If you are testing from a Guardian checkout instead of an installed plugin, run:

```bash
./plugins/guardian-security-scan/scripts/guardian scan /path/to/repo --mode daily --output compact --json
```

Use Sonnet with low or normal effort for routine scan summaries. Guardian does the dependency scan locally; higher-reasoning models are usually unnecessary for install verification.

## Skills And When To Use Them

Skill calls are slightly different by harness:

- Codex: use `$guardian-security-scan:skill-name`.
- Claude Code: use `/guardian-security-scan:skill-name`.
- Natural language usually works too, but the prefixed form is the clearest copy/paste option.

Standalone personal skills may have shorter names such as `$guarded-code`; Guardian skills are plugin skills, so they use the plugin namespace to avoid collisions with other installed skills.

### `guardian-project-scan`

Use this for normal project security scans, repeat scans, fix verification, and handoff reports.

Codex:

> $guardian-security-scan:guardian-project-scan Scan this project read-only. Do not edit files, install dependencies, or run project code. Compare this scan with the previous scan if one exists, then summarize the current posture, top actionable findings, advisory links, evidence context, and suggested next steps.

Claude Code:

> /guardian-security-scan:guardian-project-scan Scan this project read-only. Do not edit files, install dependencies, or run project code. Compare this scan with the previous scan if one exists, then summarize the current posture, top actionable findings, advisory links, evidence context, and suggested next steps.

### `guardian-daily-watch`

Use this for lightweight morning automation across known local repos. It fingerprints dependency files, skips unchanged inventory, and can refresh advisory data for known package inventories.

Codex:

> $guardian-security-scan:guardian-daily-watch Check my known local repos. Keep it lightweight, skip unchanged dependency inventories where possible, refresh advisory data for known packages if available, and summarize only new, resolved, changed, or high-priority findings.

Claude Code:

> /guardian-security-scan:guardian-daily-watch Check my known local repos. Keep it lightweight, skip unchanged dependency inventories where possible, refresh advisory data for known packages if available, and summarize only new, resolved, changed, or high-priority findings.

See [`docs/AUTOMATION.md`](docs/AUTOMATION.md) for scheduled scan strategy.

### `guardian-repo-scout`

Use this for temporary scans of public GitHub repos you do not own. Repo Scout uses disposable clones and temporary Guardian state by default, then reports high-signal findings and the recommended reporting path.

Codex:

> $guardian-security-scan:guardian-repo-scout Scan `owner/name` with temporary clones and temporary Guardian state. Do not install dependencies or run project code. Show only high-signal dependency findings, include advisory links and reporting-path guidance, and clean up temporary files when finished.

Claude Code:

> /guardian-security-scan:guardian-repo-scout Scan `owner/name` with temporary clones and temporary Guardian state. Do not install dependencies or run project code. Show only high-signal dependency findings, include advisory links and reporting-path guidance, and clean up temporary files when finished.

See [`docs/REPO_SCOUT.md`](docs/REPO_SCOUT.md) for the public-repo scouting workflow.

### `guardian-package-diet`

Use this for dependency bloat, unused packages, and "could simple local code replace this dependency?" review. This is separate from vulnerability scanning.

Codex:

> $guardian-security-scan:guardian-package-diet Analyze this repo for dependency bloat. Identify unused dependency candidates, packages used only in narrow/test/build contexts, and packages that could reasonably be replaced with simple local code. Include where each package is used and rate removal risk as low, medium, or high.

Claude Code:

> /guardian-security-scan:guardian-package-diet Analyze this repo for dependency bloat. Identify unused dependency candidates, packages used only in narrow/test/build contexts, and packages that could reasonably be replaced with simple local code. Include where each package is used and rate removal risk as low, medium, or high.

### `guardian-advisory-pr`

Use this after Guardian confirms an actionable finding and you want a maintainer-friendly PR with advisory links, dependency evidence, fix rationale, and validation notes.

Codex:

> $guardian-security-scan:guardian-advisory-pr For this confirmed Guardian finding, prepare a maintainer-friendly PR plan that explains the vulnerable package/version, advisory links, dependency path, affected code usage, recommended fix, upgrade risk, validation steps, and a short "Powered by Guardian" note.

Claude Code:

> /guardian-security-scan:guardian-advisory-pr For this confirmed Guardian finding, prepare a maintainer-friendly PR plan that explains the vulnerable package/version, advisory links, dependency path, affected code usage, recommended fix, upgrade risk, validation steps, and a short "Powered by Guardian" note.

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
