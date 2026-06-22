# Guardian

Guardian is a Codex plugin for read-only dependency risk review. It inventories npm and Python packages, checks exact versions against vulnerability and exploit-intelligence sources, and turns the result into a compact operator summary that explains what matters, what changed, and what action is justified.

Use Guardian when you want Codex to answer: "Is this project carrying known package risk, and what should we do next?"

Guardian is built for AI-assisted development, where packages can accumulate quickly, lockfiles may contain stale nested metadata, and not every scary advisory is a production incident.

## How It Works

Guardian scans project evidence in read-only mode. It does not edit dependency files or execute arbitrary project code during normal scans.

`Project evidence -> read-only inventory -> normalized packages -> security intelligence match -> project-context corroboration -> prioritized findings -> operator JSON / Markdown handoff / snapshot comparison`

The design is evidence first, explanation second. Guardian avoids telling Codex to upgrade a package until the package version, advisory match, dependency context, and project evidence support that recommendation.

## Why Use Guardian

- Catch known vulnerable, known exploited, malicious, and high exploit-likelihood packages before release or merge.
- Separate direct runtime risk from transitive, tooling-only, isolated-environment, and vendored-metadata noise.
- Compare scans over time so you can verify whether a fix actually resolved the finding.
- Generate handoff artifacts that another Codex session, maintainer, or reviewer can understand.
- Review package bloat and reduce supply-chain surface where dependencies are unused or replaceable.
- Prepare focused advisory PRs only when the evidence supports a real dependency fix.

Guardian does not try to create panic or force dependency churn. It gives you enough evidence to make a fast, sane security decision.

## Included Skills

Guardian ships with four Codex skills:

- `guardian-project-scan`: Use this for normal project security scans, repeat scans, fix verification, and operator handoffs.
- `guardian-daily-watch`: Use this for lightweight morning automation across known local repos. It detects dependency-file changes, skips unchanged inventory, and compares cached findings with low token/tool overhead.
- `guardian-package-diet`: Use this for dependency cleanup, unused packages, package bloat, and "could we replace this with simple local code?" This is not a vulnerability scan.
- `guardian-advisory-pr`: Use this after a finding is confirmed as actionable and you want a maintainer-friendly security PR with advisory links, dependency-path proof, code-usage review, fix rationale, and validation notes.

Example prompts:

```text
Use Guardian to scan this project and summarize the findings.
```

```text
Use Guardian daily watch to check my known local repos and summarize what changed.
```

```text
Use Guardian package diet to find dependency bloat and safe removal candidates.
```

```text
Use Guardian Advisory PR to prepare a maintainer-friendly security PR for this confirmed finding.
```

## Install In Codex

Guardian is packaged as a Codex marketplace repo. GitHub only hosts the files; Codex reads `.agents/plugins/marketplace.json`, finds `plugins/guardian-security-scan`, and installs the plugin from that bundle.

Install the published marketplace:

```bash
codex plugin marketplace add gateway/guardian --ref main
codex plugin add guardian-security-scan@guardian
```

Install from a local checkout while developing:

```bash
git clone https://github.com/gateway/guardian.git
codex plugin marketplace add ./guardian
codex plugin add guardian-security-scan@guardian
```

Start a new Codex thread after installing so the new skills are loaded.

## Release Verification

Before publishing a new release, run:

```bash
./scripts/release_check.sh
```

That gate validates the Codex plugin manifest, skill metadata, Python source compilation, Guardian's internal regression corpus, fixture scans, and a local Codex marketplace install smoke test.

## Intelligence Sources

Guardian uses multiple sources because no single feed is complete:

- OSV for broad ecosystem vulnerability matching.
- GitHub Security Advisories for ecosystem advisories and malicious-package classifications.
- CISA Known Exploited Vulnerabilities for exploited-in-the-wild signal.
- FIRST EPSS for exploit-likelihood prioritization.
- NVD for CVE detail and severity enrichment.
- GitLab Advisory Database ingest for additional advisory coverage.
- Bundled exact-match public campaign catalogs for selected malicious package incidents.

Guardian reports what the configured sources currently know about the package versions it can see. It cannot prove a project is safe from unknown zero-days.

For the security boundary and expectations, read [`docs/TRUST_MODEL.md`](docs/TRUST_MODEL.md).

## Scan State And Freshness

Guardian keeps local scan state in SQLite so repeat scans can be compared. By default, state is stored outside the plugin at:

```text
~/.guardian-security-scan/guardian.db
```

That database stores package inventory state, dependency-file fingerprints, advisory rows, findings, triage snapshots, policy exceptions, and remediation lifecycle data. It is runtime state only; the database is not shipped in the plugin.

Each project scan does fresh work:

- Re-inventories the target repo from manifests, lockfiles, and optional installed metadata.
- Queries OSV live for the current package versions.
- Checks bundled and generated local exact-match catalogs.
- In daily, standard, deep, and handoff modes, initializes and refreshes configured threat-intel sources such as the GitLab Advisory Database sparse checkout when available.
- Enriches matching CVEs with live CISA KEV, FIRST EPSS, and NVD details when those aliases are present.
- Queries GitHub Security Advisories when `--include-ghsa` is enabled or a scan mode enables it.
- Writes a new triage snapshot and compares it with the previous snapshot for that repo.

For daily automation, the important fields are the source status, generated timestamps, snapshot comparison, and operator report path. They show whether the run queried live sources, used local catalogs, found new issues, resolved previous issues, or saw no meaningful change.

For lightweight morning checks, use `daily-watch`. It hashes dependency manifests and lockfiles first, skips inventory for repos whose dependency files did not change, and writes fresh snapshots from cached findings so new, resolved, and unchanged evidence can be tracked cheaply. Add `--refresh-advisories` when you want the run to query live advisory sources for the known package inventory; add `--live-enrichment` only when you also want slower KEV, EPSS, and NVD enrichment.

## Efficient By Default

Guardian is built to stay lightweight for local Codex workflows and scheduled scans:

- The scanner runtime uses the Python standard library only. Guardian does not install third-party Python packages to run.
- Normal reports are compact so Codex can read an operator summary instead of spending tokens on raw lockfiles or full advisory payloads.
- `daily-watch` avoids re-inventorying unchanged repos by comparing dependency-file fingerprints before scan work starts.
- Live advisory refresh for large multi-repo watches is explicit with `--refresh-advisories` so scheduled automation stays predictable.
- Snapshot comparison prevents repeated scans from re-explaining unchanged findings as if they were new.
- Deeper live-source checks, installed-tree corroboration, and package-diet usage scans are opt-in.
- Package-diet review is separate so dependency-bloat analysis does not inflate normal vulnerability-scan output.

Live advisory queries, deep installed-tree checks, and large-repo usage searches still take time. The default workflow is intentionally conservative; deeper checks are available when the situation justifies them.

## Output

A good Guardian scan should tell you:

- Current posture: whether the repo has actionable package risk right now.
- What changed: new, resolved, changed, and unchanged findings compared with the previous scan.
- Highest-signal issues: package, version, advisory, severity, confidence, environment, and evidence.
- Action judgment: upgrade, review parent chain, no direct app action, or manual verification.
- Artifacts: operator JSON and optional Markdown handoff paths.

Guardian is intentionally conservative about vendored nested lockfiles, stale metadata, test-only packages, and isolated environments. Those cases should be visible, but they should not be treated like confirmed runtime compromise unless the evidence supports that.

## Setup

Requirements:

- Python 3.9+ available as `/usr/bin/python3` or `python3`.
- Codex with local plugin support.
- Git for repo-root detection.
- npm, pnpm, or pip only when you want package-manager corroboration or audit checks.

Guardian writes local scan state to `~/.guardian-security-scan` by default. To isolate state for a workflow, set:

```bash
export GUARDIAN_STATE_DIR=/path/to/guardian-state
```

## GitHub API Token

A GitHub token is optional.

Guardian can query GitHub Security Advisories without a token, but unauthenticated requests have lower rate limits. For deeper scans or frequent automation, set one of:

```bash
export GITHUB_TOKEN=<your token>
export GH_TOKEN=<your token>
```

If neither environment variable is set, Guardian tries `gh auth token` when the GitHub CLI is installed and authenticated. If no token is available, Guardian still runs using OSV, local catalogs, KEV, EPSS, NVD enrichment where applicable, and unauthenticated GHSA requests when requested.

Do not commit tokens to this repo. Use environment variables or your local GitHub CLI login.

## Running The Bundled CLI

Run a normal scan:

```bash
./plugins/guardian-security-scan/scripts/guardian scan /path/to/repo --mode daily --output compact --json
```

Run a lightweight morning watch over one or more known roots:

```bash
./plugins/guardian-security-scan/scripts/guardian daily-watch --root /path/to/repo --json
```

Run the same watch with live advisory refresh:

```bash
./plugins/guardian-security-scan/scripts/guardian daily-watch --root /path/to/repo --refresh-advisories --json
```

Run a deeper scan with installed-tree and GHSA corroboration:

```bash
./plugins/guardian-security-scan/scripts/guardian scan /path/to/repo --mode deep --include-installed --include-ghsa --json
```

Review package bloat:

```bash
./plugins/guardian-security-scan/scripts/guardian diet scan /path/to/repo --limit 100 --usage-limit 80 --json
```

## What Guardian Does Not Do

- It does not prove a project has no unknown zero-days.
- It does not execute arbitrary project code during normal scans.
- It does not automatically edit dependencies.
- It does not treat every transitive or vendored metadata finding as a production incident.
- It does not replace human review for high-impact security fixes.
