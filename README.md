# Guardian

Guardian is a Codex plugin for read-only dependency risk review. It inventories npm and Python packages, checks exact versions against vulnerability and exploit-intelligence sources, and turns the result into an operator-friendly summary that explains what matters, what changed, and what action is justified.

Use Guardian when you want Codex to answer: "Is this project carrying known package risk, and what should we do next?"

Guardian is built for modern AI-assisted development, where packages can accumulate quickly, lockfiles may contain stale nested metadata, and not every scary advisory is a production incident.

## Why Use Guardian

- Catch known vulnerable, known exploited, malicious, and high exploit-likelihood packages before release or merge.
- Separate direct runtime risk from transitive, tooling-only, isolated-environment, and vendored-metadata noise.
- Compare scans over time so you can verify whether a fix actually resolved the finding.
- Generate handoff artifacts that another Codex session, maintainer, or reviewer can understand.
- Review package bloat and reduce supply-chain surface where dependencies are unused or replaceable.
- Prepare focused advisory PRs only when the evidence supports a real dependency fix.

Guardian does not try to create panic or force dependency churn. Its job is to provide enough evidence to make a fast, sane security decision.

## Included Skills

Guardian ships with three Codex skills:

- `guardian-project-scan`: Use this for normal project security scans, repeat scans, fix verification, and operator handoffs. This is the default skill for dependency-risk review.
- `guardian-package-diet`: Use this when the question is dependency cleanup, unused packages, package bloat, or "could we replace this with simple local code?" This is not a vulnerability scan.
- `guardian-advisory-pr`: Use this only after a finding is confirmed as actionable and you want Codex to prepare a maintainer-friendly security PR with advisory links, dependency-path proof, code-usage review, fix rationale, and validation notes.

Example prompts:

```text
Use Guardian to scan this project and summarize the findings.
```

```text
Use Guardian package diet to find dependency bloat and safe removal candidates.
```

```text
Use Guardian Advisory PR to prepare a maintainer-friendly security PR for this confirmed finding.
```

## What Guardian Checks

Guardian uses multiple sources because no single feed is complete:

- OSV for broad ecosystem vulnerability matching.
- GitHub Security Advisories for ecosystem advisories and malicious-package classifications.
- CISA Known Exploited Vulnerabilities for exploited-in-the-wild signal.
- FIRST EPSS for exploit-likelihood prioritization.
- NVD for CVE detail and severity enrichment.
- GitLab Advisory Database ingest for additional advisory coverage.
- Bundled exact-match public campaign catalogs for selected malicious package incidents.

Guardian reports what the configured sources currently know about the package versions it can see. It cannot prove a project is safe from unknown zero-days.

## Output

A good Guardian scan should tell you:

- Current posture: whether the repo has actionable package risk right now.
- What changed: new, resolved, changed, and unchanged findings compared with the previous scan.
- Highest-signal issues: package, version, advisory, severity, confidence, environment, and evidence.
- Action judgment: upgrade, review parent chain, no direct app action, or manual verification.
- Artifacts: operator JSON and optional Markdown handoff paths.

Guardian is intentionally conservative about vendored nested lockfiles, stale metadata, test-only packages, and isolated environments. Those cases should be visible, but they should not be treated like confirmed runtime compromise unless the evidence supports that.

## Setup

Guardian is bundled inside this plugin and uses the Python standard library for its own runtime.

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
./scripts/guardian scan /path/to/repo --mode daily --output compact --json
```

Run a deeper scan with installed-tree and GHSA corroboration:

```bash
./scripts/guardian scan /path/to/repo --mode deep --include-installed --include-ghsa --json
```

Review package bloat:

```bash
./scripts/guardian diet scan /path/to/repo --limit 100 --usage-limit 80 --json
```

## What Guardian Does Not Do

- It does not prove a project has no unknown zero-days.
- It does not execute arbitrary project code during normal scans.
- It does not automatically edit dependencies.
- It does not treat every transitive or vendored metadata finding as a production incident.
- It does not replace human review for high-impact security fixes.
