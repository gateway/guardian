# Guardian

Guardian is a Codex plugin and local dependency-risk scanner for modern software projects. It helps you understand whether the packages in a repo match known vulnerability, exploit, or malicious-package intelligence, then turns that into a clear operator summary instead of a wall of scary dependency noise.

Use it when you want Codex to answer: "Is this project carrying known package risk, what actually matters, and what should we do next?"

Guardian is designed for developers using Codex or other AI coding agents who want stronger supply-chain review before releases, dependency upgrades, package installs, or maintainer-facing security PRs.

## What It Does

- Inventories npm and Python packages from manifests, lockfiles, and optional installed metadata.
- Checks exact package versions against known advisory and exploit sources.
- Labels findings as known vulnerable, known exploited, malicious package, high exploit likelihood, vendored metadata, isolated environment, runtime-linked, or transitive.
- Produces a compact operator JSON report and an optional human-readable Markdown handoff.
- Tracks snapshots so a later scan can say whether findings are new, resolved, changed, or unchanged.
- Runs a separate package diet review for dependency bloat, unused candidates, and replace-with-native opportunities.

## What It Is Used For

- Project security scans before release, deploy, or merge.
- Repeat scans to verify whether a dependency fix actually resolved an issue.
- Deep package review when a new advisory, CVE, malicious-package report, or known exploited issue appears.
- Codex handoff documents that explain the finding, evidence, code usage, and next action.
- Dependency cleanup review when a repo has accumulated packages that may be unused or replaceable.
- Safer upstream PR preparation for confirmed dependency advisories.

## Why You Would Use It

Dependency risk is no longer just "run an audit and upgrade everything." AI-assisted development often adds packages quickly, lockfiles can contain stale nested metadata, and advisories can range from harmless-in-this-context to exploited-in-the-wild. Guardian is built to help Codex separate those cases.

Guardian is useful when you need to:

- Check a repo before release or before merging dependency changes.
- Understand whether a reported issue is direct runtime risk, transitive risk, tooling-only risk, isolated virtualenv risk, or vendored metadata noise.
- Confirm whether a previous fix actually removed the finding from the next scan.
- Create a handoff document another Codex session or maintainer can act on.
- Reduce supply-chain surface by finding packages that may be unused, overkill, or replaceable with simple local code.
- Avoid unnecessary dependency churn when the evidence does not justify changing app packages.

## Sources

Guardian uses multiple sources because no single feed is complete:

- OSV for broad ecosystem vulnerability matching.
- GitHub Security Advisories for ecosystem advisories and malicious-package classifications.
- CISA Known Exploited Vulnerabilities for exploited-in-the-wild signal.
- FIRST EPSS for exploit-likelihood prioritization.
- NVD for CVE detail and severity enrichment.
- GitLab Advisory Database ingest for additional advisory coverage.
- Bundled exact-match public campaign catalogs for selected malicious package incidents.

Guardian does not prove a project is safe from unknown zero-days. It reports what the configured sources currently know about the package versions it can see.

## Setup

Guardian is bundled inside this plugin and uses the Python standard library for its own runtime.

Requirements:

- macOS, Linux, or another environment with Python 3.9+ available as `/usr/bin/python3` or `python3`.
- Codex with local plugin support.
- Git, if you want automatic repo-root detection.
- npm, pnpm, or pip only when you want Guardian to corroborate package-manager state or run package-manager audit commands.

Install in Codex from a local checkout or marketplace entry, then use the included skills:

```text
Use Guardian to scan this project and summarize the findings.
```

Guardian writes local scan state to `~/.guardian-security-scan` by default. You can isolate state for a specific workflow by setting:

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

## Advantages

- Human-readable decisions: Guardian explains what matters, why it matters, and what action is justified.
- Lower false-alarm pressure: vendored lockfiles, stale nested metadata, test-only packages, and isolated environments are not treated like confirmed runtime compromise.
- Repeatable evidence: snapshot comparison shows new, resolved, changed, and unchanged findings between scans.
- Better Codex behavior: the plugin gives Codex concrete advisory links, package context, code-usage hints, and handoff artifacts before suggesting changes.
- Supply-chain reduction: package diet mode helps identify where a repo may not need every dependency it carries.
- Safe defaults: project scans are read-only, and remediation PR work is separated from discovery.
- Lightweight runtime: Guardian itself uses the Python standard library, reducing the plugin's own dependency surface.

## Best Use

Start with a normal security scan:

```text
Use Guardian to scan this project and summarize the findings.
```

Use package diet separately when the question is cleanup rather than vulnerability remediation:

```text
Use Guardian package diet to find dependency bloat and safe removal candidates.
```

Use advisory PR support only after Guardian has found a confirmed actionable package issue:

```text
Use Guardian Advisory PR to prepare a maintainer-friendly security PR for this finding.
```

## What Good Output Looks Like

Guardian should tell you:

- Current posture: what risk exists right now.
- What changed: whether findings are new, resolved, or unchanged.
- Highest-signal issues: package, version, severity, confidence, environment, and advisory evidence.
- Whether action is justified: upgrade, parent-chain review, no direct app action, or manual verification.
- Next steps: concise actions that a developer or Codex session can safely follow.

The goal is not to create panic or dependency churn. The goal is to give you enough evidence to make a sane security decision quickly.

## Running The Bundled CLI

You can run the plugin CLI directly from a checkout:

```bash
./scripts/guardian scan /path/to/repo --mode daily --output compact --json
```

For a deeper scan:

```bash
./scripts/guardian scan /path/to/repo --mode deep --include-installed --include-ghsa --json
```

For package bloat review:

```bash
./scripts/guardian diet scan /path/to/repo --limit 100 --usage-limit 80 --json
```

## What Guardian Does Not Do

- It does not prove a project has no unknown zero-days.
- It does not execute arbitrary project code during normal scans.
- It does not automatically edit dependencies.
- It does not treat every transitive or vendored metadata finding as a production incident.
- It does not replace human review for high-impact security fixes.
