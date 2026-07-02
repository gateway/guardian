# Guardian Security Scan

This is the installable Guardian plugin bundle for Codex and Claude Code.

Guardian scans npm and Python project dependency evidence in read-only mode, matches exact package versions against advisory and exploit-intelligence sources, and returns a compact operator summary for the agent.

## Skills

- `guardian-project-scan`: normal project scans, repeat scans, fix verification, and handoffs.
- `guardian-daily-watch`: low-token morning checks across known local repos.
- `guardian-repo-scout`: temporary public GitHub repo scans with isolated state.
- `guardian-package-diet`: dependency bloat and unused-package review.
- `guardian-advisory-pr`: maintainer-friendly PR preparation for confirmed actionable findings.

Skill calls are namespaced:

- Codex: `$guardian-security-scan:guardian-project-scan`
- Claude Code: `/guardian-security-scan:guardian-project-scan`

## Test Your First Repo

After installing, open Codex or Claude Code in a project you want to scan and use one of these prompts:

Codex:

> $guardian-security-scan:guardian-project-scan Scan this project read-only. Do not edit files, install dependencies, or run project code. Give me the operator summary, top findings, and any suggested next steps.

Claude Code:

> /guardian-security-scan:guardian-project-scan Scan this project read-only. Do not edit files, install dependencies, or run project code. Give me the operator summary, top findings, and any suggested next steps.

From this plugin directory, you can also run a direct CLI scan:

```bash
./scripts/guardian scan /path/to/repo --mode daily --output compact --json
```

For a no-project install check from this plugin directory:

```bash
./scripts/guardian report summary --json
```

Use Sonnet with low or normal effort for routine scan summaries. Guardian's local runner performs the scan; higher reasoning models are usually not needed for install verification.

## Notes

- Normal scans do not edit files, install dependencies, or execute arbitrary project code.
- Guardian stores local runtime state in `~/.guardian-security-scan` unless `GUARDIAN_STATE_DIR` is set.
- GitHub tokens are optional. `GITHUB_TOKEN`, `GH_TOKEN`, or `gh auth token` improve rate limits for deeper advisory checks.
- Claude Desktop Code uses the Claude Code runtime under the hood, so tool output may mention Claude Code even when the session was launched from the Desktop app.
- Save Opus/High for complex advisory interpretation, maintainer PR review, or remediation tradeoff decisions.

For installation, usage, and project overview, see the repository README:

```text
https://github.com/gateway/guardian
```
