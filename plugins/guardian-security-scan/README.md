# Guardian Security Scan

This is the installable Guardian plugin bundle for Codex and Claude Code.

Guardian scans npm and Python project dependency evidence in read-only mode, matches exact package versions against advisory and exploit-intelligence sources, and returns a compact operator summary for the agent.

## Skills

- `guardian-project-scan`: normal project scans, repeat scans, fix verification, and handoffs.
- `guardian-daily-watch`: low-token morning checks across known local repos.
- `guardian-repo-scout`: temporary public GitHub repo scans with isolated state.
- `guardian-package-diet`: dependency bloat and unused-package review.
- `guardian-advisory-pr`: maintainer-friendly PR preparation for confirmed actionable findings.

Claude Code skill names are namespaced:

```text
/guardian-security-scan:guardian-project-scan
/guardian-security-scan:guardian-daily-watch
/guardian-security-scan:guardian-repo-scout
/guardian-security-scan:guardian-package-diet
/guardian-security-scan:guardian-advisory-pr
```

## Smoke Test

From an installed Claude plugin cache:

```bash
GUARDIAN_PLUGIN_BIN="$(find "$HOME/.claude/plugins/cache/guardian/guardian-security-scan" -path '*/scripts/guardian' -type f -print | sort | tail -n 1)"
GUARDIAN_SMOKE_STATE="$(mktemp -d "${TMPDIR:-/tmp}/guardian-smoke.XXXXXX")"
GUARDIAN_STATE_DIR="$GUARDIAN_SMOKE_STATE" "$GUARDIAN_PLUGIN_BIN" report summary --json
```

From this plugin directory:

```bash
./scripts/guardian report summary --json
```

## Notes

- Normal scans do not edit files, install dependencies, or execute arbitrary project code.
- Guardian stores local runtime state in `~/.guardian-security-scan` unless `GUARDIAN_STATE_DIR` is set.
- GitHub tokens are optional. `GITHUB_TOKEN`, `GH_TOKEN`, or `gh auth token` improve rate limits for deeper advisory checks.
- Claude Desktop Code uses the Claude Code runtime under the hood, so tool output may mention Claude Code even when the session was launched from the Desktop app.

For installation, usage, and project overview, see the repository README:

```text
https://github.com/gateway/guardian
```
