# Claude Code Plugin

Guardian can be installed as a Claude Code plugin from the same repository as the Codex plugin. The scanner runtime, skills, bundled catalogs, and scripts are all inside `plugins/guardian-security-scan`, so Claude Code can copy the plugin into its cache without depending on files outside the plugin directory.

## Install From GitHub

Add the Guardian marketplace:

```bash
claude plugin marketplace add gateway/guardian
```

Install the plugin:

```bash
claude plugin install guardian-security-scan@guardian
```

Reload plugins or start a new Claude Code session. Guardian skills are namespaced by the plugin:

```text
/guardian-security-scan:guardian-project-scan
/guardian-security-scan:guardian-daily-watch
/guardian-security-scan:guardian-repo-scout
/guardian-security-scan:guardian-package-diet
/guardian-security-scan:guardian-advisory-pr
```

## Install From A Local Checkout

From the parent directory:

```bash
git clone https://github.com/gateway/guardian.git
claude plugin marketplace add ./guardian
claude plugin install guardian-security-scan@guardian
```

From inside the Guardian checkout, use the exact local source form Claude expects:

```bash
claude plugin marketplace add ./
claude plugin install guardian-security-scan@guardian
```

## Validate Locally

Guardian includes a repository-local validator that checks the Claude marketplace file, plugin manifest, skill metadata, bundled paths, and a cache-copy smoke test:

```bash
python3 scripts/validate_claude_plugin.py
```

If the Claude Code CLI is available, also run Anthropic's validator:

```bash
claude plugin validate ./plugins/guardian-security-scan --strict
```

If Claude Desktop has installed its bundled Claude Code runtime but `claude` is not on `PATH`, the executable is usually under:

```text
~/Library/Application Support/Claude/claude-code/<version>/claude.app/Contents/MacOS/claude
```

Guardian's release check discovers that path automatically when it exists and prints the validator path it is using.

## Smoke Test

After installing, verify the cached plugin can run without spending model tokens on a full scan:

```bash
GUARDIAN_PLUGIN_BIN="$(find "$HOME/.claude/plugins/cache/guardian/guardian-security-scan" -path '*/scripts/guardian' -type f -print | sort | tail -n 1)"
GUARDIAN_SMOKE_STATE="$(mktemp -d "${TMPDIR:-/tmp}/guardian-smoke.XXXXXX")"
GUARDIAN_STATE_DIR="$GUARDIAN_SMOKE_STATE" "$GUARDIAN_PLUGIN_BIN" report summary --json
```

Run a tiny fixture scan from a Guardian checkout:

```bash
GUARDIAN_PLUGIN_BIN="$(find "$HOME/.claude/plugins/cache/guardian/guardian-security-scan" -path '*/scripts/guardian' -type f -print | sort | tail -n 1)"
GUARDIAN_SMOKE_STATE="$(mktemp -d "${TMPDIR:-/tmp}/guardian-smoke.XXXXXX")"
GUARDIAN_STATE_DIR="$GUARDIAN_SMOKE_STATE" "$GUARDIAN_PLUGIN_BIN" \
  scan ./tests/fixtures/clean-npm \
  --mode daily \
  --output compact \
  --json
```

The temporary state directory keeps smoke output from mixing with your real `~/.guardian-security-scan` history. Do not call `~/.claude/plugins/cache/guardian/guardian-security-scan/*/scripts/guardian` directly after updates. Claude can keep more than one cached plugin version, and a shell wildcard can expand to multiple binaries.

In Claude Desktop Code or Claude Code, a live skill prompt can be:

```text
Use the guardian-security-scan:guardian-project-scan skill to scan this repo read-only. Do not edit files, install dependencies, or run project code.
```

Claude Desktop Code uses the Claude Code runtime under the hood. A response that says the runner was invoked through Claude Code/Bash is still a valid Desktop Code plugin path when the session was launched from the Desktop Code UI.

## Runtime Notes

- Guardian is read-only during normal scans.
- The scanner runtime uses the Python standard library only.
- Local state is stored outside the plugin at `~/.guardian-security-scan` unless `GUARDIAN_STATE_DIR` is set.
- GitHub API tokens are optional. `GITHUB_TOKEN`, `GH_TOKEN`, or an authenticated GitHub CLI improve rate limits for deeper advisory checks.
- No hooks or MCP servers are enabled by default; Guardian contributes skills and a `guardian` executable wrapper.
