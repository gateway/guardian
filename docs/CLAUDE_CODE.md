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

```bash
git clone https://github.com/gateway/guardian.git
claude plugin marketplace add ./guardian
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

## Runtime Notes

- Guardian is read-only during normal scans.
- The scanner runtime uses the Python standard library only.
- Local state is stored outside the plugin at `~/.guardian-security-scan` unless `GUARDIAN_STATE_DIR` is set.
- GitHub API tokens are optional. `GITHUB_TOKEN`, `GH_TOKEN`, or an authenticated GitHub CLI improve rate limits for deeper advisory checks.
- No hooks or MCP servers are enabled by default; Guardian contributes skills and a `guardian` executable wrapper.
