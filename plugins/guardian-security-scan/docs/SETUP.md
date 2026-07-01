# Setup

Guardian is packaged as an installable plugin with a bundled Python runtime module.

## Requirements

- Python 3.9+
- Codex or Claude Code plugin support
- Git for repo-root detection
- Optional: npm, pnpm, and pip for package-manager corroboration
- Optional: GitHub CLI or a GitHub token for higher GitHub Advisory API limits

## State Directory

Guardian writes local state to:

```text
~/.guardian-security-scan
```

This contains scan databases, reports, snapshots, and copied local catalogs. It is intentionally outside the plugin folder so plugin updates do not carry user scan history.

Override it when needed:

```bash
export GUARDIAN_STATE_DIR=/path/to/guardian-state
```

## GitHub Authentication

GitHub authentication is optional.

Guardian checks GitHub Security Advisories in deep modes and selected enrichment paths. It looks for credentials in this order:

1. `GITHUB_TOKEN`
2. `GH_TOKEN`
3. `gh auth token`
4. unauthenticated GitHub Advisory API requests

Unauthenticated requests work but have lower rate limits. For frequent scans or automation, use a fine-scoped GitHub token through an environment variable or authenticate the GitHub CLI.

Never commit API keys or tokens.

## Common Commands

Daily project scan:

```bash
./scripts/guardian scan /path/to/repo --mode daily --output compact --json
```

Deep scan:

```bash
./scripts/guardian scan /path/to/repo --mode deep --include-installed --include-ghsa --json
```

Package diet scan:

```bash
./scripts/guardian diet scan /path/to/repo --limit 100 --usage-limit 80 --json
```

Generate a handoff:

```bash
./scripts/guardian scan /path/to/repo --mode handoff --handoff --json
```
