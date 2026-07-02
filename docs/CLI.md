# Guardian CLI

Guardian ships with a bundled CLI at:

```bash
./plugins/guardian-security-scan/scripts/guardian
```

The CLI is useful for smoke tests, local automations, and debugging plugin behavior without involving an agent.

## Requirements

- Python 3.9+ available as `/usr/bin/python3` or `python3`.
- Git for repo-root detection and optional advisory-source fetches.
- npm, pnpm, or pip only when you request package-manager corroboration or audit checks.

Guardian's scanner runtime uses the Python standard library only.

## Basic Commands

Run a normal compact project scan:

```bash
./plugins/guardian-security-scan/scripts/guardian scan /path/to/repo --mode daily --output compact --json
```

Run a deeper scan with installed-tree and GHSA corroboration:

```bash
./plugins/guardian-security-scan/scripts/guardian scan /path/to/repo --mode deep --include-installed --include-ghsa --json
```

Run daily watch:

```bash
./plugins/guardian-security-scan/scripts/guardian daily-watch --root /path/to/repo --json
```

Refresh live advisory data for known packages:

```bash
./plugins/guardian-security-scan/scripts/guardian daily-watch --root /path/to/repo --refresh-advisories --json
```

Review dependency bloat:

```bash
./plugins/guardian-security-scan/scripts/guardian diet scan /path/to/repo --limit 100 --usage-limit 80 --json
```

Scout a public GitHub repo with temporary state:

```bash
./plugins/guardian-security-scan/scripts/guardian repo-scout \
  --repo owner/name \
  --scan-mode standard \
  --include-ghsa \
  --ghsa-max-packages 40 \
  --per-repo-seconds 300 \
  --large-repo-seconds 900 \
  --total-seconds 1800 \
  --json
```

## GitHub Token

A GitHub token is optional. Guardian can use one for higher-rate GitHub Security Advisory checks.

Supported token sources:

```bash
export GITHUB_TOKEN=<your token>
export GH_TOKEN=<your token>
```

If neither environment variable is set, Guardian tries `gh auth token` when GitHub CLI is installed and authenticated.

Do not commit tokens to this repo.

## Release Verification

Before publishing a release, run:

```bash
./scripts/release_check.sh
```

That gate validates plugin manifests, Claude packaging, skill metadata, Python compilation, version-matching checks, fixture scans, and local marketplace/cache smoke tests.
