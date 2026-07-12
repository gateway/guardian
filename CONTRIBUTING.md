# Contributing to Guardian

Thanks for helping make dependency security better for AI coding agents.

## Ground rules

- **Security reports**: never open a public issue for a vulnerability in Guardian itself. Follow [`SECURITY.md`](SECURITY.md).
- **Stdlib-only runtime**: `guardian_runtime` must not gain third-party Python dependencies. If a change seems to need one, redesign the change. External system tools (`rg`, `git`, optional `gh`) must be detected at runtime and degrade honestly when missing.
- **Read-only boundary**: normal scans never edit project files, install dependencies, or execute project code. Anything that shells out must be opt-in or mode-gated and visible in output.
- **Evidence-first output**: new signals need a grade (see `guardian_runtime/src/guardian/signals.py`) and must degrade to a `source_contract` entry on failure instead of failing the scan.

## Development setup

```bash
git clone https://github.com/gateway/guardian.git
cd guardian
bash scripts/release_check.sh
```

The release gates need Python 3.10+ and ripgrep (`rg`). Machine-specific validators (Codex CLI, Claude Code CLI, skill-creator) are skipped automatically when not installed — CI runs the same script.

Run a scan from the checkout:

```bash
./plugins/guardian-security-scan/scripts/guardian scan /path/to/repo --mode daily --output compact --json
```

Local state defaults to `~/.guardian-security-scan`; point `GUARDIAN_STATE_DIR` at a temp directory while developing so you do not pollute your real scan history.

## Making changes

1. Keep changes focused; one concern per pull request.
2. Add or extend a test: fixtures live under `tests/fixtures/`, focused suites under `scripts/test_*.py`, and everything must pass `bash scripts/release_check.sh`.
3. Update `CHANGELOG.md` under the next version heading and bump both plugin manifests (`.claude-plugin/plugin.json`, `.codex-plugin/plugin.json`) when behavior changes.
4. If you touch bundled catalogs, regenerate the pinned manifest: `python3 scripts/build_catalog_manifest.py`.
5. Update user-facing docs (`README.md`, `docs/`) when output, coverage, or defaults change — the docs are treated as part of the product.

## Adding intelligence sources or catalogs

New sources must report status through `source_contract.py`, be cache-backed through `http_client.py`, and never fail a scan on their own. Bundled catalog entries are exact package/version indicators with a public reference; entries should be verifiable via `guardian catalog verify` (OSV cross-check) where possible.

## False positives

If Guardian pauses a legitimate package, the fastest fix is `guardian policy accept-name <ecosystem> <name>` locally — and an issue here with the operator JSON so we can tune the detector for everyone.
