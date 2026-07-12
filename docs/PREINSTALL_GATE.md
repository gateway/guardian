# Guardian Pre-Install Gate

Guardian can review npm and PyPI packages before an AI coding agent installs them. The gate is local-first, bounded, cached, and implemented with the Python standard library.

## What It Checks

For each proposed package, Guardian checks in this order:

1. A local exact package/version match against bundled malicious-package catalogs.
2. Name similarity against ranked npm and PyPI package snapshots to catch likely typosquats and AI-generated slopsquats.
3. Registry metadata for the concrete version, including npm lifecycle scripts or a PyPI release that only ships a source distribution.
4. One bounded OSV query for the concrete package version.

Complete results for exact requested versions are cached in local SQLite for 24 hours by default. Repeat exact-version checks normally avoid network calls. Versionless requests always resolve the registry's current `latest` version and do not reuse a cached verdict or cached mutable `latest` response.

When a prior project scan already cached fresh exact-version registry intelligence, the gate reuses it before making a registry request. New registry observations invalidate older package verdicts for the same exact version.

## Direct CLI Use

```bash
guardian check-package npm react 19.1.0 --json
guardian check-package pypi requests 2.32.4 --json
guardian check-package npm some-package --max-seconds 3 --json
```

The version is optional. When it is missing, a tag, or a range, Guardian resolves a concrete registry version before querying OSV.

Exit codes:

| Code | Verdict | Meaning |
| --- | --- | --- |
| `0` | `allow` | No checked source produced a warning or block signal. |
| `1` | `warn` | Review a typo, advisory, install behavior, or incomplete source coverage. |
| `2` | `block` | The exact package/version matched configured malicious-package evidence. |

An `allow` verdict is not a claim that a package is free of unknown zero-days.

## Agent Hook

The plugin registers a `PreToolUse` hook for supported shell package additions. It recognizes common npm, pnpm, Yarn, Bun, pip, Pipenv, uv, and Poetry forms, including manager flags before the subcommand, versioned Python executables, npm aliases, package-execution commands (`npx`, `npm exec`, `pnpx`, `pnpm dlx`, `yarn dlx`, `bunx`, and `bun x`), multiple packages, shell command segments, and bounded `sh`/`bash`/`zsh -c` wrappers.

The hook:

- denies exact malicious-catalog matches;
- pauses probable typosquats, known vulnerable versions, and direct URL/VCS installs for agent review;
- allows local filesystem installs such as `pip install -e .` or `npm install ./packages/lib` with additional context;
- allows ordinary install-script warnings with additional context;
- allows an install with a visible warning when live sources are unavailable.

Requirements-file installs and package-manager restore commands such as `npm ci` are not expanded by the hook. Scan the resolved project inventory afterward for those workflows.

Any published OSV vulnerability for the concrete requested version pauses the hook for review, regardless of advisory severity. This is intentional: installing a version already known to be vulnerable requires an explicit agent decision. Exact malicious-package evidence remains the stronger hard-block signal.

Codex and Claude Code both load the bundled hook declaration. Hook availability still depends on the host exposing the relevant shell `PreToolUse` event, so Guardian skills also require an explicit check before adding dependencies.

## False Positives

Similarity is a warning signal, not proof of malicious intent. If a legitimate package name resembles a popular package, accept it locally:

```bash
guardian policy accept-name npm legitimate-name --reason "verified publisher and repository"
```

The exception is stored in local SQLite and invalidates cached verdicts for that name.

## Configuration

The local Guardian configuration supports:

- `preinstall_gate_enabled`: default `true`.
- `preinstall_gate_block_grades`: default `corroborated-malicious` and `catalog-match`.
- `preinstall_gate_max_seconds`: default `3` seconds per command-level hook budget.
- `preinstall_gate_cache_ttl_seconds`: default `86400` seconds.

Set `preinstall_gate_enabled` to `false` to bypass package checks cleanly. The hook exits without output when disabled.

## Limits

- The gate cannot detect unpublished zero-days or malicious code absent from its evidence sources.
- Registry lifecycle scripts are behavioral review evidence, not proof of malware.
- Direct URL, VCS, and alias installs cannot be verified as normal registry package versions and pause for review.
- Local-path installs are not registry fetches; Guardian allows them with context and expects normal code review or project scanning to assess the local source.
- Shell recursion is deliberately bounded, and arbitrary shell evaluation is out of scope.
- A network outage produces incomplete coverage and a fail-open warning rather than blocking all development.
