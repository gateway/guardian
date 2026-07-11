---
name: guardian-daily-watch
description: Run Guardian's lightweight multi-repo morning watch. Use when the user asks for a scheduled, recurring, morning, daily, automation, or low-token check across known local projects to detect dependency-file changes and compare cached security findings without doing full project scans.
---

# Guardian Daily Watch

Use this skill for lightweight scheduled checks across one or more repo roots. Prefer it over `guardian-project-scan` when the user wants a morning automation, a quick multi-repo posture check, or dependency-file change detection without full code usage analysis.

## Dependency Addition Guard

Before adding any dependency while responding to scan findings, run the bundled `guardian check-package <ecosystem> <name> [version] --json`. Do not proceed on a block; explain warning evidence before continuing.

## Workflow

1. Resolve roots.
Use explicit `--root` values when provided. Otherwise use Guardian's configured `development_roots`.

2. Run the bundled command.

```bash
scripts/guardian daily-watch --root "<repo-root>" --json
```

For multiple roots, repeat `--root`.

3. Use live refresh only when needed.
Default `daily-watch` is intentionally fast: it fingerprints dependency manifests/lockfiles, skips unchanged inventory, and snapshots cached findings. Add `--refresh-advisories` when the user explicitly wants live OSV/local advisory refresh. Add `--live-enrichment` only for slower KEV, EPSS, and NVD enrichment.

4. Escalate selectively.
If daily-watch reports changed dependency files, new evidence, or a high-priority cached finding, run `guardian-project-scan` for that specific repo. Do not deep-scan every repo by default.

## Output

Summarize:

- roots inventoried vs skipped
- dependency files added, changed, or removed
- whether advisory refresh was skipped or run
- package rows and unique versions available
- new/resolved/changed snapshot evidence
- the report path

Keep the response short and automation-friendly.
