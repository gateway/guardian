---
name: guardian-project-scan
description: Run Guardian against the current project or repo, compare the new scan to the previous snapshot, generate optional operator/handoff artifacts, and summarize dependency security findings with clear next steps.
---

# Guardian Project Scan

Use this skill when the user asks to scan a project, verify whether dependency issues were fixed, check package security posture, or create a handoff for another Codex session.

## Runner

Resolve the bundled runner relative to this skill file:

```bash
../../scripts/run_guardian_project_scan.py --root "<repo-root>" --json
```

If direct relative execution is awkward, resolve the plugin root first and run:

```bash
<plugin-root>/scripts/run_guardian_project_scan.py --root "<repo-root>" --json
```

The runner writes Guardian state to `~/.guardian-security-scan` by default. Override with `GUARDIAN_STATE_DIR` only when the user asks for a separate state location.

## Workflow

1. Determine the repo root with `git rev-parse --show-toplevel`; if unavailable, use the current working directory or the user-provided path.
2. Run the bundled runner in default mode first. Default mode is read-only and optimized for normal project scans.
3. Use `--handoff` when the user wants a shareable Markdown handoff.
4. Use `--include-installed` only when installed-tree corroboration matters.
5. Use `--include-ghsa` or `--include-threat-intel` for deeper live-source review when runtime is acceptable.

## Rules

- Do not modify the scanned project.
- Do not treat vendored nested lockfiles as direct runtime compromise.
- Use snapshot compare fields for fixed/new/unchanged statements.
- Include advisory links when surfacing a concrete issue.
- Separate runtime, transitive, build/test, isolated environment, and vendored metadata findings.
- Do not mix vulnerability remediation with package bloat cleanup; use `guardian-package-diet` for cleanup.

## Summary Contract

Return a short operator summary:

- Current posture.
- What changed since the previous scan.
- Highest-signal issues, if any.
- Confidence and environment labels.
- Artifact paths for operator JSON and handoff docs.
- Concrete next steps.
- Bottom-line judgment.
