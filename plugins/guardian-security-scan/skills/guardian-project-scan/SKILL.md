---
name: guardian-project-scan
description: Run Guardian against the current project or repo, compare the new scan to the previous snapshot, generate optional operator/handoff artifacts, and summarize dependency security findings with clear next steps.
---

# Guardian Project Scan

Use this skill when the user asks to scan a project, verify whether dependency issues were fixed, check package security posture, or create a handoff for another coding-agent session.

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
6. If a large repo scan slows down in live enrichment, stop escalating blindly. Capture which phase was slow, keep partial local evidence if available, and report it as a Guardian performance follow-up.

## Rules

- Do not modify the scanned project.
- Do not treat vendored nested lockfiles as direct runtime compromise.
- Use snapshot compare fields for fixed/new/unchanged statements.
- Include advisory links when surfacing a concrete issue.
- Separate runtime, transitive, build/test, isolated environment, and vendored metadata findings.
- Treat conflicting evidence as a confidence downgrade. Examples: `npm audit --omit=dev` is clean while Guardian flags a dev-only nested package, or a stale lockfile disagrees with a manifest/requirements file.
- For npm lockfiles, verify whether nested packages are marked `dev: true` before calling them runtime-linked.
- For Python projects with both manifest pins and lockfiles, compare versions before recommending remediation; stale lockfiles should be reported as lockfile hygiene, not automatically as runtime exposure.
- Do not mix vulnerability remediation with package bloat cleanup; use `guardian-package-diet` for cleanup.

## Summary Contract

Return a short operator summary:

- Current posture.
- What changed since the previous scan.
- Highest-signal issues, if any.
- Confidence and environment labels.
- Artifact paths for operator JSON and handoff docs.
- Any scanner-efficiency issue that affected confidence, such as live-source timeouts or per-advisory enrichment bottlenecks.
- Concrete next steps.
- Bottom-line judgment.
