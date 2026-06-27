---
name: guardian-repo-scout
description: Ephemerally clone public GitHub repos, run budgeted Guardian scans with isolated state, surface high-signal dependency issues, and clean up clones/state. Use when the user wants to spend spare Codex time reviewing upstream projects without ingesting them into the normal Guardian database.
---

# Guardian Repo Scout

Use this skill when the user wants to scan public GitHub repositories they do not own, find credible dependency-security issues, and possibly prepare a maintainer-friendly advisory PR afterward.

## Workflow

1. Choose a small repo batch.
Prefer active software projects with npm or Python manifests. Avoid docs-only repositories, massive monorepos, and archived projects unless the user explicitly asks for them.

2. Run `repo-scout` with disposable state.
Default to a bounded scout pass. Guardian now preflights dependency-file
count and can automatically allocate a longer large-repo budget while keeping
live API requests paced.

```bash
scripts/guardian repo-scout \
  --repo owner/name \
  --scan-mode standard \
  --per-repo-seconds 300 \
  --large-repo-seconds 900 \
  --total-seconds 1800 \
  --include-ghsa \
  --ghsa-max-packages 40 \
  --json
```

Use `--repo-file <path>` for a newline-separated list. Use `--max-repos` when sampling a larger list.

3. Escalate only when there is signal.
If the scout output reports credible `high_signal_top_packages`, run a focused deep scan on that same repo or switch to the advisory PR skill. Do not deep-scan every repo in a broad batch by default.

4. Keep scans read-only.
Repo Scout must not install dependencies, run project scripts, modify cloned code, or write findings into the user's normal Guardian database. Clones and temporary Guardian state are deleted by default.

5. Decide whether an upstream PR is maintainable.
Before switching to `guardian-advisory-pr`, check the target repo's contribution rules, target branch, PR template, required issue/discussion, CLA text, duplicate PRs, and security disclosure expectations. Mature repos may already have internal tools; only propose a PR when Guardian can add a narrow fix plus useful validation.

6. Summarize for human decision.
Report:
- repos scanned
- elapsed time and whether any budget was hit
- whether large-repo mode was activated, including dependency-file and package counts
- API policy used for live sources, especially GHSA worker cap and request spacing
- high-signal findings only
- advisory identifiers and links when available
- confidence/runtime context if Guardian provides it
- whether a PR is worth considering
- cleanup status for temporary clones and state

## Rules

- Use Repo Scout for external public repos only. Use Guardian Project Scan for the user's local projects.
- Keep batches small unless the user explicitly approves a larger token/time spend.
- Prefer `standard` mode first. Use `deep` only for candidate repos or when the user wants a slower full pass.
- Do not use `--keep-workdir` unless debugging a scan failure; if used, tell the user where the clone/state were kept.
- If `--keep-workdir` was used for PR preparation, list exact temp paths before deleting them and verify they are gone afterward.
- If a repo times out, inspect `preflight`, `scan_scope`, `scan_policy`, `phases`, and `source_status` before retrying. Increase `--large-repo-seconds` only once when the repo is clearly large; do not launch repeated full scans.
- If live advisory enrichment is slow, keep GHSA exact checks capped and paced. Prefer a bounded focused scan or package-manager audit corroboration over repeatedly launching full deep scans.
- Do not ingest external scout repos into the user's normal Guardian database unless the user explicitly asks to track that repo.

## Handoff

When a finding looks worth reporting upstream, switch to `guardian-advisory-pr` and include:
- exact package and version
- dependency path/root-cause evidence
- code usage, if available
- advisory links
- proposed safe fix
- repository contribution requirements and maintainer-fit assessment
- "Powered by Guardian" note when the user wants attribution
