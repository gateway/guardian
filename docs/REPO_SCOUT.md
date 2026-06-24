# Guardian Repo Scout

Repo Scout is Guardian's workflow for temporary community scans of public GitHub repositories. It is meant for cases where a user wants to spend spare Codex time looking for credible dependency-security issues in upstream projects, then decide whether a maintainer-friendly PR is justified.

## Operating Rules

- Clone public repos into a temporary workspace.
- Use isolated temporary Guardian state instead of the user's normal Guardian database.
- Do not install dependencies or execute project code.
- Run with explicit per-repo and total time budgets.
- Surface only high-signal dependency PR candidates.
- Delete temporary clones and temporary state by default.

This workflow is intentionally separate from normal local project scans. Normal scans track local project history and fix verification. Repo Scout is disposable unless the user chooses to keep artifacts.

## Efficient Flow

Use a two-pass model:

1. Run a bounded standard scout pass first.

```bash
guardian repo-scout \
  --repo owner/name \
  --scan-mode standard \
  --per-repo-seconds 120 \
  --total-seconds 900 \
  --json
```

2. Escalate only if the first pass shows signal, or when the user explicitly wants stronger coverage.

```bash
guardian repo-scout \
  --repo owner/name \
  --scan-mode standard \
  --include-ghsa \
  --ghsa-max-packages 80 \
  --per-repo-seconds 180 \
  --total-seconds 240 \
  --json
```

Use `deep` mode only for candidate repos or when preparing a PR. Broad batches should not start in deep mode because one large repo can consume the whole run.

## First Large-Repo Test

Repository:

```text
openclaw/openclaw
```

Fast standard scout pass:

- Runtime: 26.7 seconds.
- Unique packages: 1,519.
- Evidence rows: 3,428.
- OSV records queried: 1,519.
- GitLab Advisory Database records read: 1,487.
- GHSA: not requested.
- High-signal PR candidates: 0.
- Temporary clones/state: deleted.

GHSA-enabled standard scout pass:

- Runtime: 41.0 seconds.
- Unique packages: 1,519.
- OSV records queried: 1,519.
- GHSA records queried: 80.
- GitLab Advisory Database records read: 1,487.
- High-signal PR candidates: 0.
- Temporary clones/state: deleted.

Decision:

```text
No maintainer PR is justified from this scan. Guardian did not find a configured-source match that looks like an actionable dependency issue in OpenClaw.
```

This is not proof that the repo is safe from unknown zero-days. It means the package versions Guardian saw did not match the configured advisory and exploit-intelligence sources used in the run.

## Second Batch Test

Repositories:

```text
n8n-io/n8n
langgenius/dify
firecrawl/firecrawl
```

Standard scout pass:

- Runtime: 319.5 seconds.
- Temporary clones/state: deleted.
- `n8n-io/n8n`: 3,972 unique packages; initial pass hit budget before snapshot, then GHSA escalation completed cleanly.
- `langgenius/dify`: 2,358 unique packages; completed.
- `firecrawl/firecrawl`: 2,274 unique packages; completed.

GHSA escalation pass:

- Runtime: 306.0 seconds.
- GHSA target count: 120 per repo.
- Temporary clones/state were kept only for evidence extraction, then deleted.
- All three repos completed without scan-budget errors.

Candidate quality after evidence review:

- `langgenius/dify` produced the strongest PR candidates.
- `langsmith@0.8.5` is a direct provider dependency in `api/providers/trace/trace-langsmith/pyproject.toml`; OSV/GHSA report `GHSA-f4xh-w4cj-qxq8`, fixed by `0.8.18`. Guardian rated this `Act Now`.
- `bleach@6.3.0` is present in `api/uv.lock` and the API project allows `bleach>=6.3.0,<7.0.0`; OSV/GHSA report medium/low advisories fixed by `6.4.0`. Guardian rated this `Fix This Week`.
- `nltk@3.9.4` is present in `api/uv.lock` and tied to Dify's `tools` optional dependency group; OSV/GHSA report `GHSA-p4gq-832x-fm9v`, but Guardian could not derive a clean fixed version because latest was still `3.9.4` at check time. This is an advisory/escalation note, not an automatic upgrade PR.
- `couchbase@4.6.0` appeared in `api/uv.lock` for Dify's Couchbase vector DB extra, but Guardian classified the exact package check as lower priority because no clean fixed version was derived automatically.
- `firecrawl/firecrawl` initially surfaced `axios@1.15.2` and `ws@8.18.3`, but evidence showed both came from `examples/scrape_and_analyze_airbnb_data_e2b/package-lock.json`. Active app/package manifests had newer `axios` and `ws` versions that exact package checks did not flag. Do not open a PR from the initial Firecrawl scout output without a narrower maintainer-use-case review.
- `n8n-io/n8n` produced several high-severity candidates, but evidence showed a mixed picture: some vulnerable versions came from `.github/scripts/pnpm-lock.yaml`, while root/package manifests already pin or override some packages to newer versions. This needs focused maintainer-aware validation before any PR.

Decision:

```text
Best immediate PR candidate: langgenius/dify for langsmith@0.8.5 -> 0.8.18, with bleach@6.3.0 -> 6.4.0 as a secondary candidate if tests confirm compatibility.
```

The batch also proved that broad GHSA escalation over large repos is workable but expensive. Prefer standard scout first, then exact package verification for candidate packages before rerunning a wide GHSA pass.

## What We Should Improve

1. Add an automatic two-stage mode.
Repo Scout should be able to run a fast first pass, then automatically escalate to GHSA or deep mode only when the repo size and finding signal justify the extra cost.

2. Write an explicit external report artifact.
Today callers can redirect JSON to a file. A first-class `--report-path` option would make automation cleaner while still deleting temporary clones and temporary database state.

3. Surface source coverage more clearly.
The output should summarize source coverage in one small block: OSV packages checked, GHSA target count, threat-intel revision, packages skipped by budget, and whether any source failed or was rate-limited.

4. Add repo preflight sizing.
Before the full scan, Guardian should estimate repo size, dependency-file count, package count, and likely scan cost. That lets Codex choose a safe budget before spending time on a huge repo.

5. Keep improving PR-candidate filters.
Repo Scout already suppresses root package self-version findings so projects like `axios/axios` do not become bad PR candidates. We should continue filtering findings that are real advisories but poor upstream PR targets, such as docs-only manifests, generated fixtures, vendored examples, and intentionally vulnerable test fixtures.

6. Add batch ranking.
For a list of repos, Guardian should rank output by "PR-worthiness": confirmed runtime/direct exposure first, then high-confidence transitive risk, then noisy or low-confidence findings last.

7. Add maintainer handoff mode.
When a candidate is found, Guardian should produce a small handoff for the PR skill with package, version, advisory links, dependency path, code usage hints, and recommended safe fix.

8. Show source path and directness in scout top findings.
The second batch showed that a high-severity finding in an example lockfile can outrank a more relevant direct app dependency. Scout summaries should include source path, project path, direct dependency status, and whether the source is root app, package workspace, CI script, example, docs, or test fixture.

9. Add exact candidate verification.
After a scout pass finds packages, Guardian should run exact `gate check-package` style verification for candidate package/version pairs before recommending a PR. This is cheaper than rerunning broad GHSA scans and gives cleaner fixed-version guidance.
