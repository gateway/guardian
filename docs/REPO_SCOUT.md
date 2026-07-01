# Guardian Repo Scout

Repo Scout is Guardian's workflow for temporary community scans of public GitHub repositories. It is meant for cases where a user wants to spend spare agent time looking for credible dependency-security issues in upstream projects, then decide whether a maintainer-friendly PR is justified.

## Operating Rules

- Clone public repos into a temporary workspace.
- Use isolated temporary Guardian state instead of the user's normal Guardian database.
- Do not install dependencies or execute project code.
- Run with explicit per-repo and total time budgets.
- Preflight dependency-file count before the full scan.
- Automatically allow a longer large-repo budget when a repo has a monorepo-sized dependency surface.
- Keep live advisory requests capped and paced so broad scans do not hammer OSV, GitHub Security Advisories, or enrichment endpoints.
- Surface only high-signal dependency PR candidates.
- Check matching upstream PRs/issues for high-signal findings.
- Classify the reporting path as public PR, issue-first, private advisory, or already tracked.
- Delete temporary clones and temporary state by default.

This workflow is intentionally separate from normal local project scans. Normal scans track local project history and fix verification. Repo Scout is disposable unless the user chooses to keep artifacts.

## Efficient Flow

Use a paced single-pass model first. Guardian will preflight the repo after clone, then switch into large-repo handling when dependency-file or package counts are high.

Run a standard scout pass:

```bash
guardian repo-scout \
  --repo owner/name \
  --scan-mode standard \
  --include-ghsa \
  --ghsa-max-packages 40 \
  --per-repo-seconds 300 \
  --large-repo-seconds 900 \
  --total-seconds 1800 \
  --json
```

Escalate only if the first pass shows signal, or when the user explicitly wants stronger coverage.

```bash
guardian repo-scout \
  --repo owner/name \
  --scan-mode standard \
  --include-ghsa \
  --ghsa-max-packages 80 \
  --per-repo-seconds 300 \
  --large-repo-seconds 1200 \
  --total-seconds 1800 \
  --json
```

Use `deep` mode only for candidate repos or when preparing a PR. Broad batches should not start in deep mode because one large repo can consume the whole run.

If a repo still times out, inspect `preflight`, `scan_scope`, `scan_policy`, `phases`, and `source_status` before retrying. Increase `--large-repo-seconds` once when the repo is clearly large; do not launch repeated full scans.

## Reporting Path

For each high-signal finding, Repo Scout adds:

- `upstream_tracking`: matching open PRs/issues found through capped GitHub search.
- `reporting_path`: the recommended next action for upstream communication.

The reporting path can be:

- `Public PR OK`: no policy or duplicate signal blocks a focused PR.
- `Open issue first`: contribution docs suggest discussion or an issue before a PR.
- `Private security advisory only`: security policy asks that vulnerability reports stay private.
- `Do not report, already tracked`: a matching open PR or issue already exists.

This check is intentionally bounded to the high-signal package list. Use `--skip-upstream-check` for an offline or faster scout pass.

## Large-Repo Handling

Repo Scout now reports:

- `preflight.dependency_file_count`: dependency files found before the scan.
- `scan_scope.unique_package_versions`: exact package/version pairs considered.
- `scan_policy.large_repo_mode`: whether Guardian switched to large-repo handling.
- `scan_policy.effective_max_seconds`: the budget used after large-repo adjustment.
- `scan_policy.effective_ghsa_max_packages`: the effective GHSA exact-match cap.
- `scan_policy.api_policy`: live-source pacing, including GHSA worker count and request spacing.

Default live-source policy is conservative:

- GHSA exact-match workers are capped at `2`.
- GHSA requests are spaced by at least `0.25` seconds per client.
- OSV batch calls pause briefly between large batches.
- Large-repo mode caps GHSA exact-match package count unless the user explicitly raises it.

This does not make scans instant. It makes long scans intentional, bounded, and less likely to hit avoidable rate limits.

## Interpreting Scout Results

A clean Repo Scout pass means Guardian did not find a configured-source match that looks like an actionable dependency issue in the package evidence it scanned. It is not proof that the upstream project has no unknown zero-days or no application-level security bugs.

High-severity advisory matches still need context before upstream reporting:

- Prefer direct runtime dependencies over example, docs, fixture, generated, or CI-only lockfiles.
- Check whether the vulnerable version appears in a root manifest, workspace package, lockfile, installed tree, or only in vendored metadata.
- Verify whether the active project already pins an override or parent dependency that resolves to a patched version.
- Search upstream issues and PRs for the same package/advisory before opening anything new.
- Follow the project's contribution and security reporting policy.

When a finding is real but broad, ambiguous, already tracked, or tied to private disclosure rules, prefer an issue, private advisory, or no duplicate report over a low-quality PR.

## Regression Expectations

Repo Scout should keep these behaviors stable:

- Large repos complete as one paced scan when the configured budget is sufficient.
- Temporary clones and temporary Guardian state are removed by default.
- GHSA exact-match checks stay capped and paced.
- High-signal findings include reporting-path guidance.
- Findings in examples, docs, fixtures, vendored metadata, generated lockfiles, or stale nested lockfiles do not outrank stronger runtime evidence.
- Scout output is useful enough to decide whether `guardian-advisory-pr` should be used next.

## What We Should Improve

1. Add an automatic two-stage mode.
Repo Scout should be able to run a fast first pass, then automatically escalate to GHSA or deep mode only when the repo size and finding signal justify the extra cost.

2. Write an explicit external report artifact.
Today callers can redirect JSON to a file. A first-class `--report-path` option would make automation cleaner while still deleting temporary clones and temporary database state.

3. Surface source coverage more clearly.
The output should summarize source coverage in one small block: OSV packages checked, GHSA target count, threat-intel revision, packages skipped by budget, and whether any source failed or was rate-limited.

4. Keep refining repo preflight sizing.
Guardian now preflights dependency-file count and reports post-inventory package counts. Future refinement should estimate scan cost even earlier and recommend a budget before live advisory refresh begins.

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
