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
