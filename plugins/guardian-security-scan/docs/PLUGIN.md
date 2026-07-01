# Plugin Usage

Guardian ships five skills for supported coding-agent plugin hosts.

## Guardian Project Scan

Use when you want the agent to scan the current repo for package security risk.

Example prompt:

```text
Use Guardian to scan this project and summarize the findings.
```

The skill runs a read-only scan, compares against the previous snapshot, and summarizes the result.

Large-repo note: if live enrichment slows down, the skill should report the slow phase and confidence impact instead of retrying repeatedly.

## Guardian Daily Watch

Use when you want a lightweight recurring check across known local repos.

Example prompt:

```text
Use Guardian daily watch to check my known local repos and summarize what changed.
```

The skill hashes dependency files, skips unchanged inventory when possible, and keeps scheduled scans token/tool efficient.

## Guardian Repo Scout

Use when you want temporary scans of public GitHub repositories without adding them to your normal Guardian database.

Example prompt:

```text
Use Guardian repo scout to scan this public repo and show only high-signal findings.
```

The skill uses disposable clones and isolated state. It preflights dependency-file count, automatically allows a longer budget for large repos, and keeps live advisory requests capped and paced so scans do not hammer OSV or GitHub advisory endpoints.

It should report cleanup status, whether large-repo mode was activated, the live-source policy used, and should only escalate to a PR when the finding is credible and the target repository's contribution rules make a PR useful.

## Guardian Package Diet

Use when you want dependency cleanup review instead of vulnerability review.

Example prompt:

```text
Use Guardian package diet to find dependency bloat and safe removal candidates.
```

The skill reports unused candidates, review-only candidates, dynamic references, and replace-with-native opportunities.

## Guardian Advisory PR

Use only after Guardian has found a confirmed actionable advisory.

Example prompt:

```text
Use Guardian Advisory PR to prepare a maintainer-friendly security PR for this finding.
```

The skill is designed to produce evidence-heavy PRs with advisory links, dependency-path proof, code-usage review, risk assessment, and validation notes.

Before opening an upstream PR, the skill checks the target repo's PR template, required base branch, CLA text, linked issue/discussion expectations, duplicate PRs/issues, and security disclosure guidance. It must not check legal attestation boxes unless the user explicitly authorizes the exact text.
