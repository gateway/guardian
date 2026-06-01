# Codex Plugin Usage

Guardian ships three Codex skills.

## Guardian Project Scan

Use when you want Codex to scan the current repo for package security risk.

Example prompt:

```text
Use Guardian to scan this project and summarize the findings.
```

The skill runs a read-only scan, compares against the previous snapshot, and summarizes the result.

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
