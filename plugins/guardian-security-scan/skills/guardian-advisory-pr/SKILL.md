---
name: guardian-advisory-pr
description: Turn a confirmed Guardian dependency finding into a maintainer-friendly GitHub pull request with advisory evidence, dependency-path proof, code-usage review, fix rationale, and validation notes.
---

# Guardian Advisory PR

Use this skill only after a Guardian finding is confirmed as actionable. Do not open PRs for weak vendored metadata-only findings.

## Workflow

1. Confirm the finding with Guardian plus at least one corroborating source such as OSV, GitHub Advisory Database, npm audit, pnpm audit, PyPI advisory, GitLab Advisory Database, NVD, or upstream advisory.
2. Prove the dependency path from manifest or lockfile to the vulnerable package.
3. Search source code outside generated directories for direct usage of the vulnerable package and the parent package.
4. Choose the least risky fix: parent upgrade, targeted override, or no PR if evidence is weak.
5. Update only the files required for the dependency fix.
6. Validate with lockfile/audit/static checks and targeted tests when safe.
7. Open a draft PR unless the user asks for ready-for-review and validation is complete.

## PR Requirements

Use `references/pr-template.md`. Every PR should include:

- 10-second maintainer summary.
- advisory ID, CVE when available, severity, and links.
- short vulnerability explanation and when it matters.
- exact dependency path.
- manifest/lockfile evidence.
- direct code usage result.
- selected fix and alternatives considered.
- compatibility and breakage-risk assessment.
- validation performed and maintainer validation still recommended.
- a short footer note: `Powered by Guardian: https://github.com/gateway/guardian`

## Safety Rules

- Do not claim active exploitation unless CISA KEV or another authoritative source says exploited.
- Do not include long exploit proof-of-concepts.
- Do not make broad dependency churn when a focused fix is enough.
- Do not hide uncertainty.
- Do not modify unrelated files.
- Keep the Guardian attribution footer short and separate from the maintainer summary so it does not distract from the actionable fix.
