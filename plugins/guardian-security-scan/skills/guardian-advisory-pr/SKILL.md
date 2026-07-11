---
name: guardian-advisory-pr
description: Turn a confirmed Guardian dependency finding into a maintainer-friendly GitHub pull request with advisory evidence, dependency-path proof, code-usage review, fix rationale, and validation notes.
---

# Guardian Advisory PR

Use this skill only after a Guardian finding is confirmed as actionable. Do not open PRs for weak vendored metadata-only findings.

## Dependency Addition Guard

Before adding or changing any dependency, run the bundled `guardian check-package <ecosystem> <name> [version] --json`. Do not proceed on a block; explain warning evidence before continuing.

## Workflow

1. Confirm the finding with Guardian plus at least one corroborating source such as OSV, GitHub Advisory Database, npm audit, pnpm audit, PyPI advisory, GitLab Advisory Database, NVD, or upstream advisory.
2. Resolve the bundled CLI relative to this skill (`../../scripts/guardian`), then run its preflight before drafting or editing: `../../scripts/guardian outreach preflight --repo owner/name --repo-dir <checkout> --advisory-id <ID> --package <name> --version <version> --json`.
3. Stop when preflight says already recorded, in-flight, default branch fixed, archived, daily cap reached, private channel, issue first, or manual verification required. Follow the returned reporting path; do not route around it.
4. Read the target repository contribution rules before editing. Check `.github/pull_request_template.md`, `CONTRIBUTING*`, CLA text, required target branch, required linked issue/discussion, title prefix rules, and `SECURITY.md` disclosure instructions.
5. Prove the dependency path from manifest or lockfile to the vulnerable package.
6. Search source code outside generated directories for direct usage of the vulnerable package and the parent package.
7. Choose the least risky fix: parent upgrade, targeted override, or no PR if evidence is weak.
8. Prepare the proposed diff and complete PR draft, then show both to the human. Do not create any PR, issue, discussion, or private report until the human explicitly confirms that exact outreach action.
9. After confirmation, update only the files required for the dependency fix and validate with lockfile/audit/static checks and targeted tests when safe.
10. Open a draft PR unless the user asks for ready-for-review and validation is complete.
11. Record the completed or declined action with the same bundled CLI: `../../scripts/guardian outreach record --repo owner/name --advisory-id <ID> --package <name> --action <public-pr|open-issue|private-report|declined> [--url <URL>] --json`.

## Maintainer-Fit Gate

Before opening an upstream PR, decide whether a PR is actually useful to the maintainers:

- Open a PR when the finding is real, the fix is narrow, the dependency path is proven, and the PR includes validation that matches the repository's expectations.
- Prefer an issue/discussion or no upstream action when the repo requires prior discussion, has an internal security process, or the fix requires broad major-version migration.
- Prefer the repository's documented `SECURITY.md` or private-advisory channel over every public path when policy requests private disclosure.
- Do not submit PRs that mainly say "maintainers should validate this." If meaningful project validation cannot be run, mark the PR draft and explain exactly what was validated and what remains.
- If a maintainer closes a PR because they already track the issue internally, acknowledge briefly and do not argue or reopen unless they ask for changes.
- Keep PR titles human-readable. Prefer `chore(deps): patch <package> security advisory` over titles that only contain CVE/GHSA identifiers.

## PR Requirements

Use `references/pr-template.md`. Every PR should include:

- a plain-English 10-second summary at the very top that states the vulnerability class, what could happen, why this repo is affected, and what the PR changes.
- advisory ID, CVE when available, severity, and links.
- short vulnerability explanation and when it matters.
- exact dependency path.
- manifest/lockfile evidence.
- direct code usage result.
- selected fix and alternatives considered.
- compatibility and breakage-risk assessment.
- validation performed and maintainer validation still recommended.
- repository-specific contribution compliance, including target branch, required CLA text, linked issue/discussion expectations, and template-required sections.
- a short footer note: `Powered by Guardian: https://github.com/gateway/guardian`

## Safety Rules

- Do not claim active exploitation unless CISA KEV or another authoritative source says exploited.
- Do not include long exploit proof-of-concepts.
- Do not make broad dependency churn when a focused fix is enough.
- Do not hide uncertainty.
- Do not modify unrelated files.
- Do not check or sign CLA/legal attestation boxes unless the user explicitly authorizes that exact text.
- Do not target a default branch blindly; use the repository's required contribution branch.
- Do not proceed when any duplicate, archive, or default-branch preflight check is unavailable; verify it manually first and record the evidence.
- Never bypass Guardian's local duplicate ledger or `max_outreach_per_day` cap.
- Human confirmation is mandatory after the final draft/diff is visible and before any external side effect.
- Keep the Guardian attribution footer short and separate from the maintainer summary so it does not distract from the actionable fix.
- Do not start the PR body with template labels like `Change:`, `Why:`, or `Risk:`. Put the human-readable issue summary first, then the structured evidence.
