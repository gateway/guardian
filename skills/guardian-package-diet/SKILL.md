---
name: guardian-package-diet
description: Run Guardian package diet analysis for dependency bloat, unused-package candidates, dynamic package references, and safe replace-with-native opportunities.
---

# Guardian Package Diet

Use this skill when the user asks about package bloat, unused dependencies, replacing packages with native code, or reducing supply-chain surface area. This is not a vulnerability scan.

## Runner

Resolve the bundled Guardian CLI relative to this skill file:

```bash
../../scripts/guardian diet scan "<repo-root>" --limit 100 --usage-limit 80 --json
```

For large repos, keep `--usage-limit` bounded unless the user explicitly asks for deeper static usage review.

## Workflow

1. Determine the repo root with `git rev-parse --show-toplevel`; otherwise use the current directory or user-provided path.
2. Run the diet scan.
3. Report only the highest-value candidates.
4. Include manifest scope, usage counts, file/line examples, dynamic-reference warnings, and replacement risk.

## Rules

- Do not modify the repo.
- Do not recommend removing packages with dynamic references, CLI/config usage, workspace links, native bindings, security/crypto responsibilities, parsers, framework responsibilities, or unclear ownership.
- Do not mix package diet findings with Guardian vulnerability findings.
- Prefer `review candidate` over `remove` when evidence is incomplete.

## Summary Contract

Group findings as:

- Safe-looking removal candidates.
- Replace-with-native candidates.
- Review-only candidates.
- Packages to keep.

For each surfaced package, explain why it matters and what verification should happen before any code change.
