---
name: guardian-package-diet
description: Run Guardian package diet analysis for dependency bloat, unused packages, replace-with-native opportunities, and license-safe Vendor Candidates.
---

# Guardian Package Diet

Use this skill when the user asks about package bloat, unused dependencies, replacing packages with native code, or reducing supply-chain surface area. This is not a vulnerability scan.

## Dependency Addition Guard

If a cleanup proposal introduces or substitutes a dependency, run the bundled `guardian check-package <ecosystem> <name> [version] --json` first. Do not proceed on a block; explain warning evidence before continuing.

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
4. Include manifest scope, usage counts, file/line examples, dynamic-reference warnings, lockfile transitive count, cached size/license/maintenance context, and replacement risk.
5. Treat `Vendor Candidate` as a review proposal, not permission to edit. Show the exact used symbols, proposed `vendor/<package>/` path, upstream version, required license attribution, and the generated watchlist command.

## Rules

- Do not modify the repo.
- Do not recommend removing packages with dynamic references, CLI/config usage, workspace links, native bindings, security/crypto responsibilities, parsers, framework responsibilities, or unclear ownership.
- Do not mix package diet findings with Guardian vulnerability findings.
- Prefer `review candidate` over `remove` when evidence is incomplete.
- Never vendor code unless Guardian has a permissive license signal and the upstream license text/attribution requirements have been verified manually.
- Write characterization tests for current behavior before extracting or swapping any implementation.
- Preserve an upstream version comment and add the original package/version with `guardian watchlist add-vendored` so future advisories still cover the copied code.
- Do not vendor native/binary, cryptography/security, parser, framework, database, or complex tooling packages.

## Summary Contract

Group findings as:

- Safe-looking removal candidates.
- Replace-with-native candidates.
- Vendor candidates that need a small attributed source extraction.
- Review-only candidates.
- Packages to keep.

For each surfaced package, explain why it matters and what verification should happen before any code change.
