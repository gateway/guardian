# Guardian Trust Model

Guardian is a local dependency-risk scanner for Codex. It is designed to help an agent make a better security decision, not to prove that a project is safe.

## What Guardian Trusts

- Project evidence it can read from manifests, lockfiles, installed package metadata, and selected source files.
- Public advisory and exploit-intelligence sources configured in the scanner.
- Bundled exact-match malicious-package catalogs checked into the plugin.
- Local scan state stored outside the plugin bundle.

## What Guardian Does Not Trust Automatically

- A scary advisory title without matching package/version evidence.
- Nested vendored lockfiles under `node_modules` without active lockfile, installed-tree, or code-usage corroboration.
- Transitive metadata that does not appear in the deployed package graph.
- Suggested upgrade targets unless the target version is also checked for known issues.

## Read-Only Scan Boundary

Normal Guardian project scans are read-only:

- Guardian does not edit project dependency files.
- Guardian does not run arbitrary project application code.
- Guardian does not install project dependencies.
- Guardian does not automatically upgrade packages.

Some optional checks may call package-manager or network commands to corroborate state. Those checks are opt-in or mode-dependent and should be described in the scan output.

## Intelligence Sources

Guardian can use OSV, GitHub Security Advisories, CISA KEV, FIRST EPSS, NVD, GitLab advisory data, and bundled local malicious-package catalogs. Source availability can change, and no source provides complete zero-day coverage.

Guardian should report source status so users can tell whether a feed was queried, skipped, cached, or unavailable.

## GitHub Token Behavior

A GitHub token is optional. Guardian checks `GITHUB_TOKEN`, then `GH_TOKEN`, then `gh auth token` if the GitHub CLI is available.

If no token is available, Guardian still runs, but GitHub Security Advisory requests may be rate-limited or skipped depending on scan mode.

Never commit tokens, private reports, generated scan databases, or local state directories.

## Dependency Footprint

Guardian's runtime uses the Python standard library only. This intentionally keeps the scanner's own supply-chain surface small.

The plugin may inspect projects that use npm, pnpm, pip, or other package managers, but Guardian does not install third-party Python packages to run its scanner.

## Decision Boundary

Guardian findings should be treated as evidence, not final judgment.

Good remediation decisions should consider:

- Whether the vulnerable version is actually present.
- Whether it is runtime, transitive, tooling-only, isolated, or vendored metadata.
- Whether an advisory is known exploited or merely theoretically vulnerable.
- Whether the package is used in code.
- Whether the proposed fixed version introduces new known issues.
- Whether tests or maintainers need to validate behavior after the change.

## Known Limits

- Guardian cannot prove absence of unknown zero-days.
- Static usage search may miss dynamic imports or generated code.
- Advisory severity may vary between sources.
- Exact-match malicious catalogs only catch packages and versions that are present in those catalogs.
- Large repositories may require bounded or deep scan modes depending on time limits.
