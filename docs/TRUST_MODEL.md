# Guardian Trust Model

Guardian is a local dependency-risk scanner for AI coding agents. It is designed to help an agent make a better security decision, not to prove that a project is safe.

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

## Local SQLite State

Guardian uses SQLite for local state. The default path is:

```text
~/.guardian-security-scan/guardian.db
```

The database stores inventory runs, current package state, advisory records, findings, triage snapshots, policy exceptions, remediation lifecycle data, exact-version registry metadata history, and cached pre-install verdicts. This state is created on the user's machine at runtime and is not included in the plugin repository.

Guardian also stores install-script and lockfile-hygiene observations by project and evidence identity. This history lets it distinguish unchanged behavior from newly introduced install scripts, unapproved resolved hosts, direct references, or same-version integrity drift.

Pre-install checks cache complete package verdicts by ecosystem, normalized name, and requested version. Incomplete network results are not cached as clean verdicts.

The database is what lets Guardian answer operational questions across runs:

- Was this finding new today?
- Did a package fix remove a previous finding?
- Did the evidence change, or only the interpretation?
- Is this unchanged noise that should not be re-explained every morning?

## Freshness Model

Guardian uses both live and local data.

Live on normal scans:

- OSV batch queries for the package versions in the current inventory.
- CISA KEV, FIRST EPSS, and NVD enrichment when a matching CVE alias is present.
- GitLab Advisory Database sparse checkout/fetch when threat-intel ingest is enabled by the selected scan mode.

Live when requested:

- GitHub Security Advisories exact package/version lookups when `--include-ghsa` is enabled or a selected scan mode enables GHSA.
- OpenSSF Malicious Packages sparse ingest in deep/handoff mode or explicit threat-intel ingest.
- Registry metadata for newly observed versions in standard mode and a bounded baseline in deep/handoff mode.

Local:

- Bundled exact-match malicious-package catalogs shipped with the plugin.
- Generated exact-match catalogs from threat-intel ingest.
- Previous scan snapshots and local remediation state in SQLite.

This means a daily automation does not only test against a static database. It re-inventories the repo, refreshes configured live sources where enabled, checks local catalogs, then compares the new result to the prior SQLite snapshot.

## Lockfile Tamper And Pinning Evidence

Guardian inspects npm JSON lockfiles plus pnpm and Yarn lockfiles with tolerant line readers. It records exact integrity values and resolved locations, then compares stable package/version identities across scans. A changed hash at the same package version or an npm URL outside `allowed_registry_hosts` is graded `behavioral-high`. Direct URL/VCS dependencies are informational on the first baseline and become `behavioral-watch` when introduced later.

Python requirements files are summarized rather than reported line by line. Guardian identifies unpinned entries, direct URL/VCS requirements, and inconsistent `--hash` usage. Go `go.sum`, Rust `Cargo.lock`, and Composer distribution checksums also feed same-version integrity drift detection.

These checks prove only that committed dependency evidence changed or points somewhere unexpected. They do not validate downloaded artifact contents, prove a registry is trustworthy, or replace package-manager signature/provenance verification. Private npm registries must be added deliberately to `allowed_registry_hosts` to avoid a high signal.

The hygiene pass is local and does not execute package managers or contact registries. The release fixture measures the pass against 600 package records and enforces a sub-100 ms budget.

## Catalog Verification And Integrity

Local exact-match entries can carry per-version OSV verification. `corroborated` means OSV/OpenSSF independently returned active malicious-package evidence for that exact package/version. `withdrawn` means the matching malicious record is withdrawn. `uncorroborated` means Guardian's local entry remains visible but OSV did not independently match it. An outage is `skipped`, not uncorroborated, and does not overwrite prior state.

Verified remote refreshes use the SHA-256 manifest bundled with the installed plugin. Guardian stages all files, verifies the entire set, validates JSON shape, and only then atomically replaces the managed local set. Hashes are not signatures: the Git/plugin distribution channel remains the trust root, and a compromise of that channel could replace both manifest and files.

## Registry Behavioral Intelligence

Guardian records field-level npm/PyPI observations for exact versions adopted by a project. It can surface recent publication, npm maintainer-set drift, disappeared npm attestations, deprecation, PyPI yanking, and missing/changed repository URLs.

These are graded behavioral signals, not proof of compromise. Provenance is recorded as unknown where a registry does not expose an equivalent field. PyPI does not provide npm-style maintainer history, so Guardian does not invent it. Informational registry hygiene is labeled `info` and does not inflate fix/watch counts.

Cost and privacy boundaries:

- unchanged daily-watch roots make zero registry-intelligence calls;
- standard first scans do not enumerate every package at the registry;
- changed versions are bounded by a package cap and cached for seven days in SQLite;
- package names and exact versions are sent to the relevant public registry;
- normalized fields and maintainer hashes are stored, not full response bodies in SQLite.

## Behavioral Install Signals

Guardian treats install-time behavior as a separate evidence class from published advisories. A behavioral signal is not proof that a package is malicious.

| Evidence | What Guardian can establish | Confidence boundary |
| --- | --- | --- |
| npm `package-lock.json` v2/v3 | Whether npm recorded `hasInstallScript` for a package version | Script body and exact lifecycle kind are not stored in the lockfile |
| Installed `node_modules/*/package.json` | Lifecycle script names and a stable hash of their bodies | Only available with the opt-in installed-tree scan |
| `pnpm-lock.yaml` | Package/version evidence | Install-script presence remains `unknown`; Guardian does not guess |
| `yarn.lock` | Package/version evidence | Install-script presence remains `unknown`; Guardian does not guess |
| `uv.lock` | Source-only distributions when no wheel is recorded | A source build can execute build hooks, but is not automatically malicious |
| pip direct URL/VCS requirement | The project explicitly installs outside a normal resolved registry pin | Guardian does not claim a published version when the reference does not expose one |

New dependencies with install-time behavior default to `watch`. A dependency that changes from no install script to an install script, or whose installed script body changes without a version change, defaults to `fix this week`. Corroborating malicious-package intelligence may raise the final posture separately.

Install-script signals follow snapshot discipline: Guardian emits the change once, stores the new observation, and does not repeat the alert while the evidence remains unchanged.

## Typosquat And Slopsquat Signals

Guardian compares only newly introduced package names, plus explicit pre-install checks, against ranked top-5,000 npm and PyPI name snapshots. It uses bounded Damerau-Levenshtein distance and targeted confusion transforms for transpositions, separators, common affixes, digit/letter substitutions, and npm scope lookalikes.

Name similarity is behavioral evidence, not proof that a package is malicious. Exact popular names are never flagged merely for being popular. Legitimate similar names can be accepted locally with:

```bash
guardian policy accept-name <npm|pypi> <name> --reason "verified publisher and repository"
```

Scan-time typo checks follow snapshot discipline: they run only for names first seen in the current inventory run, not against every package on every scan.

## Pre-Install Boundary

The package gate prioritizes local evidence, then performs bounded registry and OSV checks. Exact malicious-catalog evidence blocks by default. Typosquat, known-vulnerability, and opaque source signals require review. Source outages fail open with an explicit warning so offline development is not disabled.

The hook reduces accidental agent installs but is not a sandbox. Host support for shell `PreToolUse` interception can vary, requirements files are not expanded by the hook, and unknown installers may bypass it. Skill instructions therefore retain an explicit package-check step as defense in depth.

## HTTP Reliability And Cache

All runtime advisory and registry HTTP requests use Guardian's shared standard-library client. It applies per-host pacing, bounded exponential-backoff retries for rate limits and transient server failures, honors `Retry-After`, and uses a consistent user agent.

GET responses are cached under the local Guardian source cache. Fresh responses are served without a network request. Stale responses are conditionally revalidated with `ETag` or `Last-Modified`; a `304 Not Modified` response reuses the saved body. Operator source status includes cache hits, revalidations, and downloaded byte counts.

POST queries such as OSV package batches are not cached because the response depends on the request body. If a required source remains unavailable after retries, Guardian records a source error and completes with degraded coverage. It does not resolve previously known findings merely because a source failed.

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
- Lockfile flags show that install-time behavior exists; only installed metadata can expose script bodies for hashing.
- A newly added install script is a review signal, not evidence by itself that compromise occurred.
