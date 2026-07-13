# Changelog

All notable Guardian changes are recorded here. Versions refer to the bundled Codex and Claude Code plugin manifests.

## 1.6.3 - 2026-07-12

### Changed

- Documentation and plugin descriptions now state per-ecosystem coverage explicitly: a README ecosystem-coverage matrix clarifies that the pre-install gate, typosquat detection, and registry behavioral intelligence cover npm and PyPI, while Go, Rust, and Composer receive inventory, advisory/malicious matching, and lockfile checksum drift detection.

## 1.6.2 - 2026-07-12

### Fixed

- Package-usage analysis now detects when ripgrep is not installed. Usage results report `scan_status: unavailable`, package-diet classifications downgrade to Review with an install-ripgrep explanation instead of labeling packages Unused, and diet reports carry a top-level `usage_scan` status.

### Added

- GitHub Actions release-check workflow running the full release gates on every push and pull request, with a portable `release_check.sh` that skips machine-specific validators and still runs the hook deny smoke test from the checkout.
- README overhaul: real gate-deny demo, badges, table of contents, tool-comparison section, accurate pre-install hook coverage, and documented gate tuning plus `guardian policy accept-name`.

## 1.6.1 - 2026-07-12

### Fixed

- Local filesystem installs such as `pip install -e .`, `pip install .`, `uv pip install -e .`, and `npm install ./packages/lib` now warn without blocking the pre-install gate. Remote URL, VCS, and unresolved alias installs still pause for review.
- The install-command parser now handles additional Poetry and pip value flags plus split or clustered shell `-c` wrappers such as `bash -l -c` and `zsh -ec`.
- Outreach preflight no longer permanently blocks retryable `checks-unavailable` or `suppressed-daily-cap` ledger entries.
- Default-branch outreach checks ignore generated and vendored dependency trees such as `node_modules`, `vendor`, `dist`, build folders, and virtualenvs.
- npm registry intelligence now requests exact-version metadata before falling back to the package-wide document for release time or package context.

### Verified

- Focused regression tests cover the parser/hook bypasses, local-path hook policy, retryable outreach rows, vendored default-branch evidence, and exact-version npm registry fetch order.

## 1.6.0 - 2026-07-11

### Added

- Pre-install interception for Bun, Pipenv, versioned Python interpreters, npm/pnpm/Yarn/Bun package execution commands, manager flags before or after install subcommands, npm aliases, and bounded nested shell wrappers.
- Explicit stale-cache result state for hash-verified HTTP fallback after failed revalidation.

### Fixed

- pnpm `-w` no longer consumes the following package as a workspace value.
- Versionless package checks always resolve the registry's current `latest` version instead of reusing a 24-hour empty-version verdict.
- Per-host pacing no longer blocks requests to unrelated hosts while one host waits.
- Existing lifecycle scripts found on a first scan are informational instead of being presented as newly introduced watch items.

### Verified

- Parser and live-hook regression matrices cover every previously confirmed bypass and require vulnerable or malicious fixture requests to reach a deny decision.
- Deterministic fixtures prove latest-version changes are observed, exact-version verdict caching remains active, first-scan script noise is downgraded, post-baseline script drift remains prioritized, stale cache is explicit, and cross-host pacing is independent.
- Any exact-version OSV vulnerability continues to pause installation for review by policy; network failure remains fail-open with visible incomplete coverage.

## 1.5.2 - 2026-07-11

### Fixed

- Multi-advisory remediation selects the highest required fixed boundary instead of the lowest individual advisory boundary.
- A package affected until both a prerelease and a later stable release can no longer be pointed at the still-vulnerable prerelease.

### Verified

- A regression fixture proves fixed boundaries `5.0.0rc3` and `5.3.0` produce a minimum remediation target of `5.3.0`.
- Proposed targets remain subject to Guardian's clean-target recheck before an automated upgrade recommendation.

## 1.5.1 - 2026-07-11

### Fixed

- Upgraded installations no longer let a persisted pre-1.4 npm/PyPI capability list disable the Go, Rust, and Composer inventory parsers shipped by the current plugin.
- Native inventory capabilities are now owned by the running Guardian release instead of mutable user configuration.
- UV lock inventory now preserves production, development, and optional scopes from `pyproject.toml` instead of treating every direct extra as production.
- Triage now honors exact-version development scope for direct dev dependencies as well as transitive dev packages.
- Operator and handoff reports now retain occurrence evidence through triage, so manifest, lockfile, and installed-tree corroboration flags reflect the files Guardian actually scanned.
- Python `dist-info` and `egg-info` occurrences are recognized as installed-tree corroboration in operator evidence boxes.
- Repo Scout now carries fixed/clean target evidence into compact output and routes findings without a verified target to focused validation or issue-first discussion before inviting a dependency PR.

### Verified

- A regression fixture loads the legacy two-ecosystem configuration and successfully selects native inventory for all five supported ecosystems.
- A UV-lock regression fixture proves development-only and optional packages retain their project scopes.
- The reporting fixture proves remediation queue shaping cannot discard manifest and lockfile occurrence evidence.
- The installed-plugin project runner scans an existing upgraded Guardian state without editing its configuration or the target repository.

## 1.5.0 - 2026-07-11

### Added

- Offline npm lockfile transitive-count analysis and cached registry size/license/maintenance context for package diet.
- A strict `Vendor Candidate` tier with permissive-license, pure-source, exact-version, attribution, test-first, and upstream-watch requirements.
- Vendored package watch entries that continue exact-version advisory checks after a dependency is copied into local source.
- `guardian outreach preflight` for archive, policy, open/closed PR/issue, default-branch, duplicate-ledger, and daily-cap checks.
- `guardian outreach record` plus a durable SQLite `outreach_log` ledger and default five-action daily safety cap.

### Changed

- Package-diet scoring now weights cached unpacked size, transitive footprint, and maintenance-death evidence while degrading explicitly to usage-only offline.
- Advisory-PR guidance requires the bundled preflight and a visible final diff/draft followed by explicit human confirmation before external outreach.
- Missing GitHub or default-branch evidence stops outreach at manual verification instead of being treated as a clear check.

### Verified

- A 4 MB/two-call-site package ranks above a 10 KB package at equivalent usage.
- Permissively licensed micro-packages become Vendor Candidates, while the equivalent GPL package remains Review.
- Existing upstream tracking writes a suppressed ledger row and a repeated proposal is blocked across sessions.
- Eligible outreach requires complete checks, and the configured daily cap suppresses additional proposals.

## 1.4.0 - 2026-07-11

### Added

- Offline npm, pnpm, and Yarn resolved-host inspection with configurable approved registry hosts.
- Same-package/version integrity drift detection across npm, Go, Rust, and Composer lock evidence.
- Aggregated Python requirements hygiene for unpinned entries, newly introduced direct URLs/VCS sources, and inconsistent hash mode.
- Native Go module, Rust crates.io, and Composer Packagist inventory with exact OSV ecosystem mapping.
- Go module-graph context that keeps non-direct `go.sum` findings from being presented as direct runtime exposure.

### Changed

- Guardian's default inventory now includes npm, PyPI, Go, crates.io, and Packagist without running project package managers.
- Version comparison now follows semver prerelease ordering and handles Go pseudo-version timestamp ordering without third-party packages.
- Lockfile hygiene observations use a local SQLite ledger so unchanged scans do not repeat behavioral alerts.

### Verified

- Deterministic OSV fixtures produce findings for vulnerable Go and Rust versions.
- Rogue-host and same-version integrity fixtures each emit one high signal, while unchanged repeats emit none.
- npm JSON, pnpm, Yarn, Python requirements, Go, Cargo, and Composer parsing are covered by the Milestone 4 suite.
- The offline hygiene pass completes below 100 ms for a 600-package fixture.

## 1.3.0 - 2026-07-11

### Added

- Explicit `osv-malicious` source labeling and catalog-grade handling for OSV/OpenSSF `MAL-*` exact-version matches.
- Optional package-scoped OpenSSF Malicious Packages sparse ingest for deep, handoff, and explicit threat-intelligence runs.
- `guardian catalog verify` with per-version `corroborated`, `uncorroborated`, `withdrawn`, and outage-safe `skipped` states.
- `guardian catalog refresh` with a bundled SHA-256 manifest, complete-set validation, managed catalog storage, and fail-closed mismatch handling.
- Exact-version npm/PyPI registry metadata history for publish age, maintainer drift, npm attestations, deprecation/yanking, repository changes, package size, and install behavior.
- Mode-gated registry intelligence with one-time behavioral signals and a seven-day SQLite metadata cache.

### Changed

- Daily and unchanged watch scans make zero registry-intelligence calls; standard mode checks only versions introduced beyond an existing baseline.
- Deep and handoff modes enable a bounded registry baseline and optional OpenSSF malicious-package ingest.
- Verified managed catalogs supersede seeded copies without duplicating findings.
- Pre-install checks reuse fresh registry state and invalidate cached verdicts when registry evidence changes.

### Verified

- Live OpenSSF sparse ingest matched `MAL-2022-2` from the current upstream repository and its disposable checkout was removed.
- Live Guardian catalog refresh downloaded and SHA-256 verified all eight shipped catalogs from the public repository.
- Active, withdrawn, uncorroborated, offline, malformed, and hash-mismatch catalog paths are covered by deterministic tests.
- A two-version registry fixture emits each expected signal once, while its baseline and unchanged repeat perform zero registry requests.

## 1.2.0 - 2026-07-11

### Added

- A bounded `guardian check-package` command with allow/warn/block JSON verdicts and stable exit codes.
- A cross-compatible Codex and Claude Code `PreToolUse` hook for common npm, pnpm, Yarn, pip, uv, and Poetry package additions.
- A dedicated `guardian-check-package` skill and explicit pre-install checks across every bundled workflow skill.
- Ranked top-5,000 npm and PyPI package snapshots with reproducible provenance and a standard-library refresh script.
- Bounded Damerau-Levenshtein and targeted confusion detection for newly introduced typosquat/slopsquat package names.
- Persistent `first_seen_run_id` inventory state, accepted-name policy, and a 24-hour SQLite package-verdict cache.

### Changed

- Package checks fail open with explicit incomplete-source warnings when registry or OSV requests are unavailable.
- Cached package verdicts are invalidated when local malicious catalogs or blocking policy change.
- Scan-time typo checks run only for package names first introduced by the current inventory run.

### Verified

- Cold clean checks complete within the three-second gate budget and warm checks complete in under one second.
- Exact malicious-catalog fixture packages block locally without a network request.
- More than 20 real-world install command forms are parsed without treating restore commands or requirements files as direct package additions.
- Hook packaging validates in a copied plugin cache and Anthropic's strict plugin validator.
- Offline source failure allows the install with visible warning context rather than disabling development.

## 1.1.0 - 2026-07-11

### Added

- Persistent install-script observations and one-time drift signals for newly added or changed install-time behavior.
- Shared signal grades that distinguish advisories, behavioral review signals, and malicious-package evidence strength.
- npm lockfile lifecycle flags, installed lifecycle script hashes, conservative Python source-install evidence, and honest unknown states for pnpm and Yarn lockfiles.
- Behavioral signal sections in operator JSON, compact scan output, and Markdown handoff reports.
- A standard-library HTTP client with bounded retries, exponential backoff, `Retry-After` support, per-host pacing, soft-TTL disk caching, and conditional GET revalidation.
- Source-contract cache and download metrics.

### Changed

- OSV, GHSA, CISA KEV, FIRST EPSS, NVD, npm, and PyPI requests now use the shared HTTP policy.
- Source outages degrade scan coverage without aborting the scan or incorrectly resolving previously known findings.

### Verified

- Install-script additions alert once and remain quiet on unchanged repeat scans.
- pnpm and Yarn install-script state remains unknown unless stronger evidence exists.
- Consecutive KEV reads download the catalog once while fresh; stale cache entries revalidate without downloading the body on `304`.
- Transient `429` and `500` responses recover within bounded retries, and network timeouts remain bounded.
