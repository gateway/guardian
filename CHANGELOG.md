# Changelog

All notable Guardian changes are recorded here. Versions refer to the bundled Codex and Claude Code plugin manifests.

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
