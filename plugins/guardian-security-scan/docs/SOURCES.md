# Guardian Sources

Guardian combines live advisory APIs, local cache state, and bundled exact-match catalogs.

## Source Matrix

| Source | Contribution | Default freshness | Authentication |
| --- | --- | --- | --- |
| OSV | Exact package/version vulnerability matches and `MAL-*` malicious-package records | Queried during advisory refresh; POST responses are not cached | None |
| GitHub Security Advisories | Exact ecosystem matches, advisory detail, aliases, severity, and malware advisory type | Optional and bounded by scan mode/package cap | Optional GitHub token improves rate limits |
| CISA KEV | Confirmed exploitation-in-the-wild for matching CVEs | Queried only when a matched advisory has a CVE | None |
| FIRST EPSS | Exploit-likelihood score and percentile for matching CVEs | Queried only when a matched advisory has a CVE | None |
| NVD | CVE severity and detail enrichment when primary sources lack context | Queried only when needed | Optional NVD key is not currently required by Guardian |
| GitLab Advisory Database | Range-based npm/PyPI advisory coverage converted to current exact-version entries | Mode-gated sparse git refresh; source config defaults to 24-hour freshness | None; Git required |
| OpenSSF Malicious Packages | OSV-format reports from the OpenSSF malicious-package project, converted to current exact-version entries | Disabled in source config; enabled by deep/handoff or explicit ingest | None; Git required |
| npm/PyPI registries | Publish age, maintainer hash where available, provenance presence, deprecation/yanked state, repository URL, size, and install behavior | Changed versions only in standard mode; bounded baseline in deep mode; SQLite TTL 7 days | None |
| Bundled local catalogs | Exact package/version campaign intelligence available offline | Ships with the plugin; explicit refresh is hash-manifest verified | None |

## Request Reliability

Guardian routes runtime HTTP traffic through one standard-library client. Requests use bounded retries with backoff, honor server rate-limit delays, and share per-host pacing. GET feeds and registry metadata use a local soft-TTL cache with `ETag` and `Last-Modified` revalidation; POST-based package queries are not cached.

Source status reports whether a response came from cache, whether it was revalidated, and how many bytes were downloaded. A source that remains unavailable is reported as an error while the rest of the scan continues. Guardian preserves existing findings when their source cannot be refreshed.

Default cache policy:

- Maximum retries after the initial request: `2`
- Soft cache TTL: `21600` seconds (6 hours)
- Cache location: `~/.guardian-security-scan/source_cache/http_cache/`

These values can be changed through `http_max_retries` and `http_cache_ttl_seconds` in Guardian's local configuration.

Registry metadata also has a seven-day SQLite freshness TTL. The shared HTTP cache may satisfy a stale SQLite refresh without downloading the body again when its shorter HTTP TTL is still valid.

## Offline Behavioral Evidence

Guardian also evaluates install-time behavior from local project evidence. npm lockfiles can record `hasInstallScript`; installed package metadata can expose lifecycle script names and body hashes; selected Python source-install and direct-reference evidence is tracked conservatively. These signals do not call a registry and are graded separately from published advisories.

## Popular-Package Name Snapshots

Guardian bundles ranked top-5,000 name snapshots for npm and PyPI. They are used only for bounded typosquat/slopsquat similarity checks; popularity is not a security endorsement.

- npm names come from the public `download-counts` dataset. The committed JSON records its package version, registry artifact URL, and verified artifact SHA-256.
- PyPI names come from the public `top-pypi-packages` dataset. The committed JSON records its snapshot timestamp, source URL, and artifact SHA-256.

The npm package metadata declares MIT. The `top-pypi-packages` repository does not currently declare a repository license; Guardian records that fact as `not-declared` rather than inventing one. The bundled snapshot contains package names and ordinal ranks only, not download counts or source code.

Maintainers regenerate both files with `scripts/refresh_popular_packages.py`. The npm artifact's registry SHA-512 integrity is verified before extraction, and both resulting files retain provenance in their `source` object.

## Bundled Catalogs

The plugin includes public exact-match catalogs for selected supply-chain campaigns. These catalogs are copied into the user's Guardian state directory on first run and are not overwritten after local edits.

Bundled catalogs are exact package/version indicators. They are not file, process, or network IOC scanners.

Use `guardian catalog verify` to cross-check each local exact version against OSV malicious-package records. Guardian persists `corroborated`, `uncorroborated`, or `withdrawn` per version. If OSV is unavailable, the command reports `skipped` and preserves prior verification rather than silently downgrading it.

Use `guardian catalog refresh` to retrieve the release catalogs into a managed local subdirectory. The installed plugin ships `data/catalog_manifest.json` with a SHA-256 for every catalog. Guardian downloads and validates the complete set, then writes each managed file atomically. Any missing, malformed, or mismatched file rejects the whole refresh and leaves the prior managed set untouched.

This is not a standalone digital signature. The hash manifest and catalogs are distributed through the same Git/plugin channel, so repository/marketplace integrity remains the trust root. The manifest prevents partial, corrupted, or unexpected remote files from being accepted and refuses data that does not match the installed plugin release.

## Registry Intelligence Privacy

Registry intelligence sends the package name and requested exact version to the public npm or PyPI registry. Guardian stores normalized field-level observations and hashes npm maintainer identities; it does not store full registry response bodies in SQLite. HTTP cache bodies remain local under Guardian's state directory for the configured cache TTL.

Signals are behavioral context, not malware claims:

- a recent release can be legitimate;
- a maintainer-set change can reflect normal project ownership;
- missing provenance means attestations disappeared or were unavailable, not that the artifact is malicious;
- deprecation, yanking, and repository URL drift are informational unless stronger evidence corroborates them.

Daily watch performs no registry-intelligence request when dependency files are unchanged. Standard scans skip first-scan baseline fetches and inspect only versions introduced after a prior inventory. Deep/handoff scans may seed a bounded baseline, capped by `registry_intel_max_packages`.

## OpenSSF Cost Boundary

The OpenSSF source uses a shallow, blob-filtered sparse checkout restricted to packages in the current inventory. Git tree metadata for this large repository can still be tens of megabytes on the first fetch (about 66 MB in Guardian's July 2026 validation); later runs reuse the local source cache. It is therefore disabled for daily/standard modes unless explicitly requested.

## Source Limits

Guardian cannot detect unpublished zero-days. It can only match against configured sources and package versions visible in the scanned project.
