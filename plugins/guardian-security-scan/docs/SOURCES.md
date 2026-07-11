# Guardian Sources

Guardian combines live advisory APIs, local cache state, and bundled exact-match catalogs.

## Live And Refreshable Sources

- OSV: broad vulnerability matching for package ecosystem/version pairs.
- GitHub Security Advisories: advisory metadata, ecosystem vulnerability records, and malicious package advisory types.
- CISA KEV: known exploited-in-the-wild CVE signal.
- FIRST EPSS: exploit-likelihood score and percentile.
- NVD: CVE severity/detail enrichment when other sources are missing context.
- GitLab Advisory Database: optional upstream advisory database ingest for additional coverage.

## Request Reliability

Guardian routes runtime HTTP traffic through one standard-library client. Requests use bounded retries with backoff, honor server rate-limit delays, and share per-host pacing. GET feeds and registry metadata use a local soft-TTL cache with `ETag` and `Last-Modified` revalidation; POST-based package queries are not cached.

Source status reports whether a response came from cache, whether it was revalidated, and how many bytes were downloaded. A source that remains unavailable is reported as an error while the rest of the scan continues. Guardian preserves existing findings when their source cannot be refreshed.

Default cache policy:

- Maximum retries after the initial request: `2`
- Soft cache TTL: `21600` seconds (6 hours)
- Cache location: `~/.guardian-security-scan/source_cache/http_cache/`

These values can be changed through `http_max_retries` and `http_cache_ttl_seconds` in Guardian's local configuration.

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

## Source Limits

Guardian cannot detect unpublished zero-days. It can only match against configured sources and package versions visible in the scanned project.
