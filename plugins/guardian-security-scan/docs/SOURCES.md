# Guardian Sources

Guardian combines live advisory APIs, local cache state, and bundled exact-match catalogs.

## Live And Refreshable Sources

- OSV: broad vulnerability matching for package ecosystem/version pairs.
- GitHub Security Advisories: advisory metadata, ecosystem vulnerability records, and malicious package advisory types.
- CISA KEV: known exploited-in-the-wild CVE signal.
- FIRST EPSS: exploit-likelihood score and percentile.
- NVD: CVE severity/detail enrichment when other sources are missing context.
- GitLab Advisory Database: optional upstream advisory database ingest for additional coverage.

## Bundled Catalogs

The plugin includes public exact-match catalogs for selected supply-chain campaigns. These catalogs are copied into the user's Guardian state directory on first run and are not overwritten after local edits.

Bundled catalogs are exact package/version indicators. They are not file, process, or network IOC scanners.

## Source Limits

Guardian cannot detect unpublished zero-days. It can only match against configured sources and package versions visible in the scanned project.
