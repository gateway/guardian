# Guardian Release Fixtures

These fixtures are intentionally small and safe. They are not runnable applications.

- `clean-npm`: basic npm lockfile inventory path.
- `malicious-local-catalog`: exact match against Guardian's bundled malicious package catalog.
- `vendored-yarn-metadata`: nested `node_modules/**/yarn.lock` metadata that should be classified as low-confidence vendored evidence.
- `go-module`: direct and module-graph Go evidence with exact go.sum checksums.
- `cargo-lock`: crates.io lock evidence with a checksum used by tamper-drift tests.
- `lockfile-hygiene`: one deliberately unapproved npm resolved host plus stable integrity evidence.
- `requirements-hygiene`: mixed Python pin and hash modes for aggregated informational signals.
- `composer-lock`: direct Packagist lock evidence with a distribution checksum.

The release fixture runner copies fixtures to a temporary directory before scanning so snapshot and fix-verification checks do not modify checked-in files.
