# Guardian Release Fixtures

These fixtures are intentionally small and safe. They are not runnable applications.

- `clean-npm`: basic npm lockfile inventory path.
- `malicious-local-catalog`: exact match against Guardian's bundled malicious package catalog.
- `vendored-yarn-metadata`: nested `node_modules/**/yarn.lock` metadata that should be classified as low-confidence vendored evidence.

The release fixture runner copies fixtures to a temporary directory before scanning so snapshot and fix-verification checks do not modify checked-in files.
