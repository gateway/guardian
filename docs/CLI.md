# Guardian CLI

Guardian ships with a bundled CLI at:

```bash
./plugins/guardian-security-scan/scripts/guardian
```

The CLI is useful for smoke tests, local automations, and debugging plugin behavior without involving an agent.

## Requirements

- Python 3.9+ available as `/usr/bin/python3` or `python3`.
- Git for repo-root detection and optional advisory-source fetches.
- npm, pnpm, or pip only when you request package-manager corroboration or audit checks.

Guardian's scanner runtime uses the Python standard library only.

## Basic Commands

Run a normal compact project scan:

```bash
./plugins/guardian-security-scan/scripts/guardian scan /path/to/repo --mode daily --output compact --json
```

Run a deeper scan with installed-tree and GHSA corroboration:

```bash
./plugins/guardian-security-scan/scripts/guardian scan /path/to/repo --mode deep --include-installed --include-ghsa --json
```

Run daily watch:

```bash
./plugins/guardian-security-scan/scripts/guardian daily-watch --root /path/to/repo --json
```

Refresh live advisory data for known packages:

```bash
./plugins/guardian-security-scan/scripts/guardian daily-watch --root /path/to/repo --refresh-advisories --json
```

Review dependency bloat:

```bash
./plugins/guardian-security-scan/scripts/guardian diet scan /path/to/repo --limit 100 --usage-limit 80 --json
```

Diet reports use local lockfile graph data and fresh registry metadata already cached in SQLite; they never fetch registry metadata themselves. A `Vendor Candidate` includes attribution/tests requirements and a command to retain the upstream package on Guardian's watchlist:

```bash
guardian watchlist add-vendored \
  --ecosystem npm --name package-name --version 1.2.3 \
  --project-root /path/to/repo --license MIT --json
```

Run the outreach safety preflight before preparing an upstream security PR or issue:

```bash
guardian outreach preflight \
  --repo owner/name --repo-dir /path/to/checkout \
  --advisory-id GHSA-xxxx-xxxx-xxxx \
  --package package-name --version 1.2.3 --json
```

This command writes a durable SQLite ledger decision. It does not create external outreach.

Check a package before installation:

```bash
./plugins/guardian-security-scan/scripts/guardian check-package npm react 19.1.0 --json
./plugins/guardian-security-scan/scripts/guardian check-package pypi requests 2.32.4 --json
```

The package-check exit codes are `0` allow, `1` warn, and `2` block. See [`PREINSTALL_GATE.md`](PREINSTALL_GATE.md) for hook behavior and configuration.

Cross-verify local malicious catalogs against OSV:

```bash
./plugins/guardian-security-scan/scripts/guardian catalog verify --json
```

Refresh the managed catalog set with the installed SHA-256 manifest:

```bash
./plugins/guardian-security-scan/scripts/guardian catalog refresh --json
```

Run optional direct OpenSSF malicious-package ingest for the current inventory:

```bash
./plugins/guardian-security-scan/scripts/guardian intel ingest \
  --root /path/to/repo \
  --include-openssf-malicious \
  --json
```

Standard scans inspect registry metadata only for versions introduced after a prior inventory. Use `--include-registry-intel` to add that behavior to daily mode, or use `--mode deep` for a bounded baseline plus OpenSSF ingest.

Project scans include npm, PyPI, Go, crates.io, and Packagist evidence by default. Restrict inventory with repeatable `--ecosystem` values when needed:

```bash
guardian scan /path/to/repo --ecosystem go --ecosystem crates.io --json
```

Set `allowed_registry_hosts` in Guardian's local `config.json` when an npm project intentionally resolves packages from a private registry. Unknown npm hosts remain a high behavioral signal.

Scout a public GitHub repo with temporary state:

```bash
./plugins/guardian-security-scan/scripts/guardian repo-scout \
  --repo owner/name \
  --scan-mode standard \
  --include-ghsa \
  --ghsa-max-packages 40 \
  --per-repo-seconds 300 \
  --large-repo-seconds 900 \
  --total-seconds 1800 \
  --json
```

## GitHub Token

A GitHub token is optional. Guardian can use one for higher-rate GitHub Security Advisory checks.

Supported token sources:

```bash
export GITHUB_TOKEN=<your token>
export GH_TOKEN=<your token>
```

If neither environment variable is set, Guardian tries `gh auth token` when GitHub CLI is installed and authenticated.

Do not commit tokens to this repo.

## Release Verification

Before publishing a release, run:

```bash
./scripts/release_check.sh
```

That gate validates plugin manifests, Claude packaging, skill metadata, Python compilation, version-matching checks, fixture scans, and local marketplace/cache smoke tests.


## Trust audit

For ordinary dependency scans, `guardian scan PATH --include-installed --exclude data`
excludes stored data and cached templates from inventory. The project-scan skill
runner also accepts repeated `--exclude NAME`. Exclusions are directory basenames
and are recorded in the scan policy. Project-specific triage uses only that
project's package occurrences, even when the state database contains other roots.

```bash
guardian trust-audit
guardian trust-audit --root ~/development --json
guardian trust-audit --root ~/work --root ~/personal --exclude data --json
guardian trust-audit --node /path/to/node-installation/bin/node --json
guardian trust-audit --bundle /path/to/custom-ca.pem --max-directories 5000 --json
guardian trust-audit --root ~/development --output trust-audit.md
```

This offline, read-only macOS inventory checks `/etc/ssl/cert.pem`, Homebrew
CA/OpenSSL bundles and Python site-packages under `/opt/homebrew` and
`/usr/local`, Python.org Python/PythonT frameworks, and user Python installations
under `~/Library/Python`. Repeatable `--root` discovers nested environments by
`pyvenv.cfg`, including custom environment names. Discovery prunes dependency,
VCS, build and cache trees and does not follow directory symlinks. It inspects
immediate installed distribution metadata and the exact `certifi/cacert.pem`
and `pip/_vendor/certifi/cacert.pem` paths, never package source trees.
Overlapping roots and shared environments produce one environment/package result.
Repeat `--exclude NAME` to skip extra directory basenames (for example `data`
for stored app data and cached templates). Roots are explicit; no whole-home scan
runs automatically. Known bundle symlinks are resolved and deduplicated.
Metadata and PEM files are limited to 4 MiB.
Directory discovery is capped at 10,000 visited directories per root by default.
`--max-directories N` adjusts this bound; truncation is reported as unverified
coverage. Repeatable `--bundle PATH` selects additional PEM bundles explicitly,
without sourcing configuration or assuming that an application uses them.

Node coverage is static: known Homebrew installations, absolute PATH entries,
standard nvm/Volta/asdf/fnm layouts, `bin/node` installations beneath selected
roots, and repeatable explicit `--node` paths. Executables and sibling
`lib/libnode*.dylib` files are inspected for embedded PEM fingerprints, with a
128 MiB limit per file. No Node executable, shim, project script or package is
launched. Installation headers (`include/node/node_version.h`) provide version
evidence; they do not attest which executable an application actually runs.
Unknown layouts, headers, or release lines remain unverified. Published fixes
are tracked independently for Node 22, 24 and 26; a fix on one release line
does not establish a fix on another. Embedded PEM absence cannot establish
effective trust, and external libraries outside this layout are not inspected.

The small bundled eMudhra evidence snapshot has verification dates, exact DER
fingerprints, official advisory links and published package fixes. It is not a
live feed or broad CVE scan. Package versions alone produce review candidates;
local patches, inactive installations and runtime overrides can change exposure.
The certifi security fix is 2026.10.18; the Python guidance recommends 2026.10.19
for compatibility. Upgrading certifi alone does not update pip's vendored copy.
Environment versions are read from `pyvenv.cfg`, never by launching Python.
Pip's recommended fix requires Python >=3.10: environments reporting an older
interpreter receive an incompatible-recommendation warning. Missing interpreter
metadata yields unknown compatibility; it does not imply an upgrade is safe.
HTTPX/httpcore and other transport packages are reported as context without
inventing incident-specific affected-version ranges.
No packages are imported or executed, and no remediation runs.

Reports distinguish `demonstrated_failure`, `review_candidate`,
`no_matching_findings`, and `unverified`. This static inventory performs no
TLS probes, so it never claims demonstrated acceptance failures. Fingerprint
matches establish certificate presence only. No match does not establish safe
TLS. Keychain policy, browser revocation, inherited system-site-packages,
`.pth`/editable imports, Conda/pyenv installations outside the listed layouts,
archives, embedded binaries other than the explicit Node layouts, unlisted cross-signed variants and SPKI-equivalent
certificates are not verified. The evidence includes the parent root and Apple's
12 published TLS intermediate certificate fingerprints, not all possible chains
or certificates sharing the compromised keys. On other platforms, macOS checks are explicitly
unverified; optional environment inspection remains available.

JSON schema version 2 adds canonical `roots`, per-root discovery counts and
excluded names, `environment_details` (including source roots and Python version),
Node runtime items, and `absent_optional_locations`. The legacy `root` field
remains populated for one requested root and is null for zero/multiple roots.
Missing optional system installations are listed separately, not counted as
unverified. A missing bundle belonging to an installed package, broken symlink,
or unreadable file remains unverified. Counts describe evidence entries, not
independent vulnerabilities. Node versions and package versions do not prove
effective application trust even when their version checks have no matches.
Node `version_status` is separate from the runtime item's status: an updated
header alone leaves runtime trust unverified. Positive fingerprint matches are
preserved even when another certificate in the same file is malformed.

The `overview` separates development-root evidence from shared tooling and marks
discovery completion, without a whole-system safety score. It explicitly states
that neither device compromise nor TLS acceptance was assessed. See
[Developer trust inventory](TRUST_AUDIT.md) for vendor research, report semantics
and scope-selection guidance.

The command bypasses Guardian configuration loading, catalog seeding and SQLite
initialization. The launcher disables Python bytecode writes and ignores user/
project Python startup code (`PYTHONPATH`, site customizations and `.pth` files).
Use the launcher for these guarantees; a direct module invocation inherits the
startup behavior of the Python interpreter you choose. JSON goes to stdout; `--output PATH` explicitly creates a new
Markdown file without overwriting existing files or creating parent directories.
Exit status is 0 for completed inventory (including review/unverified results),
and 2 for argument or report-output errors. Consult JSON counts for findings.


### Three-view Trust Audit HTML report

An explicit `--output report.html` (or `.htm`, case-insensitive) creates a self-contained
HTML report. Other extensions retain Markdown output. Existing output files are
never overwritten. `--json` still emits the unchanged audit JSON to stdout and may
be combined with either report format. No default report or state is created.

The HTML file includes Project environments, Machine tooling, and What you ship
views. Every evidence item appears once, including no-match and unverified evidence.
For overlapping roots, the most specific containing root owns the displayed row;
containment is scope, not proof that an application uses the installation. Files
outside selected roots appear under shared machine tooling. Shared environments
must be selected explicitly; the renderer does not inspect project configuration.

Each selected root has a review-only Codex handoff and a release-review handoff.
The machine view has a shared-tooling handoff. Copy buttons only copy text; when
clipboard access is unavailable, the prompt expands for manual selection. No
messages, commands, upgrades or remediation are executed. Release coverage is always
**Not assessed**; this feature does not scan images, setup scripts or shipped artifacts.

Recommendations use the bundled evidence snapshot, never a live latest-version
lookup. Incompatible Python recommendations are shown as environment-migration
planning. Node fixes apply only to verified release lines. Bundle evidence may
reference a corresponding package's route only when unambiguous metadata exists in
the same site-packages directory. The package and bundle remain separate rows.

The file needs no web server, fonts, external assets or runtime dependencies.
Official HTTPS links contact their destinations only when opened by the user.
With JavaScript disabled, all views remain readable; print output includes all views.
The report and prompts contain local paths: review them before sharing.
