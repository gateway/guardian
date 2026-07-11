# Guardian v2 Hardening & Expansion Spec

Date: 2026-07-11
Status: Approved for build
Audience: implementing agent(s). This document is self-contained — it names real modules, tables, and config fields from the current codebase so tasks can be executed without re-deriving context.

---

## 1. Background and goals

Guardian today is an advisory-matching scanner: it inventories npm/Python dependency evidence read-only, matches exact versions against OSV, GHSA, CISA KEV, FIRST EPSS, NVD, GitLab Advisory DB ingest, and bundled exact-match malicious-package catalogs, then triages findings (runtime vs transitive vs vendored-metadata vs test-only) and tracks drift across scans in SQLite (`~/.guardian-security-scan/guardian.db`).

**Core gap:** everything keys off *published* intelligence. Real npm/PyPI supply-chain campaigns (worm-style credential stealers, typosquats, hijacked maintainer accounts) have an hours-to-days window before OSV/GHSA publish. Guardian currently has **no typosquat detection, no install-script analysis, no provenance/attestation checks, and no registry behavioral signals** (verified by code audit 2026-07-11).

**Goals of this spec, in priority order:**

1. Detect *behaving-bad* packages, not just *known-bad* ones — exploit the snapshot DB to alert on suspicious *change over time*.
2. Gate risk at the moment of maximum leverage: **before** an AI agent runs `npm install X` / `pip install X`.
3. Expand and *verify* intelligence sources (cross-corroboration, signed catalog updates, new ecosystems).
4. Upgrade package-diet with footprint data and a safer "vendor it" middle path.
5. Preserve the invariants that make Guardian trustworthy (see §2).

## 2. Non-negotiable invariants (apply to every workstream)

- **Stdlib-only runtime.** No third-party Python packages in `guardian_runtime`. Ever. If a task seems to need one, redesign the task.
- **Read-only scan boundary.** Normal scans never edit project files, install dependencies, or execute project code. New checks that shell out (e.g. `gh`) must be opt-in or mode-gated and reported in output.
- **Graceful source degradation.** Every new network call must produce a `source_contract` entry (`source_contract.py`) on success, skip, and failure. A single flaky source must never fail a scan.
- **Token economy.** New signals must default to compact output. Anything expensive (network fan-out, per-package registry calls) must be cache-backed, incremental (new/changed packages only), and skippable by scan mode.
- **Evidence-first.** New signals are graded (see §3) — behavioral signals are "watch"-tier by default, never auto-escalated to "act now" without corroboration.
- **Fixture-tested.** Every workstream ships fixtures under `tests/fixtures/` runnable by `scripts/run_fixture_tests.py`, and passes `scripts/release_check.sh` and `scripts/validate_claude_plugin.py`.
- **DB migrations are additive.** `db_schema.py` uses `CREATE TABLE IF NOT EXISTS`; new tables/columns must be backward-compatible with existing user databases (use `ALTER TABLE ... ADD COLUMN` guarded by pragma inspection, or new tables).

## 3. New signal-grading vocabulary (cross-cutting)

Add a shared enum used by all new detectors, in a new module `guardian_runtime/src/guardian/signals.py`:

| Grade | Meaning | Default posture impact |
|---|---|---|
| `corroborated-malicious` | Exact match in a catalog **and** confirmed by a second source (e.g. OSV `MAL-*`) | act now |
| `catalog-match` | Exact match in one catalog only | act now, flagged single-source |
| `behavioral-high` | Strong behavior signal (install script added in an update; typosquat distance 1 to top-500 name) | fix this week |
| `behavioral-watch` | Weak/ambiguous behavior signal (new package < 72h old; maintainer change) | watch |
| `advisory` | Published advisory match (existing pipeline) | severity-driven (existing) |
| `info` | Context only (provenance absent, unpinned spec) | reported, no posture change |

Tasks:

- [x] Create `signals.py` with the grade enum, ordering, and a `grade_to_posture()` helper.
- [x] Thread grades through `triage_signals.py`, `triage_rules.py`, and `reporting_operator.py` so operator JSON shows `signal_grade` per finding.
- [x] Fixture: a synthetic finding at each grade renders the correct posture bucket.

---

## 4. Workstreams

Recommended build order: **WS1 → WS7 → WS3 → WS2 → WS4 → WS5 → WS6 → WS8 → WS9 → WS10.** (WS7's HTTP layer is a dependency of WS2/WS4/WS5; WS3 is a dependency of WS2.)

---

### WS1 — Install-script change detection (highest catch-rate per line of code)

**Why:** npm lifecycle scripts (`preinstall`/`install`/`postinstall`) are the dominant execution vector in real campaigns. Guardian already fingerprints dependency files (`dependency_files.py`, `dependency_file_state` table) and snapshots package state (`package_state`). The winning signal is not "package X has a postinstall" (too noisy — thousands of legit packages do) but "**this dependency changed and the change added/modified an install script**."

**Design:**

- Parse lifecycle scripts from evidence Guardian already reads, without installing anything:
  - `package-lock.json` v2/v3: per-package `hasInstallScript: true` flags in the `packages` map.
  - Installed-tree corroboration mode (existing opt-in): read `node_modules/<pkg>/package.json` `scripts` and hash the concatenated script bodies.
  - `pnpm-lock.yaml` / `yarn.lock`: mark script presence `unknown` rather than guessing (be honest in output).
- Python analog: flag when a locked dependency's evidence indicates an **sdist** where a wheel is expected (sdist installs execute `setup.py`), and when a `requirements.txt` entry points at a direct URL/VCS ref.
- New table in `db_schema.py`:

```sql
CREATE TABLE IF NOT EXISTS install_script_state (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  root_path TEXT NOT NULL,
  ecosystem TEXT NOT NULL,
  normalized_name TEXT NOT NULL,
  version TEXT NOT NULL,
  has_install_script INTEGER,          -- 1 / 0 / NULL = unknown
  script_kinds_json TEXT,              -- ["postinstall", ...] when known
  scripts_sha256 TEXT,                 -- hash of script bodies when readable
  evidence_source TEXT NOT NULL,       -- "package-lock" | "installed-tree" | "sdist-heuristic"
  first_seen_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  UNIQUE(root_path, ecosystem, normalized_name, version, evidence_source)
);
```

- Diff logic (new module `install_scripts.py`): on each scan, compare current state to prior rows and emit:
  - `install-script-added` (version changed, old version had none) → `behavioral-high`
  - `install-script-body-changed` (same version, scripts hash changed — near-certain tamper) → `behavioral-high`
  - `new-dep-with-install-script` (first time this package appears at all) → `behavioral-watch`
  - Never re-alert on unchanged state (snapshot discipline, same as existing findings).

**Tasks:**

- [x] Extend the npm native inventory (`inventory_native/npm.py`) to capture `hasInstallScript` from lockfile `packages` entries into the package record `raw_json`.
- [x] Add installed-tree script extraction to the existing corroboration path (read `scripts` from `node_modules/*/package.json`, hash bodies with `integrity.sha256_json`).
- [x] Add sdist/direct-URL heuristics to the Python inventory path.
- [x] Add `install_script_state` table + accessors (new `db_install_scripts.py`, mirroring `db_dependency_files.py` style).
- [x] Write `install_scripts.py` diff module emitting graded signals; wire into `ops.run_project_scan` and `triage_signals.py`.
- [x] Surface in operator JSON + Markdown handoff (`reporting_operator.py`, `reporting_handoff.py`) under a distinct `behavioral_signals` section.
- [x] Fixtures: (a) lockfile update where a package gains `hasInstallScript`; (b) unchanged repeat scan emits nothing; (c) pnpm lockfile reports `unknown` honestly.
- [x] Docs: new section in `docs/TRUST_MODEL.md` (what is/isn't detectable per lockfile format) and `plugins/guardian-security-scan/docs/SOURCES.md`.

**Acceptance:** scanning the fixture twice alerts once; posture output shows `install-script-added` as fix-this-week; no new network calls; daily-watch cost unchanged for unchanged repos.

---

### WS2 — Pre-install gate for Claude Code and Codex (the differentiating feature)

**Why:** the highest-leverage moment is before `npm install`/`pip install` runs — especially with AI agents that hallucinate plausible package names ("slopsquatting"). A local, sub-second gate burns zero model tokens unless it fires.

**Design:**

- New CLI subcommand: `guardian check-package <ecosystem> <name> [version] [--json] [--max-seconds N]` (wire through `cli_parser.py` / `cli.py`):
  1. Local catalog exact match (instant).
  2. Typosquat check (WS3, instant, local).
  3. Cached registry metadata heuristics (WS5 data if cached; single registry fetch if not, bounded by `--max-seconds`, default 3).
  4. Single OSV query for the resolved version (skipped if offline; bounded timeout).
  5. Known install-script signal from registry metadata when available.
  - Output: single JSON verdict `{"verdict": "allow"|"warn"|"block", "signals": [...], "explanation": "..."}` plus exit code (0 allow, 1 warn, 2 block).
  - **Fail-open with a warn** on network failure — a security gate that blocks all installs when offline will get uninstalled.
- Claude Code integration: plugin `PreToolUse` hook on `Bash`, matching install commands (`npm install|add`, `pnpm add`, `yarn add`, `pip install`, `uv add|pip install`, `poetry add`). Hook script parses package specs from the command line, calls `guardian check-package` per new package, and returns hook-protocol deny/allow with the explanation. Add hook config to the plugin (`hooks/` directory + manifest wiring in `.claude-plugin/plugin.json`); the implementer must verify current Claude Code plugin hook manifest shape against current docs before wiring.
- Codex integration: equivalent mechanism if the Codex plugin API exposes command interception; otherwise ship the same check as a documented skill step in the Codex skills (`skills/*/SKILL.md`: "before adding a new dependency, run `guardian check-package` first").
- Config additions (`config.py` → `GuardianConfig`): `preinstall_gate_enabled: bool = True`, `preinstall_gate_block_grades: list = ["corroborated-malicious", "catalog-match"]`, `preinstall_gate_max_seconds: int = 3`.

**Tasks:**

- [x] Implement `check_package.py` orchestrator + CLI wiring, reusing `sources/osv.py` `OSVClient`, `sources/local_catalog.py`, WS3 typosquat module, and bounded registry metadata (cache-first).
- [x] Result cache table `check_package_cache` (ecosystem, name, version, verdict_json, checked_at) with TTL (default 24h) so repeat installs are instant and offline-safe.
- [x] Hook script (stdlib Python, executable) under `plugins/guardian-security-scan/hooks/`: parse install commands robustly (flags, multiple packages, version specs, git URLs — git URLs always at least `warn`).
- [x] Wire hook into Claude plugin manifest; validate with `scripts/validate_claude_plugin.py` (extended to cover hooks and copied-cache denial behavior).
- [x] Codex path: wire the compatible plugin hook and retain skill-instruction fallback in every bundled SKILL.md file.
- [x] New skill `guardian-check-package` so users/agents can invoke the gate explicitly.
- [x] Fixtures/tests: command-line parsing table test (20+ real-world install command variants); verdict tests against the malicious-local-catalog fixture; offline test asserts fail-open warn.
- [x] Docs: new `docs/PREINSTALL_GATE.md` (threat model, what it can/can't catch, how to disable, exit codes).

**Acceptance:** `guardian check-package npm left-pad` returns in <1s warm, <3s cold; installing a package present in `data/local_catalogs/*.json` is blocked with the catalog name in the explanation; disabling via config bypasses the hook cleanly.

---

### WS3 — Typosquat / slopsquat detection

**Why:** exact-match catalogs only catch known campaigns. Edit-distance and confusion checks against popular-package lists catch *novel* malicious names, including AI-hallucinated ones.

**Design:**

- Bundle popular-package name lists: `data/popular_packages/npm.json`, `data/popular_packages/pypi.json` (~5,000 names each, name + rank only, a few hundred KB). Source them from a reproducible public dataset; record source + snapshot date inside each file's header object. Ship a maintainer script (`scripts/refresh_popular_packages.py`, repo-side, not runtime) to regenerate.
- New module `typosquat.py` (stdlib only — implement Damerau-Levenshtein with early-exit bound ≤2):
  - **Skip if the name itself is in the popular list** (it IS the popular package).
  - Distance 1 to a top-500 name → `behavioral-high`. Distance 1 to top-5000, or distance 2 to top-500 → `behavioral-watch`.
  - Confusion transforms checked exactly: hyphen/underscore swap, doubled/dropped letters, `py`/`python`/`python3-` prefix-suffix games (`python-dateutil` vs `python3-dateutil`), `js`/`node-` affixes, npm scope confusion (`@types/foo` vs `types-foo`, unscoped clone of a scoped name), digit/letter substitutions (`0`/`o`, `1`/`l`).
  - Whitelist mechanism: `policy_exceptions` table already exists — reuse it (`action = "accept-name"`) so a legitimately-similar name is silenced permanently.
- **Trigger discipline:** run only on packages that are *new to the snapshot* (first_seen in `package_state` == this run) and in `check-package` (WS2). Never on the full inventory each scan — O(new deps), not O(all deps).

**Tasks:**

- [x] Implement bounded Damerau-Levenshtein + transform checks in `typosquat.py` with exhaustive unit tests (true positives: `reqests`, `lodahs`, `is-nubmer`; true negatives: `react` itself, `preact`).
- [x] Build and commit the two popular-package lists + `scripts/refresh_popular_packages.py` + provenance header.
- [x] Wire into scan pipeline for new-to-snapshot packages only; wire into WS2 `check-package`.
- [x] Reuse `policy_exceptions` for accepted names; surface the accept command in output ("to silence: `guardian policy accept-name npm preact`").
- [x] Test first-seen typo signaling, unchanged repeat silence, and accepted-name suppression.
- [x] Docs: TRUST_MODEL section on false-positive expectations and the whitelist flow.

**Acceptance:** new-dep scan overhead <50ms per new package; zero flags on a scan of Guardian's own fixture set except designed positives.

---

### WS4 — Malicious-package source expansion and catalog cross-verification

**Why:** the user requirement: "if we expand the list, we must be able to call that data and verify against new sources." OSV already ingests the OpenSSF malicious-packages repository (advisory IDs prefixed `MAL-`) — an independent live corroboration source for the bundled catalogs, and a much larger malicious-package feed in its own right.

**Design:**

- **Verify OSV `MAL-*` flow end-to-end:** existing OSV batch queries should already return `MAL-*` entries for matching versions. Confirm `osv_matching.py` doesn't filter them out; give them `advisory_source = "osv-malicious"` and `catalog-match` grade minimum.
- **Direct OpenSSF ingest (optional, mode-gated):** reuse the sparse-checkout ingest pattern from `threat_intel.py` (GitLab advisory DB) for `github.com/ossf/malicious-packages`. Generates local exact-match catalogs into `threat_intel_cache_dir`, same as GitLab flow. This makes the malicious feed available offline and to the WS2 gate.
- **`guardian catalog verify` command:** for every entry in local catalogs (`data/local_catalogs/*.json` seeded to user state), query OSV for the exact package/version and report per entry: `corroborated` (OSV MAL/GHSA-malware match), `uncorroborated` (Guardian-only), or `withdrawn` (OSV shows withdrawal). Persist verification status + timestamp into the catalog JSON (additive field). Upgrade corroborated entries to `corroborated-malicious` grade at match time.
- **Signed catalog refresh channel:** if catalogs are ever fetched remotely (e.g. from the Guardian GitHub repo), require verification: ship a public key in the plugin, sign catalog releases (minisign-compatible Ed25519 — implementable with `hashlib`/`ssl` primitives is NOT viable in pure stdlib; instead pin **SHA-256 hashes in a manifest committed to the plugin repo** and verify hashes on fetch. Signature-grade integrity comes from the git/marketplace channel; document this honestly). Refuse unverified remote catalog data.

**Tasks:**

- [ ] Audit `osv_matching.py` + `advisories.py` for `MAL-*` handling; add explicit handling, source labeling, and a fixture with a known `MAL-*` id.
- [ ] Implement OpenSSF malicious-packages ingest source in `threat_intel.py` (new source entry in `threat_intel_sources.json` default set, disabled by default, enabled by deep/daily-refresh scan modes).
- [ ] Implement `guardian catalog verify` (new `catalog_verify.py` + CLI wiring) with per-entry status output and JSON persistence.
- [ ] Implement hash-manifest-verified catalog refresh (`guardian catalog refresh`), fail-closed on mismatch, with `source_contract` reporting.
- [ ] Docs: SOURCES.md — full source matrix (what each feed contributes, freshness, auth needs); TRUST_MODEL.md — catalog verification and refresh integrity model.

**Acceptance:** `catalog verify` on the shipped catalogs completes with per-entry statuses and no crashes offline (reports `skipped`); a fixture catalog entry corroborated by an OSV MAL id shows grade `corroborated-malicious` in scan output.

---

### WS5 — Registry behavioral signals (age, maintainer drift, deprecation, provenance)

**Why:** compromised-package releases exhibit registry-visible tells before advisories publish: brand-new version, maintainer list change, missing provenance where it previously existed, repo URL mismatch. `registries.py` already fetches npm/PyPI metadata — extend rather than add a new client.

**Design:**

- Extend `registries.py` (or a new `registry_intel.py` using the WS7 HTTP layer) to extract, per package:
  - npm: `time` (per-version publish timestamps), `maintainers`, `deprecated`, `repository.url`, `dist.attestations` presence (provenance), `dist.unpackedSize`, `hasInstallScript` where present.
  - PyPI: `info.project_urls`/`home_page`, per-release `upload_time`, `yanked` flags. (PyPI JSON has no maintainer-change API — record what's available, don't fake it.)
- New table `registry_metadata_state` (root-independent — keyed by ecosystem/name): latest known version, publish timestamp, maintainers hash, provenance flag, deprecated flag, size, fetched_at. Diff on refresh.
- Signals emitted (all graded per §3):
  - `version-published-recently` (<72h at scan time, and the project just adopted it) → `behavioral-watch`
  - `maintainer-set-changed` since last snapshot → `behavioral-watch`
  - `provenance-disappeared` (previous version had npm attestations, new one doesn't) → `behavioral-high`
  - `package-deprecated` / `release-yanked` → `info`
  - `repo-url-missing-or-changed` → `info`
- **Cost discipline:** fetch only for (a) packages new/changed in this scan, (b) `check-package` calls, (c) explicit `--live-enrichment` daily-watch runs. Cache with TTL (default 7d) in the new table; conditional GET via WS7.

**Tasks:**

- [ ] Extend registry fetch to capture the field set above (npm + PyPI), tolerating absent fields.
- [ ] Add `registry_metadata_state` table + diff logic + graded signal emission into `triage_signals.py`.
- [ ] Wire into scan modes (`scan_modes.py`): off for `daily` default, on for changed packages, on for deep modes; always available to WS2 gate cache-first.
- [ ] Surface in `behavioral_signals` report section with the same snapshot discipline (alert once per change).
- [ ] Fixtures: canned registry JSON responses (offline test doubles) for each signal; maintainer-drift double-scan test.
- [ ] Docs: SOURCES.md registry-intel section, including rate-limit posture and privacy note (Guardian sends package names to registries — already true today via `LatestVersionResolver`; document it).

**Acceptance:** a daily-watch over unchanged repos performs zero registry calls; a scan adopting a 1-day-old version emits `version-published-recently` once.

---

### WS6 — Lockfile tamper and pinning hygiene checks

**Why:** cheap, high-signal, fully offline. A poisoned lockfile is an attack that survives code review because nobody reads lockfile diffs.

**Design (new module `lockfile_hygiene.py`, run during fingerprinting):**

- npm/pnpm/yarn lockfiles:
  - `resolved` URL host not in the allowed registry set (default: `registry.npmjs.org`, `registry.yarnpkg.com`; configurable `allowed_registry_hosts` for private registries) → `behavioral-high`
  - integrity hash changed for the **same** name+version between snapshots → `behavioral-high` (near-certain tamper)
  - git/http(s) tarball dependencies → `info` on first sight, `behavioral-watch` when newly introduced
- Python:
  - `requirements.txt` entries without `==` pins → `info` summary count (not per-line spam)
  - direct URL / VCS requirements newly introduced → `behavioral-watch`
  - missing `--hash` pins where some entries have them (inconsistent hash mode) → `info`

**Tasks:**

- [ ] Implement lockfile parsers' hygiene pass (npm JSON lockfiles first; pnpm YAML and yarn.lock via tolerant line-scanning — no YAML dependency).
- [ ] Snapshot integrity hashes per (name, version) into `package_state.raw_json` or a slim new column; diff between runs.
- [ ] Config: `allowed_registry_hosts` list in `GuardianConfig`.
- [ ] Wire signals into triage + reports with snapshot discipline.
- [ ] Fixtures: lockfile with a rogue `resolved` host; same-version-different-integrity double scan; requirements file mixing pinned/unpinned.
- [ ] Docs: TRUST_MODEL — what tamper checks prove and what they can't.

**Acceptance:** fully offline; adds <100ms to a 600-package scan; rogue-host fixture flags exactly one finding.

---

### WS7 — HTTP layer hardening (retries, conditional GET, shared client)

**Why:** every source client (`sources/osv.py`, `ghsa.py`, `kev.py`, `epss.py`, `nvd.py`, `registries.py`) hand-rolls `urlopen` with a timeout but no retry, no backoff, no ETag/Last-Modified caching. KEV is a multi-MB file re-downloaded on every enrichment run. This workstream is a prerequisite for WS2/WS4/WS5 fan-out.

**Design (new module `http_client.py`, stdlib only):**

- `GuardianHttp` class: GET/POST with (a) bounded retries (default 2) with exponential backoff + jitter on 429/5xx/URLError, honoring `Retry-After`; (b) per-host min-interval pacing (reuse `api_request_min_interval_seconds`); (c) conditional GET — persist ETag/Last-Modified + body in `threat_intel_cache_dir/http_cache/` keyed by URL hash, send `If-None-Match`/`If-Modified-Since`, serve cached body on 304; (d) consistent `User-Agent`; (e) structured result (status, from_cache, error) so callers can fill `source_contract` uniformly.
- Migrate all six clients to it. Behavior-preserving except: KEV/EPSS get cache; all sources get retry.
- Config additions: `http_max_retries: int = 2`, `http_cache_ttl_seconds: int = 21600` (soft TTL before conditional revalidation).

**Tasks:**

- [x] Implement `http_client.py` + unit tests using a local `http.server` test double (stdlib) covering 200/304/429-with-Retry-After/500-then-200/timeout.
- [x] Migrate `kev.py` and `epss.py` first (biggest wins), then `osv.py`, `nvd.py`, `ghsa.py`, `registries.py`.
- [x] Audit call sites so every source failure degrades to a `source_contract` error entry — grep for bare `urlopen` afterward; none may remain outside `http_client.py`.
- [x] Add cache-hit stats to source contracts (`from_cache: true`) so daily-watch output can say "KEV: cached (revalidated)".

**Acceptance:** two back-to-back daily-watch runs download KEV bytes once; a mocked 500-then-200 OSV batch succeeds; killing the network mid-scan yields a completed scan with errored source contracts, not a crash.

---

### WS8 — Ecosystem expansion: Go and Rust (then Composer)

**Why:** OSV already covers `Go`, `crates.io`, and `Packagist` — the marginal cost is a lockfile parser each. AI-assisted projects increasingly span these.

**Design:**

- Parsers (stdlib text parsing, no TOML dependency concerns — Python 3.11+ has `tomllib` for `Cargo.lock` which is TOML; use it, it's stdlib):
  - Go: `go.mod` (direct deps + `// indirect` markers) and `go.sum` (exact versions). Ecosystem `Go` in OSV; module path is the package name.
  - Rust: `Cargo.lock` via `tomllib` (`[[package]]` name/version/source/checksum). Ecosystem `crates.io`. Checksum field feeds WS6 tamper diffing for free.
  - Phase 2: `composer.lock` (JSON, trivial) → `Packagist`.
- Extend `dependency_files.dependency_file_kind()` with the new kinds; extend `inventory_native/` with `golang.py`, `cargo.py`; add to `inventory_native_supported_ecosystems` default; map ecosystems in `util.normalize_ecosystem_for_osv`.
- Triage: `go.sum` contains the full module graph including test-only deps — mark Go findings `module-graph` confidence (analogous to existing transitive labeling) unless the module appears in `go.mod` directly.

**Tasks:**

- [ ] Go parser + fixtures (`tests/fixtures/go-module/`) with a known-vulnerable pinned module version.
- [ ] Rust parser + fixtures (`tests/fixtures/cargo-lock/`) with checksum data exercised by WS6.
- [ ] OSV ecosystem mapping + `versions.py` comparison handling for Go pseudo-versions (`v0.0.0-20230101...-abcdef`) and semver crates.
- [ ] Wire into triage context labels (direct vs module-graph) and reports.
- [ ] Update README, SOURCES.md, plugin descriptions (`.claude-plugin/plugin.json`, `.codex-plugin/plugin.json` keywords/description) to say npm/Python/Go/Rust.
- [ ] Composer as a follow-up task once Go/Rust pass fixtures.

**Acceptance:** fixture scans produce advisory matches for the pinned vulnerable versions via OSV; Go test-only module findings are labeled, not shouted.

---

### WS9 — Package-diet upgrades: footprint weighting, vendor-it tier, maintenance-death

**Why:** current heuristics (`package_diet_rules.py`) are sound but argue from usage counts alone. Footprint and maintenance data make recommendations persuasive; "vendor it" is the safe middle path the user explicitly wants ("we use 0.5% of the package").

**Design:**

- **Footprint:** per candidate package compute (a) transitive dependency count from the already-parsed lockfile graph (offline), (b) `dist.unpackedSize` from WS5 registry metadata (cached). Fold into `bloat_score()`: large footprint + tiny usage raises score; zero-transitive-dep micro-packages get the strongest replace push.
- **Vendor-it tier:** new classification `Vendor Candidate` between `Replace Candidate` and `Keep`, triggered when: usage ≤ 3 call sites AND no `REPLACEMENT_RECIPES` entry AND license is permissive (MIT/ISC/BSD/Apache-2.0 from lockfile/registry metadata) AND package is pure-source (no native/binary — reuse `DO_NOT_REIMPLEMENT` exclusions). Recommendation text: extract the used functions into `vendor/<pkg>/` with license header + upstream version pin comment, and add the original package to a watch list so advisories still surface for the vendored code (`watchlist.py` exists — wire vendored packages into it).
- **Maintenance-death signal:** last publish > 30 months AND (single maintainer OR deprecated flag) from WS5 metadata → nudges classification one step toward Replace/Vendor and is stated in the reason.
- Keep all existing guardrails (wrapper-fanout, DO_NOT_REIMPLEMENT, workspace/types exemptions) intact.

**Tasks:**

- [ ] Transitive-count computation from lockfile graph (new helper in `package_diet_usage.py` or `project_model.py`).
- [ ] Integrate WS5 metadata (size, license, last-publish, maintainer count) into `package_diet.py`, cache-first, degrading gracefully to usage-only scoring offline.
- [ ] Add `Vendor Candidate` classification + bucket + priority rank + report rendering (`package_diet_rules.py`: `buckets()`, `priority_rank()`, `bloat_score()`).
- [ ] Wire vendored packages into `watchlist.py` so vulnerability scans still cover their upstream origin.
- [ ] Update `guardian-package-diet` SKILL.md: vendor-it workflow, license-attribution requirement, "write tests before swapping" instruction for the agent.
- [ ] Fixtures: micro-package with 1 call site + permissive license → Vendor Candidate; same package with GPL license → stays Review.

**Acceptance:** diet report on a fixture ranks a 4MB/2-call-site package above a 10KB/2-call-site one; offline runs still produce a complete (usage-only) report with a note that footprint data was skipped.

---

### WS10 — Repo Scout / advisory-PR safety: dedupe, pacing, reputation protection

**Why:** the outbound-PR flow is where Guardian touches other people's projects. One duplicate or noisy PR damages the project's reputation more than ten missed findings.

**Design:**

- Before proposing a PR/issue for a finding, `guardian-advisory-pr` must check (via `gh` CLI, already an optional dependency per `config.github_token()`):
  - existing open/closed PRs and issues mentioning the advisory id or package+version bump — if found, report "already addressed/in-flight" and stop;
  - whether the default branch already fixed it (lockfile at HEAD ≠ the scanned clone);
  - repo signals that PRs are unwelcome (archived repo, `CONTRIBUTING.md` says security reports via SECURITY.md — prefer the documented channel and say so).
- Local outreach ledger: new table `outreach_log` (repo, advisory_id, package, action, url, created_at) so Guardian never proposes the same finding to the same repo twice, even across sessions.
- Rate limiting: config `max_outreach_per_day: int = 5` (safety valve), enforced against the ledger.
- The skill must present findings + draft to the human for confirmation before anything is created — never auto-file. (This is prompt-side: encode it in `skills/guardian-advisory-pr/SKILL.md` as a hard instruction.)

**Tasks:**

- [ ] Implement pre-flight dedupe checks (`gh pr list --search`, `gh issue list --search`, HEAD lockfile comparison) in a new `outreach.py`, invoked by the advisory-PR flow; degrade to "checks unavailable, verify manually" without `gh`.
- [ ] Add `outreach_log` table + ledger enforcement + `max_outreach_per_day`.
- [ ] Rewrite `skills/guardian-advisory-pr/SKILL.md` with the pre-flight checklist, human-confirmation gate, and SECURITY.md-channel preference.
- [ ] Extend `docs/REPO_SCOUT.md` with the outreach policy.
- [ ] Fixture/dry-run test: ledger blocks a second proposal for the same (repo, advisory) pair.

**Acceptance:** a dry-run advisory-PR flow against a repo with an existing fix PR reports "in-flight, no action" and writes a ledger row.

---

## 5. Milestone plan

| Milestone | Workstreams | Theme | Ship gate |
|---|---|---|---|
| **M1 — See the change** | WS1, WS7, §3 signals | Behavioral detection foundation + HTTP hardening | fixtures green; daily-watch byte-count drop measured |
| **M2 — Gate the door** | WS3, WS2 | Typosquat + pre-install gate | gate blocks catalog fixture; <1s warm path; fail-open verified |
| **M3 — Trust the feeds** | WS4, WS5 | Source expansion + verification + registry intel | `catalog verify` shipping; MAL-* corroboration fixture green |
| **M4 — Widen the net** | WS6, WS8 | Tamper checks + Go/Rust | new-ecosystem fixtures green; tamper fixtures green |
| **M5 — Diet & manners** | WS9, WS10 | Vendor-it + outreach safety | diet fixture ranking correct; outreach ledger enforced |

Each milestone ends with: `scripts/run_fixture_tests.py` green, `scripts/release_check.sh` green, `scripts/validate_claude_plugin.py` green, version bump in both plugin manifests, CHANGELOG entry, and README/SOURCES/TRUST_MODEL updates for anything user-visible.

## 6. Out of scope (explicitly)

- Running untrusted project code, sandboxed dynamic analysis, or network IOC scanning — different product.
- Auto-editing dependency files or auto-merging fixes.
- A hosted service or telemetry of any kind — Guardian stays local-first; the only outbound traffic is to the documented advisory/registry sources and (opt-in) `gh`.
- Real cryptographic signature infrastructure for catalogs (documented as hash-manifest + distribution-channel integrity for now; revisit if a stdlib-compatible Ed25519 path is chosen deliberately).

## 7. Open questions for the maintainer (non-blocking; defaults chosen)

1. Popular-package list source: default plan is a public download-count dataset snapshot committed with provenance header. Acceptable to commit ~600KB of name lists to the repo? (Default: yes.)
2. Pre-install gate default: `warn` on typosquat `behavioral-high` vs `block`? (Default: warn; block only catalog-grade. Flip later with field data.)
3. Go/Rust before Composer confirmed? (Default: yes.)
