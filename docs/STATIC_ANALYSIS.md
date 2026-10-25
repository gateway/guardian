# Static analysis baseline

Reviewed for PR #9 on 2026-10-25. These checks assess code quality, not device compromise, exploitability, or complete security coverage.

## Tools and scope

- Ruff 0.17.2: Python correctness lint and formatting. Used instead of Prettier for Python. Checks use isolated configuration and Python 3.9 compatibility (the macOS Trust Audit launcher can use the system interpreter).
- Radon 6.0.1: cyclomatic complexity across the Python runtime. Complexity is a review heuristic, not a vulnerability grade.
- JSCPD 4.0.5: token-based duplication across the Python runtime, default minimum 5 lines / 50 tokens. No source upload or hosted analysis.

Analysis tools ran separately from Guardian, in disposable development caches. Guardian remains stdlib-only. No product dependencies were added.

## Results

- Scoped lint and formatting pass for the three Trust Audit modules and two new test suites. CI now repeats these checks with a pinned Ruff version. Test-only E402 exceptions allow the existing explicit import-path bootstrap.
- Broad lint (`E4,E7,E9,F,B`, Python 3.9) reports 27 findings versus 20 on the main baseline `54ef8e2`. The seven additional findings are the documented test import-path bootstrap; no additional findings remain under the same test exception. Older findings include unused imports/re-exports and existing import ordering. These require intent-aware follow-up, not automatic bulk deletion.
- JSCPD reports 18 clone groups, 239 duplicated lines out of 19,141 (1.25%), across 98 runtime files. No detected clone involves a Trust Audit module. The scanner is heuristic and does not establish absence of semantic duplication.
- The Trust Audit coordinator's cyclomatic complexity fell from 72 to 34 after separating environment, package and deduplicated-file inspection. Its largest helper is 25. Further decomposition should follow concrete behavior changes, not a numeric target.
- Existing high-complexity areas remain: CLI dispatch (201), handoff Markdown rendering (100), advisory refresh (72), and project scan coordination (63). These are maintenance priorities, not newly discovered vulnerabilities.

## Review corrections and verification

Bounded metadata snapshots now go directly to the shared parser rather than reopening inspected files. Markdown output escapes inspected text. Regression coverage includes both cases. The release metadata and catalog manifest are consistent with the next 1.7.0 version.

Local verification: 28 focused Trust Audit tests, the project-root triage regression, fixture tests, plugin manifest validations and catalog consistency passed. A Mac audit of the selected developer roots found no metadata changes across 5,713 monitored filesystem entries. This snapshot check is scoped, not an all-system I/O trace.

## Reproduce

Use a disposable development environment for analysis tools; do not add them to Guardian's runtime dependencies. From the repository root after installing the pinned analysis tools there:

```bash
files=(plugins/guardian-security-scan/guardian_runtime/src/guardian/trust_audit*.py scripts/test_trust_audit.py scripts/test_triage_root_scope.py)
ruff check --isolated --target-version py39 --select E4,E7,E9,F,B --per-file-ignores 'scripts/test_*.py:E402' "${files[@]}"
ruff format --isolated --check "${files[@]}"
ruff check --isolated --target-version py39 --select E4,E7,E9,F,B plugins/guardian-security-scan/guardian_runtime/src/guardian scripts
radon cc plugins/guardian-security-scan/guardian_runtime/src/guardian -s
jscpd plugins/guardian-security-scan/guardian_runtime/src/guardian --format python
```

The broad lint command intentionally exposes existing debt and is not a passing repository-wide CI gate. Duplication and complexity remain review reports, not arbitrary percentage gates.
