from __future__ import annotations

from .advisory_yaml import parse_advisory_yaml
from .versions import version_satisfies_range


KNOWN_RANGE_CASES = [
    {
        "name": "minimatch patched 10.x must not match multiline range",
        "version": "10.2.5",
        "expected": False,
        "yaml": '''
identifier: "CVE-2026-27903"
package_slug: "npm/minimatch"
affected_range: ">=10.0.0 <10.2.3||>=9.0.0 <9.0.7||>=6.0.0
  <6.2.2||<3.1.3"
fixed_versions:
- "10.2.3"
''',
    },
    {
        "name": "minimatch vulnerable 10.x must match multiline range",
        "version": "10.2.0",
        "expected": True,
        "yaml": '''
identifier: "CVE-2026-27903"
package_slug: "npm/minimatch"
affected_range: ">=10.0.0 <10.2.3||>=9.0.0 <9.0.7||>=6.0.0
  <6.2.2||<3.1.3"
fixed_versions:
- "10.2.3"
''',
    },
    {
        "name": "vite modern major must not match old 4.x advisory",
        "version": "8.0.14",
        "expected": False,
        "yaml": '''
identifier: "CVE-2023-34092"
package_slug: "npm/vite"
affected_range: "=2.9.15||>=3.0.2 <3.2.7||>=4.2.0
  <4.2.3||>=4.3.0 <4.3.9"
fixed_versions:
- "4.3.9"
''',
    },
    {
        "name": "path-to-regexp patched 8.x must not match pre-8 advisory",
        "version": "8.4.0",
        "expected": False,
        "yaml": '''
identifier: "CVE-2024-45296"
package_slug: "npm/path-to-regexp"
affected_range: ">=0.2.0 <1.9.0||<0.1.10||>=7.0.0 <8.0.0||>=4.0.0
  <6.3.0"
fixed_versions:
- "8.0.0"
''',
    },
    {
        "name": "qs modern 6.x must not match old backport advisory",
        "version": "6.15.2",
        "expected": False,
        "yaml": '''
identifier: "CVE-2022-24999"
package_slug: "npm/qs"
affected_range: ">=6.10.0 <6.10.3||>=6.9.0 <6.9.7||>=6.6.0
  <6.6.1||<6.2.4"
fixed_versions:
- "6.10.3"
''',
    },
]


def run_regression_corpus() -> dict:
    failures = []
    for case in KNOWN_RANGE_CASES:
        advisory = parse_advisory_yaml(case["yaml"])
        actual = version_satisfies_range(case["version"], str(advisory.get("affected_range") or ""))
        if actual != case["expected"]:
            failures.append(
                {
                    "name": case["name"],
                    "version": case["version"],
                    "expected": case["expected"],
                    "actual": actual,
                    "affected_range": advisory.get("affected_range"),
                }
            )
    return {
        "case_count": len(KNOWN_RANGE_CASES),
        "failure_count": len(failures),
        "failures": failures,
    }
