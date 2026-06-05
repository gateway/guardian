# Guardian Advisory PR Template

```md
## 10-second summary

`<This PR updates package@old to package@new for ADVISORY_ID / CVE, a severity vulnerability class advisory. In one or two sentences, explain what could happen in plain English and why this repository is affected. State whether this is active exploitation or preventive remediation.>`

`<One short paragraph: explain what changed, expected user-visible impact, and the validation already run.>`

## What Changed

- `<dependency floor / lockfile / override / parent package changed>`
- `<generated dependency sidecar updated, if applicable>`

## What Users Will See

`<No direct user-facing behavior change is expected.>`

## Why This Change Is Needed

This PR addresses `<severity>` advisory `<ADVISORY_ID>` affecting `<package>@<version>`.

Primary advisory: `<advisory URL>`

The issue is: `<short plain-English vulnerability summary>`.

This matters when: `<conditions required for impact>`.

## Advisory References

- GitHub Advisory Database: `<url if available>`
- Upstream package advisory: `<url if available>`
- OSV: `<url if available>`
- GitLab Advisory Database: `<url if available>`
- NVD CVE page: `<url if available>`
- Upstream fix commit: `<url if available>`

## Where It Appears

Dependency path:

```text
<manifest file>
-> <parent package>@<version>
-> <vulnerable package>@<version>
```

Evidence:

- `<file>:<line>`: `<what this line proves>`

## Code Usage Review

Direct vulnerable package imports: `<none|found>`  
Direct parent package imports: `<none|found>`  
Observed exposure: `<runtime-linked|tooling-only|transitive-only>`

## Fix

This PR `<updates dependency resolution / upgrades parent dependency / removes unused package>` so `<package>` resolves to a patched version.

Affected: `<package>@<old version>`  
Patched: `<fixed range>`  
Target used: `<target version>`

## Alternatives Considered

- `<option>`: `<why accepted/rejected>`

## Risk Assessment

Upgrade risk: `<low|medium|high>`

Reasoning:

- `<semver/change-size reason>`
- `<direct usage reason>`
- `<parent/tooling/runtime reason>`

## Validation

Ran:

- `<command>`: `<result>`

Suggested maintainer validation:

- `<command or smoke test>`

## Notes

This PR is not claiming active exploitation in this repo unless the advisory sources explicitly say so. It removes a known vulnerable dependency version from the resolved dependency graph and documents the scope of the change.

Powered by Guardian: https://github.com/gateway/guardian
```
