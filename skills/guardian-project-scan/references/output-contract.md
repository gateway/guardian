# Guardian Scan Output Contract

Use this structure after a Guardian project scan.

## Current Posture

State the repo, the priority headline, and whether the scan found direct runtime risk, transitive risk, isolated environment risk, vendored metadata, or no findings.

## What Changed

Use the snapshot compare result:

- `new_open_count`: new package evidence.
- `resolved_count`: evidence no longer present.
- `evidence_changed_count`: advisory/package evidence changed.
- `classification_changed_count`: prioritization changed without raw evidence changing.
- `unchanged_count`: still open and unchanged.

Do not claim a finding is fixed unless it appears in `resolved_count` or the resolved list.

## Highest-Signal Issues

For each issue you mention, include:

- package and version
- risk label
- confidence label
- environment label
- one short reason
- at least one advisory link

If all findings are vendored metadata, say no direct app dependency change is justified without corroborating lockfile, installed-tree, or code-usage evidence.

## Suggestions

Give 2-4 next steps. Prefer safe verification and parent-chain review over broad dependency churn.

## Bottom Line

End with a plain-language operator judgment.
