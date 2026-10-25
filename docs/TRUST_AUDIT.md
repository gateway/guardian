# Developer trust inventory

Guardian Trust Audit identifies incident evidence in selected development folders
and known shared developer tools. It does not diagnose a compromised device,
claim that an attack occurred, or certify that a machine is safe. It remains an
offline, read-only inventory; the normal project dependency scan is a separate
workflow with its own advisory queries and state.

## Incident context and source review

Sources reviewed on 2026-10-25. The incident concerns weak private keys in eight
eMudhra **intermediate** CAs, not evidence that the root private key was stolen.
Root removal is one mitigation. Six intermediates are for TLS; cross-signing
creates multiple certificate identities for the same keys.

| Primary source | Implication for this tool |
| --- | --- |
| [Apple](https://support.apple.com/en-us/149555) | Apple framework blocks and the PEM file used by some command-line tools are distinct. The evidence includes Apple's 12 published TLS intermediate certificate fingerprints, plus the distrusted emSign ECC G3 root. |
| [Cloudflare](https://blog.cloudflare.com/emudhra-certificate-compromise/) | Trust may live in a library, runtime, shared store or custom bundle. Updating one layer or testing a browser does not prove a background application is protected. |
| [Google](https://blog.google/security/protecting-chrome-and-android-users-from-compromised-emudhra-intermediate-ca-certificates/) | CRLSet blocks operate on public-key identities. Exact certificate matching is narrower and must not be described as comprehensive protection. |
| [Mozilla](https://blog.mozilla.org/security/2026/10/20/protecting-firefox-users-following-the-compromise-of-emudhra-intermediate-certificates/) | Firefox's OneCRL response and NSS root-store updates are separate mechanisms. A file inventory cannot establish whether browser policy updates were applied. |
| [Microsoft](https://learn.microsoft.com/windows-server/identity/ad-cs/certificate-trust) | Windows manages trusted and disallowed certificate lists separately. This is general platform documentation: an authoritative incident-specific Microsoft statement was not located in this review. No Windows mitigation status is asserted. |
| [Python guidance](https://discuss.python.org/t/information-for-python-users-regarding-emudhra-emsign-ca-certificate-security-incident/109576/1) | Existing environments and vendored package stores need independent inspection; standalone certifi does not replace pip's vendored bundle. |

No-match results mean only no match against the bundled evidence snapshot.
Alternate certificates sharing compromised keys, code-signing certificates,
chain-building, revocation and actual TLS acceptance remain outside this audit.
In particular, the presence of the unrelated AAA root alone is not flagged as
proof of this incident: the listed cross-signed intermediate fingerprints are
matched individually. This is an inventory, not a blocklist implementation.

## Report model

The overview separates selected development roots from shared tooling and shows
inspection counts, review candidates and unknowns. It deliberately has no
whole-system health score or green “safe” verdict. Overlapping roots and multiple
observations about one environment can overlap in the counts.

- **Review candidate:** exact incident certificate present or installed version
  metadata preceding a published fix. Confirm application use and the relevant
  vendor guidance before planning changes.
- **No matching findings:** no match in the inspected evidence; neither proof of
  effective distrust nor a verdict on the rest of the machine.
- **Unverified:** unreadable/unsupported inputs, missing runtime evidence or a
  discovery limit. Positive matches remain visible even in a partly malformed file.
- **Demonstrated failure:** reserved; this static command performs no TLS probes.

Node headers describe installation metadata, not an attested running binary.
Their version assessment is separate from runtime trust status; a newer header
cannot make an unverified store appear clean. Known Node files are read as data.
No Node/Python environment or project code is executed.

## Scope selection

```sh
guardian trust-audit --root ~/work --root ~/personal --exclude data --json
guardian trust-audit --root ~/work/project --root ~/shared-provider --output trust-review.md
guardian trust-audit --node /chosen/node/bin/node --bundle /chosen/custom-ca.pem --json
```

Supply shared environments explicitly when projects use sibling/provider roots.
The scanner does not source .env files, resolve project startup scripts or claim
that every discovered runtime is active. Explicit bundles let developers inspect
custom stores without exposing or executing runtime configuration.

Directory discovery stops at 10,000 visited directories per root by default;
`--max-directories N` changes that bound. Hitting it emits an unverified discovery
entry and marks coverage incomplete. Narrower roots and exclusions are preferable
to blindly increasing the bound. File-size limits still apply independently.
The bound limits traversed directories, not total bytes of directory listings or
wall-clock time on a slow filesystem.

The tool does not enumerate every application, access browsers, edit Keychain,
install updates, schedule scans, or write Guardian configuration/database state.
Only explicit `--output` writes a new Markdown report. CLI details are in
[CLI.md](CLI.md#trust-audit).
