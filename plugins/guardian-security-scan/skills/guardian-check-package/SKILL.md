---
name: guardian-check-package
description: Check an npm or PyPI package before installation using Guardian's bounded, cached pre-install verdict and explain whether to allow, review, or block it.
---

# Guardian Check Package

Use this skill before adding a new npm or Python dependency, or when the user asks whether a proposed package and version is safe to install.

## Command

Resolve the bundled CLI relative to this skill and run:

```bash
../../scripts/guardian check-package <npm|pypi> <package-name> [version] --json
```

Examples:

```bash
../../scripts/guardian check-package npm react 19.1.0 --json
../../scripts/guardian check-package pypi requests 2.32.4 --json
```

Exit codes are `0` for allow, `1` for warning/review, and `2` for block. A missing version asks the registry for its current release. Cached complete checks are reused for 24 hours by default.

## Decision Rules

- Do not install a package when Guardian returns `block`.
- Pause and explain the evidence when Guardian returns a typosquat, known-vulnerability, or opaque direct-source warning.
- Treat registry install scripts as review context, not proof of malware.
- When live sources are unavailable, Guardian fails open with a visible coverage warning. Never describe that result as a clean security check.
- An operator can silence a verified package-name false positive with `guardian policy accept-name <ecosystem> <name> --reason "..."`.
- Do not bypass a block or high-signal warning by changing install syntax.

## Hook Behavior

Guardian's plugin hook automatically checks common npm, pnpm, Yarn, pip, uv, and Poetry package additions initiated through supported shell tools. Explicitly run this skill when the hook is unavailable, when a command uses an unsupported installer, or when the user wants a verdict before any install command is formed.

## Response

Return the verdict, concrete package/version, strongest signal, source coverage, cache status, and the safe next action. Keep the response short unless the user asks for advisory detail.
