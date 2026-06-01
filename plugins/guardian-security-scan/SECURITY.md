# Security Policy

Guardian is a local dependency-risk scanner. It does not require secrets for normal daily scans.

## Reporting Issues

If you find a security issue in Guardian itself, open a GitHub security advisory or private report when available. Avoid posting working exploit details publicly before maintainers have a chance to respond.

## Secrets

Do not commit:

- GitHub tokens
- npm tokens
- PyPI tokens
- private scan databases
- generated reports containing private project paths
- local Guardian state directories

Guardian supports `GITHUB_TOKEN` and `GH_TOKEN` as environment variables. It also supports `gh auth token` from a local GitHub CLI login. These credentials are read at runtime only.

## Local State

Guardian stores scan state outside the plugin by default:

```text
~/.guardian-security-scan
```

This keeps plugin source bundles separate from local scan history.
