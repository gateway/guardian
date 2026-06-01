#!/usr/bin/env bash
# Run the release gates that should pass before publishing Guardian publicly.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PLUGIN_ROOT="$REPO_ROOT/plugins/guardian-security-scan"
CODEX_HOME_TMP="$(mktemp -d "${TMPDIR:-/tmp}/guardian-codex-release.XXXXXX")"
CODEX_HOME_RELEASE="$CODEX_HOME_TMP/codex-home"
mkdir -p "$CODEX_HOME_RELEASE"

cleanup() {
  rm -rf "$CODEX_HOME_TMP"
}
trap cleanup EXIT

echo "== plugin manifest =="
python3 "$HOME/.codex/skills/.system/plugin-creator/scripts/validate_plugin.py" "$PLUGIN_ROOT"

echo "== skills =="
for skill_dir in "$PLUGIN_ROOT"/skills/*; do
  python3 "$HOME/.codex/skills/.system/skill-creator/scripts/quick_validate.py" "$skill_dir"
done

echo "== python compile =="
python3 -m py_compile $(find "$PLUGIN_ROOT/guardian_runtime/src/guardian" -name '*.py' -print)

echo "== internal release checks =="
GUARDIAN_STATE_DIR="$CODEX_HOME_TMP/state-internal" "$PLUGIN_ROOT/scripts/guardian" validate plugin-release --json >/tmp/guardian-release-checks.json
python3 - <<'PY'
import json
from pathlib import Path

payload = json.loads(Path("/tmp/guardian-release-checks.json").read_text())
if payload.get("status") != "pass":
    raise SystemExit(json.dumps(payload, indent=2))
print("internal release checks passed")
PY

echo "== fixture scans =="
python3 "$REPO_ROOT/scripts/run_fixture_tests.py"

echo "== local Codex marketplace install =="
CODEX_HOME="$CODEX_HOME_RELEASE" codex plugin marketplace add "$REPO_ROOT" >/tmp/guardian-marketplace-add.txt
CODEX_HOME="$CODEX_HOME_RELEASE" codex plugin list --marketplace guardian >/tmp/guardian-marketplace-list.txt
CODEX_HOME="$CODEX_HOME_RELEASE" codex plugin add guardian-security-scan@guardian >/tmp/guardian-plugin-add.txt
"$CODEX_HOME_RELEASE/plugins/cache/guardian/guardian-security-scan/"*/scripts/guardian report summary --json >/tmp/guardian-installed-smoke.json

echo "release checks passed"
