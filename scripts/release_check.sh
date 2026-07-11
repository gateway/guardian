#!/usr/bin/env bash
# Run the release gates that should pass before publishing Guardian publicly.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PLUGIN_ROOT="$REPO_ROOT/plugins/guardian-security-scan"
CODEX_HOME_TMP="$(mktemp -d "${TMPDIR:-/tmp}/guardian-codex-release.XXXXXX")"
CODEX_HOME_RELEASE="$CODEX_HOME_TMP/codex-home"
mkdir -p "$CODEX_HOME_RELEASE"

find_claude_bin() {
  if [[ -n "${CLAUDE_BIN:-}" && -x "$CLAUDE_BIN" ]]; then
    printf '%s\n' "$CLAUDE_BIN"
    return 0
  fi
  if command -v claude >/dev/null 2>&1; then
    command -v claude
    return 0
  fi
  local claude_support="$HOME/Library/Application Support/Claude/claude-code"
  if [[ -d "$claude_support" ]]; then
    find "$claude_support" -path '*/claude.app/Contents/MacOS/claude' -type f -perm -111 | sort -r | head -n 1
  fi
}

cleanup() {
  rm -rf "$CODEX_HOME_TMP"
}
trap cleanup EXIT

echo "== plugin manifest =="
python3 "$REPO_ROOT/scripts/validate_codex_plugin.py"

echo "== Claude plugin packaging =="
python3 "$REPO_ROOT/scripts/validate_claude_plugin.py"
CLAUDE_BIN_FOUND="$(find_claude_bin || true)"
if [[ -n "$CLAUDE_BIN_FOUND" ]]; then
  echo "Using Claude Code validator: $CLAUDE_BIN_FOUND"
  "$CLAUDE_BIN_FOUND" plugin validate "$PLUGIN_ROOT" --strict
  "$CLAUDE_BIN_FOUND" plugin validate "$REPO_ROOT" --strict
else
  echo "Claude Code CLI not found; skipped claude plugin validate"
fi

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

echo "== pre-install gate =="
python3 "$REPO_ROOT/scripts/test_preinstall_gate.py"

echo "== local Codex marketplace install =="
CODEX_HOME="$CODEX_HOME_RELEASE" codex plugin marketplace add "$REPO_ROOT" >/tmp/guardian-marketplace-add.txt
CODEX_HOME="$CODEX_HOME_RELEASE" codex plugin list --marketplace guardian >/tmp/guardian-marketplace-list.txt
CODEX_HOME="$CODEX_HOME_RELEASE" codex plugin add guardian-security-scan@guardian >/tmp/guardian-plugin-add.txt
INSTALLED_PLUGIN_ROOT="$(find "$CODEX_HOME_RELEASE/plugins/cache/guardian/guardian-security-scan" -mindepth 1 -maxdepth 1 -type d | head -n 1)"
"$INSTALLED_PLUGIN_ROOT/scripts/guardian" report summary --json >/tmp/guardian-installed-smoke.json
GUARDIAN_STATE_DIR="$CODEX_HOME_TMP/state-codex-hook" \
  "$INSTALLED_PLUGIN_ROOT/hooks/preinstall_gate.py" <<'JSON' >/tmp/guardian-codex-hook.json
{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"npm install @beproduct/nestjs-auth@0.1.18"}}
JSON
python3 - <<'PY'
import json
from pathlib import Path

payload = json.loads(Path("/tmp/guardian-codex-hook.json").read_text())
decision = (payload.get("hookSpecificOutput") or {}).get("permissionDecision")
if decision != "deny":
    raise SystemExit(f"installed Codex hook did not deny fixture: {payload}")
print("installed Codex hook smoke passed")
PY

echo "release checks passed"
