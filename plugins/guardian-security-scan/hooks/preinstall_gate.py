#!/usr/bin/env python3
"""Codex/Claude PreToolUse entrypoint for Guardian package install checks."""

from __future__ import annotations

import json
import sys
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT / "guardian_runtime" / "src"))

from guardian.config import load_config  # noqa: E402
from guardian.db import Database  # noqa: E402
from guardian.preinstall_hook import evaluate_install_command, hook_output  # noqa: E402


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except (json.JSONDecodeError, OSError):
        return 0
    if payload.get("hook_event_name") != "PreToolUse":
        return 0
    tool_name = str(payload.get("tool_name") or "")
    if tool_name not in {"Bash", "bash", "exec_command", "shell"}:
        return 0
    command = str((payload.get("tool_input") or {}).get("command") or "")
    if not command:
        return 0
    try:
        config = load_config()
        db = Database(config.db_path)
        db.initialize()
        try:
            output = hook_output(evaluate_install_command(config, db, command))
        finally:
            db.close()
    except Exception as exc:  # A broken local config/source must not disable package installation.
        output = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "additionalContext": f"Guardian package checks were unavailable and failed open: {exc}",
            }
        }
    if output:
        json.dump(output, sys.stdout, sort_keys=True)
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
