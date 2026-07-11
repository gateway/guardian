#!/usr/bin/env python3
"""Validate Guardian's Claude Code plugin packaging without third-party deps."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
MARKETPLACE = REPO_ROOT / ".claude-plugin" / "marketplace.json"
PLUGIN_ROOT = REPO_ROOT / "plugins" / "guardian-security-scan"
PLUGIN_MANIFEST = PLUGIN_ROOT / ".claude-plugin" / "plugin.json"
HOOKS_FILE = PLUGIN_ROOT / "hooks" / "hooks.json"


def fail(message: str) -> None:
    """Abort validation with a concise failure message."""

    raise SystemExit(f"claude plugin validation failed: {message}")


def load_json(path: Path) -> dict[str, Any]:
    """Load a JSON file and make parse errors actionable."""

    try:
        payload = json.loads(path.read_text())
    except FileNotFoundError:
        fail(f"missing file: {path}")
    except json.JSONDecodeError as exc:
        fail(f"invalid JSON in {path}: {exc}")
    if not isinstance(payload, dict):
        fail(f"{path} must contain a JSON object")
    return payload


def require_string(payload: dict[str, Any], field: str, path: Path) -> str:
    """Return a required string field from a manifest-like object."""

    value = payload.get(field)
    if not isinstance(value, str) or not value.strip():
        fail(f"{path} field {field!r} must be a non-empty string")
    return value


def validate_marketplace() -> dict[str, Any]:
    """Validate the root Claude marketplace catalog and resolve the plugin entry."""

    marketplace = load_json(MARKETPLACE)
    if require_string(marketplace, "name", MARKETPLACE) != "guardian":
        fail("marketplace name must remain 'guardian'")
    owner = marketplace.get("owner")
    if not isinstance(owner, dict) or not isinstance(owner.get("name"), str):
        fail("marketplace owner.name is required")
    plugins = marketplace.get("plugins")
    if not isinstance(plugins, list) or not plugins:
        fail("marketplace plugins must be a non-empty array")
    matches = [item for item in plugins if isinstance(item, dict) and item.get("name") == "guardian-security-scan"]
    if len(matches) != 1:
        fail("marketplace must expose exactly one guardian-security-scan plugin entry")
    entry = matches[0]
    source = entry.get("source")
    if source != "./plugins/guardian-security-scan":
        fail("guardian-security-scan marketplace source must be ./plugins/guardian-security-scan")
    if not (REPO_ROOT / source).resolve().is_dir():
        fail(f"marketplace source does not exist: {source}")
    return entry


def validate_plugin_manifest(entry: dict[str, Any]) -> dict[str, Any]:
    """Validate Claude plugin metadata and its relationship to the marketplace."""

    manifest = load_json(PLUGIN_MANIFEST)
    if require_string(manifest, "name", PLUGIN_MANIFEST) != entry["name"]:
        fail("plugin manifest name must match marketplace entry name")
    require_string(manifest, "displayName", PLUGIN_MANIFEST)
    require_string(manifest, "description", PLUGIN_MANIFEST)
    if manifest.get("repository") != "https://github.com/gateway/guardian":
        fail("plugin repository must point at the public Guardian repository")
    if manifest.get("skills") != "./skills/":
        fail("plugin manifest should load the bundled ./skills/ directory")
    if manifest.get("hooks") != "./hooks/hooks.json":
        fail("plugin manifest should load the bundled PreToolUse hook")
    author = manifest.get("author")
    if not isinstance(author, dict) or author.get("name") != "Dreaming Computers":
        fail("plugin author must be Dreaming Computers")
    keywords = manifest.get("keywords")
    if not isinstance(keywords, list) or "claude-code" not in keywords:
        fail("plugin keywords must include claude-code")
    return manifest


def parse_frontmatter(path: Path) -> dict[str, str]:
    """Extract the simple YAML-like frontmatter used by Guardian skill files."""

    lines = path.read_text().splitlines()
    if not lines or lines[0].strip() != "---":
        fail(f"skill is missing frontmatter: {path}")
    values: dict[str, str] = {}
    for line in lines[1:]:
        if line.strip() == "---":
            return values
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        values[key.strip()] = value.strip()
    fail(f"skill frontmatter is not closed: {path}")


def validate_skills() -> None:
    """Verify every bundled skill has stable Claude-compatible metadata."""

    skills_dir = PLUGIN_ROOT / "skills"
    if not skills_dir.is_dir():
        fail("plugin skills directory is missing")
    skill_files = sorted(skills_dir.glob("*/SKILL.md"))
    expected = {
        "guardian-advisory-pr",
        "guardian-check-package",
        "guardian-daily-watch",
        "guardian-package-diet",
        "guardian-project-scan",
        "guardian-repo-scout",
    }
    found = {path.parent.name for path in skill_files}
    if found != expected:
        fail(f"unexpected skill set: found={sorted(found)} expected={sorted(expected)}")
    for skill_file in skill_files:
        frontmatter = parse_frontmatter(skill_file)
        if frontmatter.get("name") != skill_file.parent.name:
            fail(f"skill name mismatch in {skill_file}")
        if not frontmatter.get("description"):
            fail(f"skill description is required in {skill_file}")


def validate_runtime_paths() -> None:
    """Check files Claude will need after the plugin is copied into cache."""

    required = [
        PLUGIN_ROOT / "scripts" / "guardian",
        PLUGIN_ROOT / "scripts" / "run_guardian_project_scan.py",
        PLUGIN_ROOT / "bin" / "guardian",
        PLUGIN_ROOT / "guardian_runtime" / "src" / "guardian" / "cli.py",
        PLUGIN_ROOT / "data" / "local_catalogs",
        PLUGIN_ROOT / "data" / "popular_packages" / "npm.json",
        PLUGIN_ROOT / "data" / "popular_packages" / "pypi.json",
        HOOKS_FILE,
        PLUGIN_ROOT / "hooks" / "preinstall_gate.py",
    ]
    for path in required:
        if not path.exists():
            fail(f"required plugin path is missing: {path}")
    for executable in [
        PLUGIN_ROOT / "scripts" / "guardian",
        PLUGIN_ROOT / "bin" / "guardian",
        PLUGIN_ROOT / "hooks" / "preinstall_gate.py",
    ]:
        if not os.access(executable, os.X_OK):
            fail(f"required executable bit is missing: {executable}")


def validate_hooks() -> None:
    """Verify the plugin hook is narrow, portable, and rooted in its installed bundle."""

    payload = load_json(HOOKS_FILE)
    entries = (payload.get("hooks") or {}).get("PreToolUse")
    if not isinstance(entries, list) or len(entries) != 1:
        fail("hooks.json must define exactly one PreToolUse entry")
    entry = entries[0]
    if entry.get("matcher") != "Bash":
        fail("Guardian PreToolUse hook must match Bash only")
    commands = entry.get("hooks")
    if not isinstance(commands, list) or len(commands) != 1:
        fail("Guardian PreToolUse entry must contain one command hook")
    command = commands[0]
    if command.get("type") != "command" or "${CLAUDE_PLUGIN_ROOT}" not in command.get("command", ""):
        fail("Guardian hook command must resolve through CLAUDE_PLUGIN_ROOT")


def validate_cache_copy_smoke() -> None:
    """Copy the plugin like an installer would and run a no-network CLI command."""

    with tempfile.TemporaryDirectory(prefix="guardian-claude-plugin.") as tmp_name:
        tmp = Path(tmp_name)
        cached_plugin = tmp / "cache" / "guardian-security-scan"
        shutil.copytree(PLUGIN_ROOT, cached_plugin)
        env = os.environ.copy()
        env["GUARDIAN_STATE_DIR"] = str(tmp / "state")
        env["GUARDIAN_SEED_CATALOG_DIR"] = str(cached_plugin / "data" / "local_catalogs")
        completed = subprocess.run(
            [str(cached_plugin / "scripts" / "guardian"), "report", "summary", "--json"],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        if completed.returncode != 0:
            fail(
                "copied plugin smoke command failed\n"
                f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
            )
        try:
            json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            fail(f"copied plugin smoke output was not JSON: {exc}")

        hook_input = json.dumps({
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "npm install @beproduct/nestjs-auth@0.1.18"},
        })
        hook = subprocess.run(
            [str(cached_plugin / "hooks" / "preinstall_gate.py")],
            env=env,
            input=hook_input,
            capture_output=True,
            text=True,
            check=False,
        )
        if hook.returncode != 0:
            fail(f"copied plugin hook failed: {hook.stderr}")
        try:
            hook_payload = json.loads(hook.stdout)
        except json.JSONDecodeError as exc:
            fail(f"copied plugin hook block output was not JSON: {exc}")
        decision = (hook_payload.get("hookSpecificOutput") or {}).get("permissionDecision")
        if decision != "deny":
            fail(f"copied plugin hook did not deny local malicious fixture: {hook_payload}")

        config_path = Path(env["GUARDIAN_STATE_DIR"]) / "config.json"
        config = json.loads(config_path.read_text())
        config["preinstall_gate_enabled"] = False
        config_path.write_text(json.dumps(config, indent=2) + "\n")
        disabled_hook = subprocess.run(
            [str(cached_plugin / "hooks" / "preinstall_gate.py")],
            env=env,
            input=hook_input,
            capture_output=True,
            text=True,
            check=False,
        )
        if disabled_hook.returncode != 0 or disabled_hook.stdout.strip():
            fail(f"disabled copied plugin hook did not bypass cleanly: {disabled_hook.stdout} {disabled_hook.stderr}")


def main() -> int:
    entry = validate_marketplace()
    validate_plugin_manifest(entry)
    validate_skills()
    validate_runtime_paths()
    validate_hooks()
    validate_cache_copy_smoke()
    print("Claude plugin packaging validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
