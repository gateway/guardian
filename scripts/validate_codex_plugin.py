#!/usr/bin/env python3
"""Run Codex's validator while handling its documented hooks-field schema lag."""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
PLUGIN_ROOT = REPO_ROOT / "plugins" / "guardian-security-scan"
CODEX_SYSTEM = Path.home() / ".codex" / "skills" / ".system" / "plugin-creator"
VALIDATOR = CODEX_SYSTEM / "scripts" / "validate_plugin.py"
SPEC = CODEX_SYSTEM / "references" / "plugin-json-spec.md"
EXPECTED_LAG = "plugin.json field `hooks` is not accepted by plugin validation"


def run_validator(plugin_root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["python3", str(VALIDATOR), str(plugin_root)],
        capture_output=True,
        text=True,
        check=False,
    )


def main() -> int:
    manifest_path = PLUGIN_ROOT / ".codex-plugin" / "plugin.json"
    manifest = json.loads(manifest_path.read_text())
    hook_path = manifest.get("hooks")
    if hook_path != "./hooks/hooks.json" or not (PLUGIN_ROOT / hook_path).is_file():
        raise SystemExit("Codex plugin hook manifest path is missing or invalid")

    if not VALIDATOR.is_file():
        print("Codex plugin manifest checks passed (Codex system validator not found; skipped CLI validation)")
        return 0

    result = run_validator(PLUGIN_ROOT)
    if result.returncode == 0:
        print(result.stdout.strip())
        return 0

    errors = [line[2:] for line in result.stdout.splitlines() if line.startswith("- ")]
    spec_text = SPEC.read_text(encoding="utf-8") if SPEC.is_file() else ""
    if errors != [EXPECTED_LAG] or "- `hooks` (`string`): Hook config path." not in spec_text:
        print(result.stdout, end="")
        print(result.stderr, end="")
        raise SystemExit("Codex plugin validation failed outside the documented hooks-field schema lag")

    with tempfile.TemporaryDirectory(prefix="guardian-codex-validate-") as raw_tmp:
        copy_root = Path(raw_tmp) / "guardian-security-scan"
        shutil.copytree(PLUGIN_ROOT, copy_root)
        copy_manifest_path = copy_root / ".codex-plugin" / "plugin.json"
        copy_manifest = json.loads(copy_manifest_path.read_text())
        copy_manifest.pop("hooks", None)
        copy_manifest_path.write_text(json.dumps(copy_manifest, indent=2) + "\n")
        compatibility = run_validator(copy_root)
        if compatibility.returncode != 0:
            print(compatibility.stdout, end="")
            print(compatibility.stderr, end="")
            raise SystemExit("Codex compatibility validation failed after isolating documented hooks field")

    print("Codex plugin validation passed (documented hooks field accepted by CLI; bundled validator schema lags spec)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
