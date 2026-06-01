from __future__ import annotations

from pathlib import Path

from .advisory_yaml import audit_advisory_yaml_corpus
from .config import PROJECT_ROOT
from .regression_corpus import run_regression_corpus


def plugin_release_checks(source_dir: Path | None = None) -> dict:
    dependency_check = _runtime_dependency_check(PROJECT_ROOT / "pyproject.toml")
    regression = run_regression_corpus()
    parser_audit = None
    if source_dir is not None:
        parser_audit = audit_advisory_yaml_corpus(source_dir)
    checks = {
        "runtime_dependencies": dependency_check,
        "regression_corpus": {
            "status": "pass" if regression["failure_count"] == 0 else "fail",
            **regression,
        },
        "parser_audit": _parser_audit_check(parser_audit),
    }
    status = "pass" if all(item["status"] == "pass" for item in checks.values()) else "fail"
    return {"status": status, "checks": checks}


def _runtime_dependency_check(pyproject_path: Path) -> dict:
    dependencies = _declared_runtime_dependencies(pyproject_path)
    return {
        "status": "pass" if not dependencies else "fail",
        "dependency_count": len(dependencies),
        "dependencies": dependencies,
    }


def _parser_audit_check(parser_audit: dict | None) -> dict:
    if parser_audit is None:
        return {"status": "pass", "skipped": True, "reason": "source directory not available"}
    fail_count = int(parser_audit.get("missing_required_count") or 0) + int(
        parser_audit.get("fixed_version_range_match_count") or 0
    )
    has_source_problem = bool(parser_audit.get("problems")) or int(parser_audit.get("advisories_read") or 0) == 0
    return {"status": "pass" if fail_count == 0 and not has_source_problem else "fail", **parser_audit}


def _declared_runtime_dependencies(pyproject_path: Path) -> list[str]:
    inside = False
    dependencies: list[str] = []
    for line in pyproject_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped == "dependencies = [":
            inside = True
            continue
        if inside and stripped == "]":
            inside = False
            continue
        if inside and stripped.startswith('"'):
            dependencies.append(stripped.rstrip(",").strip('"'))
    return dependencies
