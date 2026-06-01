from __future__ import annotations

from pathlib import Path

from .versions import version_range_is_supported, version_satisfies_range


PARSER_VERSION = "guardian-advisory-yaml/1"


def parse_advisory_yaml(content: str) -> dict:
    """Parse the top-level YAML subset Guardian consumes from advisories."""
    data: dict[str, object] = {}
    current_list_key: str | None = None
    current_scalar_key: str | None = None
    raw_scalar_keys: set[str] = set()
    for raw_line in content.splitlines():
        if not raw_line.strip() or raw_line.strip() in {"---", "..."}:
            continue
        stripped = raw_line.strip()
        if current_list_key and stripped.startswith("- "):
            data.setdefault(current_list_key, []).append(_parse_yaml_scalar(stripped[2:].strip()))
            continue
        if current_scalar_key and raw_line.lstrip() != raw_line:
            data[current_scalar_key] = f"{data.get(current_scalar_key, '')} {stripped}"
            raw_scalar_keys.add(current_scalar_key)
            continue
        if raw_line.lstrip() != raw_line:
            continue
        if stripped.startswith("#") or ":" not in stripped:
            current_list_key = None
            current_scalar_key = None
            continue
        key, value = stripped.split(":", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            current_list_key = None
            current_scalar_key = None
            continue
        if value in {"|", ">"}:
            data[key] = ""
            current_list_key = None
            current_scalar_key = None
            continue
        if not value:
            data[key] = []
            current_list_key = key
            current_scalar_key = None
            continue
        data[key] = value
        current_list_key = None
        current_scalar_key = key if _scalar_may_continue(value) else None
        raw_scalar_keys.add(key)
    for key in raw_scalar_keys:
        data[key] = _parse_yaml_scalar(str(data.get(key) or ""))
    return data


def audit_advisory_yaml_corpus(source_dir: Path) -> dict:
    stats = {
        "source_path": str(source_dir),
        "source_exists": source_dir.exists(),
        "files_read": 0,
        "advisories_read": 0,
        "missing_required_count": 0,
        "unsupported_range_count": 0,
        "fixed_version_range_match_count": 0,
        "multiline_affected_range_count": 0,
        "multiline_title_count": 0,
        "problems": [],
    }
    if not source_dir.exists():
        stats["problems"].append({"path": str(source_dir), "kind": "source-directory-missing"})
        stats["status"] = "fail"
        return stats
    for path in sorted(source_dir.rglob("*.yml")):
        if "/.git/" in path.as_posix():
            continue
        stats["files_read"] += 1
        text = path.read_text(encoding="utf-8", errors="ignore")
        if "identifier:" not in text or "package_slug:" not in text:
            continue
        stats["advisories_read"] += 1
        lines = text.splitlines()
        if _field_has_continuation(lines, "affected_range"):
            stats["multiline_affected_range_count"] += 1
        if _field_has_continuation(lines, "title"):
            stats["multiline_title_count"] += 1
        advisory = parse_advisory_yaml(text)
        missing = [key for key in ("identifier", "package_slug", "affected_range") if not advisory.get(key)]
        if missing:
            stats["missing_required_count"] += 1
            stats["problems"].append({"path": str(path), "kind": "missing-required", "fields": missing})
            continue
        affected_range = str(advisory.get("affected_range") or "")
        if not version_range_is_supported(affected_range):
            stats["unsupported_range_count"] += 1
        for version in advisory.get("fixed_versions") or []:
            if isinstance(version, str) and version_satisfies_range(version, affected_range):
                stats["fixed_version_range_match_count"] += 1
                stats["problems"].append(
                    {
                        "path": str(path),
                        "kind": "fixed-version-matched-affected-range",
                        "version": version,
                        "affected_range": affected_range,
                    }
                )
                break
    if stats["advisories_read"] == 0:
        stats["problems"].append({"path": str(source_dir), "kind": "no-advisories-read"})
    stats["status"] = "fail" if stats["missing_required_count"] or stats["fixed_version_range_match_count"] or stats["problems"] else "pass"
    return stats


def _field_has_continuation(lines: list[str], field: str) -> bool:
    for index, line in enumerate(lines[:-1]):
        if line.startswith(f"{field}:") and lines[index + 1].startswith("  "):
            return True
    return False


def _scalar_may_continue(value: str) -> bool:
    if not value:
        return False
    quote = value[0] if value[0] in {"'", '"'} else None
    if quote:
        return not (len(value) > 1 and value.endswith(quote) and not value.endswith(f"\\{quote}"))
    return False


def _parse_yaml_scalar(value: str) -> object:
    value = _strip_yaml_comment(value).strip()
    if not value:
        return ""
    if value in {"[]", "{}"}:
        return [] if value == "[]" else {}
    if value.startswith("[") and value.endswith("]"):
        return [_parse_yaml_scalar(item.strip()) for item in value[1:-1].split(",") if item.strip()]
    if value[0:1] in {"'", '"'} and value[-1:] == value[0]:
        return value[1:-1].replace(f"\\{value[0]}", value[0]).replace("\\\\", "\\")
    lowered = value.lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    return value


def _strip_yaml_comment(value: str) -> str:
    quote: str | None = None
    escaped = False
    for index, char in enumerate(value):
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if quote:
            if char == quote:
                quote = None
            continue
        if char in {"'", '"'}:
            quote = char
            continue
        if char == "#" and (index == 0 or value[index - 1].isspace()):
            return value[:index]
    return value
