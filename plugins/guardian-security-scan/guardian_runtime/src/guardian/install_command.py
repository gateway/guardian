"""Parse dependency additions from shell commands without executing project code."""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass

from .util import parse_npm_spec


SHELL_SEPARATORS = {"&&", "||", ";", "|", "\n"}
VALUE_FLAGS = {
    "--abi", "--cache", "--config", "--constraint", "--cwd", "--directory",
    "--extra-index-url", "--implementation", "--index", "--index-url", "--package-lock",
    "--platform", "--prefix", "--project", "--python", "--registry", "--root",
    "--save-prefix", "--source", "--src", "--target", "--timeout", "--upgrade-strategy",
    "--user-agent", "--userconfig", "--workspace", "-C", "-c", "-i", "-w",
}
SKIP_PREFIXES = (".", "/", "file:", "git+", "git://", "github:", "http://", "https://", "ssh:")


@dataclass(frozen=True)
class InstallRequest:
    """One package request extracted from an install command."""

    ecosystem: str
    name: str | None
    version: str | None
    original_spec: str
    opaque_reason: str | None = None


def extract_install_requests(command: str) -> list[InstallRequest]:
    """Return package additions from supported npm and Python install syntaxes."""

    try:
        lexer = shlex.shlex(command.replace("\n", " ; "), posix=True, punctuation_chars=";&|")
        lexer.whitespace_split = True
        lexer.commenters = ""
        tokens = list(lexer)
    except ValueError:
        return [InstallRequest("unknown", None, None, command, "shell command could not be parsed safely")]
    requests: list[InstallRequest] = []
    for segment in _segments(tokens):
        requests.extend(_parse_segment(segment))
    return requests


def _segments(tokens: list[str]) -> list[list[str]]:
    segments: list[list[str]] = []
    current: list[str] = []
    for token in tokens:
        if token in SHELL_SEPARATORS:
            if current:
                segments.append(current)
                current = []
        else:
            current.append(token)
    if current:
        segments.append(current)
    return segments


def _parse_segment(tokens: list[str]) -> list[InstallRequest]:
    tokens = _strip_prefixes(tokens)
    if not tokens:
        return []
    command = tokens[0].rsplit("/", 1)[-1]
    args = tokens[1:]
    ecosystem: str | None = None
    specs: list[str] = []

    if command in {"npm", "pnpm"} and args and args[0] in {"add", "i", "install"}:
        ecosystem, specs = "npm", args[1:]
    elif command == "yarn" and args and args[0] == "add":
        ecosystem, specs = "npm", args[1:]
    elif command in {"pip", "pip3"} and args and args[0] == "install":
        ecosystem, specs = "pypi", args[1:]
    elif command in {"python", "python3"} and len(args) >= 3 and args[:3] == ["-m", "pip", "install"]:
        ecosystem, specs = "pypi", args[3:]
    elif command == "uv" and args:
        if args[0] == "add":
            ecosystem, specs = "pypi", args[1:]
        elif len(args) >= 2 and args[:2] == ["pip", "install"]:
            ecosystem, specs = "pypi", args[2:]
    elif command == "poetry" and args and args[0] == "add":
        ecosystem, specs = "pypi", args[1:]
    if ecosystem is None:
        return []
    return [_parse_spec(ecosystem, spec) for spec in _package_specs(specs)]


def _strip_prefixes(tokens: list[str]) -> list[str]:
    index = 0
    while index < len(tokens):
        if tokens[index] in {"command", "env", "sudo"}:
            index += 1
            continue
        if "=" in tokens[index] and not tokens[index].startswith(("@", "=")):
            key = tokens[index].split("=", 1)[0]
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
                index += 1
                continue
        break
    return tokens[index:]


def _package_specs(tokens: list[str]) -> list[str]:
    specs: list[str] = []
    skip_next = False
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if skip_next:
            skip_next = False
            index += 1
            continue
        if token in {"-r", "--requirement"}:
            skip_next = True
            index += 1
            continue
        if token in VALUE_FLAGS:
            skip_next = True
            index += 1
            continue
        if token.startswith("-"):
            index += 1
            continue
        if index + 2 < len(tokens) and tokens[index + 1] == "@":
            specs.append(f"{token} @ {tokens[index + 2]}")
            index += 3
            continue
        specs.append(token)
        index += 1
    return specs


def _parse_spec(ecosystem: str, spec: str) -> InstallRequest:
    if spec.startswith(SKIP_PREFIXES) or " @ " in spec or spec.startswith(("git@", "npm:")):
        return InstallRequest(ecosystem, None, None, spec, "direct URL, VCS, alias, or local-path dependency")
    if ecosystem == "npm":
        name, version = parse_npm_spec(spec)
        if version and version.startswith(("git", "http", "file", "npm:")):
            return InstallRequest(ecosystem, name, None, spec, "npm alias or non-registry dependency")
        return InstallRequest(ecosystem, name, version, spec)

    clean = spec.split(";", 1)[0].strip()
    match = re.match(r"^([A-Za-z0-9_.-]+)(?:\[[^]]+\])?(.*)$", clean)
    if not match:
        return InstallRequest(ecosystem, None, None, spec, "non-registry Python dependency")
    name = match.group(1)
    constraint = match.group(2).strip()
    version = constraint[2:].strip() if constraint.startswith("==") else None
    return InstallRequest(ecosystem, name, version, spec)
