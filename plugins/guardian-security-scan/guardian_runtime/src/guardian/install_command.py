"""Parse dependency additions from shell commands without executing project code."""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass

from .util import parse_npm_spec


SHELL_SEPARATORS = {"&&", "||", ";", "|", "\n"}
SHELL_COMMANDS = {"bash", "dash", "sh", "zsh"}
MAX_SHELL_RECURSION = 3
VALUE_FLAGS = {
    "--abi", "--cache", "--config", "--constraint", "--cwd", "--directory",
    "--extra-index-url", "--implementation", "--index", "--index-url",
    "--platform", "--prefix", "--project", "--python", "--registry", "--root",
    "--save-prefix", "--source", "--src", "--target", "--timeout", "--upgrade-strategy",
    "--user-agent", "--userconfig", "--workspace", "-C", "-c", "-i", "-t", "-w",
}
BOOLEAN_FLAGS_BY_MANAGER = {
    "npm": {"--package-lock"},
    "pnpm": {"-w", "--workspace-root"},
}
VALUE_FLAGS_BY_MANAGER = {
    "bun": {"--filter"},
    "pnpm": {"--filter"},
    "poetry": {"--group", "-G"},
}
REMOTE_PREFIXES = ("git+", "git://", "github:", "http://", "https://", "ssh:")


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

    return _extract_install_requests(command, depth=0)


def _extract_install_requests(command: str, *, depth: int) -> list[InstallRequest]:
    """Parse one command string while bounding nested shell wrappers."""

    try:
        lexer = shlex.shlex(command.replace("\n", " ; "), posix=True, punctuation_chars=";&|")
        lexer.whitespace_split = True
        lexer.commenters = ""
        tokens = list(lexer)
    except ValueError:
        return [InstallRequest("unknown", None, None, command, "shell command could not be parsed safely")]
    requests: list[InstallRequest] = []
    for segment in _segments(tokens):
        requests.extend(_parse_segment(segment, depth=depth))
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


def _parse_segment(tokens: list[str], *, depth: int) -> list[InstallRequest]:
    tokens = _strip_prefixes(tokens)
    if not tokens:
        return []
    command = tokens[0].rsplit("/", 1)[-1]
    args = tokens[1:]
    shell_command = _shell_command_string(args) if command in SHELL_COMMANDS else None
    if shell_command is not None:
        if depth >= MAX_SHELL_RECURSION:
            return [InstallRequest(
                "unknown",
                None,
                None,
                shell_command,
                "nested shell command exceeded Guardian's safe parsing depth",
            )]
        return _extract_install_requests(shell_command, depth=depth + 1)
    ecosystem: str | None = None
    specs: list[str] = []

    if command in {"npm", "pnpm"}:
        matched = _args_after_subcommand(args, {"add", "i", "install"}, manager=command)
        if matched is not None:
            ecosystem, specs = "npm", matched
        else:
            execution_commands = {"exec"} if command == "npm" else {"dlx"}
            matched = _args_after_subcommand(args, execution_commands, manager=command)
            if matched is not None:
                ecosystem, specs = "npm", _execution_specs(matched, manager=command)
    elif command == "yarn":
        matched = _args_after_subcommand(args, {"add"}, manager=command)
        if matched is not None:
            ecosystem, specs = "npm", matched
        else:
            matched = _args_after_subcommand(args, {"dlx"}, manager=command)
            if matched is not None:
                ecosystem, specs = "npm", _execution_specs(matched, manager=command)
    elif command == "bun":
        matched = _args_after_subcommand(args, {"add", "install"}, manager=command)
        if matched is not None:
            ecosystem, specs = "npm", matched
        else:
            matched = _args_after_subcommand(args, {"x"}, manager=command)
            if matched is not None:
                ecosystem, specs = "npm", _execution_specs(matched, manager=command)
    elif command in {"pip", "pip3"} and args and args[0] == "install":
        ecosystem, specs = "pypi", args[1:]
    elif command == "pipenv":
        matched = _args_after_subcommand(args, {"install"}, manager=command)
        if matched is not None:
            ecosystem, specs = "pypi", matched
    elif re.fullmatch(r"python(?:\d+(?:\.\d+)*)?", command) and len(args) >= 3 and args[:3] == ["-m", "pip", "install"]:
        ecosystem, specs = "pypi", args[3:]
    elif command == "uv" and args:
        if args[0] == "add":
            ecosystem, specs = "pypi", args[1:]
        elif len(args) >= 2 and args[:2] == ["pip", "install"]:
            ecosystem, specs = "pypi", args[2:]
    elif command == "poetry" and args and args[0] == "add":
        ecosystem, specs = "pypi", args[1:]
    elif command in {"bunx", "npx", "pnpx"}:
        ecosystem, specs = "npm", _execution_specs(args, manager=command)
    if ecosystem is None:
        return []
    return [_parse_spec(ecosystem, spec) for spec in _package_specs(specs, manager=command)]


def _args_after_subcommand(
    args: list[str],
    subcommands: set[str],
    *,
    manager: str,
) -> list[str] | None:
    """Locate an install subcommand after valid manager options."""

    boolean_flags = BOOLEAN_FLAGS_BY_MANAGER.get(manager, set())
    value_flags = VALUE_FLAGS | VALUE_FLAGS_BY_MANAGER.get(manager, set())
    index = 0
    while index < len(args):
        token = args[index]
        if token in subcommands:
            return args[index + 1 :]
        if token in boolean_flags or (token.startswith("-") and "=" in token):
            index += 1
            continue
        if token in value_flags:
            index += 2
            continue
        if token.startswith("-"):
            index += 1
            continue
        return None
    return None


def _execution_specs(args: list[str], *, manager: str) -> list[str]:
    """Return only package selectors, excluding arguments for the executed tool."""

    explicit: list[str] = []
    index = 0
    while index < len(args):
        token = args[index]
        if token in {"-p", "--package"} and index + 1 < len(args):
            explicit.append(args[index + 1])
            index += 2
            continue
        if token.startswith("--package="):
            explicit.append(token.split("=", 1)[1])
        index += 1
    if explicit:
        return explicit
    return _package_specs(args, manager=manager)[:1]


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


def _shell_command_string(args: list[str]) -> str | None:
    """Extract the command payload from common sh/bash/zsh -c flag forms."""

    index = 0
    while index < len(args):
        token = args[index]
        if token == "--":
            return None
        if token == "-c" or (token.startswith("-") and not token.startswith("--") and "c" in token[1:]):
            return args[index + 1] if index + 1 < len(args) else None
        if token.startswith("-"):
            index += 1
            continue
        return None
    return None


def _package_specs(tokens: list[str], *, manager: str) -> list[str]:
    specs: list[str] = []
    manager_value_flags = VALUE_FLAGS_BY_MANAGER.get(manager, set())
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
        if token in BOOLEAN_FLAGS_BY_MANAGER.get(manager, set()):
            index += 1
            continue
        if token in VALUE_FLAGS or token in manager_value_flags:
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
    if ecosystem == "npm" and "@npm:" in spec:
        _alias, real_spec = spec.split("@npm:", 1)
        name, version = parse_npm_spec(real_spec)
        if name:
            return InstallRequest(ecosystem, name, version, spec)
        return InstallRequest(ecosystem, None, None, spec, "npm alias could not be resolved safely")
    if _is_local_path_spec(spec):
        return InstallRequest(ecosystem, None, None, spec, "local-path")
    if _is_remote_or_opaque_spec(spec):
        return InstallRequest(ecosystem, None, None, spec, "direct URL, VCS, or alias dependency")
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


def _is_local_path_spec(spec: str) -> bool:
    """Classify filesystem references separately from remote opaque installs."""

    if spec in {".", ".."} or spec.startswith(("./", "../", "/", "file:")):
        return True
    if " @ " in spec:
        _name, target = spec.split(" @ ", 1)
        return target.strip().startswith((".", "/", "file:"))
    return False


def _is_remote_or_opaque_spec(spec: str) -> bool:
    if spec.startswith(REMOTE_PREFIXES) or spec.startswith(("git@", "npm:")):
        return True
    if " @ " in spec:
        return True
    return False
