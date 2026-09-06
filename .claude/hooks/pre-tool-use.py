#!/usr/bin/env python3
"""PreToolUse guardrail for elestioctl.

Why this is a hook and not a line in a prompt
---------------------------------------------
A system prompt is a request. The model reads it, weighs it against
everything else in context, and usually complies. Usually. Under pressure
(a failing check, a long session, an instruction that seems to conflict)
the model can rationalise its way past a request, and nothing stops it.

A hook is an enforcement point. It runs outside the model, before the tool
executes, on every call, with no context and no judgement. It cannot be
argued with, it does not get tired, and its behaviour is the same on the
first call and the thousandth. The rules below exist because each one
protects something that a persuasive-sounding reason could otherwise
override: the verification harness, the spec, the working tree, the
network boundary.

Honest limits: this is not a sandbox. It blocks the common shapes of each
forbidden action (the ones an agent actually reaches for), not every
possible encoding of them. `python3 -c "open(...).write(...)"` would get
past the write check. The point is to make the forbidden thing an
unmistakable, deliberate act rather than a reflex.

Protocol: Claude Code pipes a JSON object on stdin with `tool_name` and
`tool_input`. Exit 0 allows the call. Exit 2 blocks it and feeds stderr
back to the model as the reason.
"""

import json
import os
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

PROJECT = Path(os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()).resolve()

# Where writes are allowed: the project, the session scratchpad, and the
# per-project memory directory Claude Code keeps outside the repo.
WRITE_ROOTS = [
    PROJECT,
    Path("/tmp/claude-1001"),
    Path.home() / ".claude" / "projects",
]

# Files the model must never edit. `Makefile` is handled separately because
# only its verify targets are protected.
FROZEN = {"deny.toml", "spec/SPEC.md"}

# Hosts a shell command or WebFetch may contact. Everything else is blocked.
ALLOWED_HOSTS = {
    "crates.io",
    "static.crates.io",
    "index.crates.io",
    "github.com",
    "api.github.com",
    "codeload.github.com",
    "raw.githubusercontent.com",
    "objects.githubusercontent.com",
    "static.rust-lang.org",
    "docs.rs",
    "doc.rust-lang.org",
    "api.elest.io",
    "localhost",
    "127.0.0.1",
    "::1",
}

RM_RF = re.compile(r"(^|[\s;&|])rm\s+(-[a-zA-Z]*[rR][a-zA-Z]*[fF]|-[a-zA-Z]*[fF][a-zA-Z]*[rR]|-[rR]\s+-[fF]|-[fF]\s+-[rR])\b")
FORCE_PUSH = re.compile(r"git\s+push\b[^\n;&|]*\s(--force\b|--force-with-lease\b|-f\b)")
URL = re.compile(r"(?:https?|ssh|git|ftp)://[^\s'\"<>]+")
NET_TOOL = re.compile(r"(^|[\s;&|])(curl|wget|nc|ncat|telnet|ssh|scp|sftp|rsync|pip3?|npm|npx)\s+")
GIT_NET = re.compile(r"\bgit\s+(clone|fetch|pull|push|ls-remote|remote\s+add|submodule)\b")
CARGO_GIT = re.compile(r"\bcargo\s+(install|add)\b[^\n;&|]*--git\b")
QA_MARKER = PROJECT / ".qa-mode"


def block(reason: str) -> None:
    sys.stderr.write(f"BLOCKED by .claude/hooks/pre-tool-use.py: {reason}\n")
    sys.exit(2)


def inside_write_roots(path: Path) -> bool:
    try:
        resolved = path.resolve()
    except OSError:
        resolved = path
    return any(resolved == root or root in resolved.parents for root in WRITE_ROOTS)


def relative_to_project(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(PROJECT))
    except ValueError:
        return str(path)


def check_host(raw_url: str) -> None:
    host = (urlparse(raw_url).hostname or "").lower()
    if host and host not in ALLOWED_HOSTS:
        block(f"network call to '{host}' is not on the allowlist ({', '.join(sorted(ALLOWED_HOSTS))})")


def check_bash(command: str) -> None:
    if RM_RF.search(command):
        block("'rm -rf' is never allowed; delete specific files by name")
    if FORCE_PUSH.search(command):
        block("'git push --force' is never allowed")

    # Host checks apply only when the command can actually open a
    # connection. A URL inside a commit message or an echo is text, not a
    # network call; the first version of this hook blocked a commit whose
    # message contained a URL, which is a false positive, not enforcement.
    if NET_TOOL.search(command) or GIT_NET.search(command) or CARGO_GIT.search(command):
        urls = URL.findall(command)
        for url in urls:
            check_host(url)
        if NET_TOOL.search(command) and not urls:
            # A bare host with no scheme cannot be parsed reliably, so
            # require the explicit URL form.
            block("network tools must be given an explicit URL on the allowlist so the host can be checked")

    # Writes through the shell: redirections, tee, cp/mv/install destinations,
    # sed -i, and touch/mkdir. Best effort, by design (see module docstring).
    targets = []
    targets += re.findall(r"(?:^|[^<])>{1,2}\s*([^\s;&|]+)", command)
    targets += re.findall(r"\btee\s+(?:-a\s+)?([^\s;&|]+)", command)
    targets += re.findall(r"\bsed\s+-i[^\s]*\s+(?:-e\s+)?(?:'[^']*'|\"[^\"]*\"|[^\s]+)\s+([^\s;&|]+)", command)
    for m in re.finditer(r"\b(?:cp|mv|install)\s+(?:-[a-zA-Z]+\s+)*(?:[^\s;&|]+\s+)+([^\s;&|]+)", command):
        targets.append(m.group(1))
    targets += re.findall(r"\b(?:touch|mkdir)\s+(?:-[a-zA-Z]+\s+)*([^\s;&|]+)", command)
    for t in targets:
        t = t.strip("'\"")
        if t in ("/dev/null", "/dev/stderr", "/dev/stdout") or t.startswith("&"):
            continue
        p = Path(os.path.expanduser(t))
        if not p.is_absolute():
            p = PROJECT / p
        if not inside_write_roots(p):
            block(f"shell write to '{t}' is outside the project directory")
        check_frozen(p, command)

    if QA_MARKER.exists():
        for m in re.finditer(r"src/[A-Za-z0-9_/]+\.rs", command):
            if m.group(0) != "src/lib.rs":
                block(f"QA mode: reading '{m.group(0)}' is forbidden; QA sees only spec/SPEC.md, docs/API.md and src/lib.rs")


def check_frozen(path: Path, content_hint: str) -> None:
    rel = relative_to_project(path)
    if rel in FROZEN:
        block(f"'{rel}' is frozen; changing it means changing the contract, which is the user's call")
    if rel == "Makefile" and re.search(r"verify|cargo|clippy|fmt|test|audit|deny|mutants", content_hint):
        block("the verify targets in 'Makefile' are frozen; do not weaken a check to make it pass")


def check_file_tool(tool: str, inp: dict) -> None:
    raw = inp.get("file_path") or inp.get("notebook_path") or ""
    if not raw:
        return
    path = Path(os.path.expanduser(raw))
    if not path.is_absolute():
        path = PROJECT / path
    if not inside_write_roots(path):
        block(f"write to '{raw}' is outside the project directory")
    hint = " ".join(str(inp.get(k, "")) for k in ("old_string", "new_string", "content", "edits"))
    check_frozen(path, hint)


def check_read(inp: dict) -> None:
    if not QA_MARKER.exists():
        return
    raw = inp.get("file_path") or inp.get("path") or inp.get("pattern") or ""
    rel = relative_to_project(Path(os.path.expanduser(raw))) if raw else ""
    if rel.startswith("src/") and rel != "src/lib.rs":
        block(f"QA mode: reading '{rel}' is forbidden; QA sees only spec/SPEC.md, docs/API.md and src/lib.rs")
    if not raw or raw.startswith(str(PROJECT / "src")) or raw in ("src", "src/"):
        if rel in ("src", ""):
            block("QA mode: listing or searching src/ is forbidden")


def main() -> None:
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError:
        # Malformed input: fail closed. An unparseable call is not a known-safe call.
        block("could not parse hook input")
    tool = payload.get("tool_name", "")
    inp = payload.get("tool_input", {}) or {}

    if tool == "Bash":
        check_bash(inp.get("command", ""))
    elif tool in ("Edit", "Write", "MultiEdit", "NotebookEdit"):
        check_file_tool(tool, inp)
    elif tool in ("WebFetch",):
        check_host(inp.get("url", ""))
    elif tool in ("Read", "Grep", "Glob"):
        check_read(inp)
    sys.exit(0)


if __name__ == "__main__":
    main()
