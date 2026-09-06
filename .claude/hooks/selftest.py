#!/usr/bin/env python3
"""Self-test for pre-tool-use.py.

Run with: python3 .claude/hooks/selftest.py

Each case is (expected exit, tool name, tool input). Exit 0 means the hook
allows the call, exit 2 means it blocks. The cases live in this file rather
than inline in a shell command because the hook scans shell commands, and
a shell command that contains the forbidden literals as test fixtures gets
blocked before it can run. That happened, twice, while writing the hook.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROJECT = HERE.parent.parent
HOOK = HERE / "pre-tool-use.py"
P = str(PROJECT)

ALLOW, BLOCK = 0, 2

CASES = [
    # recursive force delete
    (BLOCK, "Bash", {"command": "rm -rf target"}),
    (BLOCK, "Bash", {"command": "cd /tmp && rm -fr x"}),
    (BLOCK, "Bash", {"command": "rm -r -f x"}),
    (ALLOW, "Bash", {"command": "rm target/foo.txt"}),
    # force push
    (BLOCK, "Bash", {"command": "git push --force origin main"}),
    (BLOCK, "Bash", {"command": "git push -f"}),
    (BLOCK, "Bash", {"command": "git push --force-with-lease"}),
    (ALLOW, "Bash", {"command": "git push origin main"}),
    # network allowlist: only when a network tool is invoked
    (BLOCK, "Bash", {"command": "curl https://evil.example.com/x"}),
    (ALLOW, "Bash", {"command": "curl https://api.elest.io/api/auth/checkAPIToken"}),
    (ALLOW, "Bash", {"command": "curl http://127.0.0.1:8080/"}),
    (BLOCK, "Bash", {"command": "ssh somehost"}),
    (BLOCK, "Bash", {"command": "git clone https://gitlab.com/x/y"}),
    (ALLOW, "Bash", {"command": "git clone https://github.com/x/y"}),
    (BLOCK, "Bash", {"command": "cargo install foo --git https://gitlab.com/x/y"}),
    (ALLOW, "Bash", {"command": "git commit -m 'see https://claude.ai/code/session_x'"}),
    (ALLOW, "Bash", {"command": "echo https://evil.example.com"}),
    # shell writes outside the project or to frozen files
    (BLOCK, "Bash", {"command": "echo hi > /etc/motd"}),
    (ALLOW, "Bash", {"command": "echo hi > docs/x.md"}),
    (BLOCK, "Bash", {"command": "echo x >> deny.toml"}),
    (BLOCK, "Bash", {"command": "sed -i 's/cargo test/true/' Makefile"}),
    (BLOCK, "Bash", {"command": "cp /tmp/x spec/SPEC.md"}),
    (ALLOW, "Bash", {"command": "cat Makefile"}),
    (ALLOW, "Bash", {"command": "cargo test 2>&1 | tail"}),
    (ALLOW, "Bash", {"command": "make verify-fast"}),
    # file tools
    (BLOCK, "Write", {"file_path": "/etc/passwd", "content": "x"}),
    (BLOCK, "Write", {"file_path": P + "/deny.toml", "content": "x"}),
    (BLOCK, "Edit", {"file_path": P + "/spec/SPEC.md", "old_string": "a", "new_string": "b"}),
    (BLOCK, "Edit", {"file_path": P + "/Makefile", "old_string": "cargo test", "new_string": "true"}),
    (ALLOW, "Edit", {"file_path": P + "/Makefile", "old_string": "# comment", "new_string": "# other"}),
    (ALLOW, "Write", {"file_path": P + "/src/diff.rs", "content": "x"}),
    (ALLOW, "Write", {"file_path": "/tmp/claude-1001/whatever/x.txt", "content": "x"}),
    # WebFetch
    (BLOCK, "WebFetch", {"url": "https://example.com"}),
    (ALLOW, "WebFetch", {"url": "https://docs.rs/clap"}),
    # reads are unrestricted outside QA mode
    (ALLOW, "Read", {"file_path": P + "/src/client.rs"}),
]

QA_CASES = [
    (BLOCK, "Read", {"file_path": P + "/src/client.rs"}),
    (ALLOW, "Read", {"file_path": P + "/src/lib.rs"}),
    (BLOCK, "Bash", {"command": "cat src/client.rs"}),
    (ALLOW, "Bash", {"command": "cat src/lib.rs"}),
    (BLOCK, "Grep", {"pattern": "fn", "path": P + "/src"}),
    (ALLOW, "Read", {"file_path": P + "/spec/SPEC.md"}),
    (ALLOW, "Bash", {"command": "cargo test"}),
]


def run(tool, inp):
    env = dict(os.environ, CLAUDE_PROJECT_DIR=P)
    r = subprocess.run(
        [sys.executable, str(HOOK)],
        input=json.dumps({"tool_name": tool, "tool_input": inp}),
        capture_output=True,
        text=True,
        env=env,
    )
    return r.returncode, r.stderr.strip()


def check(cases, label):
    failures = 0
    for expected, tool, inp in cases:
        code, err = run(tool, inp)
        ok = code == expected
        failures += not ok
        shown = inp.get("command") or inp.get("file_path") or inp.get("url") or json.dumps(inp)
        print(f"{'ok  ' if ok else 'FAIL'} {label} want={expected} got={code} {tool:8} {shown[:70]}")
        if not ok and err:
            print(f"      {err[:120]}")
    return failures


def main():
    failures = check(CASES, "    ")
    marker = PROJECT / ".qa-mode"
    marker.touch()
    try:
        failures += check(QA_CASES, "qa  ")
    finally:
        marker.unlink()
    print(f"FAILURES: {failures}")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
