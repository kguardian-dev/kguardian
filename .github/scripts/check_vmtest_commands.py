#!/usr/bin/env python3
"""Lint workflow shell commands for expansion the runner's shell would do.

1. A vmtest `command:` must contain no shell expansion. vmtest runs it
   through a shell of its own before the VM sees it, so any `$` there ($h,
   ${h}, $(...)) is expanded on the runner, usually to "". Only workflow
   expressions (${{ ... }}) are allowed.
2. No `run:` or `command:` may interpolate user-controlled context
   (${{ inputs.* }}, ${{ github.event.* }}) directly: Actions substitutes
   it into the script text before a shell parses it. Pass it through
   `env:` (and validate it) instead.

The whole value is checked, including folded or literal block
continuation lines.
Usage: check_vmtest_commands.py <workflow.yaml>... [--context <workflow.yaml>...]
Check 1 runs on every file; check 2 on the files after --context (all of
them when --context is not given).
"""
import re
import sys

UNTRUSTED = re.compile(r"\$\{\{\s*(inputs\.|github\.event\.)")


def blocks(lines, key):
    """(line number, value text) for every `key:` and its continuation."""
    i = 0
    while i < len(lines):
        m = re.match(r"^(\s+)(?:- )?" + key + r":\s*(.*)$", lines[i])
        if not m:
            i += 1
            continue
        indent = len(m.group(1))
        value = [m.group(2)]
        j = i + 1
        while j < len(lines) and (
            lines[j].strip() == "" or len(lines[j]) - len(lines[j].lstrip()) > indent
        ):
            value.append(lines[j])
            j += 1
        yield i + 1, "\n".join(value)
        i = j


args = sys.argv[1:]
if "--context" in args:
    k = args.index("--context")
    files, context = args[:k] + args[k + 1 :], set(args[k + 1 :])
else:
    files, context = args, set(args)

bad = 0
for path in files:
    lines = open(path).read().split("\n")
    for line, value in blocks(lines, "command"):
        rest = re.sub(r"\$\{\{.*?\}\}", "", value, flags=re.S)
        if "$" in rest:
            bad = 1
            print(f"{path}:{line}: shell expansion in a vmtest command")
    for key in ("command", "run") if path in context else ():
        for line, value in blocks(lines, key):
            if UNTRUSTED.search(value):
                bad = 1
                print(f"{path}:{line}: {key} interpolates inputs/github.event; pass it via env")
sys.exit(bad)
