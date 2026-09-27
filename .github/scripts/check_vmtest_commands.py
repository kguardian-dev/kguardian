#!/usr/bin/env python3
"""Fail if a vmtest `command:` in a workflow contains shell expansion.

vmtest runs `command` through a shell of its own before the VM sees it, so
any `$` there ($h, ${h}, $(...)) is expanded on the runner, usually to "".
Only workflow expressions (${{ ... }}) are allowed. The whole value is
checked, including folded or literal block continuation lines.
Usage: check_vmtest_commands.py <workflow.yaml>...
"""
import re
import sys

bad = 0
for path in sys.argv[1:]:
    lines = open(path).read().split("\n")
    i = 0
    while i < len(lines):
        m = re.match(r"^(\s+)command:\s*(.*)$", lines[i])
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
        rest = re.sub(r"\$\{\{.*?\}\}", "", "\n".join(value), flags=re.S)
        if "$" in rest:
            bad = 1
            print(f"{path}:{i + 1}: shell expansion in a vmtest command")
        i = j
sys.exit(bad)
