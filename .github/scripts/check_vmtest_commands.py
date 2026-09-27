#!/usr/bin/env python3
"""Lint workflow shell commands for expansion the runner's shell would do.

1. A vmtest `command:` must contain no shell expansion. vmtest runs it
   through a shell of its own before the VM sees it, so any `$` there ($h,
   ${h}, $(...)) is expanded on the runner, usually to "". Only workflow
   expressions (${{ ... }}) are allowed.
2. No `run:` or `command:` may contain an expression that reads
   user-controlled context: `inputs.*`, `github.event*` or
   `github.head_ref`, anywhere in the expression (so `format(...)`,
   `toJSON(...)` and the like count too). Actions substitutes it into the
   script text before a shell parses it. Pass it through `env:` (and
   validate it) instead.

The whole value is checked, including folded or literal block
continuation lines.
Usage: check_vmtest_commands.py <workflow.yaml>... [--context <workflow.yaml>...]
Check 1 runs on every file; check 2 on the files after --context (all of
them when --context is not given). No files, or an empty --context, is an
error (exit 2).
"""
import re
import sys

EXPRESSION = re.compile(r"\$\{\{(.*?)\}\}", re.S)
UNTRUSTED = re.compile(r"\binputs\.|\bgithub\.event\b|\bgithub\.head_ref\b")


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


def findings(path, text, context):
    """Every problem in one workflow's text, as "path:line: message"."""
    out = []
    lines = text.split("\n")
    for line, value in blocks(lines, "command"):
        if "$" in EXPRESSION.sub("", value):
            out.append(f"{path}:{line}: shell expansion in a vmtest command")
    if context:
        for key in ("command", "run"):
            for line, value in blocks(lines, key):
                if any(UNTRUSTED.search(e) for e in EXPRESSION.findall(value)):
                    out.append(
                        f"{path}:{line}: {key} interpolates user-controlled context "
                        "(inputs, github.event, github.head_ref); pass it via env"
                    )
    return out


def main(args):
    if "--context" in args:
        k = args.index("--context")
        files, context = args[:k] + args[k + 1 :], args[k + 1 :]
        if not context:
            print("--context needs at least one workflow file", file=sys.stderr)
            return 2
    else:
        files, context = args, args
    if not files:
        print("usage: check_vmtest_commands.py <workflow.yaml>... [--context <file>...]",
              file=sys.stderr)
        return 2
    bad = []
    for path in files:
        with open(path) as f:
            bad += findings(path, f.read(), path in context)
    for b in bad:
        print(b)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
