#!/usr/bin/env python3
"""Lint workflow shell commands for expansion the runner's shell would do.

1. A vmtest `command:` must contain no shell expansion. vmtest runs it
   through a shell of its own before the VM sees it, so any `$` there ($h,
   ${h}, $(...)) is expanded on the runner, usually to "". Only workflow
   expressions (${{ ... }}) are allowed.
2. No `run:`, vmtest `command:` or actions/github-script `script:` may
   contain an expression that reads user-controlled context: `inputs` in any
   form, or `github` itself, indexed, or with any member outside a small
   allowlist of safe ones (SAFE_GITHUB), anywhere in the expression (so
   `format(...)` and `toJSON(...)` count too), in any letter case. Actions
   substitutes it into the shell or JavaScript text before it is parsed.
   Pass it through `env:` (and validate it) instead; github-script reads it
   as `process.env.X`.
   Known limit: taint is not traced through `env.*`, so a user-controlled
   value copied into env and interpolated as `${{ env.X }}` is not caught.

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
# github members that are safe to interpolate: set by GitHub or by
# repository admins, never by whoever opens a pull request, and not secret
# (github.token is left out: pass it through env:, never into command text).
SAFE_GITHUB = (
    "workspace", "sha", "repository", "repository_owner", "repository_id", "run_id",
    "run_number", "run_attempt", "event_name", "server_url", "api_url", "graphql_url",
    "base_ref", "job", "action_path", "workflow", "ref", "ref_type", "retention_days",
)
# `inputs` in any form; `github` itself, indexed (github[...]) or with any
# member not in SAFE_GITHUB (event, head_ref, ref_name, actor, event_path,
# token, ...). Context names are case-insensitive in expressions.
UNTRUSTED = re.compile(
    r"\binputs\b|\bgithub\b(?!\s*\.\s*(?:" + "|".join(SAFE_GITHUB) + r")\b)",
    re.IGNORECASE,
)


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
        for key in ("command", "run", "script"):
            for line, value in blocks(lines, key):
                if any(UNTRUSTED.search(e) for e in EXPRESSION.findall(value)):
                    out.append(
                        f"{path}:{line}: {key} interpolates user-controlled context "
                        "(inputs, or a github member outside SAFE_GITHUB); pass it via env"
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
