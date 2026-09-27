#!/usr/bin/env python3
"""Fixtures for check_vmtest_commands.py: every rule has a bad case that
must be flagged and a good case that must pass.
Run: python3 .github/scripts/test_check_vmtest_commands.py
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import check_vmtest_commands as lint  # noqa: E402

WS = "${{ github.workspace }}"


def vmtest(cmd):
    return f"""jobs:
  j:
    steps:
      - uses: danobi/vmtest-action@x
        with:
          command: {cmd}
"""


def run_step(body, env=""):
    return f"""jobs:
  j:
    steps:
      - name: s
{env}        run: {body}
"""


def flagged(text, context=True):
    return lint.findings("wf.yaml", text, context)


class ShellExpansionInVmtestCommand(unittest.TestCase):
    def test_bad(self):
        for cmd in (
            '/bin/bash -c "for h in a; do X=$h; done"',
            '/bin/bash -c "X=${h}"',
            '/bin/bash -c "echo $(id)"',
        ):
            self.assertTrue(flagged(vmtest(cmd), context=False), cmd)

    def test_folded_continuation(self):
        text = vmtest(">-\n            /bin/bash -c \"a;\n            X=$h\"")
        self.assertTrue(flagged(text, context=False))

    def test_good(self):
        self.assertEqual(flagged(vmtest(f"/bin/bash -c \"{WS}/t --x\""), context=False), [])


class UserControlledContext(unittest.TestCase):
    def test_inputs_in_command(self):
        self.assertTrue(flagged(vmtest(f"/bin/bash {WS}/s.sh ${{{{ inputs.iterations }}}}")))

    def test_event_in_run(self):
        self.assertTrue(flagged(run_step("echo ${{ github.event.pull_request.title }}")))

    def test_head_ref_in_run(self):
        self.assertTrue(flagged(run_step("git checkout ${{ github.head_ref }}")))

    def test_inside_a_function(self):
        for expr in (
            "${{ format('v-{0}', github.event.pull_request.number) }}",
            "${{ toJSON(github.event) }}",
            "${{ format('{0}', inputs.x) }}",
        ):
            self.assertTrue(flagged(run_step(f"echo {expr}")), expr)

    def test_multiline_run(self):
        self.assertTrue(flagged(run_step("|\n          a=1\n          echo ${{ inputs.x }}")))

    def test_env_and_trusted_expressions_pass(self):
        env = "        env:\n          X: ${{ inputs.x }}\n"
        self.assertEqual(flagged(run_step('echo "$X"', env)), [])
        for expr in (
            "${{ github.workspace }}",
            "${{ steps.it.outputs.iterations }}",
            "${{ github.base_ref }}",
            "${{ secrets.T }}",
        ):
            self.assertEqual(flagged(run_step(f"echo {expr}")), [], expr)

    def test_off_without_context(self):
        self.assertEqual(flagged(run_step("echo ${{ inputs.x }}"), context=False), [])


class Arguments(unittest.TestCase):
    def test_no_files_is_an_error(self):
        self.assertEqual(lint.main([]), 2)

    def test_empty_context_is_an_error(self):
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            f.write(vmtest(f"{WS}/t"))
        try:
            self.assertEqual(lint.main([f.name, "--context"]), 2)
            self.assertEqual(lint.main([f.name]), 0)
        finally:
            os.unlink(f.name)


if __name__ == "__main__":
    unittest.main(verbosity=2)
