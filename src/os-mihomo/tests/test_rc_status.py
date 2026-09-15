"""Hold the rc.d status command to the rc.subr running/not-running contract."""
import os
import re
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

RC = Path(__file__).resolve().parents[1] / 'src/usr/local/etc/rc.d/mihomo'
FUNCTION = re.compile(r'(mihomo_status\(\)\n\{.*?\n\})', re.S)


class RcStatusTests(unittest.TestCase):
    """The manager keeps its GUI-visible JSON contract; rc(8) gets an exit code."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='mihomo-rc-status-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        match = FUNCTION.search(RC.read_text())
        self.assertIsNotNone(match, 'mihomo_status is missing from the rc script')
        stub = self.root / 'python3-stub'
        stub.write_text('#!/bin/sh\nprintf \'%s\\n\' "$STUB_OUTPUT"\nexit "${STUB_EXIT:-0}"\n')
        stub.chmod(0o755)
        body = match.group(1)
        # Only the manager call is replaced; JSON parsing keeps a real interpreter.
        body = body.replace('/usr/local/bin/python3 "$control" --json status',
                            shlex.quote(str(stub)) + ' "$control" --json status')
        body = body.replace("printf '%s' \"$output\" | /usr/local/bin/python3 -c",
                            "printf '%s' \"$output\" | " + shlex.quote(sys.executable) + ' -c')
        script = self.root / 'status.sh'
        script.write_text('#!/bin/sh\ncontrol=/nonexistent\n' + body + '\nmihomo_status\n')
        script.chmod(0o755)
        self.script = script

    def status(self, output, code=0):
        return subprocess.run([str(self.script)], capture_output=True, text=True, timeout=10,
                              env=dict(os.environ, STUB_OUTPUT=output, STUB_EXIT=str(code)))

    def test_running_manager_reports_success_and_keeps_the_json(self):
        result = self.status('{"ok": true, "result": {"running": true}}')
        self.assertEqual(result.returncode, 0)
        self.assertIn('"running": true', result.stdout)

    def test_stopped_manager_reports_failure_and_keeps_the_json(self):
        result = self.status('{"ok": true, "result": {"running": false}}')
        self.assertEqual(result.returncode, 1)
        self.assertIn('"running": false', result.stdout)

    def test_json_spacing_and_key_order_are_not_the_contract(self):
        result = self.status('{"result":{"running":true},"ok":true}')
        self.assertEqual(result.returncode, 0)

    def test_manager_failure_propagates_without_running_the_parser(self):
        result = self.status(
            '{"ok": false, "error": "Mihomo state changes require root privileges."}', code=1)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, '')

    def test_unparsable_output_is_not_running(self):
        result = self.status('not json')
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, 'not json\n')


if __name__ == '__main__':
    unittest.main()
