"""Package removal stops the exact owned writer before changing its files."""
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest


PACKAGE = Path(__file__).resolve().parents[1]
SERVICE = PACKAGE.name
ROUTE = 'lucky' if SERVICE == 'os-lucky' else 'ddnsgo'
HOOK = PACKAGE / 'packaging/freebsd/+PRE_DEINSTALL'


class PreDeinstallTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix=ROUTE + '-pre-deinstall-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.trace = self.root / 'trace'
        service = self.root / 'service'
        service.write_text(
            '#!/bin/sh\n'
            'printf "service:%s\\n" "$*" >> "$TRACE"\n'
            'if [ "$1 $2" = "' + SERVICE + ' onestop" ] && [ "$FAIL_STOP" = "yes" ]; then exit 7; fi\n'
            'exit 0\n')
        service.chmod(0o755)
        mirror = self.root / 'mirror'
        mirror.write_text('#!/bin/sh\nprintf "mirror:%s\\n" "$*" >> "$TRACE"\nexit 0\n')
        mirror.chmod(0o755)
        source = HOOK.read_text()
        native = '/usr/local/bin/python3 /usr/local/opnsense/scripts/' + ROUTE + '/config_mirror.py'
        self.assertEqual(1, source.count(native))
        source = source.replace(native, shlex.quote(str(mirror)))
        self.candidate = self.root / 'hook'
        self.candidate.write_text(source)
        self.environment = {
            **os.environ,
            'PATH': str(self.root) + ':' + os.environ['PATH'],
            'TRACE': str(self.trace),
            'FAIL_STOP': 'no',
        }

    def execute(self, fail=False):
        return subprocess.run(
            ['sh', str(self.candidate)],
            env={**self.environment, 'FAIL_STOP': 'yes' if fail else 'no'},
            capture_output=True, text=True, timeout=5)

    def events(self):
        return self.trace.read_text().splitlines() if self.trace.exists() else []

    def test_exact_stop_failure_aborts_before_mirror_or_package_removal(self):
        result = self.execute(fail=True)
        self.assertNotEqual(0, result.returncode)
        self.assertIn('refusing unsafe removal', result.stderr)
        self.assertEqual(['service:' + SERVICE + ' onestop'], self.events())

    def test_already_absent_service_is_idempotent_and_backup_still_runs(self):
        result = self.execute()
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual([
            'service:' + SERVICE + ' onestop',
            'mirror:mirror',
            'service:' + SERVICE + '-backup onestop',
        ], self.events())


if __name__ == '__main__':
    unittest.main()
