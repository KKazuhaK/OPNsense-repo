"""Execute the install hook with genuine mirror policy and private PHP transport."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

PACKAGE = Path(__file__).resolve().parents[1]


class InstallBackupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='speedtest-install-backup-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = self.root / 'stored.json'
        self.store.write_text('{}')
        self.events = self.root / 'events'
        self.env = dict(os.environ, PATH=str(self.root / 'bin') + os.pathsep + os.environ['PATH'],
                        TEST_EVENTS=str(self.events), TEST_STORE=str(self.store), OS_SPEEDTEST_ROOT=str(self.root))
        for command in ['service', 'configctl', 'chmod']:
            self.executable('bin/' + command, 'raise SystemExit(0)\n')
        self.executable('bin/pkg', 'print("FreeBSD:15:amd64")\n')
        self.executable('usr/local/bin/php', '''import hashlib,json,os,sys
from pathlib import Path
verb=sys.argv[-1]
with Path(os.environ['TEST_EVENTS']).open('a') as out:out.write(verb+'\\n')
store=Path(os.environ['TEST_STORE'])
fields=json.loads(store.read_text())
if verb=='import':
    if os.environ.get('TEST_IMPORT_FAIL'):sys.exit(1)
    print(json.dumps(fields))
else:
    payload=json.load(sys.stdin)
    expected=payload.pop('_expected')
    assert expected==hashlib.sha256(json.dumps(fields,ensure_ascii=True,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    if os.environ.get('TEST_EXPORT_FAIL'):sys.exit(1)
    fields.update(payload)
    store.write_text(json.dumps(fields))
    print('{"changed":true}')
''')
        python = self.root / 'usr/local/bin/python3'
        python.symlink_to(sys.executable)
        script = PACKAGE / 'src/usr/local/opnsense/scripts/speedtest/config_mirror.py'
        # Policy paths use OS_SPEEDTEST_ROOT; only the PHP executable is mapped.
        self.write('usr/local/opnsense/scripts/speedtest/config_mirror.py',
                   script.read_text().replace("PHP = '/usr/local/bin/php'", "PHP = " + repr(str(self.root / 'usr/local/bin/php'))))
        self.settings = self.write('var/db/speedtest/settings.json', json.dumps({'interface': 'wan', 'server_id': '16781', 'threads': '8'}))
        source = (PACKAGE / 'packaging/freebsd/+POST_INSTALL').read_text()
        self.hook = re.sub(r'/(?:usr/local|var)/', lambda m: str(self.root) + m.group(), source)

    def write(self, name, source):
        target = self.root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(source)
        target.chmod(0o600)
        return target

    def executable(self, name, source):
        self.write(name, '#!' + sys.executable + '\n' + source).chmod(0o755)

    def run_hook(self, **environment):
        return subprocess.run(['sh', '-c', self.hook], env=dict(self.env, **environment),
                              capture_output=True, text=True, timeout=15)

    def test_legacy_settings_without_xml_are_enrolled_immediately(self):
        result = self.run_hook()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(self.store.read_text()), json.loads(self.settings.read_text()))
        self.assertIn('export', self.events.read_text().splitlines())

    def test_failed_import_retains_xml_and_never_runs_mirror(self):
        self.store.write_text('{"threads":"12","future_scalar":"retain"}')
        before = self.store.read_bytes()
        result = self.run_hook(TEST_IMPORT_FAIL='1')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('saved backup was retained', result.stderr)
        self.assertNotIn('export', self.events.read_text().splitlines())
        self.assertEqual(self.store.read_bytes(), before)

    def test_export_failure_warns_without_failing_install_or_losing_settings(self):
        before = self.settings.read_bytes()
        result = self.run_hook(TEST_EXPORT_FAIL='1')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('could not be mirrored', result.stderr)
        self.assertEqual(self.settings.read_bytes(), before)
        self.assertEqual(json.loads(self.store.read_text()), {})
