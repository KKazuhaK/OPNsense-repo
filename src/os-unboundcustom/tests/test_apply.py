"""Execute the shipped apply transaction using isolated files and harmless commands."""
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest

PACKAGE = Path(__file__).resolve().parents[1]
APPLY = PACKAGE / 'src/opnsense/scripts/OPNsense/Unboundcustom/apply.sh'


class ApplyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='unboundcustom-apply-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.fragment = self.root / 'fragment.conf'
        self.runtime = self.root / 'runtime.conf'
        self.lock = self.root / 'apply.lock'
        self.events = self.root / 'events.jsonl'
        self.unbound = self.root / 'unbound'
        self.unbound.mkdir()
        self.original = b'# old generated fragment\r\nserver:\n verbosity: 1\n'
        self.old_runtime = b'# old runtime fragment\r\nserver:\n verbosity: 2\n'
        self.generated = '# new generated fragment\nserver:\n verbosity: 3\n'
        self.fragment.write_bytes(self.original)
        self.runtime.write_bytes(self.old_runtime)
        self.fragment.chmod(0o600)
        self.runtime.chmod(0o640)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        stub = '''#!PYTHON
import json,os,shutil,sys
from pathlib import Path
command=Path(sys.argv[0]).name
if command=='json-result':
 print(json.dumps(dict(zip(('status','code','detail'),sys.argv[-3:]))));sys.exit(0)
with Path(os.environ['TEST_EVENTS']).open('a') as output:
 output.write(json.dumps([command,*sys.argv[1:]])+'\\n')
failure=os.environ.get('TEST_FAIL','')
if command=='configctl':
 action='template' if sys.argv[1]=='template' else 'restart'
 if action=='template': Path(os.environ['TEST_FRAGMENT']).write_text(os.environ['TEST_GENERATED'])
 if failure==action: print('isolated '+action+' failure',file=sys.stderr);sys.exit(1)
elif command=='install':
 if failure=='stage': print('isolated stage failure',file=sys.stderr);sys.exit(1)
 shutil.copyfile(sys.argv[-2],sys.argv[-1]);Path(sys.argv[-1]).chmod(0o640)
elif command=='checkconf':
 if failure=='validation': print('isolated syntax failure',file=sys.stderr);sys.exit(1)
elif command=='copy':
 if failure=='backup': print('isolated backup failure',file=sys.stderr);sys.exit(1)
 shutil.copy2(sys.argv[-2],sys.argv[-1])
'''.replace('PYTHON', sys.executable)
        for name in ['configctl', 'install', 'checkconf', 'copy', 'json-result']:
            (self.bin / name).write_text(stub)
            (self.bin / name).chmod(0o755)
        source = APPLY.read_text()
        replacements = {
            '/usr/local/etc/unbound.opnsense.d/custom-options.conf': str(self.fragment),
            '/var/unbound/etc/custom-options.conf': str(self.runtime),
            '/tmp/unboundcustom.apply.lock': str(self.lock),
            '/tmp/unboundcustom-template.log': str(self.root / 'template.log'),
            '/usr/local/sbin/configctl': str(self.bin / 'configctl'),
            '/usr/local/sbin/unbound-checkconf': str(self.bin / 'checkconf'),
            '/usr/bin/install': str(self.bin / 'install'),
            '/var/unbound': str(self.unbound),
        }
        for before, after in replacements.items():
            source = source.replace(before, after)
        source = source.replace('cp -p ', shlex.quote(str(self.bin / 'copy')) + ' -p ')
        php = shutil.which('php')
        source = source.replace('/usr/local/bin/php', shlex.quote(php or str(self.bin / 'json-result')))
        self.script = self.root / 'apply.sh'
        self.script.write_text(source)

    def run_apply(self, failure=''):
        result = subprocess.run(['sh', str(self.script)], capture_output=True, text=True,
            env={**os.environ, 'TEST_FAIL': failure, 'TEST_EVENTS': str(self.events),
                 'TEST_FRAGMENT': str(self.fragment), 'TEST_GENERATED': self.generated})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, '')
        return json.loads(result.stdout)

    def operations(self):
        return [json.loads(line) for line in self.events.read_text().splitlines()] if self.events.exists() else []

    def assert_originals(self):
        self.assertEqual(self.fragment.read_bytes(), self.original)
        self.assertEqual(self.runtime.read_bytes(), self.old_runtime)
        self.assertEqual(self.fragment.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.runtime.stat().st_mode & 0o777, 0o640)
        self.assertFalse(self.lock.exists())

    def test_success_stages_and_validates_before_restart_then_retires_backups(self):
        self.assertEqual(self.run_apply(), {'status': 'ok', 'code': 'success', 'detail': ''})
        operations = self.operations()
        self.assertEqual([row[0] for row in operations], ['copy', 'copy', 'configctl', 'install', 'checkconf', 'configctl'])
        self.assertEqual(operations[2][1:], ['template', 'reload', 'OPNsense/Unboundcustom'])
        self.assertEqual(operations[-1][1:], ['unbound', 'restart'])
        self.assertEqual(self.fragment.read_text(), self.generated)
        self.assertEqual(self.runtime.read_text(), self.generated)
        self.assertEqual(self.runtime.stat().st_mode & 0o777, 0o640)
        self.assertFalse(self.lock.exists())
        self.assertFalse(Path(str(self.fragment) + '.unboundcustom-backup').exists())
        self.assertFalse(Path(str(self.runtime) + '.unboundcustom-backup').exists())

    def test_template_stage_and_validation_failures_restore_both_exact_copies(self):
        for failure, code in [('template', 'template_failed'), ('stage', 'stage_failed'), ('validation', 'validation_failed')]:
            with self.subTest(failure=failure):
                self.events.unlink(missing_ok=True)
                report = self.run_apply(failure)
                self.assertEqual(report['status'], 'failed')
                self.assertEqual(report['code'], code)
                self.assertTrue(report['detail'])
                self.assert_originals()
                self.assertNotIn(['configctl', 'unbound', 'restart'], self.operations())

    def test_restart_failure_retains_previous_fragments_and_permissions(self):
        report = self.run_apply('restart')
        self.assertEqual(report['code'], 'restart_failed')
        self.assert_originals()

    def test_failure_restores_absence_without_manufacturing_old_files(self):
        self.fragment.unlink()
        self.runtime.unlink()
        report = self.run_apply('validation')
        self.assertEqual(report['code'], 'validation_failed')
        self.assertFalse(self.fragment.exists())
        self.assertFalse(self.runtime.exists())
        self.assertFalse(self.lock.exists())

    def test_busy_apply_does_not_touch_fragments_or_run_commands(self):
        self.lock.mkdir()
        report = self.run_apply()
        self.assertEqual(report['code'], 'busy')
        self.assertEqual(self.operations(), [])
        self.assertEqual(self.fragment.read_bytes(), self.original)
        self.assertEqual(self.runtime.read_bytes(), self.old_runtime)
        self.assertTrue(self.lock.exists())

    def test_backup_failure_aborts_before_generation_without_losing_live_files(self):
        report = self.run_apply('backup')
        self.assertEqual(report['code'], 'backup_failed')
        self.assert_originals()
        self.assertNotIn(['configctl', 'template', 'reload', 'OPNsense/Unboundcustom'], self.operations())


if __name__ == '__main__':
    unittest.main()
