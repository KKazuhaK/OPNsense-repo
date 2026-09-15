"""Run real service scripts with isolated command stubs and no live services."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

REPOSITORY = Path(__file__).resolve().parents[3]


class RcBackupWiringTests(unittest.TestCase):
    def test_post_install_reconciles_runtime_even_when_saved_settings_are_disabled(self):
        hook = (REPOSITORY / 'src/os-staticarp/packaging/freebsd/+POST_INSTALL').read_text()
        self.assertEqual(hook.count('/usr/local/sbin/staticarpctl apply'), 1)
        self.assertNotIn("grep -q '^enabled=YES$'", hook)
        self.assertIn('Unable to apply the saved ARP bindings', hook)

    def test_staticarp_status_does_not_create_configuration_or_update_the_backup(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = REPOSITORY / 'src/os-staticarp/src/usr/local/sbin/staticarpctl'
            candidate = root / 'staticarpctl'
            configuration = root / 'configuration'
            candidate.write_text(source.read_text().replace('CONFIG_DIR="/usr/local/etc/staticarp"',
                                                           f'CONFIG_DIR="{configuration}"', 1))
            result = subprocess.run(['sh', str(candidate), 'status'], capture_output=True)
            self.assertEqual(result.returncode, 0)
            self.assertIn(b'enabled=NO', result.stdout)
            self.assertFalse(configuration.exists())

    def test_restart_stops_writers_before_import_and_reloads_restored_rc_values(self):
        # Reuse each service's real-controller fixture instead of maintaining
        # a second shell kill stub that can diverge from process ownership.
        for package in ('os-lucky', 'os-ddns-go'):
            with self.subTest(package=package):
                source = REPOSITORY / 'src' / package / 'tests/test_rc_service.py'
                spec = importlib.util.spec_from_file_location('cross_rc_' + package.replace('-', '_'), source)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                case = module.ServiceLifecycleTests('test_restart_stops_writers_before_import_and_obeys_restored_enable_choice')
                result = unittest.TestResult()
                case.run(result)
                self.assertTrue(result.wasSuccessful(), str(result.errors + result.failures))


@unittest.skipUnless(sys.platform.startswith('freebsd'), 'Requires the genuine native OPNsense PHP includes')
class NativeStaticarpWiringTests(unittest.TestCase):
    def test_native_settings_mirror_only_after_writes_and_report_backup_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            configuration = root / 'configuration'
            source = REPOSITORY / 'src/os-staticarp/src/usr/local/opnsense/scripts/staticarp/settings.php'
            script = source.read_text()
            original = "const STATICARP_CONFIG_DIR = '/usr/local/etc/staticarp';"
            self.assertEqual(script.count(original), 1)
            candidate = root / 'settings.php'
            script = script.replace(original, f"const STATICARP_CONFIG_DIR = '{configuration}';", 1)
            script = script.replace("const STATICARP_LOCK_FILE = '/var/db/os-staticarp-backup/settings.lock';",
                                    f"const STATICARP_LOCK_FILE = '{root / 'settings.lock'}';", 1)
            candidate.write_text(script)
            mirror = root / 'config_mirror.py'
            mirror.write_text('''import json,os,sys
from pathlib import Path
root=Path(__file__).parent
configuration=root/'configuration'
names=['settings.conf','entries.conf','interfaces.conf']
captured={name:(configuration/name).read_text() for name in names}
with (root/'calls').open('a') as output: output.write(json.dumps(captured)+'\\n')
sys.exit(1 if os.environ.get('TEST_BACKUP_FAILURE') else 0)
''')
            payload = root / 'payload.json'
            payload.write_text(json.dumps({'enabled': False, 'entries': '192.0.2.10 aa:bb:cc:dd:ee:ff', 'modes': {}}))
            result = subprocess.run(['/usr/local/bin/php', str(candidate), 'set', str(payload)], capture_output=True)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(json.loads(result.stdout)['status'], 'ok')
            captured = [json.loads(line) for line in (root / 'calls').read_text().splitlines()]
            self.assertEqual(len(captured), 1)
            self.assertEqual(captured[0]['settings.conf'], 'enabled=NO\n')
            self.assertIn('192.0.2.10 aa:bb:cc:dd:ee:ff', captured[0]['entries.conf'])
            self.assertTrue(captured[0]['interfaces.conf'])
            environment = {**os.environ, 'TEST_BACKUP_FAILURE': '1'}
            result = subprocess.run(['/usr/local/bin/php', str(candidate), 'set', str(payload)], env=environment,
                                    capture_output=True)
            answer = json.loads(result.stdout)
            self.assertEqual(answer['status'], 'failed')
            self.assertTrue(answer['saved'])
            self.assertEqual(len((root / 'calls').read_text().splitlines()), 2)
            payload.write_text(json.dumps({'enabled': True, 'entries': '', 'modes': {}}))
            result = subprocess.run(['/usr/local/bin/php', str(candidate), 'set', str(payload)], capture_output=True)
            self.assertEqual(json.loads(result.stdout)['status'], 'failed')
            self.assertEqual(len((root / 'calls').read_text().splitlines()), 2)


if __name__ == '__main__':
    unittest.main()
