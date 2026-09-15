#!/usr/local/bin/python3
"""Additional real kernel checks; run only inside an explicitly designated VNET jail."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'src/usr/local/opnsense/scripts/staticarp/runtime.py'
spec = importlib.util.spec_from_file_location('staticarp_runtime', SCRIPT)
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)
NATIVE = (sys.platform.startswith('freebsd') and os.geteuid() == 0 and
          os.environ.get('STATICARP_NATIVE_FIXTURE') == '1')
if NATIVE:
    NATIVE = subprocess.run(['/sbin/sysctl', '-n', 'security.jail.jailed'], capture_output=True,
                            text=True, check=True).stdout.strip() == '1'


@unittest.skipUnless(NATIVE, 'Requires root in a designated native VNET jail; this is additional coverage')
class NativeOwnedArpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.system = runtime.System()
        cls.device = cls.system.run('/sbin/ifconfig', 'epair', 'create').strip()
        try:
            cls.system.run('/sbin/ifconfig', cls.device, 'inet', '198.19.241.254/24', 'up')
            cls.system.run('/sbin/ifconfig', cls.device[:-1] + 'b', 'up')
        except Exception:
            cls.system.run('/sbin/ifconfig', cls.device, 'destroy')
            raise

    @classmethod
    def tearDownClass(cls):
        cls.system.run('/sbin/ifconfig', cls.device, 'destroy')

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='native-owned-arp-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.config = self.root / 'config'
        self.config.mkdir()
        self.journal = self.root / 'state/runtime.json'
        self.key = self.device + '|198.19.241.10'
        self.foreign_key = self.device + '|198.19.241.20'
        self.foreign = {'mac': '02:11:22:33:44:aa', 'permanent': True, 'published': False}
        self.system.mutate_binding(self.key, self.foreign)
        self.system.mutate_binding(self.foreign_key, self.foreign)
        self.system.run('/sbin/ifconfig', self.device, '-arp', '-staticarp')
        self.before = self.system.neighbors()
        self.before_mode = self.system.mode(self.device)
        self.save_settings()
        self.addCleanup(self.restore)

    def restore(self):
        if self.journal.exists():
            runtime.Runtime(config_dir=self.config, state_file=self.journal).apply(reset=True)
        self.system.run('/sbin/ifconfig', self.device, 'arp', '-staticarp')
        for key in (self.key, self.foreign_key):
            if self.system.binding(key) is not None:
                self.system.mutate_binding(key, None)

    def save_settings(self, enabled=True, entries='198.19.241.10 02:11:22:33:44:bb\n', mode='staticarp'):
        (self.config / 'settings.conf').write_text('enabled=' + ('YES' if enabled else 'NO') + '\n')
        (self.config / 'entries.conf').write_text(entries)
        (self.config / 'interfaces.conf').write_text('lan ' + self.device + ' ' + mode + '\n')

    def engine(self, system=None):
        return runtime.Runtime(system=system, config_dir=self.config, state_file=self.journal)

    def test_reset_restores_original_static_binding_and_mode_and_preserves_all_other_neighbors(self):
        self.engine().apply()
        self.assertEqual(self.system.binding(self.key)['mac'], '02:11:22:33:44:bb')
        self.assertEqual(self.system.mode(self.device), {'noarp': False, 'staticarp': True})
        self.engine().apply(reset=True)
        self.assertEqual(self.system.neighbors(), self.before)
        self.assertEqual(self.system.mode(self.device), self.before_mode)
        self.assertEqual(self.journal.stat().st_mode & 0o777, 0o600)

    def test_removed_binding_deletes_only_its_explicit_interface_and_never_the_unrelated_static_neighbor(self):
        new_key = self.device + '|198.19.241.11'
        self.save_settings(entries='198.19.241.11 02:11:22:33:44:cc\n')
        self.engine().apply()
        self.assertIsNotNone(self.system.binding(new_key))
        self.save_settings(entries='')
        self.engine().apply()
        self.assertIsNone(self.system.binding(new_key))
        self.assertEqual(self.system.binding(self.foreign_key), self.foreign)
        self.engine().apply(reset=True)
        self.assertEqual(self.system.neighbors(), self.before)

    def test_later_native_admin_binding_and_mode_are_preserved(self):
        self.engine().apply()
        edited = {**self.foreign, 'mac': '02:11:22:33:44:dd'}
        self.system.mutate_binding(self.key, edited)
        self.system.run('/sbin/ifconfig', self.device, 'arp', '-staticarp')
        with self.assertRaises(runtime.RuntimeErrorWithRecovery):
            self.engine().apply()
        self.engine().apply(reset=True)
        self.assertEqual(self.system.binding(self.key), edited)
        self.assertEqual(self.system.mode(self.device), {'noarp': False, 'staticarp': False})
        self.assertEqual(self.system.binding(self.foreign_key), self.foreign)

    def test_disabled_first_apply_and_reset_do_not_modify_native_state(self):
        self.save_settings(enabled=False)
        self.engine().apply()
        self.engine().apply(reset=True)
        self.assertEqual(self.system.neighbors(), self.before)
        self.assertEqual(self.system.mode(self.device), self.before_mode)
        self.assertFalse(self.journal.exists())

    def test_crash_before_journal_commit_recovers_from_the_actual_native_target(self):
        engine = self.engine()
        save = engine.save
        def fail_commit():
            if any('pending' not in row and row['after'] != row['before']
                   for row in engine.state['bindings'].values()):
                raise OSError('Simulated crash after kernel update')
            save()
        engine.save = fail_commit
        with self.assertRaises(OSError):
            engine.apply()
        durable = json.loads(self.journal.read_text())
        self.assertIn('pending', durable['bindings'][self.key])
        self.assertEqual(self.system.binding(self.key)['mac'], '02:11:22:33:44:bb')
        self.engine().apply(reset=True)
        self.assertEqual(self.system.neighbors(), self.before)
        self.assertEqual(self.system.mode(self.device), self.before_mode)


if __name__ == '__main__':
    unittest.main(verbosity=2)
