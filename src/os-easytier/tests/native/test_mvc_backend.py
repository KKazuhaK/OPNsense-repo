#!/usr/local/bin/python3
"""Exercise secret-safe TOML editing against the native Python runtime."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import tomllib
import unittest
from unittest.mock import patch

SOURCE = Path(os.environ.get('EASYTIER_SOURCE_ROOT', Path(__file__).resolve().parents[2])) / 'src/usr/local/opnsense/scripts/easytier/manage.py'
spec = importlib.util.spec_from_file_location('easytier_mvc', SOURCE)
manager = importlib.util.module_from_spec(spec)
spec.loader.exec_module(manager)


class SettingsTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.config = Path(self.directory.name) / 'config.toml'
        self.log = Path(self.directory.name) / 'easytier.log'
        self.input = Path(self.directory.name) / 'easytier_mvc_input'
        self.input.touch(mode=0o600)
        self.addCleanup(patch.stopall)
        patch.object(manager, 'CONFIG', self.config).start()
        patch.object(manager, 'LOG', self.log).start()
        patch.object(manager, 'REQUEST_ROOT', Path(self.directory.name)).start()
        patch.object(manager.pwd, 'getpwnam', return_value=type('Account', (), {'pw_uid': os.getuid()})()).start()
        self.original = '''hostname = "firewall"
[[peer]]
uri = "wss://alice:peer-password@example.test/path?token=peer-token"
[network_identity]
network_name = "office"
network_secret = "network-secret"
[credentials]
username = "test-user"
password = "test-password"
'''
        self.config.write_text(self.original)

    def test_get_and_round_trip_preserve_masked_credentials(self):
        result = manager.dispatch('settings')
        for secret in ['alice', 'peer-password', 'peer-token', 'network-secret', 'test-user', 'test-password']:
            self.assertNotIn(secret, json.dumps(result))
        self.input.write_text(result['config'].replace('firewall', 'renamed'))
        self.assertEqual(manager.dispatch('save', self.input)['status'], 'ok')
        saved = tomllib.loads(self.config.read_text())
        expected = tomllib.loads(self.original)
        expected['hostname'] = 'renamed'
        self.assertEqual(saved, expected)
        self.assertEqual(self.config.stat().st_mode & 0o777, 0o600)

    def test_concurrent_save_rejects_stale_credentials_after_first_write(self):
        public = manager.dispatch('settings')['config']
        current = tomllib.loads(public)
        current['network_identity']['network_secret'] = 'concurrent-updated-secret'
        first = Path(self.directory.name) / 'easytier_mvc_first'
        first.touch(mode=0o600)
        first.write_text(manager.render(current))
        self.input.write_text(public)
        staged, release, second_done = threading.Event(), threading.Event(), threading.Event()
        results = {}
        replace = manager.os.replace
        def controlled_replace(source, destination):
            if threading.current_thread().name == 'first-save':
                staged.set()
                if not release.wait(5):
                    raise RuntimeError('Save barrier timed out.')
            return replace(source, destination)
        def save(name, path):
            try:
                results[name] = manager.dispatch('save', path)
            except Exception as error:
                results[name] = error
            finally:
                if name == 'second':
                    second_done.set()
        with patch.object(manager.os, 'replace', side_effect=controlled_replace):
            first_thread = threading.Thread(target=save, args=('first', first), name='first-save')
            second_thread = threading.Thread(target=save, args=('second', self.input), name='second-save')
            first_thread.start()
            try:
                self.assertTrue(staged.wait(5))
                second_thread.start()
                time.sleep(0.1)
                self.assertFalse(second_done.is_set())
            finally:
                release.set()
                first_thread.join(5)
                if second_thread.ident is not None:
                    second_thread.join(5)
        self.assertEqual(results['first']['status'], 'ok')
        self.assertIsInstance(results['second'], ValueError)
        self.assertEqual(tomllib.loads(self.config.read_text())['network_identity']['network_secret'], 'concurrent-updated-secret')

    def test_stale_credentials_are_rejected_without_replacement(self):
        public = manager.dispatch('settings')['config']
        self.config.write_text(self.original.replace('network-secret', 'updated-network-secret'))
        current = self.config.read_text()
        self.input.write_text(public)
        with self.assertRaises(ValueError):
            manager.dispatch('save', self.input)
        self.assertEqual(self.config.read_text(), current)

    def test_relocated_secret_placeholder_is_rejected(self):
        public = tomllib.loads(manager.dispatch('settings')['config'])
        public['hostname'] = public['network_identity'].pop('network_secret')
        self.input.write_text(manager.render(public))
        with self.assertRaises(ValueError):
            manager.dispatch('save', self.input)
        self.assertEqual(self.config.read_text(), self.original)

    def test_reordered_stored_peer_credentials_are_rejected(self):
        second = '[[peer]]\nuri = "wss://bob:second-password@example.test/"\n'
        self.config.write_text(self.original.replace('[network_identity]', second + '[network_identity]'))
        public = manager.dispatch('settings')['config']
        changed = tomllib.loads(self.config.read_text())
        changed['peer'].reverse()
        self.config.write_text(manager.render(changed))
        current = self.config.read_text()
        self.input.write_text(public)
        with self.assertRaises(ValueError):
            manager.dispatch('save', self.input)
        self.assertEqual(self.config.read_text(), current)

    def test_symlink_and_nonprivate_request_files_are_rejected(self):
        target = Path(self.directory.name) / 'payload'
        target.write_text(self.original)
        self.input.unlink()
        self.input.symlink_to(target)
        with self.assertRaises(OSError):
            manager.dispatch('save', self.input)
        self.input.unlink()
        self.input.write_text(self.original)
        self.input.chmod(0o644)
        with self.assertRaises(ValueError):
            manager.dispatch('save', self.input)
        self.assertEqual(self.config.read_text(), self.original)

    def test_invalid_toml_does_not_replace_configuration(self):
        self.input.write_text('network_secret = "invalid-secret')
        with self.assertRaises(ValueError):
            manager.dispatch('save', self.input)
        self.assertEqual(self.config.read_text(), self.original)

    def test_log_tail_and_credential_redaction(self):
        self.log.write_text('\n'.join('line ' + str(x) for x in range(150)) + '\nnetwork_secret = "network-secret"\npeer wss://alice:peer-password@example.test/path?token=peer-token\n')
        result = manager.dispatch('log')['log']
        self.assertLessEqual(len(result.splitlines()), 100)
        self.assertNotIn('network-secret', result)
        self.assertNotIn('peer-password', result)
        self.assertNotIn('peer-token', result)
        self.assertIn('********', result)
        self.assertNotIn('line 0\n', result)


if __name__ == '__main__':
    unittest.main()
