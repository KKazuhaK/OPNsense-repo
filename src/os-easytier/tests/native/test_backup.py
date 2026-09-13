#!/usr/local/bin/python3
"""Exercise both utility backup profiles without touching live configuration."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / 'src/common'))
from config_backup import ConfigBackup, revision_token, BackupError


def profile_for(service):
    source = ROOT / 'src' / ('os-' + service) / 'src/usr/local/opnsense/scripts' / service / 'config_mirror.py'
    spec = importlib.util.spec_from_file_location(service + '_backup_profile', source)
    driver = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(driver)
    return driver.PROFILE


class BackupCase:
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='utility-backup-')
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.profile = profile_for(self.service)
        self.addCleanup(patch.stopall)
        patch.dict(os.environ, {self.profile['root_env']: str(self.root)}).start()
        self.store = {}
        self.engine = ConfigBackup(self.profile, transport=self.transport)
        self.secret = 'private-fixture-credential'
        self.rc = self.root / 'etc/rc.conf.d' / self.service
        self.write(self.rc, (self.service + '_enable="NO"\n' + self.service + '_command="' + self.secret + '"\n').encode(), 0o600)
        if self.service == 'easytier':
            self.tree = self.root / 'usr/local/etc/easytier'
            self.tree.mkdir(parents=True)
            self.tree.chmod(0o700)
            self.write(self.tree / 'config.toml', ('[network_identity]\nnetwork_secret="' + self.secret + '"\n').encode(), 0o600)
            self.write(self.tree / 'keys/custom.key', b'custom private key\x00bytes\n', 0o640)
            self.write(self.tree / '.mvc-mask-key', b'transient masking key', 0o600)
            self.write(self.tree / 'process.lock', b'transient lock', 0o600)
        else:
            self.tree = None
            self.write(self.root / 'usr/local/etc/lighttpd_webgui/conf.d/ttyd.conf', b'# custom loopback proxy\n', 0o640)
            self.write(self.root / 'usr/local/etc/ttyd.crt', b'optional TLS certificate\n', 0o644)
            self.write(self.root / 'usr/local/etc/ttyd.key', self.secret.encode(), 0o600)

    def transport(self, action, payload=None):
        if action == 'import':
            return copy.deepcopy(self.store)
        self.assertEqual(action, 'export')
        payload = copy.deepcopy(payload)
        if payload.pop('_expected') != revision_token(self.store):
            raise BackupError('The native configuration changed before its backup was saved.')
        changed = self.store != payload
        self.store = copy.deepcopy(payload)
        return {'changed': changed}

    def write(self, path, content, mode):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        path.chmod(mode)

    def persistent_paths(self):
        paths = [self.root / path.lstrip('/') for path in self.profile['files']]
        if self.tree is not None:
            paths += [self.tree / 'config.toml', self.tree / 'keys/custom.key']
        return paths

    def snapshot(self):
        return {str(path): (path.read_bytes(), path.stat().st_mode & 0o777) if path.is_file() else None
                for path in self.persistent_paths()}

    def test_exact_round_trip_preserves_credentials_disabled_state_and_modes(self):
        original = self.snapshot()
        self.assertTrue(self.engine.mirror()['ok'])
        self.assertTrue(self.store.get('archive'))
        self.assertNotIn(self.secret, json.dumps(self.store))
        for path in self.persistent_paths():
            path.unlink()
        result = self.engine.restore()
        self.assertTrue(result['ok'])
        self.assertTrue(result['snapshot'])
        self.assertEqual(self.snapshot(), original)
        self.assertIn(b'_enable="NO"', self.rc.read_bytes())

    def test_absence_snapshot_removes_later_files(self):
        for path in self.persistent_paths():
            path.unlink()
        if self.tree is not None:
            shutil.rmtree(self.tree)
        self.assertTrue(self.engine.mirror()['ok'])
        self.write(self.rc, b'accidental defaults\n', 0o644)
        if self.tree is not None:
            self.write(self.tree / 'config.toml', b'accidental = true\n', 0o644)
        result = self.engine.restore()
        self.assertTrue(result['ok'])
        self.assertTrue(result['snapshot'])
        self.assertFalse(self.rc.exists())
        if self.tree is not None:
            self.assertFalse(self.tree.exists())

    def test_checksum_tampering_changes_no_files_and_returns_no_credentials(self):
        self.assertTrue(self.engine.mirror()['ok'])
        before = self.snapshot()
        self.store['checksum'] = '0' * 64
        result = self.engine.restore()
        self.assertFalse(result['ok'])
        self.assertEqual(self.snapshot(), before)
        self.assertNotIn(self.secret, json.dumps(result))

    def test_restore_failure_rolls_back_earlier_replacements(self):
        self.assertTrue(self.engine.mirror()['ok'])
        for path in self.persistent_paths():
            self.write(path, b'current configuration before failed restore\n', 0o600)
        before = self.snapshot()
        failed_target = self.rc if self.service == 'easytier' else self.root / 'usr/local/etc/ttyd.key'
        replace = os.replace
        failed = False
        def fail_once(source, destination, *args, **kwargs):
            nonlocal failed
            if Path(destination) == failed_target and not failed:
                failed = True
                raise OSError('fixture failure')
            return replace(source, destination, *args, **kwargs)
        with patch('config_backup.os.replace', side_effect=fail_once):
            result = self.engine.restore()
        self.assertTrue(failed)
        self.assertFalse(result['ok'])
        self.assertEqual(self.snapshot(), before)
        self.assertNotIn(self.secret, json.dumps(result))

    def test_unchanged_xml_reconcile_keeps_new_external_edits(self):
        self.assertTrue(self.engine.mirror()['ok'])
        self.write(self.rc, b'new external configuration\n', 0o600)
        result = self.engine.reconcile()
        self.assertTrue(result['ok'])
        self.assertEqual(self.rc.read_bytes(), b'new external configuration\n')
        self.assertTrue(self.engine.mirror()['ok'])
        self.write(self.rc, b'replaced later\n', 0o600)
        self.assertTrue(self.engine.restore()['ok'])
        self.assertEqual(self.rc.read_bytes(), b'new external configuration\n')

    def test_transport_failure_does_not_modify_live_files(self):
        before = self.snapshot()
        def failed_transport(action, payload=None):
            raise OSError('fixture secret: ' + self.secret)
        result = ConfigBackup(self.profile, transport=failed_transport).mirror()
        self.assertFalse(result['ok'])
        self.assertEqual(self.snapshot(), before)
        self.assertNotIn(self.secret, json.dumps(result))


class EasyTierBackupTest(BackupCase, unittest.TestCase):
    service = 'easytier'

    def test_transient_files_are_not_restored(self):
        self.assertTrue(self.engine.mirror()['ok'])
        shutil.rmtree(self.tree)
        self.assertTrue(self.engine.restore()['ok'])
        self.assertTrue((self.tree / 'config.toml').is_file())
        self.assertFalse((self.tree / '.mvc-mask-key').exists())
        self.assertFalse((self.tree / 'process.lock').exists())


class TtydBackupTest(BackupCase, unittest.TestCase):
    service = 'ttyd'


if __name__ == '__main__':
    unittest.main()
