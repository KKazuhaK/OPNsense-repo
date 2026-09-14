"""Exercise this package's complete backup profile with isolated XML transport."""
import copy
import hashlib
import importlib.util
import json
import os
import shutil
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

PACKAGE = Path(__file__).parents[1]
ROUTE = 'lucky' if PACKAGE.name == 'os-lucky' else 'ddnsgo'
sys.path.insert(0, str(PACKAGE.parent / 'common'))
from config_backup import BackupError, ConfigBackup

spec = importlib.util.spec_from_file_location(ROUTE + '_profile_contract', PACKAGE / 'src/usr/local/opnsense/scripts' / ROUTE / 'config_mirror.py')
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)
PROFILE = driver.PROFILE


class XmlTransport:
    def __init__(self):
        self.fields = {}
        self.saves = 0

    def __call__(self, action, payload=None):
        if action == 'import':
            return copy.deepcopy(self.fields)
        if action != 'export':
            raise AssertionError('Unexpected native transport action.')
        payload = copy.deepcopy(payload)
        expected = hashlib.sha256(json.dumps(self.fields, sort_keys=True, ensure_ascii=True, separators=(',', ':')).encode()).hexdigest()
        if payload.pop('_expected') != expected:
            raise BackupError('The native configuration changed before its backup was saved.')
        changed = payload != self.fields
        if changed:
            self.fields = payload
            self.saves += 1
        return {'changed': changed}


class BackupProfileTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix=ROUTE + '-profile-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        mapping = patch.dict(os.environ, {PROFILE['root_env']: str(self.root)})
        mapping.start()
        self.addCleanup(mapping.stop)
        self.xml = XmlTransport()
        self.backup = ConfigBackup(PROFILE, transport=self.xml)
        self.rc_name = '/etc/rc.conf.d/' + ROUTE
        self.custom = '/usr/local/etc/' + ROUTE + ' $literal `literal` custom'
        if ROUTE == 'lucky':
            self.rc = f'lucky_enable="NO"\nlucky_conf_dir=\'{self.custom}\'\nlucky_http_port="16602"\n'.encode()
            self.seed = {self.rc_name: (self.rc, 0o600), self.custom + '/lucky.conf': (b'{"password":"PRIVATE_PROFILE_CREDENTIAL","enabled":false}\r\n', 0o600),
                         self.custom + '/TLS/server.key': (b'PRIVATE_PROFILE_TLS_KEY\x00\xff', 0o600), self.custom + '/nested/unknown.bin': (bytes(range(256)), 0o640)}
        else:
            self.rc = f'ddnsgo_enable="NO"\nddnsgo_config=\'{self.custom}/config.yaml\'\nddnsgo_listen=":9877"\nddnsgo_interval="123"\nddnsgo_extra_args="-n"\n'.encode()
            self.seed = {self.rc_name: (self.rc, 0o600), self.custom + '/config.yaml': (b'dns:\r\n  token: PRIVATE_PROFILE_CREDENTIAL\r\n  userid: 987654321\r\n', 0o600),
                         '/usr/local/etc/ddns-go/nested/unknown.bin': (bytes(range(256)), 0o640), '/usr/local/etc/ddns-go/config.yaml': (b'dns: {token: PRIVATE_DEFAULT_CREDENTIAL}\n', 0o600)}

    def path(self, name):
        return self.root / name.lstrip('/')

    def put(self, name, content, mode=0o600):
        path = self.path(name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        path.chmod(mode)
        return path

    def test_custom_literal_rc_path_disabled_service_all_bytes_modes_and_transient_exclusions(self):
        for name, (content, mode) in self.seed.items():
            self.put(name, content, mode)
        for name in ['runtime.log', 'runtime.pid', 'runtime.lock', '.mvc-pending', '.' + ROUTE + '-pending']:
            self.put(self.custom + '/' + name, b'transient must not enter XML')
        mirrored = self.backup.mirror()
        self.assertTrue(mirrored['ok'])
        self.assertTrue(mirrored['changed'])
        fields = copy.deepcopy(self.xml.fields)
        saves = self.xml.saves
        self.assertTrue(self.backup.mirror()['ok'])
        self.assertEqual(self.xml.fields, fields)
        self.assertEqual(self.xml.saves, saves)
        for name in self.seed:
            self.path(name).unlink()
        restored = self.backup.restore()
        self.assertTrue(restored['ok'])
        self.assertTrue(restored['snapshot'])
        for name, (content, mode) in self.seed.items():
            self.assertEqual(self.path(name).read_bytes(), content)
            self.assertEqual(self.path(name).stat().st_mode & 0o777, mode)
        self.assertIn(b'_enable="NO"', self.path(self.rc_name).read_bytes())
        self.assertEqual(self.backup._decode(fields)[1].keys() & {self.custom + '/runtime.log', self.custom + '/runtime.pid', self.custom + '/runtime.lock'}, set())

    def test_missing_snapshot_preserves_files_and_explicit_absence_clears_only_owned_defaults(self):
        default = '/usr/local/etc/lucky/lucky.conf' if ROUTE == 'lucky' else '/usr/local/etc/ddns-go/config.yaml'
        self.put(self.rc_name, b'existing RC bytes', 0o640)
        self.put(default, b'existing credential bytes', 0o600)
        absent = self.backup.restore()
        self.assertEqual(absent, {'ok': True, 'changed': False, 'snapshot': False})
        self.assertEqual(self.path(self.rc_name).read_bytes(), b'existing RC bytes')
        self.assertEqual(self.path(self.rc_name).stat().st_mode & 0o777, 0o640)
        self.assertEqual(self.path(default).read_bytes(), b'existing credential bytes')
        self.path(self.rc_name).unlink()
        shutil.rmtree(self.path(default).parent)
        self.assertTrue(self.backup.mirror()['ok'])
        self.put(self.rc_name, b'new configuration')
        self.put(default, b'new configuration')
        unrelated = self.put('/usr/local/etc/unrelated/keep.conf', b'UNRELATED_BYTES')
        restored = self.backup.restore()
        self.assertTrue(restored['ok'])
        self.assertTrue(restored['snapshot'])
        self.assertFalse(self.path(self.rc_name).exists())
        self.assertFalse(self.path(default).exists())
        self.assertEqual(unrelated.read_bytes(), b'UNRELATED_BYTES')

    def test_tamper_failure_never_mutates_live_credentials_modes_or_rc(self):
        for name, (content, mode) in self.seed.items():
            self.put(name, content, mode)
        self.assertTrue(self.backup.mirror()['ok'])
        self.xml.fields['checksum'] = '0' * 64
        failed = self.backup.restore()
        self.assertFalse(failed['ok'])
        self.assertNotIn('PRIVATE_', json.dumps(failed))
        for name, (content, mode) in self.seed.items():
            self.assertEqual(self.path(name).read_bytes(), content)
            self.assertEqual(self.path(name).stat().st_mode & 0o777, mode)

    def test_protected_or_expanding_rc_roots_fail_without_export(self):
        variable = 'lucky_conf_dir' if ROUTE == 'lucky' else 'ddnsgo_config'
        for value in ['/conf/config.xml', '/root/.ssh/id_rsa', '/usr/local/opnsense', '//usr/local/etc/app', '/usr/local/etc/../outside', '$(touch PRIVATE_SENTINEL)']:
            with self.subTest(path=value):
                self.put(self.rc_name, (variable + '="' + value + '"\n').encode())
                result = self.backup.mirror()
                self.assertFalse(result['ok'])
                self.assertNotIn('PRIVATE_SENTINEL', json.dumps(result))
                self.assertEqual(self.xml.fields, {})
                self.assertEqual(self.xml.saves, 0)


if __name__ == '__main__':
    unittest.main()
