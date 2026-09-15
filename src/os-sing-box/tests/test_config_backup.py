"""Restore private Sing-box state through the native-backup file contract."""
import base64
import copy
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

PACKAGE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PACKAGE.parent / 'common'))
from config_backup import ConfigBackup, revision_token, BackupError

spec = importlib.util.spec_from_file_location('singbox_config_mirror', PACKAGE / 'src/usr/local/opnsense/scripts/singbox/config_mirror.py')
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)


class SingBoxBackupTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.environment = patch.dict(os.environ, {'OS_SINGBOX_BACKUP_ROOT': str(self.root)})
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.stored = {}
        self.backup = ConfigBackup(driver.PROFILE, transport=self.transport)
        self.configuration = {
            'outbounds': [
                {'tag': 'proxy', 'type': 'trojan', 'password': 'SENTINEL_PROXY_PASSWORD',
                 'tls': {'certificate_path': '/mnt/certs/chain.pem', 'key_path': '/mnt/certs/key.pem',
                         'ech': {'key_path': '/mnt/certs/ech.key'}}},
                {'tag': 'ssh', 'type': 'ssh', 'private_key': 'SENTINEL_INLINE_KEY',
                 'private_key_path': '/mnt/keys/ssh.pem'},
            ],
            'certificate': {'certificate_path': ['/mnt/certs/trust.pem', '/etc/ssl/cert.pem'],
                            'certificate_directory_path': ['/mnt/trust', '/usr/share/certs']},
            'route': {'rule_set': [
                {'type': 'local', 'tag': ['a', 'b'], 'path': '/mnt/rules/{tag}.srs'},
                {'type': 'remote', 'url': 'https://example.invalid/SENTINEL_REMOTE_URL',
                 'initial_path': '/mnt/rules/initial.srs'},
            ]},
            'dns': {'servers': [{'type': 'hosts', 'path': ['/mnt/custom.hosts', '/etc/hosts']}]},
            'certificate_providers': [{'type': 'acme', 'data_directory': '/mnt/acme'}],
        }
        self.put(driver.CONFIG, json.dumps(self.configuration).encode())
        self.put(driver.STATE + '/integration.json', json.dumps({'schema': 1, 'transparent': True,
            'transparent_consent': True, 'device_mode': 'blacklist', 'device_list': ['192.168.9.103/32'],
            'future_policy': {'preserve': 'SENTINEL_FUTURE_FIELD'}}).encode())
        self.put(driver.STATE + '/sub/env', b"# Retain unrelated variables.\nexport SING_BOX_URL='https://example.invalid/SENTINEL_SUBSCRIPTION'\nexport EXTRA='value'\n")
        self.put(driver.STATE + '/sub/template.json', b'{"tls":{"certificate_path":"/mnt/certs/template.pem"}}\n')
        self.put(driver.RC, b'# Preserve disabled service and custom config.\nsing_box_enable="NO"\nconfig="/mnt/configuration/service.json"\n', 0o644)
        self.put('/mnt/configuration/service.json', b'{"outbounds":[{"tls":{"client_key_path":"/mnt/certs/client.pem"}}]}\n')
        for path in ['/mnt/certs/chain.pem', '/mnt/certs/key.pem', '/mnt/certs/ech.key',
                     '/mnt/certs/client.pem', '/mnt/certs/trust.pem', '/mnt/certs/template.pem',
                     '/mnt/keys/ssh.pem', '/mnt/rules/a.srs', '/mnt/rules/b.srs',
                     '/mnt/rules/initial.srs', '/mnt/custom.hosts', '/mnt/trust/extra.pem',
                     '/mnt/acme/account.json']:
            self.put(path, b'SENTINEL_PRIVATE_FILE\x00\xff\n', 0o400)
        self.put(driver.STATE + '/.mvc-key', b'SENTINEL_EDITOR_KEY')
        self.put(driver.STATE + '/debug.log', b'SENTINEL_LOG')
        self.put(driver.STATE + '/cache.db', b'SENTINEL_CACHE')
        self.put(driver.STATE + '/config.json.sample', b'SENTINEL_SAMPLE')
        self.put(driver.STATE + '/sub/sub.sh', b'#!/bin/sh\n# SENTINEL_PREVIOUS_WRAPPER\n', 0o755)

    def transport(self, action, payload=None):
        if action == 'import':
            return copy.deepcopy(self.stored)
        payload = copy.deepcopy(payload)
        if payload.pop('_expected') != revision_token(self.stored):
            raise BackupError('The native configuration changed before its backup was saved.')
        changed = self.stored != payload
        self.stored = copy.deepcopy(payload)
        return {'changed': changed}

    def put(self, path, data, mode=0o600):
        target = self.root / path.lstrip('/')
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if target.exists():
            target.chmod(0o600)
        target.write_bytes(data)
        target.chmod(mode)
        return target

    def snapshot(self):
        answer = self.backup.mirror()
        self.assertTrue(answer['ok'], answer)
        return self.backup._decode(self.stored)

    def rewrite_archive(self, transform):
        document = json.loads(gzip.decompress(base64.b64decode(self.stored['archive'])))
        transform(document)
        compressed = gzip.compress(json.dumps(document).encode(), mtime=0)
        self.stored['archive'] = base64.b64encode(compressed).decode()
        self.stored['checksum'] = hashlib.sha256(compressed).hexdigest()

    def live_state(self, files):
        return {path: ((self.root / path.lstrip('/')).read_bytes(),
                       (self.root / path.lstrip('/')).stat().st_mode & 0o777)
                for path in files if (self.root / path.lstrip('/')).exists()}

    def test_roundtrip_preserves_credentials_rc_templates_references_and_modes(self):
        roots, entries, files = self.snapshot()
        wanted = self.live_state(files)
        self.assertIn(driver.STATE + '/integration.json', files)
        self.assertIn('/mnt/configuration/service.json', files)
        self.assertIn('/mnt/certs/client.pem', files)
        self.assertIn('/mnt/certs/template.pem', files)
        self.assertIn('/mnt/rules/a.srs', files)
        self.assertIn('/mnt/rules/b.srs', files)
        self.assertIn('/mnt/acme/account.json', files)
        self.assertIn('/mnt/trust/extra.pem', files)
        self.assertNotIn('/etc/hosts', files)
        self.assertFalse(any(path.startswith('/etc/ssl') for path, kind in roots))
        for name in ['.mvc-key', 'debug.log', 'cache.db', 'config.json.sample']:
            self.assertNotIn(driver.STATE + '/' + name, entries)
        for path in files:
            self.put(path, b'SENTINEL_STALE_DISK', 0o644)
        stale = self.put(driver.STATE + '/obsolete/config.json', b'SENTINEL_OBSOLETE')
        answer = self.backup.restore()
        self.assertTrue(answer['ok'], answer)
        self.assertTrue(answer['changed'])
        self.assertEqual(wanted, self.live_state(files))
        self.assertFalse(stale.exists())
        self.assertIn(b'sing_box_enable="NO"', (self.root / driver.RC.lstrip('/')).read_bytes())
        self.assertEqual(b'SENTINEL_CACHE', (self.root / (driver.STATE + '/cache.db').lstrip('/')).read_bytes())
        self.assertFalse(self.backup.mirror()['changed'])

    def test_snapshot_absence_removes_new_settings_and_rc_without_seeding(self):
        for path in [driver.STATE + '/sub/env', driver.STATE + '/sub/template.json', driver.RC]:
            (self.root / path.lstrip('/')).unlink()
        self.snapshot()
        for path in [driver.STATE + '/sub/env', driver.STATE + '/sub/template.json', driver.RC]:
            self.put(path, b'SENTINEL_STALE_AFTER_RESTORE')
        result = self.backup.restore()
        self.assertTrue(result['ok'], result)
        self.assertTrue(result['snapshot'])
        for path in [driver.STATE + '/sub/env', driver.STATE + '/sub/template.json', driver.RC]:
            self.assertFalse((self.root / path.lstrip('/')).exists(), path)

    def test_restore_preserves_incoming_package_wrapper_instead_of_archived_software(self):
        roots, entries, files = self.snapshot()
        wrapper = driver.STATE + '/sub/sub.sh'
        self.assertNotIn(wrapper, entries)
        incoming = b'#!/bin/sh\n# SENTINEL_INCOMING_SAFE_WRAPPER\n'
        target = self.put(wrapper, incoming, 0o755)
        self.put(driver.CONFIG, b'{"outbounds":[]}\n')
        result = self.backup.restore()
        self.assertTrue(result['ok'], result)
        self.assertEqual(incoming, target.read_bytes())
        self.assertEqual(0o755, target.stat().st_mode & 0o777)
        self.assertEqual(self.configuration, json.loads((self.root / driver.CONFIG.lstrip('/')).read_bytes()))

    def test_absent_xml_section_leaves_existing_settings_unchanged(self):
        before = (self.root / driver.CONFIG.lstrip('/')).read_bytes()
        result = self.backup.restore()
        self.assertTrue(result['ok'], result)
        self.assertFalse(result['snapshot'])
        self.assertEqual(before, (self.root / driver.CONFIG.lstrip('/')).read_bytes())

    def test_corrupt_checksum_rejected_before_any_write(self):
        roots, entries, files = self.snapshot()
        before = self.live_state(files)
        self.stored['checksum'] = '0' * 64
        result = self.backup.restore()
        self.assertFalse(result['ok'])
        self.assertEqual(before, self.live_state(files))
        self.assertNotIn('SENTINEL_', json.dumps(result))

    def test_forged_unreferenced_path_rejected_before_any_write(self):
        roots, entries, files = self.snapshot()
        before = self.live_state(files)
        self.rewrite_archive(lambda doc: doc['entries'].append({'path': '/mnt/unreferenced-secret',
                             'kind': 'file', 'mode': 0o600, 'data': base64.b64encode(b'SENTINEL_FORGED').decode()}))
        result = self.backup.restore()
        self.assertFalse(result['ok'])
        self.assertEqual(before, self.live_state(files))
        self.assertFalse((self.root / 'mnt/unreferenced-secret').exists())

    def test_unsafe_mode_rejected_before_any_write(self):
        roots, entries, files = self.snapshot()
        before = self.live_state(files)
        self.rewrite_archive(lambda doc: doc['entries'][0].update(mode=0o4777))
        self.assertFalse(self.backup.restore()['ok'])
        self.assertEqual(before, self.live_state(files))

    def test_partial_filesystem_failure_rolls_back_current_bytes_and_modes(self):
        roots, entries, files = self.snapshot()
        changed = copy.deepcopy(self.configuration)
        changed['outbounds'][0]['password'] = 'SENTINEL_CURRENT_EDIT'
        self.put(driver.CONFIG, json.dumps(changed).encode(), 0o644)
        self.put(driver.STATE + '/sub/env', b'SENTINEL_CURRENT_ENV', 0o640)
        before = self.live_state(files)
        original_replace = os.replace
        failed = False
        def fail_once(source, destination):
            nonlocal failed
            if not failed and Path(destination) == self.root / driver.CONFIG.lstrip('/'):
                failed = True
                raise OSError('SENTINEL_PRIVATE_FILESYSTEM_DIAGNOSTIC')
            return original_replace(source, destination)
        with patch('config_backup.os.replace', side_effect=fail_once):
            result = self.backup.restore()
        self.assertFalse(result['ok'])
        self.assertTrue(failed)
        self.assertEqual(before, self.live_state(files))
        self.assertNotIn('SENTINEL_', json.dumps(result))

    def test_restored_xml_is_not_overwritten_and_disk_edits_are_not_replayed(self):
        self.snapshot()
        restored = copy.deepcopy(self.stored)
        newer = copy.deepcopy(self.configuration)
        newer['outbounds'][0]['password'] = 'SENTINEL_NEWER_PASSWORD'
        self.put(driver.CONFIG, json.dumps(newer).encode())
        self.assertTrue(self.backup.mirror()['ok'])
        self.stored = restored
        self.assertFalse(self.backup.mirror()['ok'])
        self.assertEqual(restored, self.stored)
        result = self.backup.reconcile()
        self.assertTrue(result['ok'], result)
        self.assertEqual(self.configuration, json.loads((self.root / driver.CONFIG.lstrip('/')).read_bytes()))
        self.put(driver.CONFIG, json.dumps(newer).encode())
        self.assertFalse(self.backup.reconcile()['changed'])
        self.assertEqual(newer, json.loads((self.root / driver.CONFIG.lstrip('/')).read_bytes()))

    def test_relative_reference_and_external_symlink_warn_without_replacing_snapshot(self):
        self.snapshot()
        old = copy.deepcopy(self.stored)
        broken = copy.deepcopy(self.configuration)
        broken['outbounds'][0]['tls']['key_path'] = 'relative/SENTINEL_PRIVATE_KEY'
        self.put(driver.CONFIG, json.dumps(broken).encode())
        result = self.backup.mirror()
        self.assertFalse(result['ok'])
        self.assertEqual(old, self.stored)
        self.assertNotIn('SENTINEL_', json.dumps(result))
        self.put(driver.CONFIG, json.dumps(self.configuration).encode())
        key = self.root / 'mnt/certs/key.pem'
        key.unlink()
        key.symlink_to('/etc/passwd')
        self.assertFalse(self.backup.mirror()['ok'])
        self.assertEqual(old, self.stored)

    def test_literal_dollar_and_backtick_paths_roundtrip_without_shell_expansion(self):
        configured = '/mnt/configuration/$literal`config`.json'
        key = '/mnt/keys/$literal`key`.pem'
        self.put(driver.RC, b'sing_box_enable="NO"\nconfig="/mnt/configuration/\\$literal\\`config\\`.json"\n')
        self.put(configured, json.dumps({'outbounds': [{'tls': {'key_path': key}}]}).encode())
        self.put(key, b'SENTINEL_LITERAL_PATH_KEY', 0o400)
        roots, entries, files = self.snapshot()
        self.assertIn(configured, files)
        self.assertIn(key, files)
        self.put(key, b'SENTINEL_STALE_KEY')
        self.assertTrue(self.backup.restore()['ok'])
        self.assertEqual(b'SENTINEL_LITERAL_PATH_KEY', (self.root / key.lstrip('/')).read_bytes())


if __name__ == '__main__':
    unittest.main()
