"""Exercise the three small-service profiles against the shared backup engine."""
import base64
import copy
import hashlib
import importlib.util
import json
import os
import re
import shutil
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

REPOSITORY = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPOSITORY / 'src/common'))
import config_backup


class XmlTransport:
    def __init__(self):
        self.fields = {}
        self.saves = 0

    def __call__(self, action, payload=None):
        if action == 'import':
            return copy.deepcopy(self.fields)
        if action != 'export':
            raise AssertionError('Unexpected transport action')
        payload = copy.deepcopy(payload)
        if payload.pop('_expected') != config_backup.revision_token(self.fields):
            raise config_backup.BackupError('The native configuration changed before its backup was saved.')
        changed = self.fields != payload
        if changed:
            self.fields = copy.deepcopy(payload)
            self.saves += 1
        return {'changed': changed}


def profile(package, route):
    path = REPOSITORY / 'src' / package / 'src/usr/local/opnsense/scripts' / route / 'config_mirror.py'
    spec = importlib.util.spec_from_file_location(route + '_backup_profile', path)
    driver = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(driver)
    return driver.PROFILE


PROFILES = [profile('os-staticarp', 'staticarp'), profile('os-lucky', 'lucky'), profile('os-ddns-go', 'ddnsgo')]


def seed(root, selected):
    module = selected['module']
    if module == 'Staticarp':
        files = {
            '/etc/rc.conf.d/staticarp': (b'staticarp_enable="NO"\n', 0o600),
            '/usr/local/etc/staticarp/settings.conf': (b'enabled=NO\n', 0o640),
            '/usr/local/etc/staticarp/entries.conf': (b'192.0.2.10 aa:bb:cc:dd:ee:ff\r\n', 0o600),
            '/usr/local/etc/staticarp/interfaces.conf': (b'lan vtnet1 -arp\n', 0o640),
            '/usr/local/etc/staticarp/nested/unknown.dat': (bytes(range(256)), 0o600),
        }
    elif module == 'Lucky':
        files = {
            '/etc/rc.conf.d/lucky': (b'lucky_enable="NO"\nlucky_conf_dir="/usr/local/etc/lucky-user"\nlucky_http_port="16602"\n', 0o600),
            '/usr/local/etc/lucky-user/lucky.conf': (b'{"password":"SENTINEL_CREDENTIAL","enabled":false}\n', 0o600),
            '/usr/local/etc/lucky-user/certificates/server.key': (b'SENTINEL_PRIVATE_KEY\x00\xff', 0o600),
            '/usr/local/etc/lucky-user/nested/unknown.dat': (bytes(range(256)), 0o640),
        }
    else:
        files = {
            '/etc/rc.conf.d/ddnsgo': (b'ddnsgo_enable="NO"\nddnsgo_config="/usr/local/etc/ddns-go-user/config.yaml"\nddnsgo_listen=":9877"\nddnsgo_interval="123"\nddnsgo_extra_args="-n"\n', 0o600),
            '/usr/local/etc/ddns-go/config.yaml': (b'dns:\n  token: SENTINEL_DEFAULT_CREDENTIAL\n', 0o600),
            '/usr/local/etc/ddns-go/nested/unknown.dat': (bytes(range(256)), 0o640),
            '/usr/local/etc/ddns-go-user/config.yaml': (b'dns:\n  token: SENTINEL_CREDENTIAL\n  userid: 987654321\n', 0o600),
        }
    for name, (data, mode) in files.items():
        path = root / name.lstrip('/')
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(mode)
    return files


def contents(root, files):
    return {name: ((root / name.lstrip('/')).read_bytes(), (root / name.lstrip('/')).stat().st_mode & 0o777)
            for name in files}


class ConfigBackupTests(unittest.TestCase):
    def test_exact_round_trip_custom_paths_modes_disabled_and_unknown_files(self):
        for selected in PROFILES:
            with self.subTest(module=selected['module']), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                original = seed(root, selected)
                transient = root / next(name for name in original if '/usr/local/etc/' in name).lstrip('/')
                transient = transient.parent / 'running.log'
                transient.write_bytes(b'SENTINEL_TRANSIENT')
                outside = root / 'var/db/unrelated/config.bin'
                outside.parent.mkdir(parents=True)
                outside.write_bytes(b'UNRELATED')
                xml = XmlTransport()
                with patch.dict(os.environ, {selected['root_env']: str(root)}):
                    engine = config_backup.ConfigBackup(selected, transport=xml)
                    self.assertTrue(engine.mirror()['ok'])
                    self.assertEqual(xml.fields['schema'], '1')
                    archive = base64.b64decode(xml.fields['archive'], validate=True)
                    self.assertEqual(xml.fields['checksum'], hashlib.sha256(archive).hexdigest())
                    self.assertNotIn('SENTINEL_CREDENTIAL', json.dumps(xml.fields))
                    self.assertFalse(engine.mirror()['changed'])
                    self.assertEqual(xml.saves, 1)
                    for name, (data, _) in original.items():
                        path = root / name.lstrip('/')
                        path.write_bytes(data.replace(b'"NO"', b'"YES"') if name.startswith('/etc/') else b'RUNTIME_EDIT')
                        path.chmod(0o644)
                    transient.unlink()
                    self.assertTrue(engine.restore()['ok'])
                    self.assertEqual(contents(root, original), original)
                    self.assertFalse(transient.exists())
                    self.assertEqual(outside.read_bytes(), b'UNRELATED')

    def test_missing_snapshot_is_safe_and_recorded_absence_is_restored(self):
        for selected in PROFILES:
            with self.subTest(module=selected['module']), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                xml = XmlTransport()
                with patch.dict(os.environ, {selected['root_env']: str(root)}):
                    engine = config_backup.ConfigBackup(selected, transport=xml)
                    missing = engine.restore()
                    self.assertTrue(missing['ok'])
                    self.assertFalse(missing['snapshot'])
                    self.assertTrue(engine.mirror()['ok'])
                    fixed_files = selected['files']
                    roots = selected['trees'] + [item['default'] for item in selected['rc_paths']]
                    for name in fixed_files:
                        path = root / name.lstrip('/')
                        path.parent.mkdir(parents=True, exist_ok=True)
                        path.write_bytes(b'CREATED_AFTER_SNAPSHOT')
                    for name in roots:
                        path = root / name.lstrip('/')
                        if any(item['default'] == name and item['kind'] == 'file' for item in selected['rc_paths']):
                            path.parent.mkdir(parents=True, exist_ok=True)
                            path.write_bytes(b'CREATED_AFTER_SNAPSHOT')
                        else:
                            path.mkdir(parents=True, exist_ok=True)
                            (path / 'config.bin').write_bytes(b'CREATED_AFTER_SNAPSHOT')
                    restored = engine.restore()
                    self.assertTrue(restored['ok'])
                    self.assertTrue(restored['snapshot'])
                    for name in fixed_files + roots:
                        self.assertFalse((root / name.lstrip('/')).exists(), name)

    def test_tampered_archive_does_not_change_live_configuration(self):
        for selected in PROFILES:
            with self.subTest(module=selected['module']), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                original = seed(root, selected)
                xml = XmlTransport()
                with patch.dict(os.environ, {selected['root_env']: str(root)}):
                    engine = config_backup.ConfigBackup(selected, transport=xml)
                    self.assertTrue(engine.mirror()['ok'])
                    xml.fields['archive'] = base64.b64encode(b'INVALID_ARCHIVE_SENTINEL_CREDENTIAL').decode()
                    result = engine.restore()
                    self.assertFalse(result['ok'])
                    self.assertNotIn('SENTINEL_CREDENTIAL', json.dumps(result))
                    self.assertEqual(contents(root, original), original)

    def test_reconcile_preserves_newer_files_and_pending_xml_cannot_be_overwritten(self):
        for selected in PROFILES:
            with self.subTest(module=selected['module']), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                original = seed(root, selected)
                xml = XmlTransport()
                with patch.dict(os.environ, {selected['root_env']: str(root)}):
                    engine = config_backup.ConfigBackup(selected, transport=xml)
                    self.assertTrue(engine.mirror()['ok'])
                    first = copy.deepcopy(xml.fields)
                    name = next(name for name in original if '/usr/local/etc/' in name)
                    path = root / name.lstrip('/')
                    path.write_bytes(b'NEWER_EXTERNAL_CONFIGURATION')
                    self.assertTrue(engine.reconcile()['ok'])
                    self.assertEqual(path.read_bytes(), b'NEWER_EXTERNAL_CONFIGURATION')
                    self.assertTrue(engine.mirror()['changed'])
                    xml.fields = first
                    self.assertFalse(engine.mirror()['ok'])
                    self.assertEqual(xml.fields, first)
                    self.assertTrue(engine.reconcile()['ok'])
                    self.assertEqual(path.read_bytes(), original[name][0])

    def test_unsafe_dynamic_root_and_symlink_are_rejected(self):
        for selected in PROFILES:
            with self.subTest(module=selected['module']), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                original = seed(root, selected)
                xml = XmlTransport()
                with patch.dict(os.environ, {selected['root_env']: str(root)}):
                    engine = config_backup.ConfigBackup(selected, transport=xml)
                    if selected['rc_paths']:
                        field = selected['rc_paths'][0]
                        (root / field['file'].lstrip('/')).write_text(field['variable'] + '="/conf/config.xml"\n')
                        self.assertFalse(engine.mirror()['ok'])
                        self.assertEqual(xml.fields, {})
                        seed(root, selected)
                    name = next(name for name in original if '/usr/local/etc/' in name)
                    path = root / name.lstrip('/')
                    path.unlink()
                    outside = root / 'unrelated.bin'
                    outside.write_bytes(b'UNRELATED')
                    path.symlink_to(outside)
                    self.assertFalse(engine.mirror()['ok'])
                    self.assertEqual(outside.read_bytes(), b'UNRELATED')
                    self.assertEqual(xml.fields, {})

    def test_lucky_escaped_literal_directory_is_preserved_without_shell_expansion(self):
        selected = PROFILES[1]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = '/usr/local/etc/lucky $literal `literal` "quoted"'
            escaped = re.sub(r'([\\"$`])', r'\\\1', directory)
            rc = root / 'etc/rc.conf.d/lucky'
            rc.parent.mkdir(parents=True)
            original_rc = f'lucky_enable="NO"\nlucky_conf_dir="{escaped}"\nlucky_http_port="16601"\n'.encode()
            rc.write_bytes(original_rc)
            rc.chmod(0o600)
            application = root / directory.lstrip('/')
            application.mkdir(parents=True)
            configuration = application / 'config.bin'
            configuration.write_bytes(b'SENTINEL_CREDENTIAL\x00\xff')
            configuration.chmod(0o640)
            xml = XmlTransport()
            with patch.dict(os.environ, {selected['root_env']: str(root)}):
                engine = config_backup.ConfigBackup(selected, transport=xml)
                self.assertTrue(engine.mirror()['ok'])
                shutil.rmtree(application)
                rc.write_bytes(b'lucky_enable="YES"\n')
                self.assertTrue(engine.restore()['ok'])
                self.assertEqual(configuration.read_bytes(), b'SENTINEL_CREDENTIAL\x00\xff')
                self.assertEqual(configuration.stat().st_mode & 0o777, 0o640)
                self.assertEqual(rc.read_bytes(), original_rc)
                self.assertEqual(rc.stat().st_mode & 0o777, 0o600)

    def test_restore_write_failure_rolls_back_before_returning_generic_error(self):
        selected = PROFILES[0]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = seed(root, selected)
            xml = XmlTransport()
            with patch.dict(os.environ, {selected['root_env']: str(root)}):
                engine = config_backup.ConfigBackup(selected, transport=xml)
                self.assertTrue(engine.mirror()['ok'])
                for name in original:
                    (root / name.lstrip('/')).write_bytes(b'PRE_RESTORE_RUNTIME')
                before = contents(root, original)
                replace = config_backup.os.replace
                failed = []
                def fail_once(source, destination, *args, **kwargs):
                    if Path(destination) == root / 'usr/local/etc/staticarp/entries.conf' and not failed:
                        failed.append(True)
                        raise OSError('SENTINEL_CREDENTIAL')
                    return replace(source, destination, *args, **kwargs)
                with patch.object(config_backup.os, 'replace', side_effect=fail_once):
                    result = engine.restore()
                self.assertTrue(failed, 'The failure injection never reached the restore write')
                self.assertFalse(result['ok'])
                self.assertNotIn('SENTINEL_CREDENTIAL', json.dumps(result))
                self.assertEqual(contents(root, original), before)

    def test_embedded_application_writes_are_captured_by_the_real_watcher(self):
        for selected in PROFILES[1:]:
            with self.subTest(module=selected['module']), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                original = seed(root, selected)
                xml = XmlTransport()
                with patch.dict(os.environ, {selected['root_env']: str(root)}):
                    engine = config_backup.ConfigBackup(selected, transport=xml)
                    self.assertTrue(engine.mirror()['ok'])
                    initial_checksum = xml.fields['checksum']
                    transport_file = root / 'transport.json'
                    transport_file.write_text(json.dumps(xml.fields))
                    transport_file.chmod(0o600)
                    program = '''import json,os,sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from config_backup import ConfigBackup, revision_token, BackupError
selected=json.loads(sys.argv[2])
stored=Path(sys.argv[3])
def transport(action,payload=None):
    if action=='import':
        return json.loads(stored.read_text())
    before=json.loads(stored.read_text())
    if payload.pop('_expected') != revision_token(before):
        raise BackupError('The native configuration changed before its backup was saved.')
    temporary=stored.with_name('.mvc-transport')
    temporary.write_text(json.dumps(payload))
    temporary.chmod(0o600)
    os.replace(temporary,stored)
    return {'changed':before!=payload}
answer=ConfigBackup(selected,transport=transport).watch()
sys.exit(0 if answer['ok'] else 1)
'''
                    process = subprocess.Popen([sys.executable, '-c', program,
                                                str(REPOSITORY / 'src/common'), json.dumps(selected), str(transport_file)],
                                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    name = next(name for name in original if '/usr/local/etc/' in name)
                    changed = original[name][0].replace(b'SENTINEL_', b'SENTINEL_WATCH_UPDATED_')
                    (root / name.lstrip('/')).write_bytes(changed)
                    try:
                        # The watcher shares the preceding manual save's durable
                        # 30-second history budget across separate processes.
                        deadline = time.monotonic() + config_backup.WATCH_INTERVAL + 5
                        while time.monotonic() < deadline:
                            if json.loads(transport_file.read_text())['checksum'] != initial_checksum:
                                break
                            self.assertIsNone(process.poll(), 'The watcher exited before capturing the external write')
                            time.sleep(0.1)
                        else:
                            self.fail('The watcher did not capture the embedded application write')
                    finally:
                        process.terminate()
                        try:
                            stdout, stderr = process.communicate(timeout=5)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            stdout, stderr = process.communicate()
                    self.assertEqual(process.returncode, 0)
                    self.assertNotIn(b'SENTINEL_', stdout + stderr)
                    xml.fields = json.loads(transport_file.read_text())
                    (root / name.lstrip('/')).write_bytes(b'LOST_AFTER_WATCH')
                    self.assertTrue(engine.restore()['ok'])
                    self.assertEqual((root / name.lstrip('/')).read_bytes(), changed)

    def test_driver_reports_failure_as_a_nonzero_process_exit(self):
        for selected in PROFILES:
            route = selected['module'].lower()
            package = {'staticarp': 'os-staticarp', 'lucky': 'os-lucky', 'ddnsgo': 'os-ddns-go'}[route]
            driver = REPOSITORY / 'src' / package / 'src/usr/local/opnsense/scripts' / route / 'config_mirror.py'
            with self.subTest(module=selected['module']), tempfile.TemporaryDirectory() as temporary:
                environment = os.environ.copy()
                environment[selected['root_env']] = temporary
                environment['PYTHONPATH'] = str(REPOSITORY / 'src/common')
                result = subprocess.run([sys.executable, str(driver), 'invalid-action'], env=environment,
                                        capture_output=True, check=False)
                self.assertEqual(result.returncode, 1)
                self.assertFalse(json.loads(result.stdout)['ok'])


if __name__ == '__main__':
    unittest.main()
