"""Exercise full DDNS-Go requests without installed configuration or services."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import yaml

PACKAGE = Path(__file__).parents[1]
SOURCE = PACKAGE / 'src/usr/local/opnsense/scripts/ddnsgo/settings.py'
COMMON = PACKAGE.parent / 'common/config_backup.py'


class BackendContractTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.config = self.root / 'default.yaml'
        self.rc = self.root / 'service.rc'
        self.log = self.root / 'ddns.log'
        source = SOURCE.read_text()
        for original, replacement in [("CONFIG = Path('/usr/local/etc/ddns-go/config.yaml')", f'CONFIG = Path({str(self.config)!r})'),
                                      ("RC_CONFIG = Path('/etc/rc.conf.d/ddnsgo')", f'RC_CONFIG = Path({str(self.rc)!r})'),
                                      ("LOG = Path('/var/log/ddnsgo.log')", f'LOG = Path({str(self.log)!r})')]:
            self.assertEqual(source.count(original), 1)
            source = source.replace(original, replacement, 1)
        self.helper = self.root / 'settings.py'
        self.helper.write_text(source)
        shutil.copyfile(COMMON, self.root / 'config_backup.py')
        (self.root / 'config_mirror.py').write_text("import os,sys\nfrom pathlib import Path\nroot=Path(__file__).parent\nwith (root/'mirror-calls').open('a') as out:out.write('mirror\\n')\nprint('PRIVATE_BACKUP_SENTINEL',file=sys.stderr)\nsys.exit(int(os.environ.get('TEST_BACKUP_FAIL','0')))\n")
        self.config.write_bytes(b'dns:\n  token: PRIVATE_PROVIDER_CREDENTIAL\n  enabled: true\n')

    def request(self, action, value=None, **environment):
        command = [sys.executable, str(self.helper), action]
        if value is not None:
            payload = self.root / 'request.json'
            payload.write_text(json.dumps(value))
            command.append(str(payload))
        result = subprocess.run(command, capture_output=True, text=True, env={**os.environ, **environment}, timeout=10)
        self.assertEqual(result.returncode, 0, 'The helper must return structured failures instead of crashing.')
        self.assertEqual(result.stderr, '', 'Privileged diagnostics must not escape onto the response channel.')
        return json.loads(result.stdout)

    def test_custom_literal_rc_path_is_the_daemon_configuration(self):
        custom = self.root / 'custom $literal `literal` "quoted".yaml'
        raw = b'dns:\r\n  id: 123456789\r\n  password: CUSTOM_PRIVATE_SECRET\r\n  enabled: true\r\n'
        custom.write_bytes(raw)
        escaped = str(custom).replace('\\', '\\\\').replace('"', '\\"').replace('$', '\\$').replace('`', '\\`')
        self.rc.write_text(f'ddnsgo_enable="NO"\nddnsgo_config="{escaped}"\nddnsgo_listen=\':12345\'\n')
        original_default = self.config.read_bytes()
        given = self.request('get')['settings']
        self.assertEqual(given['revision'], hashlib.sha256(raw).hexdigest())
        self.assertEqual(given['listen'], ':12345')
        self.assertNotIn('CUSTOM_PRIVATE_SECRET', json.dumps(given))
        self.assertNotIn('123456789', json.dumps(given))
        given['config_content'] = given['config_content'].replace('enabled: true', 'enabled: false')
        self.assertEqual(self.request('set', given)['status'], 'ok')
        self.assertEqual(yaml.safe_load(custom.read_bytes()), {'dns': {'id': 123456789, 'password': 'CUSTOM_PRIVATE_SECRET', 'enabled': False}})
        self.assertEqual(custom.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.config.read_bytes(), original_default)
        self.assertEqual(list(self.root.glob('.ddnsgo-*')), [])

    def test_invalid_documents_and_stale_revision_do_not_write_or_mirror(self):
        original = self.config.read_bytes()
        revision = self.request('get')['settings']['revision']
        for content in ['', '   ', '[]', '42', 'token: [PRIVATE_BAD_YAML', '!!python/object:PRIVATE_BAD_YAML {}', 'a: &a {b: *a}', 'a: ' + 'x' * 1048576]:
            with self.subTest(content=content[:40]):
                response = self.request('set', {'revision': revision, 'config_content': content})
                self.assertEqual(response['status'], 'failed')
                self.assertNotIn('PRIVATE_BAD_YAML', json.dumps(response))
                self.assertEqual(self.config.read_bytes(), original)
                self.assertFalse((self.root / 'mirror-calls').exists())
                self.assertEqual(list(self.root.glob('.ddnsgo-*')), [])
        response = self.request('set', {'revision': 'stale', 'config_content': 'token: PRIVATE_NEW_SECRET'})
        self.assertEqual(response['status'], 'failed')
        self.assertNotIn('PRIVATE_NEW_SECRET', json.dumps(response))
        self.assertEqual(self.config.read_bytes(), original)

    def test_nonmapping_requests_are_structured_and_secret_safe(self):
        original = self.config.read_bytes()
        for value in [[], ['PRIVATE_REQUEST_SECRET'], True, 1, 'PRIVATE_REQUEST_SECRET']:
            with self.subTest(value=value):
                response = self.request('set', value)
                self.assertEqual(response['status'], 'failed')
                self.assertNotIn('PRIVATE_REQUEST_SECRET', json.dumps(response))
        self.assertEqual(self.request('unknown')['status'], 'failed')
        self.assertEqual(self.config.read_bytes(), original)
        self.assertFalse((self.root / 'mirror-calls').exists())

    def test_unsafe_or_expanding_rc_path_is_rejected_without_shell_execution(self):
        marker = self.root / 'shell-was-executed'
        original = self.config.read_bytes()
        for assignment in ['relative', '/', str(self.root / 'unused' / '..' / 'escaped'), str(self.root / 'control\x7f'), f'$(touch {marker})', f'`touch {marker}`']:
            with self.subTest(assignment=assignment):
                self.rc.write_text(f'ddnsgo_config="{assignment}"\n')
                response = self.request('get')
                self.assertEqual(response['status'], 'failed')
                self.assertEqual(self.config.read_bytes(), original)
                self.assertFalse(marker.exists())
                self.assertFalse((self.root / 'mirror-calls').exists())

    def test_nested_marker_types_survive_and_relocation_is_rejected(self):
        original = {'providers': [{'token': 'ONE_PRIVATE_SECRET', 'id': 987654321, 'privatekey': False, 'enabled': True, 'unset': None}, {'token': 'TWO_PRIVATE_SECRET', 'id': 123}], 'arbitrary': 1.25}
        self.config.write_text(yaml.safe_dump(original, sort_keys=False))
        given = self.request('get')['settings']
        document = yaml.safe_load(given['config_content'])
        self.assertIs(document['providers'][0]['enabled'], True)
        self.assertIsNone(document['providers'][0]['unset'])
        self.assertTrue(document['providers'][0]['privatekey'].startswith('__DDNSGO_KEEP_'))
        for mutation in ['reverse', 'insert', 'move']:
            altered = yaml.safe_load(given['config_content'])
            if mutation == 'reverse':
                altered['providers'].reverse()
            elif mutation == 'insert':
                altered['providers'].insert(0, {'token': 'new-token'})
            else:
                altered['moved'] = altered['providers'][0]['token']
            response = self.request('set', {**given, 'config_content': yaml.safe_dump(altered)})
            self.assertEqual(response['status'], 'failed')
            self.assertEqual(yaml.safe_load(self.config.read_bytes()), original)
        document['providers'][0]['enabled'] = False
        self.assertEqual(self.request('set', {**given, 'config_content': yaml.safe_dump(document)})['status'], 'ok')
        original['providers'][0]['enabled'] = False
        self.assertEqual(yaml.safe_load(self.config.read_bytes()), original)

    def test_bounded_logs_mask_stored_and_named_credentials_without_mutation(self):
        original = self.config.read_bytes()
        self.log.write_bytes(b'x' * 65000 + b'\n' + b''.join(f'line {number} --> token=PRIVATE_PROVIDER_CREDENTIAL api_key=UNKNOWN_PRIVATE_SECRET\n'.encode() for number in range(300)) + b'final \xff\n')
        response = self.request('log')
        self.assertLessEqual(len(response['log'].splitlines()), 200)
        self.assertIn('line 299 -->', response['log'])
        self.assertIn('\ufffd', response['log'])
        self.assertNotIn('PRIVATE_PROVIDER_CREDENTIAL', response['log'])
        self.assertNotIn('UNKNOWN_PRIVATE_SECRET', response['log'])
        self.assertEqual(self.config.read_bytes(), original)
        self.assertFalse((self.root / 'mirror-calls').exists())

    def test_atomic_replace_failure_cleans_temporary_file_and_skips_backup(self):
        sys.path.insert(0, str(self.root))
        self.addCleanup(lambda: sys.path.remove(str(self.root)))
        spec = importlib.util.spec_from_file_location('private_ddns_contract', self.helper)
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
        original = self.config.read_bytes()
        given = self.request('get')['settings']
        payload = self.root / 'request.json'
        payload.write_text(json.dumps(given))
        with patch.object(sys, 'argv', ['settings.py', 'set', str(payload)]), patch.object(helper.os, 'replace', side_effect=OSError('simulated disk failure')), patch.object(helper, 'mirror_settings') as mirror:
            with self.assertRaises(OSError):
                helper.main()
            mirror.assert_not_called()
        self.assertEqual(self.config.read_bytes(), original)
        self.assertEqual(list(self.root.glob('.ddnsgo-*')), [])

    def test_real_backup_subprocess_failure_is_visible_and_suppressed(self):
        given = self.request('get')['settings']
        given['config_content'] = given['config_content'].replace('enabled: true', 'enabled: false')
        response = self.request('set', given, TEST_BACKUP_FAIL='1')
        self.assertEqual(response['status'], 'failed')
        self.assertTrue(response['saved'])
        self.assertNotIn('PRIVATE_BACKUP_SENTINEL', json.dumps(response))
        self.assertNotIn('PRIVATE_PROVIDER_CREDENTIAL', json.dumps(response))
        self.assertFalse(yaml.safe_load(self.config.read_bytes())['dns']['enabled'])


if __name__ == '__main__':
    unittest.main()
