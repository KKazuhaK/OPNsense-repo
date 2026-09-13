"""Exercise complete helper requests with private rc files and real subprocesses."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).parents[1] / 'src/usr/local/opnsense/scripts/lucky/settings.py'
COMMON = Path(__file__).parents[2] / 'common/config_backup.py'
sys.path.insert(0, str(COMMON.parent))


class BackendContractTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.rc = self.root / 'rc.conf'
        self.helper = self.root / 'settings.py'
        self.helper.write_text(SOURCE.read_text().replace("CONFIG = Path('/etc/rc.conf.d/lucky')", f'CONFIG = Path({str(self.rc)!r})', 1))
        shutil.copyfile(COMMON, self.root / 'config_backup.py')
        (self.root / 'config_mirror.py').write_text("import os,sys\nfrom pathlib import Path\nroot=Path(__file__).parent\nwith (root/'mirror-calls').open('a') as out:out.write('mirror\\n')\nprint('PRIVATE_BACKUP_SENTINEL',file=sys.stderr)\nsys.exit(int(os.environ.get('TEST_BACKUP_FAIL','0')))\n")

    def request(self, action, value=None, **environment):
        command = [sys.executable, str(self.helper), action]
        if value is not None:
            payload = self.root / 'request.json'
            payload.write_text(json.dumps(value))
            command.append(str(payload))
        result = subprocess.run(command, capture_output=True, text=True, env={**os.environ, **environment}, timeout=10)
        self.assertEqual(result.returncode, 0, 'The helper crashed instead of returning structured failure.')
        self.assertEqual(result.stderr, '', 'Privileged diagnostics escaped onto the response channel.')
        return json.loads(result.stdout)

    def test_get_is_side_effect_free_and_defaults_are_usable(self):
        self.assertEqual(self.request('get')['settings'], {'enabled': True, 'conf_dir': '/usr/local/etc/lucky', 'web_port': 16601})
        self.assertFalse(self.rc.exists())
        self.assertFalse((self.root / 'mirror-calls').exists())

    def test_invalid_port_types_and_bounds_preserve_configuration(self):
        original = b'lucky_enable="NO"\nlucky_conf_dir="/private-existing"\nlucky_http_port="16601"\n'
        for value in [True, False, 1.5, [], {}, 'not-a-port', 0, -1, 65536]:
            with self.subTest(port=value):
                self.rc.write_bytes(original)
                response = self.request('set', {'conf_dir': str(self.root / 'new-directory'), 'web_port': value})
                self.assertEqual(response['status'], 'failed')
                self.assertEqual(self.rc.read_bytes(), original)
                self.assertFalse((self.root / 'mirror-calls').exists())
                self.assertFalse((self.root / 'new-directory').exists())

    def test_unsafe_paths_are_rejected_before_any_write(self):
        for path in ['relative', '/', str(self.root / 'unused' / '..' / 'escaped'), str(self.root / 'control\x7f'), str(self.root / 'control\n')]:
            with self.subTest(path=path):
                self.assertEqual(self.request('set', {'conf_dir': path})['status'], 'failed')
                self.assertFalse(self.rc.exists())
                self.assertFalse((self.root / 'mirror-calls').exists())

    def test_nonmapping_or_unknown_action_returns_structured_failure(self):
        for value in [[], ['secret-value'], True, 1, 'secret-value']:
            with self.subTest(value=value):
                response = self.request('set', value)
                self.assertEqual(response['status'], 'failed')
                self.assertNotIn('secret-value', json.dumps(response))
        self.assertEqual(self.request('not-an-action')['status'], 'failed')
        self.assertFalse(self.rc.exists())

    def test_literal_custom_path_boundary_ports_modes_and_backup_failure(self):
        directory = self.root / 'lucky $literal `literal` "quoted"'
        for port in [1, 65535]:
            response = self.request('set', {'enabled': False, 'conf_dir': str(directory), 'web_port': str(port)})
            self.assertEqual(response['status'], 'ok')
            self.assertEqual(self.request('get')['settings'], {'enabled': False, 'conf_dir': str(directory), 'web_port': port})
            self.assertEqual(self.rc.stat().st_mode & 0o777, 0o644)
            self.assertEqual(list(self.root.glob('.lucky-*')), [])
        response = self.request('set', {'web_port': 16602}, TEST_BACKUP_FAIL='1')
        self.assertEqual(response['status'], 'failed')
        self.assertTrue(response['saved'])
        self.assertNotIn('PRIVATE_BACKUP_SENTINEL', json.dumps(response))
        self.assertEqual(self.request('get')['settings']['web_port'], 16602)
        self.assertEqual(len((self.root / 'mirror-calls').read_text().splitlines()), 3)

    def test_atomic_rc_replace_failure_preserves_bytes_and_cleans_request(self):
        original = b'lucky_enable="NO"\nlucky_conf_dir="/private-existing"\nlucky_http_port="16601"\n'
        self.rc.write_bytes(original)
        spec = importlib.util.spec_from_file_location('private_lucky_contract', self.helper)
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
        payload = self.root / 'request.json'
        payload.write_text(json.dumps({'conf_dir': str(self.root / 'new-directory'), 'web_port': 16602}))
        with patch.object(sys, 'argv', ['settings.py', 'set', str(payload)]), patch.object(helper.os, 'replace', side_effect=OSError('simulated disk failure')), patch.object(helper, 'mirror_settings') as mirror:
            with self.assertRaises(OSError):
                helper.main()
            mirror.assert_not_called()
        self.assertEqual(self.rc.read_bytes(), original)
        self.assertEqual(list(self.root.glob('.lucky-*')), [])

    def test_singlequoted_or_unquoted_rc_values_are_read_without_reverting_custom_settings(self):
        directory = self.root / 'singlequoted $literal `literal` custom'
        self.rc.write_text(f"lucky_enable='NO'\nlucky_conf_dir='{directory}'\nlucky_http_port=16603\n")
        self.assertEqual(self.request('get')['settings'], {'enabled': False, 'conf_dir': str(directory), 'web_port': 16603})
        self.assertFalse((self.root / 'mirror-calls').exists())
        self.assertEqual(self.request('set', {'web_port': 16604})['status'], 'ok')
        self.assertEqual(self.request('get')['settings'], {'enabled': False, 'conf_dir': str(directory), 'web_port': 16604})


if __name__ == '__main__':
    unittest.main()
