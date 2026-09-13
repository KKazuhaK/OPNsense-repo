"""Exercise service, RPC, serialization and file-failure paths in private state."""
import contextlib
import datetime
import fcntl
import importlib.util
import io
import json
import math
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[2] / 'src/usr/local/opnsense/scripts/easytier/manage.py'
spec = importlib.util.spec_from_file_location('easytier_runtime', SOURCE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='easytier-runtime-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.addCleanup(patch.stopall)
        for name, path in {'CONFIG': 'config.toml', 'LOG': 'log', 'SAVE_LOCK': 'save.lock',
                           'OPERATION_LOCK': 'operation.lock', 'PID': 'pid', 'SYSTEM_CONFIG': 'system.xml',
                           'REQUEST_ROOT': '.'}.items():
            patch.object(m, name, self.root / path).start()
        patch.object(m.pwd, 'getpwnam', return_value=SimpleNamespace(pw_uid=os.getuid())).start()
        self.config = m.CONFIG
        self.original = 'hostname="router"\n[network_identity]\nnetwork_name="test"\nnetwork_secret="SENTINEL_SECRET"\n'
        self.config.write_text(self.original)
        self.mirror = patch.object(m, 'mirror_configuration', return_value=True).start()
        self.run = patch.object(m, 'run', return_value=SimpleNamespace(returncode=0, stdout='version 1')).start()

    def cli(self, *arguments):
        output = io.StringIO()
        with patch.object(sys, 'argv', ['manage.py', *arguments]), contextlib.redirect_stdout(output):
            self.assertEqual(m.main(), 0)
        return json.loads(output.getvalue())

    def request(self, contents):
        path = self.root / 'easytier_mvc_request'
        path.write_bytes(contents if isinstance(contents, bytes) else contents.encode())
        path.chmod(0o600)
        return path

    def test_complex_toml_render_round_trip_keeps_types_and_array_table_structure(self):
        document = tomllib.loads('''title="测试\\nrouter"
enabled=true
empty=[]
infinity=inf
missing=nan
date=2026-09-13
time=12:34:56.123
instant=2026-09-13T12:34:56Z
"dotted.key"={nested=[1,2,3], flag=false}
[[peer]]
uri="wss://example.invalid"
options={headers={name="first"}}
[[peer]]
uri="tcp://example.invalid:11010"
options={headers={name="second"}}
''')
        rendered = tomllib.loads(m.render(document))
        self.assertTrue(math.isnan(rendered.pop('missing')))
        document.pop('missing')
        self.assertEqual(rendered, document)
        self.assertIsInstance(rendered['date'], datetime.date)
        self.assertIsInstance(rendered['time'], datetime.time)
        self.assertIsInstance(rendered['instant'], datetime.datetime)

    def test_empty_nul_oversize_or_invalid_utf8_requests_preserve_current_file(self):
        for value in ('', '   ', 'hostname="bad\0value"', 'x' * 1048577, b'\xff'):
            with self.subTest(value_type=type(value).__name__, size=len(value)):
                result = self.cli('save', str(self.request(value)))
                self.assertEqual(result['status'], 'failed')
                self.assertNotIn('SENTINEL_', str(result))
                self.assertEqual(self.config.read_text(), self.original)
        self.mirror.assert_not_called()

    def test_atomic_replace_failure_preserves_original_mode_and_removes_staging_file(self):
        mode = self.config.stat().st_mode & 0o777
        with patch.object(m.os, 'replace', side_effect=OSError('SENTINEL_PRIVATE_FAILURE')):
            result = self.cli('save', str(self.request('hostname="edited"')))
        self.assertEqual(result['status'], 'failed')
        self.assertNotIn('SENTINEL_', str(result))
        self.assertEqual(self.config.read_text(), self.original)
        self.assertEqual(self.config.stat().st_mode & 0o777, mode)
        self.assertEqual(list(self.root.glob('.config.*')), [])
        self.mirror.assert_not_called()

    def test_missing_action_argument_or_invalid_network_identity_returns_structured_failure(self):
        for arguments in ((), ('save',), ('unknown',)):
            self.assertEqual(self.cli(*arguments)['status'], 'failed')
        self.config.write_text('network_identity="SENTINEL_INVALID_SHAPE"')
        result = self.cli('status')
        self.assertEqual(result['status'], 'failed')
        self.assertNotIn('SENTINEL_', str(result))

    def test_start_stop_and_restart_use_expected_enable_choice_and_release_lock(self):
        for action, enabled in (('start', 'YES'), ('stop', 'NO'), ('restart', None)):
            with self.subTest(action=action):
                self.run.reset_mock()
                self.assertEqual(self.cli(action)['status'], 'ok')
                calls = [call.args[0] for call in self.run.call_args_list]
                expected = [] if enabled is None else [['/usr/sbin/sysrc', '-f', '/etc/rc.conf.d/easytier',
                                                       'easytier_enable=' + enabled]]
                self.assertEqual(calls, expected + [[m.RC, 'one' + action]])
                with m.OPERATION_LOCK.open('a') as handle:
                    fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def test_enable_failure_does_not_start_service_or_mirror(self):
        self.run.return_value = SimpleNamespace(returncode=1, stdout='SENTINEL_PRIVATE_DIAGNOSTIC')
        result = m.dispatch('start')
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(self.run.call_count, 1)
        self.assertNotIn('SENTINEL_', str(result))
        self.mirror.assert_not_called()

    def test_failed_service_or_timeout_is_safe_and_does_not_mirror(self):
        for result in (SimpleNamespace(returncode=1, stdout='SENTINEL_PRIVATE_DIAGNOSTIC'),
                       subprocess.TimeoutExpired('SENTINEL_PRIVATE_COMMAND', 1)):
            self.run.side_effect = result if isinstance(result, Exception) else None
            self.run.return_value = result
            answer = self.cli('restart')
            self.assertEqual(answer['status'], 'failed')
            self.assertNotIn('SENTINEL_', str(answer))
        self.mirror.assert_not_called()

    def test_offline_peers_do_not_query_rpc_and_failed_rpc_does_not_expose_diagnostics(self):
        self.run.return_value = SimpleNamespace(returncode=1)
        self.assertEqual(m.dispatch('peers'), {'status': 'ok', 'running': False, 'rows': []})
        self.assertEqual(self.run.call_count, 1)
        self.run.side_effect = [SimpleNamespace(returncode=0),
                               SimpleNamespace(returncode=1, stdout='SENTINEL_PRIVATE_DIAGNOSTIC')]
        result = m.dispatch('peers')
        self.assertEqual(result['status'], 'failed')
        self.assertNotIn('SENTINEL_', str(result))

    def test_peer_table_skips_headers_malformed_rows_and_scrubs_credentials(self):
        output = '| ipv4 | a | b | c | d | e | f | g | h | i |\n|---|---|\n' + \
            '| malformed | row |\n| 192.0.2.1 | a | b | c | d | e | f | g | h | SENTINEL_SECRET | ignored |\n'
        self.run.side_effect = [SimpleNamespace(returncode=0), SimpleNamespace(returncode=0, stdout=output)]
        rows = m.dispatch('peers')['rows']
        self.assertEqual(len(rows), 1)
        self.assertEqual(len(rows[0]), 10)
        self.assertEqual(rows[0][-1], '********')

    def test_status_and_log_defaults_are_bounded_and_do_not_leak_stored_secret(self):
        m.PID.write_text('12345\n')
        m.SYSTEM_CONFIG.write_text('<opnsense><system><language>zh_CN</language></system></opnsense>')
        self.run.return_value = SimpleNamespace(returncode=0, stdout='version SENTINEL_SECRET')
        result = m.dispatch('status')
        self.assertTrue(result['running'])
        self.assertEqual(result['pid'], '12345')
        self.assertEqual(result['language'], 'zh_CN')
        self.assertNotIn('SENTINEL_', str(result))
        m.LOG.write_bytes(b'old\n' * 1000000 + b'password=SENTINEL_SECRET\n' * 101 + b'\xfftail\n')
        text = m.dispatch('log')['log']
        self.assertEqual(len(text.splitlines()), 100)
        self.assertNotIn('old', text)
        self.assertNotIn('SENTINEL_', text)
        self.assertIn('\ufffdtail', text)
        self.assertEqual(m.dispatch('clear_log')['status'], 'ok')
        self.assertEqual(m.LOG.read_bytes(), b'')

    def test_request_owner_and_mode_checks_reject_nonprivate_handoffs(self):
        path = self.request('hostname="safe"')
        path.chmod(0o644)
        with self.assertRaises(ValueError): m.request_text(path)
        path.chmod(0o600)
        metadata = path.stat()
        with patch.object(m.os, 'fstat', return_value=SimpleNamespace(st_mode=metadata.st_mode, st_uid=123456)):
            with self.assertRaises(ValueError): m.request_text(path)


if __name__ == '__main__':
    unittest.main()
