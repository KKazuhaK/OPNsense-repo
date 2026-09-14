"""Exercise the real snapshot entry point without opening the live PF device."""
import base64
import contextlib
import importlib.util
import io
import json
import os
import runpy
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / 'src/usr/local/opnsense/scripts/pftop/snapshot.py'
spec = importlib.util.spec_from_file_location('pftop_snapshot', SOURCE)
snapshot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(snapshot)


def encoded(value):
    return base64.b64encode(json.dumps(value).encode()).decode()


class SnapshotTests(unittest.TestCase):
    def invoke(self, given, stdout='STATE OUTPUT\n', stderr='', status=0):
        process = subprocess.CompletedProcess([], status, stdout, stderr)
        with patch.object(snapshot.sys, 'argv', ['snapshot.py', encoded(given)]), \
                patch.object(snapshot.os, 'access', side_effect=lambda path, mode: path == '/usr/sbin/pftop'), \
                patch.object(snapshot.subprocess, 'run', return_value=process) as command:
            result = snapshot.main()
        return result, command

    def test_default_snapshot_uses_one_argv_and_bounded_native_execution(self):
        result, command = self.invoke({})
        self.assertEqual(result, {'status': 'ok', 'output': 'STATE OUTPUT\n', 'error': ''})
        command.assert_called_once_with(['/usr/sbin/pftop', '-b', '-w', '135', '-v', 'default', '-o', 'bytes', '100'],
                                        capture_output=True, text=True, errors='replace', timeout=15)

    def test_each_view_sort_and_count_preserves_pftop_option_semantics(self):
        for view in snapshot.VIEWS:
            for sort in snapshot.SORTS:
                for count in snapshot.COUNTS:
                    with self.subTest(view=view, sort=sort, count=count):
                        _, command = self.invoke({'view': view, 'sort': sort, 'count': count})
                        args = command.call_args.args[0]
                        self.assertEqual(args[-1], '-a' if count == 'all' else count)
                        self.assertEqual('-o' in args, view not in ('queue', 'label', 'rules'))
                        if '-o' in args:
                            self.assertEqual(args[args.index('-o') + 1], sort)

    def test_filter_is_trimmed_and_kept_as_one_literal_argument(self):
        expression = 'host 192.0.2.1; $(touch SHOULD_NOT_EXIST)'
        _, command = self.invoke({'filter': '  ' + expression + '  '})
        args = command.call_args.args[0]
        self.assertEqual(args[args.index('-f') + 1], expression)
        self.assertEqual(args.count(expression), 1)
        self.assertNotIn('shell', command.call_args.kwargs)
        _, command = self.invoke({'filter': ' '})
        self.assertNotIn('-f', command.call_args.args[0])

    def test_invalid_options_and_control_filters_never_launch_a_command(self):
        bad = [{'view': 'default; id'}, {'sort': 'bytes -a'}, {'count': '0'}, {'count': 100},
               {'filter': 'x' * 161}, {'filter': 'host\n192.0.2.1'}, {'filter': 'host\x00value'},
               {'filter': 'host\x7fvalue'}, [], None, 'default']
        for given in bad:
            with self.subTest(given=given), patch.object(snapshot.sys, 'argv', ['snapshot.py', encoded(given)]), \
                    patch.object(snapshot.subprocess, 'run') as command:
                with self.assertRaises(ValueError):
                    snapshot.main()
                command.assert_not_called()
        self.assertEqual(self.invoke({'filter': 'x' * 160})[0]['status'], 'ok')

    def test_failed_command_retains_diagnostics_and_limits_combined_output(self):
        result, _ = self.invoke({}, stdout='states\n', stderr='PF device unavailable\n', status=1)
        self.assertEqual(result, {'status': 'failed', 'output': 'states\nPF device unavailable\n',
                                  'error': 'pftop returned an error.'})
        result, _ = self.invoke({}, stdout='x' * 524287, stderr='ERROR', status=1)
        self.assertEqual(len(result['output']), 524288)
        self.assertTrue(result['output'].endswith('E'))

    def test_missing_binary_and_timeout_do_not_report_success(self):
        with patch.object(snapshot.sys, 'argv', ['snapshot.py', encoded({})]), \
                patch.object(snapshot.os, 'access', return_value=False), patch.object(snapshot.subprocess, 'run') as command:
            with self.assertRaisesRegex(ValueError, 'not found'):
                snapshot.main()
            command.assert_not_called()
        with patch.object(snapshot.sys, 'argv', ['snapshot.py', encoded({})]), \
                patch.object(snapshot.os, 'access', return_value=True), \
                patch.object(snapshot.subprocess, 'run', side_effect=subprocess.TimeoutExpired(['pftop'], 15)):
            with self.assertRaises(subprocess.TimeoutExpired):
                snapshot.main()
        for failure in [subprocess.TimeoutExpired(['pftop'], 15), OSError('PF snapshot unavailable')]:
            output = io.StringIO()
            with patch.object(snapshot.sys, 'argv', ['snapshot.py', encoded({})]), \
                    patch.object(snapshot.os, 'access', return_value=True), \
                    patch.object(snapshot.subprocess, 'run', side_effect=failure), contextlib.redirect_stdout(output):
                runpy.run_path(str(SOURCE), run_name='__main__')
            result = json.loads(output.getvalue())
            self.assertEqual(result['status'], 'failed')
            self.assertEqual(result['output'], '')
            self.assertTrue(result['error'])

    def test_cli_malformed_payloads_always_return_structured_failure(self):
        for arguments in [[], ['bad-base64!'], [encoded([])], [encoded(None)], [base64.b64encode(b'{').decode()]]:
            with self.subTest(arguments=arguments):
                process = subprocess.run([sys.executable, str(SOURCE), *arguments], capture_output=True, text=True, timeout=5)
                self.assertEqual(process.returncode, 0, process.stderr)
                result = json.loads(process.stdout)
                self.assertEqual(result['status'], 'failed')
                self.assertEqual(result['output'], '')
                self.assertTrue(result['error'])
                self.assertEqual(process.stderr, '')

    def test_cli_real_subprocess_preserves_literal_filter_and_decodes_bad_bytes(self):
        with tempfile.TemporaryDirectory(prefix='pftop-runtime-') as directory:
            root = Path(directory)
            binary = root / 'pftop'
            binary.write_text('#!' + sys.executable + '\nimport json,os,sys\n'
                              'open(os.environ["PFTOP_TEST_ARGS"],"w").write(json.dumps(sys.argv[1:]))\n'
                              'sys.stdout.buffer.write(b"native snapshot\\xff\\n")\n'
                              'sys.stderr.write("diagnostic\\n")\n')
            binary.chmod(0o755)
            candidate = root / 'snapshot.py'
            needle = "('/usr/local/sbin/pftop', '/usr/sbin/pftop', '/usr/bin/pftop')"
            self.assertEqual(SOURCE.read_text().count(needle), 1)
            candidate.write_text(SOURCE.read_text().replace(needle, repr((str(binary),)), 1))
            args_file = root / 'arguments.json'
            environment = {**os.environ, 'PFTOP_TEST_ARGS': str(args_file)}
            expression = 'host 192.0.2.1; touch ' + str(root / 'injected')
            process = subprocess.run([sys.executable, str(candidate), encoded({'filter': expression})],
                                     env=environment, capture_output=True, text=True, timeout=5)
            result = json.loads(process.stdout)
            self.assertEqual(result, {'status': 'ok', 'output': 'native snapshot\ufffd\ndiagnostic\n', 'error': ''})
            args = json.loads(args_file.read_text())
            self.assertEqual(args[args.index('-f') + 1], expression)
            self.assertFalse((root / 'injected').exists())


if __name__ == '__main__':
    unittest.main()
