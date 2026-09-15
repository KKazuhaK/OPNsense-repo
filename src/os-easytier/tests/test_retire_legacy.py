"""A retired plugin namespace does not authorize deleting administrator rules."""
import importlib.util
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import subprocess
import sys
import unittest
from unittest import mock

SOURCE = Path(__file__).resolve().parents[1] / 'src/usr/local/opnsense/scripts/easytier/retire_legacy.py'
spec = importlib.util.spec_from_file_location('retire_easytier_legacy', SOURCE)
legacy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(legacy)


class Retirement(unittest.TestCase):
    def run_case(self, rules, contents=legacy.GENERATED, query_exit=0, clear_exit=0, replace=False):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'easytier.rules'
            path.write_bytes(contents)
            calls = []
            def runner(arguments):
                calls.append(arguments)
                if arguments[-1] == '-sr':
                    return SimpleNamespace(returncode=query_exit, stdout=rules)
                if replace:
                    path.write_bytes(b'Administrator replacement\n')
                return SimpleNamespace(returncode=clear_exit, stdout='')
            warning = legacy.retire(path, runner, os.geteuid())
            return warning, calls, path.read_bytes() if path.exists() else None

    def test_exact_old_and_canonical_renderings_are_retired(self):
        for rule in legacy.KNOWN:
            with self.subTest(rule=rule):
                warning, calls, remaining = self.run_case(rule + '\n')
                self.assertEqual(warning, '')
                self.assertEqual(calls[-1], ['/sbin/pfctl', '-a', 'easytier', '-F', 'rules'])
                self.assertIsNone(remaining)

    def test_extra_or_edited_rules_preserve_anchor_and_file(self):
        for rule in ('block drop all', legacy.GENERATED.decode() + 'block drop all\n',
                     legacy.GENERATED.decode().replace('from any', 'from 192.168.1.2')):
            with self.subTest(rule=rule):
                warning, calls, remaining = self.run_case(rule)
                self.assertTrue(warning)
                self.assertEqual(len(calls), 1)
                self.assertEqual(remaining, legacy.GENERATED)

    def test_failed_inspection_or_clear_preserves_file(self):
        for query_exit, clear_exit in ((1, 0), (0, 1)):
            with self.subTest(query_exit=query_exit):
                warning, calls, remaining = self.run_case(legacy.GENERATED.decode(), query_exit=query_exit,
                                                         clear_exit=clear_exit)
                self.assertTrue(warning)
                self.assertEqual(remaining, legacy.GENERATED)
                self.assertEqual(len(calls), 1 if query_exit else 2)

    def test_empty_anchor_only_retires_exact_generated_file(self):
        for data in (legacy.GENERATED, b'Administrator contents\n'):
            with self.subTest(data=data):
                warning, calls, remaining = self.run_case('', contents=data)
                self.assertEqual(warning, '')
                self.assertEqual(len(calls), 1)
                self.assertEqual(remaining, None if data == legacy.GENERATED else data)

    def test_file_replaced_during_clear_is_preserved(self):
        warning, calls, remaining = self.run_case(legacy.GENERATED.decode(), replace=True)
        self.assertEqual(warning, '')
        self.assertEqual(remaining, b'Administrator replacement\n')

    def test_same_named_fifo_does_not_block_installation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'easytier.rules'
            os.mkfifo(path)
            code = ('import os,runpy,sys; from pathlib import Path; '
                    'assert runpy.run_path(sys.argv[1])["snapshot"](Path(sys.argv[2]),os.geteuid()) is None')
            subprocess.run([sys.executable, '-B', '-c', code, str(SOURCE), str(path)],
                           check=True, timeout=2)
            self.assertTrue(path.exists())

    def test_cli_failure_is_visible_to_package_hooks(self):
        with mock.patch.object(legacy, 'retire', return_value='preserved'):
            self.assertEqual(legacy.main(), 1)
        with mock.patch.object(legacy, 'retire', return_value=''):
            self.assertEqual(legacy.main(), 0)


if __name__ == '__main__':
    unittest.main()
