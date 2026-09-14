"""Prove new and nested package suites run, and failed coverage cannot pass CI."""
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

RUNNER = Path(__file__).with_name('run.py')


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        (self.root / 'tests').mkdir()
        shutil.copyfile(RUNNER, self.root / 'tests/run.py')
        self.package = self.root / 'src/os-fixture/tests'
        self.package.mkdir(parents=True)

    def fixture(self, directory, name, failing=False):
        directory.mkdir(parents=True, exist_ok=True)
        (directory / name).write_text(
            'import unittest\n'
            'class Behavior(unittest.TestCase):\n'
            '    def test_behavior(self):\n'
            f'        self.assertTrue({not failing!r})\n'
        )

    def run_cli(self, *arguments):
        return subprocess.run([sys.executable, '-B', str(self.root / 'tests/run.py'),
                               '--python-only', *arguments], capture_output=True, text=True, timeout=20)

    def test_discovers_new_package_and_nested_suites_without_init_files(self):
        self.fixture(self.package, 'test_outer.py')
        self.fixture(self.package / 'native', 'test_inner.py')
        result = self.run_cli('--package', 'os-fixture')
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertEqual(2, result.stderr.count('Ran 1 test'))
        self.assertIn('test_outer.Behavior', result.stderr)
        self.assertIn('test_inner.Behavior', result.stderr)
        self.assertIn('2 suite commands', result.stdout)

    def test_failed_suite_fails_runner_while_remaining_suites_still_execute(self):
        self.fixture(self.package, 'test_outer.py', failing=True)
        self.fixture(self.package / 'native', 'test_inner.py')
        result = self.run_cli('--package', 'os-fixture')
        self.assertEqual(1, result.returncode)
        self.assertIn('FAILED (1) [os-fixture]', result.stderr)
        self.assertEqual(2, result.stderr.count('Ran 1 test'))
        self.assertIn('test_inner.Behavior', result.stderr)

    def test_package_without_tests_and_unknown_selection_are_rejected(self):
        result = self.run_cli('--package', 'os-fixture')
        self.assertEqual(2, result.returncode)
        self.assertIn('has no Python test suite', result.stderr)
        self.fixture(self.package, 'test_outer.py')
        result = self.run_cli('--package', 'os-typo')
        self.assertEqual(2, result.returncode)
        self.assertIn('Unknown packages: os-typo', result.stderr)

    def test_list_is_read_only_even_when_suite_would_fail(self):
        self.fixture(self.package, 'test_outer.py', failing=True)
        result = self.run_cli('--package', 'os-fixture', '--list', '--native')
        self.assertEqual(0, result.returncode)
        self.assertIn('test_*.py', result.stdout)
        self.assertNotIn('Ran 1 test', result.stderr)

    def test_requested_live_tests_cannot_be_silently_omitted_by_package_selection(self):
        self.fixture(self.package, 'test_outer.py')
        for flag, package in [('--bandwidth', 'os-speedtest'), ('--device-policy', 'os-mihomo')]:
            with self.subTest(flag=flag):
                result = self.run_cli('--package', 'os-fixture', '--list', flag)
                self.assertEqual(2, result.returncode)
                self.assertIn('requires selecting ' + package, result.stderr)
