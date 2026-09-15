#!/usr/local/bin/python3
"""Additional real Perl mutable-title and supervisor tests in a designated jail."""
import importlib.util
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

PACKAGE = Path(__file__).resolve().parents[2]
DIRECTORY = PACKAGE / 'src/usr/local/opnsense/scripts/ddclient'
sys.path.insert(0, str(DIRECTORY))
spec = importlib.util.spec_from_file_location('perl_backend', DIRECTORY / 'perl_backend.py')
backend = importlib.util.module_from_spec(spec)
spec.loader.exec_module(backend)
sys.path.insert(0, '/usr/local/opnsense/site-python')
NATIVE = (sys.platform.startswith('freebsd') and os.geteuid() == 0 and os.uname().machine == 'amd64'
          and os.environ.get('DDCLIENT_NATIVE_FIXTURE') == '1' and Path(backend.PERL).exists()
          and importlib.util.find_spec('daemonize', package=None) is not None)
if NATIVE:
    NATIVE = subprocess.run(['/sbin/sysctl', '-n', 'security.jail.jailed'], capture_output=True,
                            text=True, check=True).stdout.strip() == '1'


@unittest.skipUnless(NATIVE, 'Requires Perl/Core daemonize in a designated native jail; additional coverage only')
class NativePerlBackendTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='native-ddclient-perl-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.pidfile = self.root / 'supervisor.pid'
        self.program = self.root / 'ddclient'
        self.program.write_text('''use strict;
use warnings;
$0 = 'ddclient - sleeping for 120 seconds';
$SIG{TERM} = sub { exit 0; };
while (1) { sleep 1; }
''')
        self.program_patch = mock.patch.object(backend, 'PROGRAM', str(self.program))
        self.program_patch.start()
        self.addCleanup(self.program_patch.stop)
        self.child = backend.Child(self.pidfile)
        self.other = subprocess.Popen([backend.PERL, str(self.program)])
        self.addCleanup(self.cleanup_process, self.other)

    @staticmethod
    def cleanup_process(process):
        if process.poll() is None:
            process.kill()
        process.wait(timeout=3)
        for stream in (process.stdout, process.stderr):
            if stream is not None:
                stream.close()

    def test_actual_foreground_perl_child_survives_title_mutation_and_only_owned_child_stops(self):
        process = self.child.launch(120)
        self.addCleanup(self.cleanup_process, process)
        self.assertIsNotNone(self.child.load())
        self.assertRegex(self.child.load()['identity']['birth'], r'^[0-9]+:[0-9]+$')
        time.sleep(.1)
        live = self.child.table.read(process.pid)
        self.assertTrue(any('sleeping' in argument for argument in live['argv']))
        self.child.cleanup(timeout=1)
        process.wait(timeout=3)
        self.assertEqual(process.returncode, 0)
        self.assertIsNone(self.other.poll())
        self.assertFalse(self.child.journal.exists())

    def test_missing_parent_pidfile_still_cleans_actual_journalled_child(self):
        process = self.child.launch(120)
        self.addCleanup(self.cleanup_process, process)
        self.assertFalse(self.pidfile.exists())
        self.child.cleanup(timeout=1)
        process.wait(timeout=3)
        self.assertEqual(process.returncode, 0)
        self.assertIsNone(self.other.poll())

    def test_actual_python_supervisor_records_and_stops_with_perl_title_changed(self):
        candidate = self.root / 'perl_backend.py'
        source = (DIRECTORY / 'perl_backend.py').read_text()
        source = source.replace("PROGRAM = '/usr/local/sbin/ddclient'", 'PROGRAM = ' + repr(str(self.program)), 1)
        source = source.replace("CONFIG = '/usr/local/etc/ddclient.conf'", 'CONFIG = ' + repr(str(self.root / 'config')), 1)
        candidate.write_text(source)
        environment = {**os.environ, 'PYTHONPATH': str(DIRECTORY)}
        process = subprocess.Popen(['/usr/local/bin/python3', str(candidate), '-f', '-p', str(self.pidfile), '--delay', '120'],
                                   env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.addCleanup(self.cleanup_process, process)
        with mock.patch.object(backend, '__file__', str(candidate)):
            deadline = time.monotonic() + 5
            while not self.pidfile.exists() and time.monotonic() < deadline:
                time.sleep(.02)
            self.assertTrue(self.pidfile.exists())
            backend.parent(self.pidfile).record(timeout=2)
            backend.ready(self.pidfile)
            child_pid = self.child.load()['identity']['pid']
            backend.stop(self.pidfile)
            process.wait(timeout=3)
            self.assertEqual(process.returncode, 0, process.stderr.read().decode())
            self.assertIsNone(self.child.table.read(child_pid))
            self.assertIsNone(self.other.poll())
            self.assertFalse(self.pidfile.exists())
            self.assertFalse(self.child.journal.exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
