#!/usr/local/bin/python3
"""Additional native process checks inside a designated jail; no router services are used."""
import importlib.util
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

PACKAGE = Path(__file__).resolve().parents[2]
SCRIPT = PACKAGE / 'src/usr/local/opnsense/scripts/ddclient/process_owner.py'
spec = importlib.util.spec_from_file_location('ddclient_owner', SCRIPT)
owner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(owner)
NATIVE = (sys.platform.startswith('freebsd') and os.geteuid() == 0 and os.uname().machine == 'amd64'
          and os.environ.get('DDCLIENT_NATIVE_FIXTURE') == '1')
if NATIVE:
    NATIVE = subprocess.run(['/sbin/sysctl', '-n', 'security.jail.jailed'], capture_output=True,
                            text=True, check=True).stdout.strip() == '1'


@unittest.skipUnless(NATIVE, 'Requires a designated native jail; additional coverage only')
class NativeProcessOwnerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='native-ddclient-process-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.script = self.root / 'ddclient_opn.py'
        self.script.write_text('''import argparse,os,signal,time
from pathlib import Path
parser=argparse.ArgumentParser();parser.add_argument('-p');parser.add_argument('-c');parser.add_argument('--ignore-term',action='store_true')
args=parser.parse_args()
if args.ignore_term:signal.signal(signal.SIGTERM,signal.SIG_IGN)
Path(args.p).write_text(str(os.getpid())+'\\n')
while True:time.sleep(.1)
''')
        self.pidfile = self.root / 'owned.pid'
        self.child = self.spawn(self.pidfile)
        self.other = self.spawn(self.root / 'other.pid')
        self.control = owner.Owner(self.pidfile, self.script, sys.executable)

    def spawn(self, pidfile):
        process = subprocess.Popen([sys.executable, str(self.script), '-p', str(pidfile),
                                    '-c', '/private/literal $HOME `date` "quotes".json'])
        def cleanup():
            if process.poll() is None:
                process.kill()
            process.wait(timeout=3)
        self.addCleanup(cleanup)
        deadline = time.monotonic() + 3
        while not pidfile.exists() and time.monotonic() < deadline:
            time.sleep(.01)
        self.assertTrue(pidfile.exists())
        return process

    def test_native_record_and_stop_preserve_another_same_script_instance(self):
        live = self.control.table.read(self.child.pid)
        self.assertEqual(live['argv'][1], str(self.script))
        self.assertEqual(live['argv'][-1], '/private/literal $HOME `date` "quotes".json')
        self.assertRegex(live['birth'], r'^[0-9]+:[0-9]+$')
        self.control.record(timeout=1)
        self.control.stop(timeout=1)
        self.child.wait(timeout=3)
        self.assertEqual(self.child.returncode, -signal.SIGTERM)
        self.assertIsNone(self.other.poll())
        self.assertFalse(self.pidfile.exists())

    def test_a_pidfile_pointing_at_other_instance_cannot_kill_it(self):
        self.control.record(timeout=1)
        self.pidfile.write_text(str(self.other.pid) + '\n')
        with self.assertRaises(RuntimeError):
            self.control.stop(timeout=.1)
        self.assertIsNone(self.child.poll())
        self.assertIsNone(self.other.poll())

    def test_actual_foreign_python_script_argument_does_not_establish_ownership(self):
        foreign = self.root / 'foreign.py'
        foreign.write_text('import time\nwhile True:time.sleep(.1)\n')
        process = subprocess.Popen([sys.executable, str(foreign), str(self.script)])
        def cleanup():
            if process.poll() is None:
                process.kill()
            process.wait(timeout=3)
        self.addCleanup(cleanup)
        self.pidfile.write_text(str(process.pid) + '\n')
        with self.assertRaises(RuntimeError):
            self.control.stop(timeout=.1)
        self.assertIsNone(process.poll())
        self.assertIsNone(self.child.poll())
        self.assertIsNone(self.other.poll())


if __name__ == '__main__':
    unittest.main(verbosity=2)
