"""Exercise the independent watcher through real FreeBSD rc and daemon."""
import os
from pathlib import Path
import shlex
import signal
import subprocess
import sys
import tempfile
import time
import unittest

PACKAGE = Path(__file__).resolve().parents[2]
ROUTE = 'lucky' if PACKAGE.name == 'os-lucky' else 'ddnsgo'


@unittest.skipUnless(sys.platform.startswith('freebsd'), 'requires native FreeBSD rc and daemon')
class NativeWatcherTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix=ROUTE + '-watcher-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.addCleanup(self.stop_private_worker)
        worker = self.root / 'config_mirror.py'
        worker.write_text(r"""import json,os,signal,sys,time
from pathlib import Path
root=Path(__file__).parent
if sys.argv[1]=='reconcile':
    (root/'reconciled').touch()
    sys.exit(7 if os.environ.get('TEST_RECONCILE_FAIL') else 0)
if sys.argv[1]!='watch':sys.exit(8)
stopping=False
def stop(signum,frame):
    global stopping
    stopping=True
signal.signal(signal.SIGTERM,stop)
(root/'started').write_text(str(os.getpid()))
while not stopping:time.sleep(0.02)
(root/'stopped').touch()
""")
        framework = self.root / 'rc.subr'
        framework.write_text('. /etc/rc.subr\nload_rc_config() { eval "${rcvar}=\\${TEST_ENABLE:-YES}"; }\n')
        source = PACKAGE / 'src/usr/local/etc/rc.d' / (PACKAGE.name + '-backup')
        script = source.read_text().replace(ROUTE + '_backup', 'fixture_' + ROUTE + '_backup')
        originals = {'. /etc/rc.subr': '. ' + shlex.quote(str(framework)),
                     '/var/run/' + ROUTE + '-backup.pid': str(self.root / 'watch.pid'),
                     '/usr/local/opnsense/scripts/' + ROUTE + '/config_mirror.py': str(worker)}
        for original, replacement in originals.items():
            self.assertGreater(script.count(original), 0, 'Review watcher isolation after a source change.')
            script = script.replace(original, replacement)
        self.helper = self.root / 'watch-rc'
        self.helper.write_text(script)

    def request(self, action, **environment):
        return subprocess.run(['sh', str(self.helper), action], env={**os.environ, **environment}, capture_output=True, text=True, timeout=8)

    def wait_file(self, name):
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            if (self.root / name).exists():return
            time.sleep(0.025)
        self.fail('The private watcher did not publish ' + name)

    def stop_private_worker(self):
        if (self.root / 'started').exists() and not (self.root / 'stopped').exists():
            pid = int((self.root / 'started').read_text())
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            deadline=time.monotonic()+2
            while not (self.root/'stopped').exists() and time.monotonic()<deadline:time.sleep(0.025)

    def assert_started_and_stop(self):
        self.wait_file('started')
        self.assertTrue((self.root / 'reconciled').exists())
        self.assertEqual(int((self.root / 'watch.pid').read_text()), int((self.root / 'started').read_text()))
        self.assertEqual(self.request('status').returncode, 0)
        stopped = self.request('onestop')
        self.assertEqual(stopped.returncode, 0, stopped.stderr)
        self.wait_file('stopped')
        self.assertFalse((self.root / 'watch.pid').exists())
        self.assertNotEqual(self.request('status').returncode, 0)

    def test_start_status_and_stop_signal_only_the_private_watch_process(self):
        started = self.request('start')
        self.assertEqual(started.returncode, 0, started.stderr)
        self.assert_started_and_stop()

    def test_disabled_watch_does_not_start_without_explicit_one_action(self):
        self.request('start', TEST_ENABLE='NO')
        self.assertFalse((self.root / 'started').exists())
        self.assertFalse((self.root / 'reconciled').exists())
        self.assertFalse((self.root / 'watch.pid').exists())
        started = self.request('onestart', TEST_ENABLE='NO')
        self.assertEqual(started.returncode, 0, started.stderr)
        self.assert_started_and_stop()

    def test_reconcile_failure_prevents_worker_and_pid_creation(self):
        failed = self.request('start', TEST_RECONCILE_FAIL='1')
        self.assertNotEqual(failed.returncode, 0)
        self.assertTrue((self.root / 'reconciled').exists())
        self.assertFalse((self.root / 'started').exists())
        self.assertFalse((self.root / 'watch.pid').exists())


if __name__ == '__main__':
    unittest.main()
