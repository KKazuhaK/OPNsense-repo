"""Validate watcher PID, status and shutdown with the genuine FreeBSD rc framework."""
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

REPOSITORY = Path(__file__).resolve().parents[3]


@unittest.skipUnless(sys.platform.startswith('freebsd'), 'Requires the native FreeBSD daemon and rc framework')
class NativeWatchRcTests(unittest.TestCase):
    def test_three_watcher_scripts_start_report_status_and_stop_their_own_worker(self):
        for package, route, service in [('os-staticarp', 'staticarp', 'os-staticarp'),
                                        ('os-lucky', 'lucky', 'os-lucky'),
                                        ('os-ddns-go', 'ddnsgo', 'os-ddns-go')]:
            with self.subTest(route=route), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                worker = root / 'config_mirror.py'
                worker.write_text('''import json,os,signal,sys,time
from pathlib import Path
root=Path(__file__).parent
if sys.argv[1]=='reconcile':
    print(json.dumps({'ok':True,'snapshot':False,'changed':False}))
else:
    stopping=False
    def stop(signum,frame):
        global stopping
        stopping=True
    signal.signal(signal.SIGTERM,stop)
    (root/'started').write_text(str(os.getpid()))
    while not stopping: time.sleep(0.05)
    (root/'stopped').touch()
''')
                source = REPOSITORY / 'src' / package / 'src/usr/local/etc/rc.d' / (service + '-backup')
                script = source.read_text()
                script = script.replace(route + '_backup', 'native_' + route + '_backup')
                script = script.replace('/var/run/' + route + '-backup.pid', str(root / 'watch.pid'))
                script = script.replace('/usr/local/opnsense/scripts/' + route + '/config_mirror.py', str(worker))
                candidate = root / 'watch-rc'
                candidate.write_text(script)
                environment = dict(os.environ, **{'native_' + route + '_backup_enable': 'NO', route + '_enable': 'NO'})
                disabled = subprocess.run(['sh', str(candidate), 'start'], env=environment, capture_output=True)
                self.assertFalse((root / 'started').exists(), 'The fixture must initially have its rc flag disabled')
                start = subprocess.run(['sh', str(candidate), 'onestart'], env=environment, capture_output=True)
                try:
                    self.assertEqual(start.returncode, 0, start.stderr.decode())
                    deadline = time.monotonic() + 3
                    while not (root / 'started').exists() and time.monotonic() < deadline:
                        time.sleep(0.05)
                    self.assertTrue((root / 'started').exists(), 'The watcher worker was not launched')
                    first_pid = (root / 'watch.pid').read_text()
                    repeated = subprocess.run(['sh', str(candidate), 'onestart'], env=environment, capture_output=True)
                    self.assertIn(repeated.returncode, (0, 1), repeated.stderr.decode())
                    self.assertEqual((root / 'watch.pid').read_text(), first_pid, 'Repeated boot callbacks spawned another watcher')
                    status = subprocess.run(['sh', str(candidate), 'status'], capture_output=True)
                    self.assertEqual(status.returncode, 0, status.stderr.decode())
                    self.assertEqual(int((root / 'watch.pid').read_text()), int((root / 'started').read_text()))
                    stop = subprocess.run(['sh', str(candidate), 'onestop'], env=environment, capture_output=True)
                    self.assertEqual(stop.returncode, 0, stop.stderr.decode())
                    self.assertFalse((root / 'watch.pid').exists())
                    deadline = time.monotonic() + 3
                    while not (root / 'stopped').exists() and time.monotonic() < deadline:
                        time.sleep(0.05)
                    self.assertTrue((root / 'stopped').exists(), 'Stopping the watcher did not signal its own worker')
                finally:
                    if (root / 'started').exists() and not (root / 'stopped').exists():
                        pid = int((root / 'started').read_text())
                        try:
                            os.kill(pid, signal.SIGTERM)
                        except ProcessLookupError:
                            pass


if __name__ == '__main__':
    unittest.main()
