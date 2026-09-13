"""Exercise speed-test process failures and the real detached lock handoff."""
import contextlib
import fcntl
import importlib.util
import io
import json
import os
import signal
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

from test_speedtest import REAL, SCRIPT


class ExecutionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.state = Path(self.directory.name)
        spec = importlib.util.spec_from_file_location('execution_speedtest', SCRIPT)
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        self.module.STATE = str(self.state)
        for name, filename in [('RESULT', 'result.json'), ('PROGRESS', 'progress.json'),
                               ('LOCK', 'run.lock')]:
            setattr(self.module, name, str(self.state / filename))
        self.module.BINARY = str(self.state / 'speedtest-go')

    def process(self, output=REAL, exitcode=0):
        process = Mock(stdout=io.StringIO(output), pid=424242)
        process.wait.return_value = exitcode
        process.poll.return_value = exitcode
        return process

    def unlocked(self):
        with open(self.module.LOCK, 'a') as guard:
            fcntl.flock(guard, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def progress(self):
        return json.loads(Path(self.module.PROGRESS).read_text())

    def test_success_publishes_stages_result_units_and_private_permissions(self):
        process = self.process()
        updates = []
        original = self.module.publish

        def observe(*args, **kwargs):
            updates.append(args[0])
            return original(*args, **kwargs)

        with patch.object(self.module.subprocess, 'Popen', return_value=process) as launch, \
                patch.object(self.module, 'publish', side_effect=observe):
            self.assertEqual(0, self.module.main(['runner', '--server', '123', '--interface', 'em0']))
        self.assertEqual(['/bin/timeout', '180', self.module.BINARY, '--unix',
                          '--server', '123', '--interface', 'em0'], launch.call_args.args[0])
        self.assertTrue(launch.call_args.kwargs['start_new_session'])
        result = json.loads(Path(self.module.RESULT).read_text())
        self.assertAlmostEqual(267.69, result['servers'][0]['dl_speed'] * 8 / 1e6)
        self.assertEqual('done', self.progress()['state'])
        self.assertEqual('loss', self.progress()['stages'][-1]['stage'])
        self.assertEqual('done', updates[-1])
        self.assertGreater(updates.count('running'), 2)
        self.assertEqual(0o600, Path(self.module.RESULT).stat().st_mode & 0o777)
        self.assertEqual(0o644, Path(self.module.PROGRESS).stat().st_mode & 0o777)
        self.assertTrue(process.stdout.closed)
        self.unlocked()

    def test_launch_exit_and_partial_output_failures_remove_stale_results(self):
        for outcome in ('launch', 'exit', 'partial'):
            with self.subTest(outcome=outcome):
                Path(self.module.RESULT).write_text('{"stale":true}')
                process = self.process(exitcode=2) if outcome == 'exit' else self.process('ISP: 1.2.3.4 (ISP)\n')
                kwargs = {'side_effect': FileNotFoundError('missing executable')} if outcome == 'launch' else {'return_value': process}
                with patch.object(self.module.subprocess, 'Popen', **kwargs):
                    self.assertEqual(1, self.module.main(['runner']))
                self.assertFalse(Path(self.module.RESULT).exists())
                self.assertEqual('failed', self.progress()['state'])
                self.assertTrue(self.progress()['error'])
                if outcome != 'launch':
                    self.assertTrue(process.stdout.closed)
                self.unlocked()

    def test_elapsed_deadline_kills_and_reaps_child_before_reporting_failure(self):
        process = self.process('ISP: 1.2.3.4 (ISP)\n')
        with patch.object(self.module.subprocess, 'Popen', return_value=process), \
                patch.object(self.module.time, 'time', side_effect=[0, 0, 0, 181, 182]), \
                patch.object(self.module.os, 'killpg') as kill:
            self.assertEqual(1, self.module.main(['runner']))
        kill.assert_called_once_with(process.pid, signal.SIGKILL)
        process.wait.assert_called_once_with(timeout=5)
        self.assertTrue(process.stdout.closed)
        self.assertIn('time limit', self.progress()['error'])
        self.assertFalse(Path(self.module.RESULT).exists())
        self.unlocked()

    def test_atomic_publish_failures_keep_previous_bytes_and_remove_staging(self):
        target = Path(self.module.PROGRESS)
        target.write_bytes(b'previous')
        target.chmod(0o640)
        for operation in ('dump', 'chmod', 'rename'):
            with self.subTest(operation=operation):
                owner = self.module.json if operation == 'dump' else self.module.os
                with patch.object(owner, operation, side_effect=OSError('injected write failure')):
                    with self.assertRaises(OSError):
                        self.module.write(str(target), {'state': 'running'}, 0o644)
                self.assertEqual(b'previous', target.read_bytes())
                self.assertEqual(0o640, target.stat().st_mode & 0o777)
                self.assertEqual([target], list(self.state.iterdir()))

    def test_failed_progress_write_releases_run_lock(self):
        with patch.object(self.module, 'publish', side_effect=OSError('disk full')):
            with self.assertRaises(OSError):
                self.module.main(['runner'])
        self.unlocked()

    def test_midstream_write_failure_kills_and_reaps_engine_and_its_child_before_unlock(self):
        self.midstream_failure(use_timeout=False)

    @unittest.skipUnless(Path('/bin/timeout').is_file(), 'Requires the native timeout wrapper')
    def test_real_timeout_wrapper_failure_kills_engine_and_descendant(self):
        self.midstream_failure(use_timeout=True)

    def midstream_failure(self, use_timeout):
        child_pid = self.state / 'child.pid'
        fixture = self.state / 'engine.py'
        fixture.write_text(
            f'#!{sys.executable}\n'
            'import pathlib, subprocess, sys, time\n'
            'child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(10)"])\n'
            f'pathlib.Path({str(child_pid)!r}).write_text(str(child.pid))\n'
            'print("ISP: 1.2.3.4 (fixture)", flush=True)\n'
            'time.sleep(10)\n'
        )
        fixture.chmod(0o700)
        self.module.BINARY = str(fixture)
        original_launch = subprocess.Popen
        launched = []

        def launch(arguments, **options):
            command = arguments if use_timeout else [sys.executable, '-u', str(fixture)]
            process = original_launch(command, **options)
            launched.append(process)
            return process

        original_publish = self.module.publish
        updates = 0

        def publish(*arguments, **options):
            nonlocal updates
            updates += 1
            if updates == 2:
                raise OSError('injected progress disk failure')
            return original_publish(*arguments, **options)

        with patch.object(self.module.subprocess, 'Popen', side_effect=launch), \
                patch.object(self.module, 'publish', side_effect=publish):
            with self.assertRaisesRegex(OSError, 'progress disk failure'):
                self.module.main(['runner'])
        self.assertEqual(-signal.SIGKILL, launched[0].returncode)
        self.assertTrue(launched[0].stdout.closed)
        pid = int(child_pid.read_text())
        deadline = time.monotonic() + 3
        while True:
            status = subprocess.run(['ps', '-p', str(pid), '-o', 'stat='], capture_output=True, text=True)
            if not status.stdout.strip() or status.stdout.strip().startswith('Z'):
                break
            if time.monotonic() >= deadline:
                self.fail('The engine descendant survived the failed progress write')
            time.sleep(0.02)
        self.unlocked()

    @unittest.skipUnless(hasattr(os, 'fork'), 'Detached execution requires POSIX fork')
    def test_detached_child_keeps_lock_until_result_is_published(self):
        ready = self.state / 'ready'
        release = self.state / 'release'
        binary = self.state / 'fixture.py'
        binary.write_text(
            'import pathlib, time\n'
            f'ready = pathlib.Path({str(ready)!r})\n'
            f'release = pathlib.Path({str(release)!r})\n'
            'ready.touch()\n'
            'deadline = time.monotonic() + 8\n'
            'while not release.exists() and time.monotonic() < deadline:\n'
            '    time.sleep(0.02)\n'
            f'print({REAL!r}, flush=True)\n'
        )
        source = SCRIPT.read_text().replace("STATE = '/var/db/speedtest'", f'STATE = {str(self.state)!r}')
        # Replace the platform timeout executable with a bounded local fixture.
        source = source.replace("command = ['/bin/timeout', str(TIMEOUT), BINARY, '--unix'] + arguments",
                                f'command = [{sys.executable!r}, {str(binary)!r}] + arguments')
        runner = self.state / 'runner.py'
        runner.write_text(source)
        try:
            accepted = subprocess.run([sys.executable, str(runner), '--background'],
                                      capture_output=True, text=True, timeout=5)
            self.assertEqual(0, accepted.returncode, accepted.stderr)
            self.assertEqual({'status': 'ok'}, json.loads(accepted.stdout))
            deadline = time.monotonic() + 5
            while not ready.exists() and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertTrue(ready.exists(), 'Detached binary was not started')
            before = Path(self.module.PROGRESS).read_bytes()
            denied = subprocess.run([sys.executable, str(runner), '--background'],
                                    capture_output=True, text=True, timeout=5)
            self.assertEqual(1, denied.returncode)
            self.assertIn('already running', denied.stderr)
            self.assertEqual(before, Path(self.module.PROGRESS).read_bytes())
        finally:
            release.touch()
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                with contextlib.suppress(FileNotFoundError, json.JSONDecodeError):
                    if self.progress()['state'] == 'done':
                        break
                time.sleep(0.02)
        self.assertEqual('done', self.progress()['state'])
        self.assertEqual('16781', json.loads(Path(self.module.RESULT).read_text())['servers'][0]['id'])
        deadline = time.monotonic() + 2
        while True:
            try:
                self.unlocked()
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.02)
