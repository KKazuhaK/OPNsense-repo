"""Check terminal metadata and execute the real rc functions with private dependencies."""
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

PACKAGE = Path(__file__).resolve().parents[2]
SOURCE = PACKAGE / 'src/usr/local/opnsense/scripts/ttyd/manage.py'
spec = importlib.util.spec_from_file_location('ttyd_runtime', SOURCE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ttyd-runtime-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.addCleanup(patch.stopall)
        patch.object(m, 'CONFIG', self.root / 'config.xml').start()
        patch.object(m, 'RC_CONFIG', self.root / 'rc').start()

    def test_ssh_port_bounds_missing_empty_and_malformed_system_configuration(self):
        for value, expected in (('1', 1), ('65535', 65535), ('0', 22), ('-1', 22),
                                ('65536', 22), ('', 22), ('SENTINEL_SECRET', 22)):
            m.CONFIG.write_text('<opnsense><system><ssh><port>' + value + '</port></ssh></system></opnsense>')
            self.assertEqual(m.ssh_port(), expected)
        m.CONFIG.write_text('<invalid')
        self.assertEqual(m.ssh_port(), 22)
        m.CONFIG.unlink()
        self.assertEqual(m.ssh_port(), 22)

    def test_status_reports_stopped_service_and_only_public_metadata(self):
        m.RC_CONFIG.write_text('ttyd_interface="::1"\nttyd_port="7682"\nttyd_command="SENTINEL_PRIVATE_COMMAND"\n')
        with patch.object(m, 'run', return_value=SimpleNamespace(returncode=1)) as run:
            result = m.dispatch('status')
        self.assertFalse(result['running'])
        self.assertEqual((result['listen'], result['port'], result['target']), ('::1', '7682', 'Custom command'))
        self.assertNotIn('SENTINEL_', str(result))
        run.assert_called_once_with('status')

    def test_service_runner_passes_a_single_verb_without_shell_interpretation(self):
        with patch.object(m.subprocess, 'run', return_value=SimpleNamespace(returncode=0)) as run:
            m.run('restart')
        run.assert_called_once_with([m.RC, 'onerestart'], capture_output=True, text=True, timeout=30)
        with patch.object(m, 'run') as run:
            self.assertEqual(m.dispatch('restart; command')['status'], 'failed')
        run.assert_not_called()

    def test_mirror_requires_success_and_explicit_true_even_when_worker_output_is_wrong(self):
        for code, output in ((0, '{"ok":true}'), (0, '{"ok":1}'), (0, '{}'),
                             (0, '[]'), (0, 'invalid'), (1, '{"ok":true}')):
            with patch.object(m.subprocess, 'run', return_value=SimpleNamespace(returncode=code, stdout=output)):
                self.assertEqual(m.mirror_configuration(), code == 0 and output == '{"ok":true}')
        for error in (OSError('SENTINEL_PRIVATE_FAILURE'), subprocess.TimeoutExpired('private', 1)):
            with patch.object(m.subprocess, 'run', side_effect=error):
                self.assertFalse(m.mirror_configuration())

    def test_cli_query_failure_returns_safe_json(self):
        source = SOURCE.read_text().replace("RC = '/usr/local/etc/rc.d/os-ttyd'", "RC = " + repr(str(self.root / 'absent-rc')))
        source = source.replace("CONFIG = Path('/conf/config.xml')", 'CONFIG = Path(' + repr(str(self.root / 'config.xml')) + ')')
        source = source.replace("RC_CONFIG = Path('/etc/rc.conf.d/ttyd')", 'RC_CONFIG = Path(' + repr(str(self.root / 'rc')) + ')')
        runner = self.root / 'runner.py'
        runner.write_text(source)
        result = subprocess.run([sys.executable, str(runner)], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)['status'], 'failed')
        self.assertEqual(result.stderr, '')


class RcTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ttyd-rc-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.events = self.root / 'events'
        self.env = dict(os.environ, TTYD_TEST_EVENTS=str(self.events), TTYD_TEST_ROOT=str(self.root))
        self.pid = self.root / 'var/run/ttyd.pid'
        self.pid.parent.mkdir(parents=True)
        self.log = self.root / 'var/log/ttyd.log'
        self.log.parent.mkdir(parents=True)
        self.rc_config = self.root / 'etc/rc.conf.d/ttyd'
        self.rc_config.parent.mkdir(parents=True)
        self.rc_config.write_text('ttyd_enable="YES"\nttyd_port="7682"\n')
        self.bin = self.root / 'usr/local/os-ttyd/bin/ttyd'
        self.executable(self.bin, '#!/bin/sh\nexit 0\n')
        self.executable(self.root / 'usr/local/bin/python3', '''#!/bin/sh
printf 'python %s\\n' "$*" >> "$TTYD_TEST_EVENTS"
case "$*" in *ssh-port) printf '%s\\n' "${TTYD_TEST_SSH_PORT:-10511}";;
*) exit "${TTYD_TEST_RESTORE_FAIL:-0}";; esac
''')
        self.executable(self.root / 'usr/sbin/daemon', '''#!/usr/bin/env python3
import json,os,sys
with open(os.environ['TTYD_TEST_EVENTS'],'a') as out: out.write('daemon '+json.dumps(sys.argv[1:])+'\\n')
''')
        self.executable(self.root / 'bin/timeout', '''#!/bin/sh
echo "timeout $*" >> "$TTYD_TEST_EVENTS"
shift
exec "$@"
''')
        self.executable(self.root / 'bin/ps', '''#!/bin/sh
echo "ps $*" >> "$TTYD_TEST_EVENTS"
[ "${TTYD_TEST_PS_FAIL:-0}" = 0 ] || exit 1
printf '%s\\n' "${TTYD_TEST_PS_IDENTITY-daemon daemon: ttyd:daemon[12346] (daemon)}"
''')
        library = self.root / 'rc.subr'
        library.write_text('''load_rc_config() {
    echo load >> "$TTYD_TEST_EVENTS"
    . "$TTYD_TEST_ROOT/etc/rc.conf.d/ttyd"
}
service() { echo "service $*" >> "$TTYD_TEST_EVENTS"; return "${TTYD_TEST_SSH_FAIL:-0}"; }
kill() { echo "kill $*" >> "$TTYD_TEST_EVENTS"; return "${TTYD_TEST_KILL_FAIL:-0}"; }
pkill() { echo "pkill $*" >> "$TTYD_TEST_EVENTS"; }
run_rc_command() {
    case "$1" in
    start) [ "$ttyd_enable" = YES ] || return 0; ttyd_prestart && ttyd_start;;
    onestart) ttyd_prestart && ttyd_start;;
    stop|onestop) ttyd_stop;;
    status|onestatus) ttyd_status;;
    esac
}
''')
        source = (PACKAGE / 'src/usr/local/etc/rc.d/os-ttyd').read_text()
        source = source.replace('. /etc/rc.subr', '. __TTYD_TEST_RC_SUBR__')
        source = re.sub(r'(?<![A-Za-z0-9_./-])/(usr/local|usr/sbin|etc|var|bin)(?=/)',
                        lambda match: str(self.root / match.group(1)), source)
        source = source.replace('__TTYD_TEST_RC_SUBR__', shlex.quote(str(library)))
        self.script = self.root / 'rc'
        self.script.write_text(source)

    def executable(self, path, source):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source)
        path.chmod(0o700)

    def invoke(self, action, **environment):
        return subprocess.run(['sh', str(self.script), action], capture_output=True, text=True,
                              env=dict(self.env, **environment), timeout=5)

    def trace(self):
        return self.events.read_text().splitlines() if self.events.exists() else []

    def test_invalid_pid_never_queries_or_signals_a_process_or_group(self):
        for pid in ('', '0', '1', '0001', '-1', 'garbage', '2 3', '9999999999999999999999999999999'):
            with self.subTest(pid=pid):
                self.events.unlink(missing_ok=True)
                self.pid.write_text(pid)
                self.assertEqual(self.invoke('onestatus').returncode, 1)
                self.assertFalse(any(line.startswith(('kill ', 'ps ', 'timeout ')) for line in self.trace()))
                self.assertEqual(self.invoke('onestop').returncode, 0)
                self.assertFalse(self.pid.exists())
                self.assertFalse(any(line.startswith(('kill ', 'pkill ')) for line in self.trace()))

    def test_stop_signals_only_valid_daemon_and_children_then_removes_pid(self):
        self.pid.write_text('12345\n')
        self.assertEqual(self.invoke('onestop').returncode, 0)
        self.assertEqual([line for line in self.trace() if line.startswith(('kill ', 'pkill '))],
                         ['kill -0 12345', 'pkill -TERM -P 12345', 'kill -TERM 12345'])
        self.assertFalse(self.pid.exists())
        self.assertTrue(any(line.startswith('timeout 2 ') for line in self.trace()))
        self.assertTrue(any(line.endswith('-p 12345 -o comm= -o command=') for line in self.trace()))

    def test_reused_pid_wrong_title_or_failed_identity_check_never_signals(self):
        for identity in ('sleep /bin/sleep 30', 'daemon daemon: other:daemon[12346] (daemon)',
                         'python daemon: ttyd:daemon[12346] (daemon)',
                         'daemon daemon: ttyd:daemon[12346] (daemon) extra', ''):
            with self.subTest(identity=identity):
                self.events.unlink(missing_ok=True)
                self.pid.write_text('12345\n')
                self.assertEqual(1, self.invoke('onestatus', TTYD_TEST_PS_IDENTITY=identity).returncode)
                self.assertEqual(0, self.invoke('onestop', TTYD_TEST_PS_IDENTITY=identity).returncode)
                self.assertFalse(self.pid.exists())
                self.assertFalse(any(line.startswith(('kill ', 'pkill ')) for line in self.trace()))
        self.events.unlink(missing_ok=True)
        self.pid.write_text('12345\n')
        self.assertEqual(0, self.invoke('onestop', TTYD_TEST_PS_FAIL='1').returncode)
        self.assertFalse(any(line.startswith(('kill ', 'pkill ')) for line in self.trace()))

    def test_dead_pid_reports_stopped_and_does_not_send_termination(self):
        self.pid.write_text('12345\n')
        self.assertEqual(self.invoke('onestatus', TTYD_TEST_KILL_FAIL='1').returncode, 1)
        self.assertEqual(self.invoke('onestop', TTYD_TEST_KILL_FAIL='1').returncode, 0)
        self.assertFalse(any('-TERM' in line for line in self.trace()))

    def test_start_restores_before_reading_rc_and_uses_current_ssh_port_and_private_log(self):
        self.assertEqual(self.invoke('onestart').returncode, 0)
        trace = self.trace()
        self.assertIn('config_mirror.py reconcile', trace[0])
        self.assertEqual(trace[1], 'load')
        arguments = json.loads(next(line[7:] for line in trace if line.startswith('daemon ')))
        self.assertIn('--writable', arguments)
        self.assertEqual(arguments[arguments.index('--port') + 1], '7682')
        self.assertIn('-p 10511', arguments[-1])
        self.assertEqual(self.log.stat().st_mode & 0o777, 0o600)

    def test_restore_failure_disabled_service_missing_binary_and_ssh_failure_do_not_launch(self):
        self.assertNotEqual(self.invoke('onestart', TTYD_TEST_RESTORE_FAIL='1').returncode, 0)
        self.assertNotIn('load', self.trace())
        self.events.unlink()
        self.rc_config.write_text('ttyd_enable="NO"\n')
        self.assertEqual(self.invoke('start').returncode, 0)
        self.assertFalse(any(line.startswith('daemon ') for line in self.trace()))
        self.assertNotEqual(self.invoke('onestart', TTYD_TEST_SSH_FAIL='1').returncode, 0)
        self.bin.unlink()
        self.assertNotEqual(self.invoke('onestart').returncode, 0)
        self.assertFalse(any(line.startswith('daemon ') for line in self.trace()))

    def test_custom_terminal_command_and_literal_shell_characters_remain_single_argument(self):
        custom = "printf '%s' 'SENTINEL_PRIVATE; $(example)'"
        self.rc_config.write_text('ttyd_enable="YES"\nttyd_command=' + shlex.quote(custom) + '\n')
        self.assertEqual(self.invoke('onestart').returncode, 0)
        arguments = json.loads(next(line[7:] for line in self.trace() if line.startswith('daemon ')))
        self.assertEqual(arguments[-2:], ['-c', custom])


@unittest.skipUnless(sys.platform.startswith('freebsd'), 'Requires native FreeBSD daemon process titles')
class NativePidTests(unittest.TestCase):
    def setUp(self):
        # Reuse private rc dependencies, retaining genuine ps and signal commands.
        self.rc = RcTests(methodName='runTest')
        self.rc.setUp()
        self.addCleanup(self.rc.doCleanups)
        source = self.rc.script.read_text()
        for executable in ('timeout', 'ps'):
            source = source.replace(str(self.rc.root / 'bin' / executable), '/bin/' + executable)
        self.rc.script.write_text(source)
        library = self.rc.root / 'rc.subr'
        library.write_text('\n'.join(line for line in library.read_text().splitlines()
                                     if not line.startswith(('kill() ', 'pkill() '))) + '\n')

    def alive(self, pid):
        result = subprocess.run(['/bin/ps', '-p', str(pid), '-o', 'stat='],
                                capture_output=True, text=True, timeout=2)
        state = result.stdout.strip()
        return result.returncode == 0 and bool(state) and not state.startswith('Z')

    def wait_for(self, predicate):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(0.02)
        self.assertTrue(predicate(), 'The private native process did not reach the expected state')

    def cleanup_child(self, pid):
        result = subprocess.run(['/bin/ps', '-p', str(pid), '-o', 'command='],
                                capture_output=True, text=True, timeout=2)
        if str(self.rc.root) in result.stdout:
            try:
                os.kill(pid, 15)
            except ProcessLookupError:
                pass

    def test_native_daemon_title_is_accepted_and_supervisor_and_child_are_stopped(self):
        childfile = self.rc.root / 'child.pid'
        child = self.rc.root / 'child.py'
        child.write_text('import os,pathlib,time\n'
                         f'pathlib.Path({str(childfile)!r}).write_text(str(os.getpid()))\n'
                         'time.sleep(30)\n')
        subprocess.run(['/usr/sbin/daemon', '-P', str(self.rc.pid), '-r', '-f',
                        '-t', 'ttyd:daemon', sys.executable, str(child)],
                       check=True, capture_output=True, timeout=5)
        supervisor = None
        child_pid = None
        try:
            self.wait_for(lambda: self.rc.pid.exists() and childfile.exists())
            supervisor = int(self.rc.pid.read_text())
            child_pid = int(childfile.read_text())
            self.assertTrue(self.alive(child_pid))
            status = self.rc.invoke('onestatus')
            self.assertEqual(0, status.returncode, status.stderr)
            self.assertIn(f'is running as pid {supervisor}', status.stdout)
            stopped = self.rc.invoke('onestop')
            self.assertEqual(0, stopped.returncode, stopped.stderr)
            self.assertFalse(self.rc.pid.exists())
            self.wait_for(lambda: not self.alive(supervisor) and not self.alive(child_pid))
        finally:
            if supervisor is not None and self.alive(supervisor):
                os.kill(supervisor, 15)
            if childfile.exists():
                self.cleanup_child(int(childfile.read_text()))
            if child_pid is not None:
                self.cleanup_child(child_pid)

    def test_stale_live_unrelated_pid_preserves_both_process_and_child(self):
        childfile = self.rc.root / 'unrelated-child.pid'
        child = self.rc.root / 'unrelated-child.py'
        child.write_text('import time\ntime.sleep(30)\n')
        parent = self.rc.root / 'unrelated-parent.py'
        parent.write_text('import pathlib,subprocess,sys\n'
                          f'child=subprocess.Popen([sys.executable,{str(child)!r}])\n'
                          f'pathlib.Path({str(childfile)!r}).write_text(str(child.pid))\n'
                          'child.wait()\n')
        process = subprocess.Popen([sys.executable, str(parent)],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        child_pid = None
        try:
            self.wait_for(childfile.exists)
            child_pid = int(childfile.read_text())
            self.rc.pid.write_text(str(process.pid))
            status = self.rc.invoke('onestatus')
            self.assertEqual(1, status.returncode, status.stderr)
            self.assertIn('is not running', status.stdout)
            self.assertEqual(0, self.rc.invoke('onestop').returncode)
            self.assertFalse(self.rc.pid.exists())
            self.assertIsNone(process.poll(), 'Stop signalled the unrelated process')
            self.assertTrue(self.alive(child_pid), 'Stop signalled an unrelated child')
        finally:
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=5)
            if child_pid is not None:
                self.cleanup_child(child_pid)


if __name__ == '__main__':
    unittest.main()
