"""Exercise real service bodies with private RC files and isolated commands."""
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest

PACKAGE = Path(__file__).parents[1]
ROUTE = 'lucky' if PACKAGE.name == 'os-lucky' else 'ddnsgo'
SERVICE = PACKAGE.name
SOURCE = PACKAGE / 'src/usr/local/etc/rc.d' / SERVICE
NATIVE = sys.platform.startswith('freebsd')


class ServiceLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix=ROUTE + '-rc-contract-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.application = self.root / 'application $literal `literal` "quoted"'
        self.application.mkdir()
        self.config = self.application / 'config.conf'
        self.config.write_text('OLD_RUNNING_CONFIGURATION')
        self.rc = self.root / 'service.rc'
        self.restored = self.root / 'restored.rc'
        self.events = self.root / 'events'
        self.pid = self.root / 'supervisor.pid'
        self.rc.write_text(self.rc_contents())
        self.restored.write_text(self.rc_contents(port='16602', listen=':9877', interval='123', extra='-n -skipVerify'))
        self.environment = {**os.environ, 'TEST_ROOT': str(self.root), 'TEST_RC': str(self.rc), 'TEST_RESTORED_RC': str(self.restored),
                            'TEST_CONFIGURATION': str(self.config), 'TEST_APPLY': '1'}
        mirror = self.root / 'config_mirror.py'
        mirror.write_text(r"""import json,os,sys
from pathlib import Path
root=Path(os.environ['TEST_ROOT'])
with (root/'events').open('a') as output:output.write(json.dumps({'call':sys.argv[1]})+'\n')
if os.environ.get('TEST_BACKUP_FAIL')==sys.argv[1]:sys.exit(7)
if sys.argv[1]=='reconcile' and os.environ.get('TEST_APPLY')=='1':
    Path(os.environ['TEST_RC']).write_bytes(Path(os.environ['TEST_RESTORED_RC']).read_bytes())
    Path(os.environ['TEST_CONFIGURATION']).write_text('RESTORED_CONFIGURATION')
""")
        daemon = self.root / 'daemon'
        daemon.write_text('#!' + sys.executable + '\n' + r"""import json,os,sys
from pathlib import Path
with (Path(os.environ['TEST_ROOT'])/'events').open('a') as output:output.write(json.dumps({'call':'daemon','args':sys.argv[1:]})+'\n')
sys.exit(6 if os.environ.get('TEST_DAEMON_FAIL') else 0)
""")
        daemon.chmod(0o755)
        framework = self.root / 'rc.subr'
        prefix = '. /etc/rc.subr\n' if NATIVE else ''
        framework.write_text(prefix + r"""load_rc_config() {
    printf '{"call":"load_rc"}\n' >> "$TEST_ROOT/events"
    if [ -f "$TEST_RC" ]; then . "$TEST_RC"; fi
}
checkyesno() { eval "value=\${$1}"; [ "$value" = "YES" ]; }
pgrep() { [ "$2" = 111 ] && echo 222; }
kill() {
    if [ "$1" = "-0" ]; then
        case "$2" in
            111) [ -f "$TEST_ROOT/parent-alive" ]; return $? ;;
            222) [ -f "$TEST_ROOT/child-alive" ]; return $? ;;
            *) return 1 ;;
        esac
    fi
    if [ "$2" = 111 ]; then
        printf '{"call":"supervisor_stop"}\n' >> "$TEST_ROOT/events"
        rm -f "$TEST_ROOT/parent-alive"
    elif [ "$2" = 222 ]; then
        printf '{"call":"writer_stop"}\n' >> "$TEST_ROOT/events"
        printf '%s' OLD_SHUTDOWN_CONFIGURATION > "$TEST_CONFIGURATION"
        [ "${TEST_STUCK:-}" = yes ] || rm -f "$TEST_ROOT/child-alive"
    else
        return 1
    fi
}
sleep() { :; }
""")
        if not NATIVE:
            with framework.open('a') as output:
                output.write(r"""run_rc_command() {
    case "$1" in
        start) checkyesno "$rcvar" || return 0; "$start_precmd" && "$start_cmd" ;;
        onestart|forcestart) "$start_precmd" && "$start_cmd" ;;
        restart) checkyesno "$rcvar" || return 0; "$restart_cmd" ;;
        onerestart|forcerestart) "$restart_cmd" ;;
        stop|onestop) "$stop_cmd" ;;
        status) "$status_cmd" ;;
        *) return 1 ;;
    esac
}
""")
        script = SOURCE.read_text()
        replacements = {'. /etc/rc.subr': '. ' + shlex.quote(str(framework)),
                        'pidfile="/var/run/${name}.pid"': 'pidfile="' + str(self.pid) + '"',
                        'logfile="/var/log/${name}.log"': 'logfile="' + str(self.root / 'log') + '"',
                        'command="/usr/sbin/daemon"': 'command="' + str(daemon) + '"',
                        f'{ROUTE}_bin="/usr/local/bin/' + ('lucky' if ROUTE == 'lucky' else 'ddns-go') + '"': f'{ROUTE}_bin="{daemon}"'}
        for original, replacement in replacements.items():
            self.assertEqual(script.count(original), 1, 'Review command isolation after a source change.')
            script = script.replace(original, replacement, 1)
        driver = f'/usr/local/bin/python3 /usr/local/opnsense/scripts/{ROUTE}/config_mirror.py'
        self.assertGreater(script.count(driver), 0)
        script = script.replace(driver, shlex.quote(sys.executable) + ' ' + shlex.quote(str(mirror)))
        fallback = '/usr/local/etc/lucky' if ROUTE == 'lucky' else '/usr/local/etc/ddns-go/config.yaml'
        script = script.replace(fallback, str(self.root / 'default-application'))
        self.candidate = self.root / SERVICE
        self.candidate.write_text(script)

    def rc_contents(self, enabled='YES', port='16601', listen=':9876', interval='300', extra=''):
        if ROUTE == 'lucky':
            values = {'enable': enabled, 'conf_dir': str(self.application), 'http_port': port}
        else:
            values = {'enable': enabled, 'config': str(self.config), 'listen': listen, 'interval': interval, 'extra_args': extra}
        def quote(value):
            return '"' + value.replace('\\', '\\\\').replace('"', '\\"').replace('$', '\\$').replace('`', '\\`') + '"'
        return ''.join(f'{ROUTE}_{name}={quote(value)}\n' for name, value in values.items())

    def request(self, action, **environment):
        return subprocess.run(['sh', str(self.candidate), action], env={**self.environment, **environment}, capture_output=True, text=True, timeout=10)

    def calls(self):
        return [json.loads(line) for line in self.events.read_text().splitlines()] if self.events.exists() else []

    def running(self):
        self.pid.write_text('111\n')
        (self.root / 'parent-alive').touch()
        (self.root / 'child-alive').touch()

    def test_status_does_not_initialize_or_mirror_configuration(self):
        self.rc.unlink()
        result = self.request('status')
        self.assertEqual(result.returncode, 1)
        self.assertNotIn('reconcile', [event['call'] for event in self.calls()])
        self.assertNotIn('mirror', [event['call'] for event in self.calls()])
        self.assertFalse((self.root / 'log').exists())
        self.assertFalse((self.root / 'default-application').exists())
        self.assertFalse(self.rc.exists())

    def test_start_preloads_restored_rc_and_preserves_literal_path_arguments(self):
        result = self.request('start')
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.calls()
        self.assertEqual([event['call'] for event in calls], ['reconcile', 'load_rc', 'daemon', 'mirror'])
        arguments = calls[2]['args']
        if ROUTE == 'lucky':
            self.assertEqual(arguments[-4:], ['-cd', str(self.application), '-port', '16602'])
        else:
            self.assertEqual(arguments[-8:], ['-c', str(self.config), '-l', ':9877', '-f', '123', '-n', '-skipVerify'])
        self.assertEqual((self.root / 'log').stat().st_mode & 0o777, 0o600)

    def test_disabled_restored_rc_does_not_launch_normal_start_but_forced_start_does(self):
        self.restored.write_text(self.rc_contents(enabled='NO'))
        self.request('start')
        self.assertNotIn('daemon', [event['call'] for event in self.calls()])
        self.events.unlink()
        self.assertEqual(self.request('onestart').returncode, 0)
        self.assertIn('daemon', [event['call'] for event in self.calls()])
        self.assertIn(f'{ROUTE}_enable="NO"', self.rc.read_text())

    def test_restart_stops_writers_before_import_and_obeys_restored_enable_choice(self):
        for enabled, action, start in [('YES', 'restart', True), ('NO', 'restart', False), ('NO', 'onerestart', True)]:
            with self.subTest(enabled=enabled, action=action):
                self.rc.write_text(self.rc_contents())
                self.restored.write_text(self.rc_contents(enabled=enabled, port='16602', listen=':9877'))
                self.events.unlink(missing_ok=True)
                self.running()
                result = self.request(action)
                self.assertEqual(result.returncode, 0, result.stderr)
                calls = [event['call'] for event in self.calls()]
                self.assertLess(calls.index('writer_stop'), calls.index('reconcile'))
                self.assertLess(calls.index('reconcile'), calls.index('mirror'))
                self.assertEqual('daemon' in calls, start)
                self.assertEqual(self.config.read_text(), 'RESTORED_CONFIGURATION')

    def test_stuck_writer_blocks_import_daemon_and_backup(self):
        self.running()
        result = self.request('restart', TEST_STUCK='yes')
        self.assertNotEqual(result.returncode, 0)
        calls = [event['call'] for event in self.calls()]
        self.assertIn('writer_stop', calls)
        for forbidden in ['reconcile', 'daemon', 'mirror']:
            self.assertNotIn(forbidden, calls)
        self.assertTrue(self.pid.exists())
        self.assertEqual(self.config.read_text(), 'OLD_SHUTDOWN_CONFIGURATION')

    def test_reconcile_failure_prevents_start_and_rc_loading(self):
        original = self.rc.read_bytes()
        result = self.request('start', TEST_BACKUP_FAIL='reconcile')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.calls(), [{'call': 'reconcile'}])
        self.assertEqual(self.rc.read_bytes(), original)
        self.assertFalse((self.root / 'log').exists())

    def test_daemon_or_backup_failure_has_nonzero_status(self):
        result = self.request('start', TEST_DAEMON_FAIL='1')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('mirror', [event['call'] for event in self.calls()])
        self.events.unlink()
        result = self.request('start', TEST_BACKUP_FAIL='mirror')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual([event['call'] for event in self.calls()][-2:], ['daemon', 'mirror'])

    def test_stop_flushes_writers_before_mirroring_and_removes_own_pid(self):
        self.running()
        self.assertEqual(self.request('onestop').returncode, 0)
        calls = [event['call'] for event in self.calls()]
        self.assertLess(calls.index('writer_stop'), calls.index('mirror'))
        self.assertNotIn('reconcile', calls)
        self.assertFalse(self.pid.exists())
        self.assertEqual(self.config.read_text(), 'OLD_SHUTDOWN_CONFIGURATION')


if __name__ == '__main__':
    unittest.main()
