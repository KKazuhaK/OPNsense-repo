"""Exercise real RC dispatch and restoration order with a scoped controller fixture."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

PACKAGE = Path(__file__).resolve().parents[1]


class RcBackupTests(unittest.TestCase):
    def fixture(self, action, restored_enabled='YES', fail_restore=False, fail_stop=False, absent_rc=False):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        events = root / 'events'
        events.touch()
        rc = root / 'service.rc'
        restored = root / 'restored.rc'
        old_config = root / 'old.json'
        default_config = root / 'default.json'
        old_pid = root / 'old.pid'
        old_pid.write_text('222\n')
        old_config.write_text('OLD_CONFIGURATION')
        default_config.write_text('OLD_DEFAULT_CONFIGURATION')
        # Restored RC deliberately removes config and pidfile overrides.
        rc.write_text(f'export sing_box_enable="NO"\nconfig="{old_config}"\npidfile="{old_pid}"\n')
        restored.write_text(f'sing_box_enable="{restored_enabled}"\n')
        alive = root / 'alive'
        if 'restart' in action:
            alive.touch()
        subr = root / 'rc.subr'
        subr.write_text('''load_rc_config() {
    printf '%s\n' load >> "$TEST_EVENTS"
    [ ! -f "$TEST_RC" ] || . "$TEST_RC"
}
ps() { printf '%s\n' sing-box; }
kill() {
    if [ "$1" = "-0" ]; then [ -f "$TEST_ALIVE" ]; return $?; fi
    [ "$TEST_FAIL_STOP" != "1" ] || return 1
    printf 'stop:%s:%s\n' "$config" "$pidfile" >> "$TEST_EVENTS"
    printf '%s' OLD_SHUTDOWN_CONFIGURATION > "$config"
    rm -f "$TEST_ALIVE"
}
fixture_start() {
    printf 'start:%s:%s:%s\n' "$config" "$pidfile" "$sing_box_enable" >> "$TEST_EVENTS"
    [ "$(cat "$config")" = "RESTORED_CONFIGURATION" ]
}
run_rc_command() {
    action="$1"
    case "$action" in
        one*) action="${action#one}"; sing_box_enable=YES ;;
        force*) action="${action#force}"; sing_box_enable=YES ;;
        fast*) action="${action#fast}" ;;
        quiet*) action="${action#quiet}" ;;
    esac
    if [ "$action" = start ]; then
        case "$sing_box_enable" in YES|yes) "$start_cmd" ;; *) return 0 ;; esac
    elif [ "$action" = stop ]; then
        "$stop_cmd"
    else
        return 1
    fi
}
''')
        mirror = root / 'config_mirror.py'
        mirror.write_text('''import os,sys
from pathlib import Path
with Path(os.environ['TEST_EVENTS']).open('a') as output: output.write('reconcile\\n')
if os.environ['TEST_FAIL_RESTORE']=='1': sys.exit(1)
if 'restart' in os.environ['TEST_ACTION'] and Path(os.environ['TEST_ALIVE']).exists(): sys.exit(2)
rc=Path(os.environ['TEST_RC'])
if os.environ['TEST_ABSENT_RC']=='1': rc.unlink(missing_ok=True)
else: rc.write_bytes(Path(os.environ['TEST_RESTORED_RC']).read_bytes())
Path(os.environ['TEST_DEFAULT_CONFIG']).write_text('RESTORED_CONFIGURATION')
''')
        integration = root / 'integration.py'
        integration.write_text("""import os,sys
from pathlib import Path
args=sys.argv[1:]
assert args[0]=='stop'
if os.environ['TEST_FAIL_STOP']=='1': sys.exit(1)
config=Path(args[args.index('--config')+1]); pid=Path(args[args.index('--pidfile')+1])
with Path(os.environ['TEST_EVENTS']).open('a') as output: output.write(f'stop:{config}:{pid}\\n')
config.write_text('OLD_SHUTDOWN_CONFIGURATION')
Path(os.environ['TEST_ALIVE']).unlink(missing_ok=True)
""")
        source = (PACKAGE / 'src/usr/local/etc/rc.d/sing-box').read_text()
        source = source.replace('. /etc/rc.subr', f'. "{subr}"', 1)
        source = source.replace('pidfile="/var/run/sing-box.pid"', 'pidfile="$TEST_DEFAULT_PID"', 1)
        source = source.replace('config="/usr/local/etc/sing-box/config.json"', 'config="$TEST_DEFAULT_CONFIG"', 1)
        source = source.replace('start_cmd="${name}_start"', 'start_cmd="fixture_start"', 1)
        source = source.replace('/usr/local/bin/python3 /usr/local/opnsense/scripts/singbox/config_mirror.py',
                                f'"{sys.executable}" "{mirror}"')
        source = source.replace('/usr/local/bin/python3 /usr/local/opnsense/scripts/singbox/integration.py',
                                f'"{sys.executable}" "{integration}"')
        candidate = root / 'sing-box'
        candidate.write_text(source)
        environment = {**os.environ, 'TEST_EVENTS': str(events), 'TEST_RC': str(rc),
                       'TEST_RESTORED_RC': str(restored), 'TEST_DEFAULT_CONFIG': str(default_config),
                       'TEST_DEFAULT_PID': str(root / 'default.pid'), 'TEST_ALIVE': str(alive),
                       'TEST_FAIL_RESTORE': str(int(fail_restore)), 'TEST_FAIL_STOP': str(int(fail_stop)),
                       'TEST_ABSENT_RC': str(int(absent_rc)), 'TEST_ACTION': action}
        result = subprocess.run(['sh', str(candidate), action], env=environment, capture_output=True, text=True)
        return root, result, events.read_text().splitlines()

    def test_start_reconciles_before_load_and_enabled_check(self):
        for action in ['start', 'onestart', 'faststart', 'forcestart', 'quietstart']:
            with self.subTest(action=action):
                root, result, events = self.fixture(action)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(events[:2], ['reconcile', 'load'])
                self.assertTrue(any(event.startswith('start:') for event in events))

    def test_restart_stops_old_pid_before_reconcile_and_reloads_removed_overrides(self):
        for action in ['restart', 'onerestart', 'fastrestart', 'forcerestart', 'quietrestart']:
            for enabled in ['YES', 'NO']:
                with self.subTest(action=action, enabled=enabled):
                    root, result, events = self.fixture(action, enabled)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(events[:2], ['load', f'stop:{root / "old.json"}:{root / "old.pid"}'])
                    self.assertEqual(events[2:4], ['reconcile', 'load'])
                    self.assertEqual((root / 'old.json').read_text(), 'OLD_SHUTDOWN_CONFIGURATION')
                    starts = [event for event in events if event.startswith('start:')]
                    should_start = enabled == 'YES' or action.startswith(('one', 'force'))
                    self.assertEqual(bool(starts), should_start)
                    if starts:
                        self.assertEqual(starts[0], f'start:{root / "default.json"}:{root / "default.pid"}:YES')

    def test_restored_rc_absence_clears_old_enable_and_custom_paths(self):
        root, result, events = self.fixture('restart', absent_rc=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(events[-2:], ['reconcile', 'load'])
        self.assertFalse(any(event.startswith('start:') for event in events))

    def test_failed_restore_prevents_load_and_start(self):
        root, result, events = self.fixture('start', fail_restore=True)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(events, ['reconcile'])
        self.assertIn('Unable to prepare', result.stdout)

    def test_failed_stop_prevents_restore_and_start(self):
        root, result, events = self.fixture('restart', fail_stop=True)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(events, ['load'])
        self.assertTrue((root / 'alive').exists())


if __name__ == '__main__':
    unittest.main()
