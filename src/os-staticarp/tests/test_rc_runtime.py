"""Verify service reconciliation and enable semantics with private rc command stubs."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

PACKAGE = Path(__file__).resolve().parents[1]


class ServiceRcTests(unittest.TestCase):
    def test_start_reconciles_before_rc_load_and_honors_restored_disable(self):
        for action, enabled, expected in [('start', 'YES', ['reconcile', 'load', 'apply']),
                                           ('start', 'NO', ['reconcile', 'load']),
                                           ('onestart', 'NO', ['reconcile', 'load', 'apply']),
                                           ('restart', 'YES', ['reconcile', 'load', 'reset', 'apply']),
                                           ('stop', 'YES', ['load', 'reset'])]:
            with self.subTest(action=action, enabled=enabled), tempfile.TemporaryDirectory(prefix='staticarp-rc-') as temporary:
                root = Path(temporary)
                events = root / 'events'
                rc = root / 'rc.subr'
                rc.write_text('''load_rc_config() { echo load >> "$STATICARP_TEST_EVENTS"; staticarp_enable="$STATICARP_TEST_ENABLE"; }
run_rc_command() {
    case "$1" in
        stop) "$stop_cmd" ;;
        restart) "$stop_cmd"; [ "$staticarp_enable" = YES ] && "$start_cmd" || true ;;
        onestart) "$start_cmd" ;;
        start) [ "$staticarp_enable" = YES ] && "$start_cmd" || true ;;
        *) exit 64 ;;
    esac
}
''')
                commands = '''mirror() { echo reconcile >> "$STATICARP_TEST_EVENTS"; }
control() { echo "$1" >> "$STATICARP_TEST_EVENTS"; }
'''
                source = (PACKAGE / 'src/usr/local/etc/rc.d/os-staticarp').read_text()
                source = source.replace('. /etc/rc.subr', '. "' + str(rc) + '"\n' + commands, 1)
                source = source.replace('/usr/local/bin/python3 /usr/local/opnsense/scripts/staticarp/config_mirror.py reconcile', 'mirror')
                source = source.replace('/usr/local/sbin/staticarpctl', 'control')
                candidate = root / 'rc-staticarp'
                candidate.write_text(source)
                process = subprocess.run(['sh', str(candidate), action], capture_output=True,
                                         env={**os.environ, 'STATICARP_TEST_EVENTS': str(events), 'STATICARP_TEST_ENABLE': enabled}, timeout=5)
                self.assertEqual(process.returncode, 0, process.stderr)
                self.assertEqual(events.read_text().splitlines(), expected)

    def test_failed_reconcile_prevents_rc_load_or_kernel_control(self):
        with tempfile.TemporaryDirectory(prefix='staticarp-rc-') as temporary:
            root = Path(temporary)
            events = root / 'events'
            rc = root / 'rc.subr'
            rc.write_text('load_rc_config() { echo BAD >> "$STATICARP_TEST_EVENTS"; }\n'
                          'run_rc_command() { echo BAD >> "$STATICARP_TEST_EVENTS"; }\n')
            source = (PACKAGE / 'src/usr/local/etc/rc.d/os-staticarp').read_text()
            source = source.replace('. /etc/rc.subr', '. "' + str(rc) + '"\nmirror() { return 1; }', 1)
            source = source.replace('/usr/local/bin/python3 /usr/local/opnsense/scripts/staticarp/config_mirror.py reconcile', 'mirror')
            candidate = root / 'rc-staticarp'
            candidate.write_text(source)
            process = subprocess.run(['sh', str(candidate), 'start'], capture_output=True,
                                     env={**os.environ, 'STATICARP_TEST_EVENTS': str(events)}, timeout=5)
            self.assertEqual(process.returncode, 1)
            self.assertFalse(events.exists())


if __name__ == '__main__':
    unittest.main()
