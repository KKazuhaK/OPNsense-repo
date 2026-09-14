"""Run real service scripts with isolated command stubs and no live services."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

REPOSITORY = Path(__file__).resolve().parents[3]


class RcBackupWiringTests(unittest.TestCase):
    def test_staticarp_status_does_not_create_configuration_or_update_the_backup(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = REPOSITORY / 'src/os-staticarp/src/usr/local/sbin/staticarpctl'
            candidate = root / 'staticarpctl'
            configuration = root / 'configuration'
            candidate.write_text(source.read_text().replace('CONFIG_DIR="/usr/local/etc/staticarp"',
                                                           f'CONFIG_DIR="{configuration}"', 1))
            result = subprocess.run(['sh', str(candidate), 'status'], capture_output=True)
            self.assertEqual(result.returncode, 0)
            self.assertIn(b'enabled=NO', result.stdout)
            self.assertFalse(configuration.exists())

    def test_restart_stops_writers_before_import_and_reloads_restored_rc_values(self):
        for package, route, service in [('os-lucky', 'lucky', 'os-lucky'), ('os-ddns-go', 'ddnsgo', 'os-ddns-go')]:
            for enabled, action in [('YES', 'restart'), ('NO', 'restart'), ('NO', 'onerestart')]:
                with self.subTest(route=route, enabled=enabled, action=action), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    application = root / 'application'
                    application.mkdir()
                    configuration = application / 'config.conf'
                    configuration.write_text('OLD_RUNNING_CONFIGURATION')
                    rc = root / 'service.rc'
                    restored_rc = root / 'restored.rc'
                    if route == 'lucky':
                        original = f'lucky_enable="YES"\nlucky_conf_dir="{application}"\nlucky_http_port="16601"\n'
                        restored = original.replace('enable="YES"', f'enable="{enabled}"').replace('16601', '16602')
                        new_argument = '16602'
                    else:
                        original = f'ddnsgo_enable="YES"\nddnsgo_config="{configuration}"\nddnsgo_listen=":9876"\nddnsgo_interval="300"\nddnsgo_extra_args=""\n'
                        restored = original.replace('enable="YES"', f'enable="{enabled}"').replace(':9876', ':9877')
                        new_argument = ':9877'
                    rc.write_text(original)
                    restored_rc.write_text(restored)
                    (root / 'supervisor.pid').write_text('111\n')
                    (root / 'alive').touch()
                    events = root / 'events'
                    events.touch()
                    stub = root / 'rc.subr'
                    stub.write_text('''load_rc_config() { . "$TEST_RC"; }
checkyesno() { eval "value=\\${$1}"; [ "$value" = "YES" ]; }
pgrep() { echo 222; }
kill() {
    if [ "$1" = "-0" ]; then
        [ "$2" = "111" ] && [ -f "$TEST_ALIVE" ]
        return $?
    fi
    if [ "$2" = "111" ]; then
        rm -f "$TEST_ALIVE"
    else
        printf '%s\\n' writer_stop >> "$TEST_EVENTS"
        printf '%s' OLD_SHUTDOWN_CONFIGURATION > "$TEST_CONFIGURATION"
    fi
}
run_rc_command() {
    if [ "$1" = "restart" ] && ! checkyesno "$rcvar"; then return 1; fi
    "$restart_cmd"
}
''')
                    mirror = root / 'config_mirror.py'
                    mirror.write_text('''import os,sys
from pathlib import Path
events=Path(os.environ['TEST_EVENTS'])
with events.open('a') as output: output.write(sys.argv[1]+'\\n')
configuration=Path(os.environ['TEST_CONFIGURATION'])
if sys.argv[1]=='reconcile':
    Path(os.environ['TEST_RC']).write_bytes(Path(os.environ['TEST_RESTORED_RC']).read_bytes())
    configuration.write_text('RESTORED_CONFIGURATION')
elif configuration.read_text()!='RESTORED_CONFIGURATION':
    sys.exit(1)
''')
                    daemon = root / 'daemon'
                    daemon.write_text('''#!/bin/sh
printf '%s\\n' daemon >> "$TEST_EVENTS"
printf '%s\\n' "$*" > "$TEST_ARGUMENTS"
''')
                    daemon.chmod(0o755)
                    source = REPOSITORY / 'src' / package / 'src/usr/local/etc/rc.d' / service
                    script = source.read_text()
                    script = script.replace('. /etc/rc.subr', f'. "{stub}"', 1)
                    script = script.replace('pidfile="/var/run/${name}.pid"', 'pidfile="$TEST_PID"', 1)
                    script = script.replace('logfile="/var/log/${name}.log"', 'logfile="$TEST_LOG"', 1)
                    script = script.replace('command="/usr/sbin/daemon"', f'command="{daemon}"', 1)
                    binary = 'lucky' if route == 'lucky' else 'ddns-go'
                    script = script.replace(f'{route}_bin="/usr/local/bin/{binary}"', f'{route}_bin="{daemon}"', 1)
                    script = script.replace(f'/usr/local/bin/python3 /usr/local/opnsense/scripts/{route}/config_mirror.py',
                                            f'"{sys.executable}" "{mirror}"')
                    candidate = root / service
                    candidate.write_text(script)
                    environment = {**os.environ, 'TEST_RC': str(rc), 'TEST_RESTORED_RC': str(restored_rc),
                                   'TEST_CONFIGURATION': str(configuration), 'TEST_EVENTS': str(events),
                                   'TEST_ALIVE': str(root / 'alive'), 'TEST_PID': str(root / 'supervisor.pid'),
                                   'TEST_LOG': str(root / 'log'), 'TEST_ARGUMENTS': str(root / 'arguments')}
                    result = subprocess.run(['sh', str(candidate), action], env=environment, capture_output=True)
                    self.assertEqual(result.returncode, 0, result.stderr.decode())
                    calls = events.read_text().splitlines()
                    self.assertLess(calls.index('writer_stop'), calls.index('reconcile'))
                    self.assertLess(calls.index('reconcile'), calls.index('mirror'))
                    self.assertEqual(configuration.read_text(), 'RESTORED_CONFIGURATION')
                    should_start = enabled == 'YES' or action == 'onerestart'
                    self.assertEqual('daemon' in calls, should_start)
                    if should_start:
                        self.assertLess(calls.index('daemon'), calls.index('mirror'))
                        self.assertIn(new_argument, (root / 'arguments').read_text())


@unittest.skipUnless(sys.platform.startswith('freebsd'), 'Requires the genuine native OPNsense PHP includes')
class NativeStaticarpWiringTests(unittest.TestCase):
    def test_native_settings_mirror_only_after_writes_and_report_backup_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            configuration = root / 'configuration'
            source = REPOSITORY / 'src/os-staticarp/src/usr/local/opnsense/scripts/staticarp/settings.php'
            script = source.read_text()
            original = "const STATICARP_CONFIG_DIR = '/usr/local/etc/staticarp';"
            self.assertEqual(script.count(original), 1)
            candidate = root / 'settings.php'
            script = script.replace(original, f"const STATICARP_CONFIG_DIR = '{configuration}';", 1)
            script = script.replace("const STATICARP_LOCK_FILE = '/var/db/os-staticarp-backup/settings.lock';",
                                    f"const STATICARP_LOCK_FILE = '{root / 'settings.lock'}';", 1)
            candidate.write_text(script)
            mirror = root / 'config_mirror.py'
            mirror.write_text('''import json,os,sys
from pathlib import Path
root=Path(__file__).parent
configuration=root/'configuration'
names=['settings.conf','entries.conf','interfaces.conf']
captured={name:(configuration/name).read_text() for name in names}
with (root/'calls').open('a') as output: output.write(json.dumps(captured)+'\\n')
sys.exit(1 if os.environ.get('TEST_BACKUP_FAILURE') else 0)
''')
            payload = root / 'payload.json'
            payload.write_text(json.dumps({'enabled': False, 'entries': '192.0.2.10 aa:bb:cc:dd:ee:ff', 'modes': {}}))
            result = subprocess.run(['/usr/local/bin/php', str(candidate), 'set', str(payload)], capture_output=True)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(json.loads(result.stdout)['status'], 'ok')
            captured = [json.loads(line) for line in (root / 'calls').read_text().splitlines()]
            self.assertEqual(len(captured), 1)
            self.assertEqual(captured[0]['settings.conf'], 'enabled=NO\n')
            self.assertIn('192.0.2.10 aa:bb:cc:dd:ee:ff', captured[0]['entries.conf'])
            self.assertTrue(captured[0]['interfaces.conf'])
            environment = {**os.environ, 'TEST_BACKUP_FAILURE': '1'}
            result = subprocess.run(['/usr/local/bin/php', str(candidate), 'set', str(payload)], env=environment,
                                    capture_output=True)
            answer = json.loads(result.stdout)
            self.assertEqual(answer['status'], 'failed')
            self.assertTrue(answer['saved'])
            self.assertEqual(len((root / 'calls').read_text().splitlines()), 2)
            payload.write_text(json.dumps({'enabled': True, 'entries': '', 'modes': {}}))
            result = subprocess.run(['/usr/local/bin/php', str(candidate), 'set', str(payload)], capture_output=True)
            self.assertEqual(json.loads(result.stdout)['status'], 'failed')
            self.assertEqual(len((root / 'calls').read_text().splitlines()), 2)


if __name__ == '__main__':
    unittest.main()
