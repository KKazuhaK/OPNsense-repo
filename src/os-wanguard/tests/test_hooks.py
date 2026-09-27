"""Execute the package hooks and the rc.d script under a private root with stubs."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

PACKAGE = Path(__file__).resolve().parents[1]
HOOKS = PACKAGE / 'packaging/freebsd'
RC = PACKAGE / 'src/usr/local/etc/rc.d/wanguard'
sys.path.insert(0, str(PACKAGE / 'src/usr/local/opnsense/scripts/wanguard'))
import guard  # noqa: E402

RECORDER = '''#!PYTHON
import json, os, sys
from pathlib import Path
name = Path(sys.argv[0]).name
with open(os.environ['HOOK_EVENTS'], 'a') as output:
    output.write(json.dumps([name] + sys.argv[1:]) + '\\n')
if name == 'configctl' and sys.argv[1:] == ['template', 'reload', 'OPNsense/Wanguard']:
    target = Path(os.environ['HOOK_ROOT']) / 'etc/rc.conf.d/wanguard'
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text('wanguard_enable="%s"\\n' % os.environ.get('HOOK_ENABLE', 'NO'))
if name == 'pkg':
    abi = os.environ.get('HOOK_ABI', '')
    if not abi:
        sys.exit(1)
    print(abi)
sys.exit(1 if os.environ.get('HOOK_FAIL') == name else 0)
'''.replace('PYTHON', sys.executable)


class HookTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='wanguard-hooks-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / 'root'
        self.bin = Path(self.temporary.name) / 'bin'
        self.bin.mkdir()
        self.events = Path(self.temporary.name) / 'events'
        for name in ['configctl', 'service', 'pkg']:
            (self.bin / name).write_text(RECORDER)
            (self.bin / name).chmod(0o755)
        # The installed package, as pkg leaves it before the post-install hook.
        shutil.copytree(PACKAGE / 'src', self.root)
        register = self.root / 'usr/local/opnsense/scripts/firmware/register.php'
        register.parent.mkdir(parents=True)
        register.write_text(RECORDER.replace('name = Path(sys.argv[0]).name', "name = 'register'"))
        register.chmod(0o755)
        for path in [self.root / 'usr/local/opnsense/scripts/wanguard/helper.php',
                     self.root / 'usr/local/etc/rc.d/wanguard']:
            path.chmod(0o600)

    def put(self, relative, content='x'):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        return path

    def run_hook(self, name, upgrade=False, **environment):
        # One pass, so the private root itself (under /var on macOS) is never rewritten.
        source = re.sub(r'(?<![A-Za-z0-9_./-])/(usr/local|var|etc/rc\.conf\.d)(?=/)',
                        lambda match: str(self.root / match.group(1)), (HOOKS / name).read_text())
        hook = Path(self.temporary.name) / name
        hook.write_text(source)
        env = {**os.environ, 'PATH': str(self.bin) + os.pathsep + os.environ['PATH'],
               'HOOK_EVENTS': str(self.events), 'HOOK_ROOT': str(self.root), **environment}
        env.pop('PKG_UPGRADE', None)
        if upgrade:
            env['PKG_UPGRADE'] = '1'
        return subprocess.run(['sh', str(hook)], capture_output=True, text=True, env=env, timeout=20)

    def calls(self):
        if not self.events.exists():
            return []
        return [json.loads(line) for line in self.events.read_text().splitlines()]

    def test_every_hook_is_strict_shell(self):
        for name in ['+PRE_INSTALL', '+POST_INSTALL', '+PRE_DEINSTALL', '+POST_DEINSTALL']:
            with self.subTest(hook=name):
                text = (HOOKS / name).read_text()
                self.assertTrue(text.startswith('#!/bin/sh\nset -eu\n'))
                self.assertEqual(subprocess.run(['sh', '-n', str(HOOKS / name)]).returncode, 0)
                # Installing or removing the plugin never touches a DHCP client.
                self.assertNotIn('dhclient', text)

    def test_pre_install_accepts_only_supported_abis(self):
        for abi, code in [('FreeBSD:15:amd64', 0), ('FreeBSD:14:amd64', 0), ('FreeBSD:16:amd64', 0),
                          ('FreeBSD:13:amd64', 1), ('FreeBSD:15:aarch64', 1), ('', 1)]:
            with self.subTest(abi=abi):
                result = self.run_hook('+PRE_INSTALL', HOOK_ABI=abi)
                self.assertEqual(result.returncode, code, result.stderr)
                if code:
                    self.assertIn('Unsupported ABI', result.stderr)

    def test_a_fresh_install_prepares_everything_and_stays_stopped(self):
        caches = [self.put('var/lib/php/tmp/opnsense_menu_cache.xml'), self.put('var/lib/php/tmp/opnsense_acl_cache.json')]
        result = self.run_hook('+POST_INSTALL')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.calls(), [
            ['register', 'install', 'os-wanguard'],
            ['service', 'configd', 'restart'],
            ['configctl', 'template', 'reload', 'OPNsense/Wanguard'],
            ['configctl', 'template', 'reload', 'OPNsense/Syslog'],
            ['configctl', 'syslog', 'restart']])
        self.assertEqual((self.root / 'var/db/os-wanguard').stat().st_mode & 0o777, 0o700)
        self.assertFalse(any(path.exists() for path in caches))
        self.assertEqual((self.root / 'usr/local/etc/rc.d/wanguard').stat().st_mode & 0o777, 0o755)
        self.assertEqual((self.root / 'usr/local/opnsense/scripts/wanguard/wanguard.py').stat().st_mode & 0o777, 0o755)
        self.assertEqual((self.root / 'usr/local/opnsense/scripts/wanguard/helper.php').stat().st_mode & 0o777, 0o644)
        self.assertIn('Services > WAN Guard', result.stdout)

    def test_an_enabled_reinstall_or_upgrade_restarts_the_service(self):
        state = self.put('var/db/os-wanguard/state.json', '{"kept": true}')
        result = self.run_hook('+POST_INSTALL', HOOK_ENABLE='YES')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.calls()[-1], ['service', 'wanguard', 'restart'])
        self.assertEqual(state.read_text(), '{"kept": true}')

    def test_install_survives_failing_services_with_warnings(self):
        for failing in ['configctl', 'service']:
            with self.subTest(failing=failing):
                self.events.unlink(missing_ok=True)
                result = self.run_hook('+POST_INSTALL', HOOK_FAIL=failing, HOOK_ENABLE='YES')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('Warning', result.stderr)
                self.assertIn(['register', 'install', 'os-wanguard'], self.calls())

    def test_pre_deinstall_always_stops_the_daemon_and_nothing_else(self):
        for upgrade in [False, True]:
            for failing in ['', 'service']:
                with self.subTest(upgrade=upgrade, failing=failing):
                    self.events.unlink(missing_ok=True)
                    result = self.run_hook('+PRE_DEINSTALL', upgrade=upgrade, HOOK_FAIL=failing)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(self.calls(), [['service', 'wanguard', 'onestop']])

    def test_an_upgrade_keeps_the_setting_and_the_state(self):
        kept = [self.put('etc/rc.conf.d/wanguard', 'wanguard_enable="YES"\n'),
                self.put('var/db/os-wanguard/state.json'), self.put('var/run/wanguard/daemon.lock')]
        result = self.run_hook('+POST_DEINSTALL', upgrade=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.calls(), [])
        self.assertTrue(all(path.exists() for path in kept))

    def test_removal_cleans_up_runtime_files_but_leaves_config_xml(self):
        removed = [self.put('etc/rc.conf.d/wanguard'), self.put('var/run/wanguard.pid'),
                   self.put('var/run/wanguard/daemon.lock'), self.put('var/db/os-wanguard/state.json'),
                   self.put('var/db/os-wanguard/dhclient.leases.igc1.discarded'),
                   self.put('var/lib/php/tmp/opnsense_menu_cache.xml'),
                   # Left behind at runtime by an older, unfixed build; pkg
                   # does not track it, so only this hook can clean it up.
                   self.put('usr/local/opnsense/scripts/wanguard/__pycache__/guard.cpython-313.pyc'),
                   self.put('usr/local/opnsense/scripts/wanguard/__pycache__/wanguard.cpython-313.pyc')]
        config = self.put('conf/config.xml', '<wanguard>kept</wanguard>')
        lease = self.put('var/db/dhclient.leases.igc1', 'live lease')
        result = self.run_hook('+POST_DEINSTALL')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(any(path.exists() for path in removed))
        self.assertFalse((self.root / 'var/run/wanguard').exists())
        self.assertFalse((self.root / 'var/db/os-wanguard').exists())
        self.assertFalse((self.root / 'usr/local/opnsense/scripts/wanguard/__pycache__').exists())
        # Everything else the package shipped there stays.
        self.assertTrue((self.root / 'usr/local/opnsense/scripts/wanguard/wanguard.py').exists())
        self.assertEqual(config.read_text(), '<wanguard>kept</wanguard>')
        self.assertEqual(lease.read_text(), 'live lease')
        self.assertEqual(self.calls(), [
            ['register', 'remove', 'os-wanguard'],
            ['configctl', 'template', 'reload', 'OPNsense/Syslog'],
            ['configctl', 'syslog', 'restart'],
            ['service', 'configd', 'restart']])

    def test_an_upgrade_leaves_pycache_alone(self):
        # PKG_UPGRADE exits before the cleanup runs at all; the new package's
        # own files (and -B everywhere) take over from there.
        cache = self.put('usr/local/opnsense/scripts/wanguard/__pycache__/guard.cpython-313.pyc')
        result = self.run_hook('+POST_DEINSTALL', upgrade=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(cache.exists())


class RcScriptTests(unittest.TestCase):
    """Run the real rc.d functions with rc.subr and the process tools stubbed."""

    STUBS = {
        'daemon': '''#!/bin/sh
printf '%s\\n' "$*" >> "$RC_EVENTS"
while [ "$#" -gt 0 ]; do
    if [ "$1" = "-P" ]; then pidfile="$2"; fi
    shift
done
sleep 60 >/dev/null 2>&1 &
echo "$!" > "$pidfile"
''',
        'pgrep': '''#!/bin/sh
[ "$1" = "-F" ] && kill -0 "$(cat "$2")" 2>/dev/null
''',
        'pkill': '''#!/bin/sh
printf 'pkill %s\\n' "$*" >> "$RC_EVENTS"
[ "$1" = "-F" ] && kill "$(cat "$2")"
''',
        'python3': '''#!/bin/sh
printf 'python3 %s\\n' "$*" >> "$RC_EVENTS"
''',
    }

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='wanguard-rc-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.events = self.root / 'events'
        for name, body in self.STUBS.items():
            (self.root / name).write_text(body)
            (self.root / name).chmod(0o755)
        source = RC.read_text()
        replacements = {
            '. /etc/rc.subr': 'load_rc_config() { :; }\n'
                              'run_rc_command() { case "$1" in start) wanguard_start ;; onestop|stop) wanguard_stop ;;'
                              ' onestatus|status) wanguard_status ;; reload) wanguard_reload ;; esac; }',
            '/usr/sbin/daemon': str(self.root / 'daemon'), '/bin/pgrep': str(self.root / 'pgrep'),
            '/bin/pkill': str(self.root / 'pkill'), '/usr/local/bin/python3': str(self.root / 'python3'),
            '/var/run': str(self.root / 'var/run'), '/var/db': str(self.root / 'var/db'),
        }
        for old in replacements:
            self.assertIn(old, source)
        source = re.sub('|'.join(re.escape(old) for old in replacements),
                        lambda match: replacements[match.group(0)], source)
        self.script = self.root / 'wanguard'
        self.script.write_text(source)
        self.addCleanup(self.cleanup)

    def cleanup(self):
        pidfile = self.root / 'var/run/wanguard.pid'
        if pidfile.exists():
            subprocess.run(['kill', pidfile.read_text().strip()], capture_output=True)

    def rc(self, command):
        return subprocess.run(['sh', str(self.script), command], capture_output=True, text=True, timeout=20,
                              env={**os.environ, 'RC_EVENTS': str(self.events)})

    def lines(self):
        return self.events.read_text().splitlines() if self.events.exists() else []

    def test_start_status_stop_and_reload(self):
        self.assertEqual(self.rc('onestatus').stdout, 'wanguard is not running.\n')
        started = self.rc('start')
        self.assertEqual(started.returncode, 0, started.stderr)
        pidfile = self.root / 'var/run/wanguard.pid'
        self.assertEqual(self.lines(), ['-f -r -R 30 -P %s -S -T wanguard %s -B /usr/local/opnsense/scripts/wanguard/wanguard.py run'
                                        % (pidfile, self.root / 'python3')])
        for directory in ['var/run/wanguard', 'var/db/os-wanguard']:
            self.assertEqual((self.root / directory).stat().st_mode & 0o777, 0o700)
        status = self.rc('onestatus')
        self.assertEqual((status.returncode, status.stdout),
                         (0, 'wanguard is running as pid %s.\n' % pidfile.read_text().strip()))
        again = self.rc('start')
        self.assertEqual(again.stdout, 'wanguard is already running.\n')
        self.assertEqual(len(self.lines()), 1)
        self.assertEqual(self.rc('reload').returncode, 0)
        self.assertEqual(self.lines()[-1], 'python3 -B /usr/local/opnsense/scripts/wanguard/wanguard.py wake')
        started_at = time.monotonic()
        stopped = self.rc('onestop')
        self.assertEqual(stopped.returncode, 0, stopped.stdout)
        self.assertLess(time.monotonic() - started_at, 5)
        self.assertEqual(self.lines()[-1], 'pkill -F %s' % pidfile)
        status = self.rc('onestatus')
        self.assertEqual((status.returncode, status.stdout), (1, 'wanguard is not running.\n'))
        self.assertEqual(self.rc('onestop').stdout, 'wanguard is not running.\n')

    def test_configd_status_action_never_raises_on_a_stopped_service(self):
        """rc.d onestatus exits 1 when stopped, by the standard rc.subr
        convention (asserted above): a normal, expected answer, not a failure.

        configd's own script_output action runs its command as
        subprocess.run(cmd, shell=True, check=not disable_errors), and
        disable_errors comes from the actions.d entry's 'errors' key
        (ConfigdTests.test_status_action_tolerates_a_stopped_service in
        test_wiring.py checks that entry is 'errors:no'). This reproduces
        that exact call against the real rc.d script on both sides of the
        flag, so the GUI's status widget gets the real text ('wanguard is
        not running.') instead of configd's swallowed 'Execute error'.
        """
        command = 'sh %s onestatus' % self.script
        env = {**os.environ, 'RC_EVENTS': str(self.events)}
        with self.assertRaises(subprocess.CalledProcessError):
            subprocess.run(command, shell=True, check=True, capture_output=True, text=True, env=env, timeout=20)
        result = subprocess.run(command, shell=True, check=False, capture_output=True, text=True, env=env, timeout=20)
        self.assertEqual((result.returncode, result.stdout), (1, 'wanguard is not running.\n'))

    def test_rc_shape(self):
        text = RC.read_text()
        for line in ['# PROVIDE: wanguard', '# REQUIRE: NETWORKING', '# KEYWORD: shutdown', 'rcvar="wanguard_enable"',
                     ': "${wanguard_enable:=NO}"', 'extra_commands="reload"']:
            self.assertIn(line, text)
        # rc.subr would try to match a process against a variable of this name.
        self.assertNotIn('\npidfile=', text)
        # A stop waits out a helper call already under way, so a restart (the
        # one after an upgrade, say) never finds the old daemon still there.
        limit = int(re.search(r'if \[ "\$count" -ge ([0-9]+) \]', text).group(1))
        self.assertGreater(limit, guard.ACTION_TIMEOUT + guard.POLL)
        self.assertEqual(subprocess.run(['sh', '-n', str(RC)]).returncode, 0)


if __name__ == '__main__':
    unittest.main()
