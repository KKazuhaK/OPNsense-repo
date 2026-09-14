"""Execute package lifecycle hooks with an isolated firmware registration boundary."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest


HOOKS = Path(__file__).resolve().parents[1] / 'packaging/freebsd'


class LifecycleHookTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.plugins = self.root / 'plugins.json'
        self.plugins.write_text(json.dumps(['os-ddclient', 'os-other']))
        self.calls = self.root / 'calls.log'
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.env = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ['PATH'],
                        TEST_PLUGINS=str(self.plugins), TEST_CALLS=str(self.calls))
        self.env.pop('PKG_UPGRADE', None)
        self.executable('usr/local/bin/python3', '''import os,sys
from pathlib import Path
with Path(os.environ['TEST_CALLS']).open('a') as stream:
    stream.write('control ' + ' '.join(sys.argv[2:]) + '\\n')
if sys.argv[2:3] == ['reconcile-backup'] and os.environ.get('TEST_FAIL_RECONCILE') == '1':
    raise SystemExit(1)
''')
        self.executable('usr/local/bin/php', "print('{}')\n")
        self.executable('usr/local/opnsense/scripts/firmware/register.php', '''import json,os,sys
from pathlib import Path
path = Path(os.environ['TEST_PLUGINS'])
plugins = set(json.loads(path.read_text()))
action, name = sys.argv[1:]
if action == 'install': plugins.add(name)
elif action == 'remove': plugins.discard(name)
else: raise SystemExit('Unexpected registration action')
path.write_text(json.dumps(sorted(plugins)))
with Path(os.environ['TEST_CALLS']).open('a') as stream:
    stream.write('register ' + action + ' ' + name + '\\n')
''')
        for name in ('service', 'configctl'):
            self.executable('bin/' + name, '''import os,sys
from pathlib import Path
with Path(os.environ['TEST_CALLS']).open('a') as stream:
    stream.write(Path(sys.argv[0]).name + ' ' + ' '.join(sys.argv[1:]) + '\\n')
''')
        (self.root / 'var/log').mkdir(parents=True)

    def executable(self, name, source):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('#!' + sys.executable + '\n' + source)
        path.chmod(0o755)

    def run_hook(self, name, upgrade=False):
        source = (HOOKS / name).read_text()
        source = re.sub(r'/(?:usr/local|var)/', lambda match: str(self.root) + match.group(), source)
        env = dict(self.env)
        if upgrade:
            env['PKG_UPGRADE'] = ''
        return subprocess.run(['sh', '-c', source], env=env, capture_output=True,
                              text=True, timeout=10)

    def test_install_and_reinstall_register_only_mihomo_without_changing_other_plugins(self):
        for upgrade in (False, True):
            result = self.run_hook('+POST_INSTALL', upgrade)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual(['os-ddclient', 'os-mihomo', 'os-other'],
                             json.loads(self.plugins.read_text()))
        self.assertEqual(2, self.calls.read_text().count('register install os-mihomo'))

    def test_failed_fresh_restore_finishes_install_registration_without_defaults_or_startup(self):
        self.env['TEST_FAIL_RECONCILE'] = '1'
        cache = self.root / 'var/lib/php/tmp'
        cache.mkdir(parents=True)
        for name in ('opnsense_menu_cache.xml', 'opnsense_acl_cache.json'):
            (cache / name).write_text('obsolete UI cache')
        config = self.root / 'conf/config.xml'
        config.parent.mkdir()
        saved = b'<opnsense><OPNsense><Mihomo><backup><checksum>corrupt</checksum><secret>private-saved-secret</secret></backup></Mihomo></OPNsense></opnsense>'
        config.write_bytes(saved)
        result = self.run_hook('+POST_INSTALL')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('needs repair', result.stderr)
        calls = self.calls.read_text().splitlines()
        self.assertEqual(calls, ['control reconcile-backup', 'service configd restart', 'register install os-mihomo'])
        self.assertEqual(config.read_bytes(), saved)
        self.assertFalse((self.root / 'var/db/os-mihomo/settings.json').exists())
        self.assertFalse(list(cache.iterdir()), 'A failed first restore must still clear stale menu/ACL caches')
        for name in ('mihomo.log', 'mihomo_sub.log'):
            self.assertEqual((self.root / 'var/log' / name).stat().st_mode & 0o777, 0o640)

    def test_solver_removal_keeps_desired_plugin_until_explicit_firmware_removal(self):
        self.plugins.write_text(json.dumps(['os-ddclient', 'os-mihomo', 'os-other']))
        result = self.run_hook('+PRE_DEINSTALL', upgrade=True)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn('control suspend', self.calls.read_text())
        result = self.run_hook('+POST_DEINSTALL', upgrade=True)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(['os-ddclient', 'os-mihomo', 'os-other'],
                         json.loads(self.plugins.read_text()))
        result = self.run_hook('+PRE_DEINSTALL')
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn('control remove', self.calls.read_text())
        result = self.run_hook('+POST_DEINSTALL')
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(['os-ddclient', 'os-mihomo', 'os-other'],
                         json.loads(self.plugins.read_text()))
        self.assertNotIn('register remove', self.calls.read_text())
        # Official firmware/remove.sh performs this after the package operation.
        result = subprocess.run([str(self.root / 'usr/local/opnsense/scripts/firmware/register.php'),
                                 'remove', 'os-mihomo'], env=self.env,
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(['os-ddclient', 'os-other'], json.loads(self.plugins.read_text()))
        self.assertEqual(1, self.calls.read_text().count('register remove os-mihomo'))
