"""Run real install/remove hooks and statistics readers against private files."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

PACKAGE = Path(__file__).resolve().parents[1]


class HookTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='ddclient-hooks-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.events = self.root / 'events'
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        program = '''#!PYTHON
import json,os,sys
from pathlib import Path
command=Path(sys.argv[0]).name
with Path(os.environ['HOOK_EVENTS']).open('a') as output: output.write(json.dumps([command,*sys.argv[1:]])+'\\n')
if command=='pkg': sys.exit(0 if os.environ.get('OFFICIAL_INSTALLED')=='1' else 1)
sys.exit(1 if os.environ.get('HOOK_COMMAND_FAIL')=='1' else 0)
'''.replace('PYTHON', sys.executable)
        for name in ['pkg', 'configctl', 'service', 'register']:
            (self.bin / name).write_text(program)
            (self.bin / name).chmod(0o755)
        self.config = self.put('/conf/config.xml', b'SENTINEL_NATIVE_CONFIG_AND_CREDENTIALS')
        self.document = self.put('/usr/local/etc/ddclient.json', b'SENTINEL_GENERATED_CREDENTIALS', 0o644)

    def put(self, path, content, mode=0o600):
        target = self.root / path.lstrip('/')
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        target.chmod(mode)
        return target

    def run_hook(self, name, **environment):
        source = (PACKAGE / 'packaging/freebsd' / name).read_text()
        source = source.replace('/usr/local/opnsense/scripts/firmware/register.php', str(self.bin / 'register'))
        for prefix in ['/usr/local', '/var/lib']:
            source = source.replace(prefix, str(self.root) + prefix)
        target = self.root / 'hook.sh'
        target.write_text(source)
        return subprocess.run(['sh', str(target)], capture_output=True, text=True,
            env={**os.environ, 'PATH': str(self.bin) + os.pathsep + os.environ['PATH'],
                 'HOOK_EVENTS': str(self.events), **environment})

    def calls(self):
        return [json.loads(line) for line in self.events.read_text().splitlines()] if self.events.exists() else []

    def test_official_package_conflict_aborts_before_any_install_mutation(self):
        result = self.run_hook('+PRE_INSTALL', OFFICIAL_INSTALLED='1')
        self.assertEqual(result.returncode, 1)
        self.assertIn('remove the official os-ddclient', result.stderr)
        self.assertEqual(self.calls(), [['pkg', 'info', '-e', 'os-ddclient-[0-9]*']])
        self.assertEqual(self.config.read_bytes(), b'SENTINEL_NATIVE_CONFIG_AND_CREDENTIALS')
        self.events.unlink()
        self.assertEqual(self.run_hook('+PRE_INSTALL', OFFICIAL_INSTALLED='0').returncode, 0)

    def test_install_clears_only_generated_caches_and_reloads_before_restart(self):
        cache = self.put('/usr/local/opnsense/scripts/ddclient/lib/__pycache__/fixture.pyc', b'cache')
        self.assertEqual(self.run_hook('+POST_INSTALL').returncode, 0)
        self.assertFalse(cache.exists())
        self.assertEqual(self.calls(), [['service', 'configd', 'restart'],
            ['register', 'install', 'os-ddclient-opnwall'],
            ['configctl', 'template', 'reload', 'OPNsense/ddclient'], ['configctl', 'ddclient', 'restart']])
        self.assertEqual(self.config.read_bytes(), b'SENTINEL_NATIVE_CONFIG_AND_CREDENTIALS')

    def test_remove_stops_daemon_but_keeps_native_settings_and_generated_credentials(self):
        self.assertEqual(self.run_hook('+PRE_DEINSTALL').returncode, 0)
        self.assertEqual(self.run_hook('+POST_DEINSTALL').returncode, 0)
        self.assertEqual(self.calls()[0], ['configctl', 'ddclient', 'stop'])
        self.assertIn(['register', 'remove', 'os-ddclient-opnwall'], self.calls())
        self.assertEqual(self.document.read_bytes(), b'SENTINEL_GENERATED_CREDENTIALS')
        self.assertEqual(self.config.read_bytes(), b'SENTINEL_NATIVE_CONFIG_AND_CREDENTIALS')

    def test_install_service_failure_still_registers_package_and_returns_success(self):
        self.assertEqual(self.run_hook('+POST_INSTALL', HOOK_COMMAND_FAIL='1').returncode, 0)
        self.assertIn(['register', 'install', 'os-ddclient-opnwall'], self.calls())

    def test_setup_restricts_both_generated_credential_files_to_root(self):
        conf = self.put('/usr/local/etc/ddclient.conf', b'SENTINEL_PERL_CREDENTIALS', 0o666)
        source = (PACKAGE / 'src/usr/local/opnsense/scripts/ddclient/setup.sh').read_text()
        source = source.replace('/usr/local', str(self.root) + '/usr/local')
        script = self.root / 'setup.sh'
        script.write_text(source)
        result = subprocess.run(['sh', str(script)], capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(conf.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.document.stat().st_mode & 0o777, 0o600)


class StatisticsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='ddclient-stats-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.old, self.new = self.root / 'ddclient.cache', self.root / 'ddclient_opn.status'
        source = (PACKAGE / 'src/usr/local/opnsense/scripts/ddclient/stats').read_text()
        source = source.replace('/var/tmp/ddclient.cache', str(self.old)).replace('/var/tmp/ddclient_opn.status', str(self.new))
        self.script = self.root / 'stats.py'
        self.script.write_text(source)

    def result(self):
        result = subprocess.run([sys.executable, str(self.script)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_absent_status_and_legacy_cache_parse_without_daemon_calls(self):
        self.assertEqual(self.result(), {'hosts': {}})
        self.old.write_text('# ddclient version=3.11\n# updated (1234)\nhost=router.example.invalid,ip=8.8.8.8,mtime=1234\n')
        answer = self.result()
        self.assertEqual(answer['updated'], 1234)
        self.assertEqual(answer['hosts']['router.example.invalid']['ip'], '8.8.8.8')

    def test_newest_backend_status_wins_and_preserves_account_identity(self):
        self.old.write_text('# ddclient version=3.11\n# updated (1234)\nhost=old.example.invalid,ip=8.8.4.4,mtime=1234\n')
        native = {'fixture-account': {'ip': '8.8.8.8', 'mtime': 2000, 'status': 'good'}}
        self.new.write_text(json.dumps(native))
        os.utime(self.old, (10, 10))
        os.utime(self.new, (20, 20))
        self.assertEqual(self.result(), native)
        os.utime(self.old, (30, 30))
        self.assertIn('old.example.invalid', self.result()['hosts'])


if __name__ == '__main__':
    unittest.main()
