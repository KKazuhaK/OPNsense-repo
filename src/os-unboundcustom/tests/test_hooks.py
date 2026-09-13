"""Execute package hooks with isolated files and recorded service commands."""
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
        self.temporary = tempfile.TemporaryDirectory(prefix='unboundcustom-hooks-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.events = self.root / 'events'
        stub = '''#!PYTHON
import json,os,sys
from pathlib import Path
with Path(os.environ['HOOK_EVENTS']).open('a') as output: output.write(json.dumps([Path(sys.argv[0]).name,*sys.argv[1:]])+'\\n')
sys.exit(1 if os.environ.get('HOOK_FAIL')=='1' else 0)
'''.replace('PYTHON', sys.executable)
        for name in ['configctl', 'service', 'register']:
            (self.bin / name).write_text(stub)
            (self.bin / name).chmod(0o755)

    def put(self, path, value=b'retain'):
        target = self.root / path.lstrip('/')
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(value)
        return target

    def run_hook(self, name, fail=False):
        source = (PACKAGE / 'packaging/freebsd' / name).read_text()
        source = source.replace('/usr/local/opnsense/scripts/firmware/register.php', str(self.bin / 'register'))
        for prefix in ['/usr/local', '/var/unbound', '/var/lib']:
            source = source.replace(prefix, str(self.root) + prefix)
        target = self.root / 'hook.sh'
        target.write_text(source)
        return subprocess.run(['sh', str(target)], capture_output=True, env={**os.environ,
            'PATH': str(self.bin) + os.pathsep + os.environ['PATH'], 'HOOK_EVENTS': str(self.events), 'HOOK_FAIL': '1' if fail else '0'})

    def calls(self):
        return [json.loads(line) for line in self.events.read_text().splitlines()] if self.events.exists() else []

    def test_install_registers_and_generates_only_the_owned_template(self):
        config = self.put('/conf/config.xml', b'SENTINEL_NATIVE_OPTIONS')
        self.assertEqual(self.run_hook('+POST_INSTALL').returncode, 0)
        self.assertEqual(self.calls(), [['service', 'configd', 'restart'],
            ['register', 'install', 'os-unboundcustom'],
            ['configctl', 'template', 'reload', 'OPNsense/Unboundcustom'], ['configctl', 'webgui', 'restart']])
        self.assertEqual(config.read_bytes(), b'SENTINEL_NATIVE_OPTIONS')

    def test_remove_deletes_owned_fragments_but_preserves_user_settings_and_other_includes(self):
        paths = ['/usr/local/etc/unbound.opnsense.d/custom-options.conf',
                 '/usr/local/etc/unbound.opnsense.d/custom-options.conf.unboundcustom-backup',
                 '/var/unbound/etc/custom-options.conf', '/var/unbound/etc/custom-options.conf.unboundcustom-backup']
        owned = [self.put(path) for path in paths]
        other = self.put('/usr/local/etc/unbound.opnsense.d/other-plugin.conf')
        config = self.put('/conf/config.xml', b'SENTINEL_NATIVE_OPTIONS')
        self.assertEqual(self.run_hook('+POST_DEINSTALL').returncode, 0)
        self.assertFalse(any(path.exists() for path in owned))
        self.assertTrue(other.exists())
        self.assertEqual(config.read_bytes(), b'SENTINEL_NATIVE_OPTIONS')
        self.assertIn(['register', 'remove', 'os-unboundcustom'], self.calls())
        self.assertIn(['configctl', 'unbound', 'restart'], self.calls())

    def test_hook_service_failures_do_not_prevent_package_registration(self):
        self.assertEqual(self.run_hook('+POST_INSTALL', fail=True).returncode, 0)
        self.assertIn(['register', 'install', 'os-unboundcustom'], self.calls())


if __name__ == '__main__':
    unittest.main()
