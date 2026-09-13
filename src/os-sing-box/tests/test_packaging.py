"""Execute package hooks against isolated files and harmless service stubs."""
import json
import os
from pathlib import Path
import shutil
import re
import subprocess
import tempfile
import unittest


PACKAGE = Path(__file__).resolve().parents[1]
LIVE = ['/usr/local/etc/sing-box/config.json', '/usr/local/etc/sing-box/sub/env',
        '/usr/local/etc/sing-box/sub/template.json', '/etc/rc.conf.d/sing_box']


class PackagingStateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for path in LIVE:
            source = PACKAGE / 'src' / (path.lstrip('/') + '.sample')
            destination = self.root / (path.lstrip('/') + '.sample')
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
        for path in ['var/db', 'var/log', 'var/lib/php/tmp', 'usr/local/www',
                     'usr/local/opnsense/mvc/app/models/OPNsense', 'conf']:
            (self.root / path).mkdir(parents=True, exist_ok=True)
        self.stubs = self.root / 'stubs'
        self.stubs.mkdir()
        self.trace = self.root / 'trace'
        for name in ['service', 'configctl']:
            path = self.stubs / name
            path.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$HOOK_TRACE"\n'
                            'if [ "$*" = "sing-box status" ]; then exit "${HOOK_STOPPED:-1}"; fi\nexit 0\n')
            path.chmod(0o755)
        self.environment = dict(os.environ, PATH=str(self.stubs) + ':' + os.environ['PATH'],
                                HOOK_TRACE=str(self.trace), HOOK_STOPPED='1')

    def hook(self, name, upgrade=False):
        source = (PACKAGE / 'packaging/freebsd' / name).read_text()
        # Redirect every filesystem root the hooks use. Commands are intercepted
        # by stubs, so these checks cannot restart a production daemon.
        source = re.sub(r'/(?:usr/local|etc|var|conf)(?=/|[\s\x22\x27])(?:/[^\s\x22\x27()]*)?|/tmp/config\.xml\.tmp',
                        lambda match: str(self.root / match.group().lstrip('/')), source)
        environment = self.environment.copy()
        if upgrade:
            environment['PKG_UPGRADE'] = '1'
        else:
            environment.pop('PKG_UPGRADE', None)
        result = subprocess.run(['sh'], input=source, text=True, capture_output=True, env=environment)
        self.assertEqual(0, result.returncode, result.stderr)

    def existing(self, enabled='NO'):
        content = [json.dumps({'experimental': {'clash_api': {'secret': ''}}, 'outbounds': [{'password': 'SENTINEL_PASSWORD'}]}),
                   "export SING_BOX_URL='https://example.invalid/SENTINEL_URL'\n",
                   '{"secret":"SENTINEL_TEMPLATE"}\n',
                   '# Preserve this existing enable choice.\nsing_box_enable="' + enabled + '"\n']
        for path, value in zip(LIVE, content):
            (self.root / path.lstrip('/')).write_text(value)
        return content

    def assert_existing(self, content):
        for path, value in zip(LIVE, content):
            self.assertEqual(value, (self.root / path.lstrip('/')).read_text(), path)

    def test_only_samples_and_upgrade_backup_hook_ship(self):
        for path in LIVE:
            self.assertFalse((PACKAGE / 'src' / path.lstrip('/')).exists(), path)
            self.assertTrue((PACKAGE / 'src' / (path.lstrip('/') + '.sample')).is_file(), path)
        source = (PACKAGE / 'build.sh').read_text()
        self.assertIn("('pre-install', '+PRE_INSTALL')", source)
        self.assertIn('packaging/freebsd/+PRE_INSTALL', source)

    def test_install_preserves_existing_credentials_and_disabled_choice(self):
        content = self.existing()
        self.hook('+POST_INSTALL')
        self.assert_existing(content)
        commands = self.trace.read_text()
        self.assertNotIn('sing-box start', commands)
        self.assertNotIn('sing-box restart', commands)
        self.assertNotIn('SENTINEL_', commands)

    def test_fresh_install_initializes_private_settings_once(self):
        self.hook('+POST_INSTALL')
        config = json.loads((self.root / LIVE[0].lstrip('/')).read_text())
        secret = config['experimental']['clash_api']['secret']
        self.assertTrue(secret)
        self.assertNotEqual('CHANGE_ME', secret)
        content = [(self.root / path.lstrip('/')).read_text() for path in LIVE]
        self.hook('+POST_INSTALL')
        self.assert_existing(content)
        self.assertEqual(1, self.trace.read_text().count('sing-box start'))
        for path in LIVE[:3]:
            self.assertEqual(0o600, (self.root / path.lstrip('/')).stat().st_mode & 0o777)

    def test_upgrade_restores_old_package_owned_settings_without_enabling_service(self):
        content = self.existing()
        self.hook('+PRE_INSTALL', upgrade=True)
        for path in LIVE:
            (self.root / path.lstrip('/')).unlink()
        self.hook('+POST_INSTALL', upgrade=True)
        self.assert_existing(content)
        self.assertFalse((self.root / 'var/db/os-sing-box-upgrade').exists())
        self.assertNotIn('sing-box start', self.trace.read_text())
        self.assertNotIn('sing-box restart', self.trace.read_text())

    def test_upgrade_deinstall_hooks_keep_settings_and_running_service_resumes(self):
        content = self.existing(enabled='YES')
        self.environment['HOOK_STOPPED'] = '0'
        self.hook('+PRE_INSTALL', upgrade=True)
        self.hook('+PRE_DEINSTALL', upgrade=True)
        self.hook('+POST_DEINSTALL', upgrade=True)
        self.assert_existing(content)
        for path in LIVE:
            (self.root / path.lstrip('/')).unlink()
        self.hook('+POST_INSTALL', upgrade=True)
        self.assert_existing(content)
        self.assertEqual(1, self.trace.read_text().count('sing-box restart'))
        self.assertNotIn('sing-box stop', self.trace.read_text())


if __name__ == '__main__':
    unittest.main()
