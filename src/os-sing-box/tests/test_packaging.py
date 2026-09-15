"""Execute package hooks against isolated files and harmless service stubs."""
import json
import os
from pathlib import Path
import shutil
import re
import subprocess
import sys
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
                                HOOK_TRACE=str(self.trace), HOOK_STOPPED='1',
                                HOOK_FILTER_RECEIPT=str(self.root / 'var/db/os-sing-box/filter-reload-pending.json'))
        python = self.root / 'usr/local/bin/python3'
        python.parent.mkdir(parents=True, exist_ok=True)
        python.symlink_to(sys.executable)
        php = self.root / 'usr/local/bin/php'
        php.write_text('#!/bin/sh\nprintf "network-setup:%s\\n" "$2" >> "$HOOK_TRACE"\n'
                       '[ "${HOOK_SETUP_FAIL:-0}" != "1" ] || exit 1\n'
                       'case "$2" in\n'
                       '  retire-legacy) result="${HOOK_RETIRE_RESULT:-unchanged}" ;;\n'
                       '  remove) result="${HOOK_REMOVE_RESULT:-unchanged}" ;;\n'
                       '  *) result="${HOOK_SETUP_RESULT:-unchanged}" ;;\n'
                       'esac\n'
                       'if [ "$result" = changed ]; then\n'
                       '  mkdir -p "$(dirname "$HOOK_FILTER_RECEIPT")"\n'
                       '  printf "{\\\"schema\\\":1,\\\"pending\\\":true}\\n" > "$HOOK_FILTER_RECEIPT"\n'
                       '  chmod 0600 "$HOOK_FILTER_RECEIPT"\n'
                       'fi\n'
                       'printf "%s\\n" "$result"\n')
        php.chmod(0o755)
        scripts = self.root / 'usr/local/opnsense/scripts/singbox'
        scripts.mkdir(parents=True, exist_ok=True)
        integration = scripts / 'integration.py'
        integration.write_text(
            'import json,os,pathlib,subprocess,sys\n'
            'action = sys.argv[1]\n'
            'if action == "reload-filter":\n'
            ' receipt = pathlib.Path(os.environ["HOOK_FILTER_RECEIPT"])\n'
            ' if receipt.exists():\n'
            '  if os.environ.get("HOOK_FILTER_FAIL") == "1": sys.exit(1)\n'
            '  subprocess.run(["configctl", "filter", "reload"], check=True)\n'
            '  receipt.unlink()\n'
            ' print(json.dumps({"ok": True, "reloaded": not receipt.exists()}))\n'
            'elif action == "status":\n'
            ' print(json.dumps({"ok": True, "running": False, "process_alive": False}))\n'
            ' sys.exit(1)\n'
            'else:\n'
            ' print(json.dumps({"ok": True}))\n')
        driver = scripts / 'config_mirror.py'
        driver.write_text('import json,os,sys\n'
                          'with open(os.environ["HOOK_TRACE"], "a") as trace: trace.write("backup " + sys.argv[1] + "\\n")\n'
                          'failed = sys.argv[1] == "import-config" and os.environ.get("HOOK_RESTORE_FAIL") == "1"\n'
                          'print(json.dumps({"ok": not failed, "snapshot": os.environ.get("HOOK_SNAPSHOT") == "1"}))\n'
                          'sys.exit(1 if failed else 0)\n')

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
        self.assertIn('src/usr/local/opnsense/scripts/singbox/config_setup.php', source)
        post = (PACKAGE / 'packaging/freebsd/+POST_INSTALL').read_text()
        self.assertIn('singbox/integration.py init', post)
        self.assertIn('singbox/config_setup.php retire-legacy', post)
        self.assertNotIn('/tmp/config.xml.tmp', post)
        self.assertNotIn('CONFIG_FILE=', post)

    def test_install_preserves_existing_credentials_and_disabled_choice(self):
        content = self.existing()
        self.hook('+POST_INSTALL')
        self.assert_existing(content)
        commands = self.trace.read_text()
        self.assertNotIn('sing-box start', commands)
        self.assertNotIn('sing-box restart', commands)
        self.assertNotIn('filter reload', commands)
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
        self.assertNotIn('sing-box start', self.trace.read_text())
        self.assertIn('sing_box_enable="NO"', content[3])
        self.assertNotIn('network-setup:', self.trace.read_text())
        self.assertNotIn('filter reload', self.trace.read_text())
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
        self.assertEqual(1, self.trace.read_text().count('network-setup:retire-legacy'))
        self.assertNotIn('filter reload', self.trace.read_text())

    def test_upgrade_reloads_filter_only_when_exact_legacy_policy_was_removed(self):
        self.existing()
        self.environment['HOOK_RETIRE_RESULT'] = 'changed'
        self.hook('+POST_INSTALL', upgrade=True)
        trace = self.trace.read_text()
        self.assertEqual(1, trace.count('network-setup:retire-legacy'))
        self.assertEqual(1, trace.count('filter reload'))

    def test_deinstall_reloads_filter_only_when_owned_configuration_was_removed(self):
        self.existing()
        self.hook('+PRE_DEINSTALL')
        trace = self.trace.read_text()
        self.assertEqual(1, trace.count('network-setup:remove'))
        self.assertNotIn('filter reload', trace)

        self.trace.unlink()
        self.environment['HOOK_REMOVE_RESULT'] = 'changed'
        self.hook('+PRE_DEINSTALL')
        trace = self.trace.read_text()
        self.assertEqual(1, trace.count('network-setup:remove'))
        self.assertEqual(1, trace.count('filter reload'))

    def test_failed_filter_reload_keeps_receipt_and_next_noop_hook_retries(self):
        self.existing()
        self.environment['HOOK_REMOVE_RESULT'] = 'changed'
        source = (PACKAGE / 'packaging/freebsd/+PRE_DEINSTALL').read_text()
        source = re.sub(r'/(?:usr/local|etc|var|conf)(?=/|[\s\x22\x27])(?:/[^\s\x22\x27()]*)?|/tmp/config\.xml\.tmp',
                        lambda match: str(self.root / match.group().lstrip('/')), source)
        result = subprocess.run(['sh'], input=source, text=True, capture_output=True,
                                env={**self.environment, 'HOOK_FILTER_FAIL': '1'})
        self.assertNotEqual(0, result.returncode)
        receipt = Path(self.environment['HOOK_FILTER_RECEIPT'])
        self.assertTrue(receipt.is_file())

        self.environment['HOOK_REMOVE_RESULT'] = 'unchanged'
        self.hook('+PRE_DEINSTALL')
        self.assertFalse(receipt.exists())
        self.assertEqual(1, self.trace.read_text().count('filter reload'))

    def test_invalid_change_results_fail_before_filter_reload(self):
        self.existing()
        for hook, variable, upgrade in (('+POST_INSTALL', 'HOOK_RETIRE_RESULT', True),
                                        ('+PRE_DEINSTALL', 'HOOK_REMOVE_RESULT', False)):
            with self.subTest(hook=hook):
                self.trace.unlink(missing_ok=True)
                environment = self.environment | {variable: 'unexpected'}
                source = (PACKAGE / 'packaging/freebsd' / hook).read_text()
                source = re.sub(r'/(?:usr/local|etc|var|conf)(?=/|[\s\x22\x27])(?:/[^\s\x22\x27()]*)?|/tmp/config\.xml\.tmp',
                                lambda match: str(self.root / match.group().lstrip('/')), source)
                if upgrade:
                    environment['PKG_UPGRADE'] = '1'
                result = subprocess.run(['sh'], input=source, text=True, capture_output=True,
                                        env=environment)
                self.assertNotEqual(0, result.returncode)
                self.assertIn('invalid result', result.stderr)
                self.assertNotIn('filter reload', self.trace.read_text())

    def test_restored_snapshot_does_not_seed_intentionally_absent_settings(self):
        self.environment['HOOK_SNAPSHOT'] = '1'
        shutil.rmtree(self.root / 'usr/local/etc/sing-box')
        self.hook('+POST_INSTALL')
        for path in LIVE:
            self.assertFalse((self.root / path.lstrip('/')).exists(), path)
        self.assertNotIn('sing-box start', self.trace.read_text())
        self.assertFalse((self.root / 'usr/local/etc/sing-box').exists())

    def test_restored_snapshot_permissions_remain_unchanged(self):
        self.environment['HOOK_SNAPSHOT'] = '1'
        content = self.existing()
        for path in LIVE[:3]:
            (self.root / path.lstrip('/')).chmod(0o400)
        state = self.root / 'usr/local/etc/sing-box'
        state.chmod(0o750)
        self.hook('+POST_INSTALL')
        self.assert_existing(content)
        self.assertEqual(0o750, state.stat().st_mode & 0o777)
        for path in LIVE[:3]:
            self.assertEqual(0o400, (self.root / path.lstrip('/')).stat().st_mode & 0o777)

    def test_failed_restore_neither_seeds_files_mirrors_nor_starts_service(self):
        self.environment['HOOK_RESTORE_FAIL'] = '1'
        self.hook('+POST_INSTALL')
        for path in LIVE:
            self.assertFalse((self.root / path.lstrip('/')).exists(), path)
        trace = self.trace.read_text()
        self.assertNotIn('backup mirror', trace)
        self.assertNotIn('sing-box start', trace)

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
        self.assertEqual(1, self.trace.read_text().count('sing-box onerestart'))
        self.assertNotIn('sing-box stop', self.trace.read_text())
        self.assertEqual(1, self.trace.read_text().count('network-setup:retire-legacy'))

    def test_upgrade_records_and_restarts_an_exact_owned_paused_core(self):
        content = self.existing(enabled='YES')
        integration = self.root / 'usr/local/opnsense/scripts/singbox/integration.py'
        integration.write_text(
            'import json,sys\n'
            'if sys.argv[1] == "status":\n'
            ' print(json.dumps({"ok":True,"running":False,"process_alive":True,"paused":True}))\n'
            ' sys.exit(1)\n')
        self.hook('+PRE_INSTALL', upgrade=True)
        self.assertTrue((self.root / 'var/db/os-sing-box-upgrade/running').is_file())
        self.hook('+PRE_DEINSTALL', upgrade=True)
        self.hook('+POST_DEINSTALL', upgrade=True)
        for path in LIVE:
            (self.root / path.lstrip('/')).unlink()
        self.hook('+POST_INSTALL', upgrade=True)
        self.assert_existing(content)
        self.assertEqual(1, self.trace.read_text().count('sing-box onerestart'))
        self.assertEqual(1, self.trace.read_text().count('network-setup:retire-legacy'))

    def test_failed_legacy_retirement_aborts_before_filter_reload_or_restart(self):
        self.existing(enabled='YES')
        self.environment['HOOK_STOPPED'] = '0'
        self.hook('+PRE_INSTALL', upgrade=True)
        source = (PACKAGE / 'packaging/freebsd/+POST_INSTALL').read_text()
        source = re.sub(r'/(?:usr/local|etc|var|conf)(?=/|[\s\x22\x27])(?:/[^\s\x22\x27()]*)?|/tmp/config\.xml\.tmp',
                        lambda match: str(self.root / match.group().lstrip('/')), source)
        result = subprocess.run(['sh'], input=source, text=True, capture_output=True,
                                env={**self.environment, 'PKG_UPGRADE': '1', 'HOOK_SETUP_FAIL': '1'})
        self.assertNotEqual(0, result.returncode)
        self.assertIn('legacy Sing-box TUN policy retirement failed', result.stderr)
        trace = self.trace.read_text()
        self.assertNotIn('filter reload', trace)
        self.assertNotIn('sing-box onerestart', trace)

    def test_failed_restore_keeps_private_legacy_upgrade_recovery_files(self):
        content = self.existing()
        self.hook('+PRE_INSTALL', upgrade=True)
        for path in LIVE:
            (self.root / path.lstrip('/')).unlink()
        self.environment['HOOK_RESTORE_FAIL'] = '1'
        self.hook('+POST_INSTALL', upgrade=True)
        recovery = self.root / 'var/db/os-sing-box-upgrade'
        self.assertEqual(0o700, recovery.stat().st_mode & 0o777)
        for relative, expected in zip(['config.json', 'sub/env', 'sub/template.json', 'sing_box'], content):
            saved = recovery / relative
            self.assertEqual(expected, saved.read_text(), relative)
            self.assertEqual(0o600, saved.stat().st_mode & 0o777)
        for path in LIVE:
            self.assertFalse((self.root / path.lstrip('/')).exists(), path)


if __name__ == '__main__':
    unittest.main()
