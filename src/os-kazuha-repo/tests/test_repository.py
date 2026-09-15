"""Run repository hooks and bootstrap failures against a private filesystem."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

PLUGIN = Path(__file__).resolve().parents[1]
ROOT = PLUGIN.parents[1]
HOOK = PLUGIN / 'src/usr/local/opnsense/scripts/firmware/repos/kazuha.sh'
BOOTSTRAP = ROOT / 'client.sh'
KEY = PLUGIN / 'src/usr/local/share/kazuha-repo/kazuha.pub'


class RepositoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / 'root'
        self.bin = self.base / 'bin'
        self.bin.mkdir()
        self.repos = self.root / 'usr/local/etc/pkg/repos'
        self.keys = self.root / 'usr/local/etc/pkg/keys'
        self.repos.mkdir(parents=True)
        self.keys.mkdir(parents=True)
        source_key = self.root / 'usr/local/share/kazuha-repo/kazuha.pub'
        source_key.parent.mkdir(parents=True)
        shutil.copyfile(KEY, source_key)
        self.config = self.repos / 'kazuha.conf'
        self.config.write_text('original repository configuration\n')
        self.other = self.repos / 'OPNsense.conf'
        self.other.write_text('unrelated repository configuration\n')
        self.old_key = self.keys / 'kazuha.pub'
        self.old_key.write_text('original key\n')
        self.env = dict(os.environ, PATH=str(self.bin) + ':' + os.environ['PATH'],
                        KAZUHA_REPO_ROOT=str(self.root), SERIES='26.7', KEY_SOURCE=str(KEY),
                        TRACE=str(self.base / 'trace'), FAIL_PHASE='', CORRUPT_KEY='',
                        CATALOG=json.dumps({'os-kazuha-repo': '1.0.0'}))
        for name, code in {
            'opnsense-version': 'import os; print(os.environ["SERIES"])',
            'sha256': 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[-1], "rb").read()).hexdigest())',
            'id': 'print(0)',
            'fetch': '''import os,sys,shutil
from pathlib import Path
assert sys.argv[-1] == "https://kkazuhak.github.io/OPNsense-repo/kazuha.pub"
output = Path(sys.argv[sys.argv.index("-o") + 1])
shutil.copyfile(os.environ["KEY_SOURCE"], output)
if os.environ["CORRUPT_KEY"]: output.write_text("wrong key")''',
            'pkg': '''import os,sys,json
from pathlib import Path
args=sys.argv[1:]
if args[:2] == ["version", "-t"]:
 order = ["1.0.0", "1.0.1", "1.0.9", "1.1.0", "1.1.1"]
 left,right=args[2:]
 left_key=order.index(left) if left in order else left
 right_key=order.index(right) if right in order else right
 print(">" if left_key > right_key else "<" if left_key < right_key else "=")
 sys.exit(0)
assert args[0] == "-4"
with open(os.environ["TRACE"], "a") as trace: trace.write(json.dumps(args)+"\\n")
candidate = any(x.startswith("REPOS_DIR=") for x in args)
phase = "candidate" if candidate else "install" if "install" in args else "active"
if candidate:
 repo=Path(next(x.split("=",1)[1] for x in args if x.startswith("REPOS_DIR="))) / "kazuha.conf"
 content=repo.read_text()
 assert 'signature_type: "pubkey"' in content
 assert 'https://kkazuhak.github.io/OPNsense-repo/repo/${ABI}' in content
 assert str(repo.parents[1] / "kazuha.pub") in content
if os.environ["FAIL_PHASE"] == phase: sys.exit(1)
if "rquery" in args:
 if "%n %v" in args:
  value=json.loads(os.environ.get("CATALOG", "{}" )).get(args[-1])
  versions=value if isinstance(value, list) else [value] if value else []
  for version in versions: print(args[-1]+" "+version)
 else: print("1.0.0" if "%v" in args else "os-kazuha-repo")''',
        }.items():
            path = self.bin / name
            path.write_text('#!' + sys.executable + '\n' + code + '\n')
            path.chmod(0o755)

    def run_script(self, script, *arguments):
        return subprocess.run(['sh', str(script), *arguments], env=self.env, capture_output=True, text=True)

    def restore_manifest(self, content, catalog):
        hook = self.root / 'usr/local/opnsense/scripts/firmware/repos/kazuha.sh'
        hook.parent.mkdir(parents=True, exist_ok=True)
        hook.write_text('''#!/bin/sh
case "$1" in
manifest) cat "$KAZUHA_REPO_ROOT/restore-manifest" ;;
mirror) exit 0 ;;
*) exit 1 ;;
esac
''')
        (self.root / 'restore-manifest').write_text(content)
        self.env['CATALOG'] = json.dumps({'os-kazuha-repo': '1.0.0', **catalog})

    def test_bootstrap_restores_manifest_names_using_current_signed_catalog_versions(self):
        self.restore_manifest('os-kazuha-repo 1.0.0\nos-frp 1.0.0\nos-speedtest 1.1.0\n',
                              {'os-frp': ['1.0.1', '1.0.9', '1.1.0'], 'os-speedtest': '1.1.1'})
        result = self.run_script(BOOTSTRAP, '--restore-plugins')
        self.assertEqual(0, result.returncode, result.stderr)
        calls = [json.loads(line) for line in (self.base / 'trace').read_text().splitlines()]
        restore = [call for call in calls if 'install' in call and 'os-frp-1.1.0' in call]
        self.assertEqual(1, len(restore))
        self.assertEqual(['os-frp-1.1.0', 'os-speedtest-1.1.1'], restore[0][-2:])
        self.assertTrue(all('-r' in call and 'kazuha' in call for call in restore))

    def test_bootstrap_selects_latest_repository_plugin_from_historical_catalog(self):
        self.env['CATALOG'] = json.dumps({'os-kazuha-repo': ['1.0.0', '1.0.1']})
        result = self.run_script(BOOTSTRAP)
        self.assertEqual(0, result.returncode, result.stderr)
        calls = [json.loads(line) for line in (self.base / 'trace').read_text().splitlines()]
        fetch = [call for call in calls if 'fetch' in call]
        install = [call for call in calls if 'install' in call]
        self.assertEqual('os-kazuha-repo-1.0.1', fetch[-1][-1])
        self.assertEqual('os-kazuha-repo-1.0.1', install[-1][-1])

    def test_restore_preflights_all_plugins_before_installing_any_of_them(self):
        self.restore_manifest('os-frp 1.0.0\nos-missing 1.0.0\n', {'os-frp': '1.0.1'})
        result = self.run_script(BOOTSTRAP, '--restore-plugins')
        self.assertNotEqual(0, result.returncode)
        self.assertIn('unavailable', result.stderr)
        calls = [json.loads(line) for line in (self.base / 'trace').read_text().splitlines()]
        self.assertFalse(any('install' in call and 'os-frp-1.0.1' in call for call in calls))

    def test_restore_rejects_invalid_manifest_names_and_versions(self):
        for content in ['--repository 1.0.0\n', 'os-frp 1.0.0;touch\n',
                        'os-frp 1.0.0 extra\n', 'os-frp\n']:
            with self.subTest(content=content):
                self.restore_manifest(content, {'os-frp': '1.0.1'})
                self.assertNotEqual(0, self.run_script(BOOTSTRAP, '--restore-plugins').returncode)

    def test_bootstrap_requires_explicit_restore_option(self):
        self.restore_manifest('os-frp 1.0.0\n', {'os-frp': '1.0.1'})
        self.assertEqual(0, self.run_script(BOOTSTRAP).returncode)
        calls = [json.loads(line) for line in (self.base / 'trace').read_text().splitlines()]
        self.assertFalse(any('os-frp-1.0.1' in call for call in calls))

    def assert_original_files(self):
        self.assertEqual('original repository configuration\n', self.config.read_text())
        self.assertEqual('original key\n', self.old_key.read_text())
        self.assertEqual('unrelated repository configuration\n', self.other.read_text())

    def test_hook_tracks_running_series_without_rewriting_other_repositories(self):
        for series, suffix in [('26.7', ''), ('27.1', '/27.1'), ('27.7', '/27.7')]:
            self.env['SERIES'] = series
            result = self.run_script(HOOK)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertIn('repo/${ABI}' + suffix + '"', self.config.read_text())
            self.assertIn('signature_type: "pubkey"', self.config.read_text())
            self.assertEqual(KEY.read_bytes(), self.old_key.read_bytes())
            self.assertEqual(0o644, self.config.stat().st_mode & 0o777)
            self.assertEqual(0o644, self.old_key.stat().st_mode & 0o777)
            self.assertEqual('unrelated repository configuration\n', self.other.read_text())

    def test_hook_rejects_bad_key_or_series_before_changing_files(self):
        for series in ['27.2', '27.1/path', '$(touch /tmp/no)', '', '27.1\n27.7']:
            self.env['SERIES'] = series
            self.assertNotEqual(0, self.run_script(HOOK).returncode)
            self.assert_original_files()
        self.env['SERIES'] = '26.7'
        (self.root / 'usr/local/share/kazuha-repo/kazuha.pub').write_text('bad trust anchor')
        self.assertNotEqual(0, self.run_script(HOOK).returncode)
        self.assert_original_files()

    def test_bootstrap_rejects_bad_key_or_missing_signed_catalog_before_changing_files(self):
        self.env['CORRUPT_KEY'] = 'yes'
        self.assertNotEqual(0, self.run_script(BOOTSTRAP).returncode)
        self.assert_original_files()
        self.assertFalse((self.base / 'trace').exists())
        self.env['CORRUPT_KEY'] = ''
        self.env['FAIL_PHASE'] = 'candidate'
        self.env['SERIES'] = '27.1'
        self.assertNotEqual(0, self.run_script(BOOTSTRAP).returncode)
        self.assert_original_files()
        calls = [json.loads(x) for x in (self.base / 'trace').read_text().splitlines()]
        self.assertEqual(1, len(calls))
        self.assertIn('update', calls[0])

    def test_bootstrap_restores_existing_files_if_active_update_or_install_fails(self):
        for phase in ['active', 'install']:
            self.env['FAIL_PHASE'] = phase
            self.assertNotEqual(0, self.run_script(BOOTSTRAP).returncode)
            self.assert_original_files()

    def test_bootstrap_removes_only_original_unsigned_upstream_configuration(self):
        legacy = self.repos / 'opnwall.conf'
        configurations = [
            ('opnwall: {\n url: "https://opnwall.github.io/OPNsense-repo/repo/${ABI}",\n priority: 10,\n enabled: yes\n}\n', False),
            ('opnwall: {url: "https://custom.invalid/repo/${ABI}", enabled: yes}\n', True),
            ('opnwall: {url: "https://opnwall.github.io/OPNsense-repo/repo/${ABI}", signature_type: "pubkey", enabled: yes}\n', True),
        ]
        for content, preserved in configurations:
            legacy.write_text(content)
            result = self.run_script(BOOTSTRAP)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual(preserved, legacy.exists())
            if preserved:
                self.assertEqual(content, legacy.read_text())
            self.assertEqual(KEY.read_bytes(), self.old_key.read_bytes())
            self.assertEqual('unrelated repository configuration\n', self.other.read_text())
        calls = [json.loads(x) for x in (self.base / 'trace').read_text().splitlines()]
        self.assertTrue(all(x[0] == '-4' for x in calls))
        last = calls[-1]
        self.assertIn('-U', last)
        self.assertEqual('os-kazuha-repo-1.0.0', last[-1])
        cachedir = next(x for x in last if x.startswith('PKG_CACHEDIR='))
        self.assertTrue(any(cachedir in x and 'fetch' in x for x in calls))

    def test_upgrade_deinstall_cannot_unregister_or_remove_trust_configuration(self):
        self.env['PKG_UPGRADE'] = 'yes'
        result = self.run_script(PLUGIN / 'packaging/freebsd/+POST_DEINSTALL')
        self.assertEqual(0, result.returncode, result.stderr)
        self.assert_original_files()

    def test_temporary_package_removal_preserves_desired_registration_and_trust(self):
        script = PLUGIN / 'packaging/freebsd/+POST_DEINSTALL'
        self.assertNotIn('register.php', script.read_text())
        self.env.pop('PKG_UPGRADE', None)
        result = self.run_script(script)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assert_original_files()

    def test_metadata_and_key_identify_the_repository_plugin(self):
        metadata = json.loads((PLUGIN / 'src/usr/local/opnsense/version/kazuha-repo').read_text())
        self.assertEqual('os-kazuha-repo', metadata['product_id'])
        self.assertEqual('26.7', metadata['product_abi'])
        self.assertEqual('1.0.1', metadata['product_version'])
        self.assertEqual('92e83cb0267c3ef27cb355bc2f045c3449fd5c741d1030c7a90c879b00fa5e9b', hashlib.sha256(KEY.read_bytes()).hexdigest())


if __name__ == '__main__':
    unittest.main()
