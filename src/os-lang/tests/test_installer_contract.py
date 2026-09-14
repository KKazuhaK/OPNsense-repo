"""Exercise real file installation and archive guards under a private install root."""
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest
import zipfile

from fixture import HelperFixture, PHP


BODY = '''$given = json_decode(file_get_contents($argv[1]), true, 512, JSON_THROW_ON_ERROR);
$log = [];
$readme = '';
switch ($given['action']) {
    case 'url': $ok = langtool_validate_url($given['value'], $log); break;
    case 'entries': $ok = langtool_validate_entries($given['value'], $log); break;
    case 'checksum': $ok = langtool_validate_checksum($given['value'], $log); break;
    case 'files': $ok = langtool_install_files($given['staging'], $given['entries'], $log); break;
    case 'install': $ok = langtool_install($log, $readme); break;
    default: throw new RuntimeException('Invalid fixture action');
}
echo json_encode(['ok' => $ok, 'log' => $log, 'readme' => $readme], JSON_THROW_ON_ERROR);
'''


@unittest.skipUnless(PHP, 'requires PHP CLI')
class InstallerContractTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='lang-installer-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.fixture = HelperFixture(self.root)
        self.staging = self.root / 'staging'
        self.staging.mkdir()
        self.outside = self.root / 'outside'
        self.outside.mkdir()
        self.helper = self.fixture.library(BODY)

    def request(self, value, checksum='', **environment):
        helper = self.fixture.library(BODY, checksum=checksum)
        payload = self.root / 'request.json'
        payload.write_text(json.dumps(value))
        result = subprocess.run([PHP, str(helper), str(payload)], text=True, capture_output=True, env={**os.environ, **environment}, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, '')
        return json.loads(result.stdout)

    def stage(self, entry, content=b'new localized content'):
        path = self.staging / entry
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return path

    def test_download_origin_and_checksum_validation(self):
        for url in ['not a URL', 'http://cloud.pfchina.org/file.zip', 'https://untrusted.invalid/file.zip', 'https://cloud.pfchina.org.untrusted.invalid/file.zip']:
            with self.subTest(url=url):
                self.assertFalse(self.request({'action': 'url', 'value': url})['ok'])
        self.assertTrue(self.request({'action': 'url', 'value': 'https://CLOUD.PFCHINA.ORG/file.zip'})['ok'])
        archive = self.root / 'checksum.zip'
        archive.write_bytes(b'exact archive bytes')
        actual = hashlib.sha256(archive.read_bytes()).hexdigest()
        self.assertTrue(self.request({'action': 'checksum', 'value': str(archive)}, checksum=actual.upper())['ok'])
        self.assertFalse(self.request({'action': 'checksum', 'value': str(archive)}, checksum='0' * 64)['ok'])
        self.assertFalse((self.fixture.state / 'private-reload').exists())

    def test_unsafe_or_unsupported_entries_are_rejected(self):
        for entry in ['', '/etc/master.passwd', '../escaped', 'share/../../escaped', 'share\\escaped', 'share/a\x00b', 'conf/config.xml', 'var/db/config']:
            with self.subTest(entry=entry):
                self.assertFalse(self.request({'action': 'entries', 'value': [entry]})['ok'])
        self.assertTrue(self.request({'action': 'entries', 'value': ['share/locale/zh_CN/messages.mo', 'opnsense/mvc/app/views/OPNsense/Core/a.volt', 'readme.md']})['ok'])
        self.assertEqual(list(self.fixture.install.iterdir()), [])

    def test_existing_file_bytes_mode_and_owner_survive_atomic_install(self):
        entry = 'share/locale/zh_CN/messages.mo'
        self.stage(entry, b'localized\x00binary\r\n\xe4\xb8\xad\xe6\x96\x87')
        destination = self.fixture.install / entry
        destination.parent.mkdir(parents=True)
        destination.write_bytes(b'previous content')
        destination.chmod(0o640)
        owner = (destination.stat().st_uid, destination.stat().st_gid)
        self.assertTrue(self.request({'action': 'files', 'staging': str(self.staging), 'entries': [entry]})['ok'])
        self.assertEqual(destination.read_bytes(), (self.staging / entry).read_bytes())
        self.assertEqual(destination.stat().st_mode & 0o777, 0o640)
        self.assertEqual((destination.stat().st_uid, destination.stat().st_gid), owner)
        self.assertEqual(list(destination.parent.glob('.lang_update_*')), [])

    def test_language_tool_cannot_overwrite_itself(self):
        protected = ['www/lang_update.php', 'opnsense/scripts/langtool/manage.php', 'opnsense/mvc/app/controllers/OPNsense/LangTool/Api/SettingsController.php', 'opnsense/mvc/app/models/OPNsense/LangTool/ACL/ACL.xml', 'opnsense/mvc/app/views/OPNsense/LangTool/index.volt', 'opnsense/service/conf/actions.d/actions_langtool.conf']
        for entry in protected:
            self.stage(entry, b'untrusted replacement')
            destination = self.fixture.install / entry
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(b'keep existing helper')
        self.assertTrue(self.request({'action': 'files', 'staging': str(self.staging), 'entries': protected + ['readme.md']})['ok'])
        for entry in protected:
            self.assertEqual((self.fixture.install / entry).read_bytes(), b'keep existing helper')

    def test_source_and_destination_symlinks_cannot_write_outside_root(self):
        outside = self.outside / 'victim'
        outside.write_bytes(b'outside unchanged')
        for kind in ['source', 'source-parent', 'destination', 'destination-parent']:
            with self.subTest(kind=kind):
                entry = 'share/' + kind + '/messages.mo'
                source = self.stage(entry)
                destination = self.fixture.install / entry
                destination.parent.mkdir(parents=True)
                if kind == 'source':
                    source.unlink()
                    source.symlink_to(outside)
                elif kind == 'source-parent':
                    source.unlink()
                    source.parent.rmdir()
                    source.parent.symlink_to(self.outside)
                    (self.outside / 'messages.mo').write_bytes(b'outside source')
                elif kind == 'destination':
                    destination.symlink_to(outside)
                else:
                    destination.parent.rmdir()
                    destination.parent.symlink_to(self.outside)
                response = self.request({'action': 'files', 'staging': str(self.staging), 'entries': [entry]})
                self.assertFalse(response['ok'])
                self.assertEqual(outside.read_bytes(), b'outside unchanged')
        self.assertFalse((self.fixture.state / 'private-reload').exists())

    @unittest.skipUnless(shutil.which('unzip'), 'requires unzip for the real archive pipeline')
    def test_full_archive_install_reads_readme_cleans_temp_and_reloads_only_fixture(self):
        entry = 'share/locale/messages.mo'
        destination = self.fixture.install / entry
        destination.parent.mkdir(parents=True)
        destination.write_bytes(b'old localization')
        destination.chmod(0o600)
        archive = self.root / 'fixture.zip'
        with zipfile.ZipFile(archive, 'w') as handle:
            handle.writestr(entry, b'new exact localization\x00bytes')
            handle.writestr('readme.md', 'fixture readme 中文\r\n')
            handle.writestr('opnsense/scripts/langtool/manage.php', b'do not install')
        shutil.copyfile(Path(__file__).parents[1] / 'src/usr/local/opnsense/scripts/langtool/validate_archive.py', self.root / 'validate_archive.py')
        binary = self.root / 'bin'
        binary.mkdir()
        fetch = binary / 'fetch'
        fetch.write_text('#!/bin/sh\n[ "$1" = "-T" ] && [ "$2" = "60" ] && [ "$3" = "-o" ] || exit 1\ncp "$LANGTOOL_TEST_ARCHIVE" "$4"\n')
        fetch.chmod(0o755)
        response = self.request({'action': 'install'}, PATH=str(binary) + os.pathsep + os.environ['PATH'], LANGTOOL_TEST_ARCHIVE=str(archive))
        self.assertTrue(response['ok'], response['log'])
        self.assertEqual(response['readme'], 'fixture readme 中文\r\n')
        self.assertEqual(destination.read_bytes(), b'new exact localization\x00bytes')
        self.assertEqual(destination.stat().st_mode & 0o777, 0o600)
        self.assertTrue((self.fixture.state / 'private-reload').exists())
        self.assertIn('Cleaning temporary files...', response['log'])
        self.assertFalse((self.fixture.install / 'opnsense/scripts/langtool/manage.php').exists())

    @unittest.skipUnless(shutil.which('unzip'), 'requires unzip for the real archive pipeline')
    def test_download_or_archive_failure_never_installs_or_reloads_and_removes_workspace(self):
        shutil.copyfile(Path(__file__).parents[1] / 'src/usr/local/opnsense/scripts/langtool/validate_archive.py', self.root / 'validate_archive.py')
        binary = self.root / 'bin'
        binary.mkdir()
        fetch = binary / 'fetch'
        fetch.write_text('#!/bin/sh\nprintf "%s" "$4" > "$LANGTOOL_TEST_FETCHED_PATH"\n[ -z "$LANGTOOL_TEST_DOWNLOAD_FAIL" ] || exit 1\ncp "$LANGTOOL_TEST_ARCHIVE" "$4"\n')
        fetch.chmod(0o755)
        fetched = self.root / 'fetched-path'
        archive = self.root / 'fixture.zip'
        for kind in ['download', 'corrupt', 'traversal']:
            with self.subTest(kind=kind):
                if kind == 'traversal':
                    with zipfile.ZipFile(archive, 'w') as handle:
                        handle.writestr('../escape', b'untrusted outside bytes')
                else:
                    archive.write_bytes(b'invalid ZIP')
                response = self.request({'action': 'install'}, PATH=str(binary) + os.pathsep + os.environ['PATH'], LANGTOOL_TEST_ARCHIVE=str(archive),
                                        LANGTOOL_TEST_FETCHED_PATH=str(fetched), LANGTOOL_TEST_DOWNLOAD_FAIL='1' if kind == 'download' else '')
                self.assertFalse(response['ok'])
                self.assertFalse(Path(fetched.read_text()).parent.exists(), 'Failed installation left its temporary workspace behind.')
                self.assertEqual(list(self.fixture.install.iterdir()), [])
                self.assertFalse((self.fixture.state / 'private-reload').exists())
                self.assertIn('Cleaning temporary files...', response['log'])


if __name__ == '__main__':
    unittest.main()
