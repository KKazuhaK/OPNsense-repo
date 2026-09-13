"""Use native Core and pkg when available; keep every write in private fixtures."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from urllib.parse import unquote_to_bytes

PACKAGE = Path(__file__).resolve().parents[1]
NATIVE_CORE = Path('/usr/local/opnsense/mvc/app/config/loader.php').is_file()


class NativeTests(unittest.TestCase):
    @unittest.skipUnless(NATIVE_CORE, 'Requires genuine native OPNsense Core and field types')
    def test_native_model_validation_credentials_and_xml_roundtrip(self):
        result = subprocess.run(['php', str(PACKAGE / 'tests/native/test-model.php'), str(PACKAGE)],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn('Native DynDNS model passed', result.stdout)

    @unittest.skipUnless(shutil.which('pkg') and os.uname().sysname == 'FreeBSD', 'Requires native FreeBSD pkg')
    def test_package_stages_the_registered_service_and_plugin_paths(self):
        with tempfile.TemporaryDirectory(prefix='ddclient-package-') as directory:
            work = Path(directory)
            environment = {**os.environ, 'TARGET_ABI': 'native',
                           'WORKDIR': str(work / 'work'), 'DISTDIR': str(work / 'dist')}
            environment.pop('ABI', None)
            result = subprocess.run(['sh', str(PACKAGE / 'build.sh')], env=environment,
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            package = work / 'dist/os-ddclient-opnwall.pkg'
            with tarfile.open(package) as archive:
                members = {member.name.lstrip('./'): member for member in archive.getmembers()}
                manifest = json.load(archive.extractfile(members['+MANIFEST']))
                required = ['usr/local/etc/rc.d/ddclient_opn', 'usr/local/etc/inc/plugins.inc.d/ddclient.inc',
                    'usr/local/opnsense/scripts/ddclient/ddclient_opn.py',
                    'usr/local/opnsense/mvc/app/models/OPNsense/DynDNS/DynDNS.xml',
                    'usr/local/opnsense/mvc/app/controllers/OPNsense/DynDNS/Api/AccountsController.php']
                for name in required:
                    self.assertIn(name, members, 'A registered runtime path is absent from the package')
                self.assertNotIn('etc/rc.d/ddclient_opn', members)
                self.assertNotIn('etc/inc/plugins.inc.d/ddclient.inc', members)
                self.assertTrue(members[required[0]].mode & 0o111)
                for source in (PACKAGE / 'src').rglob('*'):
                    if not source.is_file() or any(part.startswith('._') or part == '.DS_Store' or
                            part == '__pycache__' for part in source.relative_to(PACKAGE / 'src').parts):
                        continue
                    name = source.relative_to(PACKAGE / 'src').as_posix()
                    if name.startswith('etc/'):
                        name = 'usr/local/' + name
                    self.assertIn(name, members)
                    self.assertEqual(archive.extractfile(members[name]).read(), source.read_bytes(), name)
                for name in ['usr/local/etc/ddclient.json', 'usr/local/etc/ddclient.conf',
                             'conf/config.xml', 'var/tmp/ddclient_opn.status']:
                    self.assertNotIn(name, members)
                self.assertFalse(any('__pycache__' in name or name.endswith(('.pyc', '.pyo')) for name in members))
                for phase, filename in {'pre-install': '+PRE_INSTALL', 'post-install': '+POST_INSTALL',
                        'pre-deinstall': '+PRE_DEINSTALL', 'post-deinstall': '+POST_DEINSTALL'}.items():
                    self.assertEqual(unquote_to_bytes(manifest['scripts'][phase]),
                                     (PACKAGE / 'packaging/freebsd' / filename).read_bytes().removesuffix(b'\n'))
                version = json.load(archive.extractfile(members['usr/local/opnsense/version/ddclient-opnwall']))
                self.assertEqual(version['product_version'], manifest['version'])
                self.assertEqual(version['product_id'], manifest['name'])

    @unittest.skipUnless(shutil.which('pkg') and os.uname().sysname == 'FreeBSD', 'Requires native FreeBSD pkg')
    def test_abi_native_environment_does_not_override_pkg_detection(self):
        with tempfile.TemporaryDirectory(prefix='ddclient-native-abi-') as directory:
            root = Path(directory)
            environment = {**os.environ, 'ABI': 'native', 'WORKDIR': str(root / 'work'),
                           'DISTDIR': str(root / 'dist')}
            environment.pop('TARGET_ABI', None)
            result = subprocess.run(['sh', str(PACKAGE / 'build.sh')], env=environment, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            expected = subprocess.check_output(['env', '-u', 'ABI', 'pkg', 'config', 'ABI'], text=True).strip()
            with tarfile.open(root / 'dist/os-ddclient-opnwall.pkg') as archive:
                manifest = json.load(archive.extractfile('+MANIFEST'))
                self.assertEqual(manifest['abi'], expected)


if __name__ == '__main__':
    unittest.main()
