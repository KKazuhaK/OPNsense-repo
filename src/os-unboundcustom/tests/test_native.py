"""Verify the actual native model and standalone archive in private locations."""
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
    def test_native_model_raw_directives_disabled_state_and_xml_roundtrip(self):
        result = subprocess.run(['php', str(PACKAGE / 'tests/native/test-model.php'), str(PACKAGE)],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn('Native Unboundcustom model passed', result.stdout)

    @unittest.skipUnless(shutil.which('pkg') and os.uname().sysname == 'FreeBSD', 'Requires native FreeBSD pkg')
    def test_native_package_matches_model_actions_templates_and_hooks(self):
        with tempfile.TemporaryDirectory(prefix='unboundcustom-package-') as directory:
            root = Path(directory)
            environment = {**os.environ, 'ABI': 'native', 'WORKDIR': str(root / 'work'),
                           'DISTDIR': str(root / 'dist')}
            result = subprocess.run(['sh', str(PACKAGE / 'build.sh')], env=environment, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            expected = subprocess.check_output(['env', '-u', 'ABI', 'pkg', 'config', 'ABI'], text=True).strip()
            with tarfile.open(root / 'dist/os-unboundcustom.pkg') as archive:
                members = {member.name.lstrip('./'): member for member in archive.getmembers()}
                manifest = json.load(archive.extractfile(members['+MANIFEST']))
                self.assertEqual(manifest['abi'], expected)
                base = 'usr/local/opnsense/'
                for name in ['scripts/OPNsense/Unboundcustom/apply.sh',
                    'service/conf/actions.d/actions_unboundcustom.conf',
                    'service/templates/OPNsense/Unboundcustom/custom-options.conf',
                    'mvc/app/models/OPNsense/Unboundcustom/General.xml']:
                    self.assertIn(base + name, members)
                    self.assertEqual(archive.extractfile(members[base + name]).read(),
                                     (PACKAGE / 'src/opnsense' / name).read_bytes())
                self.assertTrue(members[base + 'scripts/OPNsense/Unboundcustom/apply.sh'].mode & 0o111)
                for source in (PACKAGE / 'src/opnsense').rglob('*'):
                    if not source.is_file() or any(part.startswith('._') or part == '.DS_Store'
                            for part in source.relative_to(PACKAGE / 'src/opnsense').parts):
                        continue
                    name = base + source.relative_to(PACKAGE / 'src/opnsense').as_posix()
                    self.assertIn(name, members)
                    self.assertEqual(archive.extractfile(members[name]).read(), source.read_bytes(), name)
                for phase, filename in {'post-install': '+POST_INSTALL', 'pre-deinstall': '+PRE_DEINSTALL',
                                        'post-deinstall': '+POST_DEINSTALL'}.items():
                    self.assertEqual(unquote_to_bytes(manifest['scripts'][phase]),
                                     (PACKAGE / 'packaging/freebsd' / filename).read_bytes().removesuffix(b'\n'))
                version = json.load(archive.extractfile(members[base + 'version/unboundcustom']))
                self.assertEqual(version['product_version'], manifest['version'])
                self.assertEqual(version['product_id'], manifest['name'])
                self.assertNotIn('conf/config.xml', members)
                self.assertNotIn('usr/local/etc/unbound.opnsense.d/custom-options.conf', members)
                self.assertFalse(any(name.startswith('original/') or '__pycache__' in name or name.endswith(('.pyc', '.pyo')) for name in members))


if __name__ == '__main__':
    unittest.main()
