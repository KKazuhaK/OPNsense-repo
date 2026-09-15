"""Run the build entry point and reject contaminated package archives."""
import hashlib
import importlib.util
import io
import json
import lzma
import os
from pathlib import Path
import shutil
import re
import subprocess
import sys
import tarfile
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('verify_repo', REPO / 'verify-repo.py')
verify = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verify)
spec = importlib.util.spec_from_file_location('build_target', REPO / 'src/os-mihomo/packaging/target.py')
target_helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(target_helper)


# The build script owns the version; a bump must not need an edit here as well.
BUILD_VERSION = re.search(r'^VERSION="\$\{VERSION:-([^}"]+)\}"',
                          (Path(__file__).resolve().parents[1] / 'build.sh').read_text(),
                          re.MULTILINE).group(1)


class BuildTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.project = self.root / 'project'
        self.project.mkdir()
        (self.root / 'common').mkdir()
        shutil.copyfile(REPO / 'src/common/process_identity.py', self.root / 'common/process_identity.py')
        shutil.copyfile(REPO / 'src/common/route_control.py', self.root / 'common/route_control.py')
        shutil.copyfile(REPO / 'src/common/tun_policy_routing.py',
                        self.root / 'common/tun_policy_routing.py')
        shutil.copyfile(REPO / 'src/os-mihomo/build.sh', self.project / 'build.sh')
        (self.project / 'packaging').mkdir()
        for name in ('targets.json', 'target.py'):
            shutil.copyfile(REPO / 'src/os-mihomo/packaging' / name, self.project / 'packaging' / name)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.created = self.root / 'pkg-created'
        self.env = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ['PATH'],
                        FAKE_PKG_CREATED=str(self.created), FAKE_NATIVE_RELEASE='15.1-RELEASE',
                        FAKE_NATIVE_MAJOR='15', FAKE_PKG_ABI='FreeBSD:15:amd64')
        for name in ('TARGET_PROFILE', 'TARGET_ABI', 'TARGET_PRODUCT_ABI', 'TARGET_PYTHON', 'ABI', 'DISTDIR'):
            self.env.pop(name, None)
        self.command('uname', '''import os,sys
args=sys.argv[1:]
print({'-s':'FreeBSD','-m':'amd64','-K':str(int(os.environ['FAKE_NATIVE_MAJOR'])*100000+1000)}[args[0]])
''')
        self.command('freebsd-version', "import os\nprint(os.environ['FAKE_NATIVE_RELEASE'])\n")
        self.command('pkg', '''import io,json,os,sys,tarfile
from pathlib import Path
args=sys.argv[1:]
if args[:2]==['config','ABI']:
    print(os.environ['FAKE_PKG_ABI'])
elif args[0]=='query':
    name=args[-1]
    if name=='curl':origin,version='ftp/curl','8.20.0'
    elif name.startswith('python3'):origin,version='lang/'+name,os.environ['FAKE_PKG_PYTHON_VERSION']
    elif name.endswith('-pyyaml'):origin,version='devel/py-pyyaml',os.environ['FAKE_PKG_YAML_VERSION']
    else:raise SystemExit('Unexpected dependency')
    print(origin,version,os.environ.get('FAKE_DEP_ABI',os.environ['FAKE_PKG_ABI']))
elif args[0]=='create':
    manifest=Path(args[args.index('-M')+1]);stage=Path(args[args.index('-r')+1]);output=Path(args[args.index('-o')+1])
    data=json.loads(manifest.read_text())
    with tarfile.open(output/(data['name']+'-'+data['version']+'.pkg'),'w:gz') as archive:
        for name in ['+MANIFEST','+COMPACT_MANIFEST']:
            info=tarfile.TarInfo(name);info.size=manifest.stat().st_size
            archive.addfile(info,io.BytesIO(manifest.read_bytes()))
        for path in stage.rglob('*'):
            if path.is_file():archive.add(path,arcname=str(path.relative_to(stage)),recursive=False)
        if os.environ.get('FAKE_PKG_EXTRA_BYTECODE'):
            info=tarfile.TarInfo('usr/local/opnsense/scripts/mihomo/__pycache__/mihomo.cpython-314.pyc');info.size=5
            archive.addfile(info,io.BytesIO(b'cache'))
    Path(os.environ['FAKE_PKG_CREATED']).touch()
elif args[0]!='info':
    raise SystemExit('Unexpected pkg operation')
''')
        self.command('sha256', "import hashlib,sys\nprint(hashlib.sha256(open(sys.argv[-1],'rb').read()).hexdigest())\n")
        for name in ('usr/local/bin/mihomo', 'usr/bin/mihomo_sub', 'usr/local/etc/rc.d/mihomo',
                     'usr/local/opnsense/scripts/mihomo/mihomo.py',
                     'usr/local/opnsense/scripts/mihomo/setup_unbound.php'):
            path = self.project / 'src' / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('exec /usr/local/bin/python3 fixture\n')
        product = self.project / 'src/usr/local/opnsense/version/mihomo'
        product.parent.mkdir(parents=True)
        product.write_text(json.dumps({'product_id': 'os-mihomo', 'product_name': 'mihomo',
                                      'product_abi': '26.7', 'product_version': '1.1.1'}))
        asset = self.project / 'src/usr/local/bin/clash-meta-freebsd-amd64.xz'
        asset.write_bytes(lzma.compress(b'core fixture'))
        packaging = self.project / 'packaging/freebsd'
        packaging.mkdir(parents=True)
        for name in ('pkg-descr', '+PRE_INSTALL', '+POST_INSTALL', '+PRE_DEINSTALL', '+POST_DEINSTALL'):
            (packaging / name).write_text('exec /usr/local/bin/python3 fixture\n')

    def command(self, name, content):
        path = self.bin / name
        path.write_text('#!' + sys.executable + '\n' + content)
        path.chmod(0o755)

    def interpreter(self):
        interpreter = shutil.which('python3.13')
        if not interpreter and sys.version_info[:2] == (3, 13):
            interpreter = sys.executable
        if not interpreter:
            self.skipTest('Positive build cases require Python 3.13; verified on CI and FreeBSD.')
        self.env['MIHOMO_PYTHON'] = interpreter
        self.env['FAKE_PKG_PYTHON_VERSION'] = subprocess.check_output(
            [interpreter, '-B', '-c', 'import sys;print("%s.%s.%s" % sys.version_info[:3])'], text=True).strip()
        self.env['FAKE_PKG_YAML_VERSION'] = subprocess.check_output(
            [interpreter, '-B', '-c', 'import yaml; print(yaml.__version__)'], text=True).strip() + '_1'

    def current_interpreter(self):
        self.env.update(MIHOMO_PYTHON=sys.executable,
                        TARGET_PYTHON='.'.join(map(str, sys.version_info[:2])),
                        TARGET_PRODUCT_ABI='27.1',
                        FAKE_PKG_PYTHON_VERSION='.'.join(map(str, sys.version_info[:3])))
        self.env['FAKE_PKG_YAML_VERSION'] = subprocess.check_output(
            [sys.executable, '-B', '-c', 'import yaml; print(yaml.__version__)'], text=True).strip() + '_1'
        # Native target fixtures must not read the actual test host's firmware series.
        self.command('opnsense-version', "print('27.1')\n")

    def package_path(self, abi='FreeBSD:15:amd64', series=None):
        directory = self.project / 'dist' / abi
        if series:
            directory /= series
        return directory / ('os-mihomo-%s.pkg' % BUILD_VERSION)

    def manifest(self, package):
        with tarfile.open(package) as archive:
            return json.load(archive.extractfile('+MANIFEST'))

    def build(self):
        return subprocess.run(['sh', str(self.project / 'build.sh')], env=self.env,
                              capture_output=True, text=True, timeout=30)

    def test_python_314_is_rejected_before_staging(self):
        self.command('wrong-python', '''import runpy,sys
args=sys.argv[1:]
if args[0]=='-B':args.pop(0)
sys.argv=args
sys.version_info=(3,14,0)
runpy.run_path(args[0],run_name='__main__')
''')
        wrong = self.bin / 'wrong-python'
        self.env['MIHOMO_PYTHON'] = str(wrong)
        result = self.build()
        self.assertNotEqual(0, result.returncode)
        self.assertIn('must be Python 3.13', result.stderr)
        self.assertFalse((self.project / 'work').exists())
        self.assertFalse(self.created.exists())

    def test_build_excludes_source_bytecode_and_matches_python_dependency(self):
        self.interpreter()
        cache = self.project / 'src/usr/local/opnsense/scripts/mihomo/__pycache__'
        cache.mkdir()
        (cache / 'mihomo.cpython-314.pyc').write_bytes(b'ignored cache')
        (cache.parent / 'legacy.pyc').write_bytes(b'ignored bytecode')
        (cache.parent / 'legacy.pyo').write_bytes(b'ignored optimized bytecode')
        result = self.build()
        self.assertEqual(0, result.returncode, result.stderr)
        with tarfile.open(self.package_path()) as archive:
            self.assertFalse(any('__pycache__' in name or name.endswith(('.pyc', '.pyo')) for name in archive.getnames()))
            manifest = json.load(archive.extractfile('+MANIFEST'))
        self.assertEqual(self.env['FAKE_PKG_PYTHON_VERSION'], manifest['deps']['python313']['version'])
        self.assertEqual('26.7', manifest['annotations']['product_abi'])
        self.assertEqual(BUILD_VERSION, manifest['annotations']['product_version'])
        self.assertEqual('FreeBSD:15:amd64', manifest['abi'])
        self.assertEqual('freebsd:15:x86:64', manifest['arch'])
        with tarfile.open(self.package_path()) as archive:
            product = json.load(archive.extractfile('usr/local/opnsense/version/mihomo'))
            self.assertEqual(manifest['annotations'], product)
            self.assertIn(b'/usr/local/bin/python3.13', archive.extractfile('usr/bin/mihomo_sub').read())
        self.assertIn('/usr/local/bin/python3.13', manifest['scripts']['pre-install'])

    def test_dependency_patch_mismatch_prevents_package_creation(self):
        self.interpreter()
        self.env['FAKE_PKG_PYTHON_VERSION'] = '3.13.99_1'
        result = self.build()
        self.assertNotEqual(0, result.returncode)
        self.assertIn('differs from the python313 package dependency', result.stderr)
        self.assertFalse(self.created.exists())

    def test_packager_added_bytecode_is_rejected(self):
        self.interpreter()
        self.env['FAKE_PKG_EXTRA_BYTECODE'] = '1'
        result = self.build()
        self.assertTrue(self.created.exists())
        self.assertNotEqual(0, result.returncode)
        self.assertIn('Python bytecode must not be packaged', result.stderr)

    def test_explicit_native_future_abi_changes_manifest_and_preserves_outputs(self):
        self.current_interpreter()
        first = self.build()
        self.assertEqual(0, first.returncode, first.stderr)
        earlier = self.package_path(series='27.1').read_bytes()
        self.env.update(TARGET_ABI='FreeBSD:16:amd64', FAKE_PKG_ABI='FreeBSD:16:amd64',
                        FAKE_NATIVE_MAJOR='16', FAKE_NATIVE_RELEASE='16.0-RELEASE')
        second = self.build()
        self.assertEqual(0, second.returncode, second.stderr)
        manifest = self.manifest(self.package_path(abi='FreeBSD:16:amd64', series='27.1'))
        self.assertEqual('FreeBSD:16:amd64', manifest['abi'])
        self.assertEqual('freebsd:16:x86:64', manifest['arch'])
        self.assertEqual('27.1', manifest['annotations']['product_abi'])
        package_name = 'python' + self.env['TARGET_PYTHON'].replace('.', '')
        self.assertEqual(self.env['FAKE_PKG_PYTHON_VERSION'], manifest['deps'][package_name]['version'])
        self.assertEqual(earlier, self.package_path(series='27.1').read_bytes())

    def test_relabeling_pkg_abi_without_native_base_is_rejected(self):
        self.current_interpreter()
        self.env.update(TARGET_ABI='FreeBSD:16:amd64', FAKE_PKG_ABI='FreeBSD:16:amd64')
        result = self.build()
        self.assertNotEqual(0, result.returncode)
        self.assertIn('Target, native FreeBSD and pkg ABI must match', result.stderr)
        self.assertFalse(self.created.exists())

    def test_foreign_dependency_and_kernel_are_rejected(self):
        self.current_interpreter()
        self.env['FAKE_DEP_ABI'] = 'FreeBSD:14:amd64'
        result = self.build()
        self.assertNotEqual(0, result.returncode)
        self.assertIn('incompatible native build dependency', result.stderr)
        self.assertFalse(self.created.exists())
        self.env.pop('FAKE_DEP_ABI')
        self.env['FAKE_NATIVE_MAJOR'] = '16'
        result = self.build()
        self.assertNotEqual(0, result.returncode)
        self.assertIn('Build kernel and userland', result.stderr)
        self.assertFalse(self.created.exists())

    def test_staging_profile_and_invalid_target_are_rejected(self):
        self.current_interpreter()
        self.env['TARGET_PROFILE'] = '27.1'
        result = self.build()
        self.assertNotEqual(0, result.returncode)
        self.assertIn('not ready for building', result.stderr)
        self.env.pop('TARGET_PROFILE')
        self.env['TARGET_ABI'] = 'FreeBSD:16:arm64'
        result = self.build()
        self.assertNotEqual(0, result.returncode)
        self.assertIn('Target ABI must', result.stderr)
        self.assertFalse(self.created.exists())

    def test_wrong_native_opnsense_series_is_rejected_before_staging(self):
        self.current_interpreter()
        self.command('opnsense-version', "print('26.7')\n")
        result = self.build()
        self.assertNotEqual(0, result.returncode)
        self.assertIn('Native OPNsense product ABI differs', result.stderr)
        self.assertFalse((self.project / 'work').exists())
        self.assertFalse(self.created.exists())

    def test_native_opnsense_series_is_recorded_in_build_metadata(self):
        self.current_interpreter()
        result = self.build()
        self.assertEqual(0, result.returncode, result.stderr)
        metadata = self.project / 'work/freebsd-pkg/FreeBSD:15:amd64/27.1/meta/build-target.json'
        self.assertEqual('27.1', json.loads(metadata.read_text())['native_product_abi'])


class TargetTests(unittest.TestCase):
    def test_matrix_includes_only_committed_complete_enabled_target(self):
        project = REPO / 'src/os-mihomo'
        result = target_helper.enabled_targets(project)
        self.assertEqual(['26.7'], [target['profile'] for target in result])
        self.assertEqual('repo/FreeBSD:15:amd64', result[0]['repository'])
        output = subprocess.check_output([sys.executable, '-B', str(project / 'packaging/target.py'), '--matrix'], text=True)
        self.assertEqual({'include': result}, json.loads(output))

    def test_explicit_target_does_not_enter_committed_matrix(self):
        project = REPO / 'src/os-mihomo'
        target = target_helper.resolve_target(project, {'TARGET_ABI': 'FreeBSD:16:amd64',
            'TARGET_PRODUCT_ABI': '27.1', 'TARGET_PYTHON': '3.14'})
        self.assertEqual('explicit', target['profile'])
        self.assertEqual('repo/FreeBSD:16:amd64/27.1', target['repository'])
        self.assertEqual('python314', target['python_package'])
        self.assertNotIn(target, target_helper.enabled_targets(project))
        with self.assertRaisesRegex(ValueError, 'explicit TARGET_PRODUCT_ABI'):
            target_helper.resolve_target(project, {'TARGET_ABI': 'FreeBSD:16:amd64'})

    def test_enabled_target_with_missing_native_release_does_not_enter_matrix(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            (project / 'packaging').mkdir()
            config = target_helper.recipes(REPO / 'src/os-mihomo')
            config['targets']['27.1']['enabled'] = True
            (project / 'packaging/targets.json').write_text(json.dumps(config))
            with self.assertRaisesRegex(ValueError, 'no native release or repository'):
                target_helper.enabled_targets(project)

    def test_repository_cannot_escape_target_or_use_another_series(self):
        for repository in ('repo/FreeBSD:15:amd64/../27.1', 'repo/FreeBSD:14:amd64',
                           'repo/FreeBSD:15:amd64/26.1', '/repo/FreeBSD:15:amd64'):
            with self.assertRaisesRegex(ValueError, 'Target repository'):
                target_helper.target_values('FreeBSD:15:amd64', '26.7', '3.13', repository=repository)

    def test_business_or_other_product_series_are_not_implicit_ce_targets(self):
        for series in ('26.4', '26.10', '26.2', '26.07'):
            with self.assertRaisesRegex(ValueError, 'OPNsense CE series'):
                target_helper.target_values('FreeBSD:15:amd64', series, '3.13')

    def test_python_transform_covers_versioned_paths_without_corrupting_binary(self):
        target = target_helper.target_values('FreeBSD:16:amd64', '27.1', '3.14')
        data = b'#!/usr/local/bin/python3\nexec /usr/local/bin/python3.13 x\n'
        self.assertEqual(b'#!/usr/local/bin/python3.14\nexec /usr/local/bin/python3.14 x\n',
                         target_helper.transform_content(data, target))
        binary = b'\xff/usr/local/bin/python3\x00'
        self.assertEqual(binary, target_helper.transform_content(binary, target))

    def test_shared_routing_source_rejects_file_and_parent_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / 'os-mihomo'
            common = root / 'common'
            project.mkdir()
            common.mkdir()
            source = common / 'route_control.py'
            source.write_text('owned\n')
            self.assertEqual(b'owned\n', target_helper.shared_source(project, 'route_control.py'))
            outside = root / 'outside.py'
            outside.write_text('foreign\n')
            source.unlink()
            source.symlink_to(outside)
            with self.assertRaisesRegex(ValueError, 'missing or unsafe'):
                target_helper.shared_source(project, 'route_control.py')
            source.unlink()
            common.rmdir()
            common.symlink_to(root, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, 'missing or unsafe'):
                target_helper.shared_source(project, 'route_control.py')

            repository = root / 'repository'
            actual = root / 'actual'
            repository.mkdir()
            (actual / 'src/os-mihomo').mkdir(parents=True)
            (actual / 'src/common').mkdir()
            (actual / 'src/common/route_control.py').write_text('foreign\n')
            (repository / 'src').symlink_to(actual / 'src', target_is_directory=True)
            with self.assertRaisesRegex(ValueError, 'missing or unsafe'):
                target_helper.shared_source(
                    repository / 'src/os-mihomo', 'route_control.py')


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        source = self.root / 'src/os-mihomo/src/usr/local/bin'
        source.mkdir(parents=True)
        (source / 'clash-meta-freebsd-amd64.xz').write_bytes(lzma.compress(b'core fixture'))
        self.files = {'/usr/local/bin/mihomo': b'core fixture'}
        self.manifest = {'name': 'os-mihomo', 'abi': 'FreeBSD:15:amd64',
                         'files': {name: '1$' + hashlib.sha256(data).hexdigest() for name, data in self.files.items()}}

    def package(self, extra=()):
        package = self.root / 'fixture.pkg'
        manifest = json.dumps(self.manifest).encode()
        members = [('+MANIFEST', manifest), ('+COMPACT_MANIFEST', manifest)]
        members += [(name.lstrip('/'), data) for name, data in self.files.items()]
        with tarfile.open(package, 'w:gz') as archive:
            for name, data in members + list(extra):
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        return package

    def test_manifest_correct_package_is_accepted(self):
        verify.verify_source_package(self.package(), self.root)

    def test_unmanifested_bytecode_is_rejected(self):
        for name in ('usr/local/bin/__pycache__/mihomo.cpython-314.pyc', 'usr/local/bin/mihomo.pyo'):
            with self.assertRaisesRegex(ValueError, 'Python bytecode'):
                verify.verify_source_package(self.package([(name, b'cache')]), self.root)

    def test_unmanifested_file_and_duplicate_member_are_rejected(self):
        # One message each, not one regex for both: a shared pattern lets either
        # tamper be caught by the other one's check and still look tested.
        cases = [(('usr/local/bin/unexpected', b'extra'), 'archive inventory'),
                 (('usr/local/bin/mihomo', b'core fixture'), 'lists a member twice')]
        for extra, message in cases:
            with self.assertRaisesRegex(ValueError, message):
                verify.verify_source_package(self.package([extra]), self.root)
