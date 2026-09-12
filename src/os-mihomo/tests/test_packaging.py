"""Run the build entry point and reject contaminated package archives."""
import hashlib
import importlib.util
import io
import json
import lzma
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('verify_repo', REPO / 'verify-repo.py')
verify = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verify)


class BuildTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.project = self.root / 'project'
        self.project.mkdir()
        shutil.copyfile(REPO / 'src/os-mihomo/build.sh', self.project / 'build.sh')
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.created = self.root / 'pkg-created'
        self.env = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ['PATH'],
                        FAKE_PKG_CREATED=str(self.created))
        self.command('pkg', '''import io,json,os,sys,tarfile
from pathlib import Path
args=sys.argv[1:]
if args[:2]==['config','ABI']:
    print('FreeBSD:15:amd64')
elif args[0]=='query':
    values={'curl':('ftp/curl','8.20.0'), 'python313':('lang/python313',os.environ['FAKE_PKG_PYTHON_VERSION']), 'py313-pyyaml':('devel/py-pyyaml','6.0.3_1')}
    print(' '.join(values[args[-1]]))
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
            path.write_text('fixture\n')
        asset = self.project / 'src/usr/local/bin/clash-meta-freebsd-amd64.xz'
        asset.write_bytes(lzma.compress(b'core fixture'))
        packaging = self.project / 'packaging/freebsd'
        packaging.mkdir(parents=True)
        for name in ('pkg-descr', '+PRE_INSTALL', '+POST_INSTALL', '+PRE_DEINSTALL', '+POST_DEINSTALL'):
            (packaging / name).write_text('fixture\n')

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

    def build(self):
        return subprocess.run(['sh', str(self.project / 'build.sh')], env=self.env,
                              capture_output=True, text=True, timeout=30)

    def test_python_314_is_rejected_before_staging(self):
        wrong = self.bin / 'wrong-python'
        wrong.write_text('#!/bin/sh\nprintf "3.14\\n"\n')
        wrong.chmod(0o755)
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
        with tarfile.open(self.project / 'dist/os-mihomo-1.1.1.pkg') as archive:
            self.assertFalse(any('__pycache__' in name or name.endswith(('.pyc', '.pyo')) for name in archive.getnames()))
            manifest = json.load(archive.extractfile('+MANIFEST'))
        self.assertEqual(self.env['FAKE_PKG_PYTHON_VERSION'], manifest['deps']['python313']['version'])

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
        for extra in [('usr/local/bin/unexpected', b'extra'), ('usr/local/bin/mihomo', b'core fixture')]:
            with self.assertRaisesRegex(ValueError, 'archive inventory'):
                verify.verify_source_package(self.package([extra]), self.root)
