"""Exercise the actual script-only builder with current and future metadata."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

PLUGIN = Path(__file__).resolve().parents[1]


class BuildTests(unittest.TestCase):
    def test_current_and_future_profiles_have_wildcard_abi_and_no_runtime_dependency(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'plugin'
            shutil.copytree(PLUGIN, source, ignore=shutil.ignore_patterns('work', 'dist', '__pycache__'))
            scripts = source / 'src/usr/local/opnsense/scripts/firmware/repos'
            (scripts / '__pycache__').mkdir()
            (scripts / '__pycache__/junk.cpython-314.pyc').write_bytes(b'bytecode')
            (scripts / 'junk.pyc').write_bytes(b'bytecode')
            (scripts / 'junk.pyo').write_bytes(b'bytecode')
            commands = root / 'bin'
            commands.mkdir()
            for name in ['python3.13', 'python3.14']:
                (commands / name).symlink_to(sys.executable)
            code = '''import json,os,sys,tarfile
from pathlib import Path
args=sys.argv[1:]
if args[:2] == ["config", "ABI"]: print(os.environ["NATIVE_ABI"])
elif args[0] == "create":
 manifest_path=Path(args[args.index("-M")+1]); manifest=json.loads(manifest_path.read_text())
 stage=Path(args[args.index("-r")+1]); output=Path(args[args.index("-o")+1]) / (manifest["name"]+"-"+manifest["version"]+".pkg")
 with tarfile.open(output,"w") as archive:
  archive.add(manifest_path,arcname="+MANIFEST")
  archive.add(manifest_path,arcname="+COMPACT_MANIFEST")
  for path in manifest["files"]: archive.add(stage / path.lstrip("/"),arcname=path.lstrip("/"))
elif args[0] != "info": raise AssertionError(args)
'''
            (commands / 'pkg').write_text('#!' + sys.executable + '\n' + code)
            (commands / 'pkg').chmod(0o755)
            (commands / 'sha256').write_text('#!' + sys.executable + '\nimport hashlib,sys; print(hashlib.sha256(open(sys.argv[-1],"rb").read()).hexdigest())\n')
            (commands / 'sha256').chmod(0o755)
            for series, python, native_abi in [('26.7', '3.13', 'FreeBSD:15:amd64'), ('27.1', '3.14', 'FreeBSD:16:amd64')]:
                env = dict(os.environ, PATH=str(commands) + ':' + os.environ['PATH'],
                           TARGET_PRODUCT_ABI=series, TARGET_PYTHON=python, NATIVE_ABI=native_abi,
                           VERSION='1.0.0', DISTDIR=str(source / 'dist'))
                env.pop('BUILD_PYTHON', None)
                result = subprocess.run(['sh', str(source / 'build.sh')], env=env, text=True, capture_output=True)
                self.assertEqual(0, result.returncode, result.stdout + result.stderr)
                with tarfile.open(source / 'dist/os-kazuha-repo-1.0.0.pkg') as archive:
                    manifest = json.loads(archive.extractfile('+MANIFEST').read())
                    metadata = json.loads(archive.extractfile('usr/local/opnsense/version/kazuha-repo').read())
                    self.assertEqual('FreeBSD:*:amd64', manifest['abi'])
                    self.assertFalse(manifest.get('deps'))
                    self.assertEqual(series, metadata['product_abi'])
                    self.assertEqual(metadata, manifest['annotations'])
                    self.assertEqual(3, len(manifest['files']))
                    self.assertEqual(5, len(archive.getnames()))
                    self.assertFalse(any('__pycache__' in n or n.endswith(('.pyc', '.pyo')) for n in archive.getnames()))
                    for path, digest in manifest['files'].items():
                        self.assertEqual(digest, '1$' + hashlib.sha256(archive.extractfile(path.lstrip('/')).read()).hexdigest())


if __name__ == '__main__':
    unittest.main()
