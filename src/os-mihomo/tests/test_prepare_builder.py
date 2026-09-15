"""Install a matched dependency recipe through the actual private repository script."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

PROJECT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('prepare_target', PROJECT / 'packaging/target.py')
target = importlib.util.module_from_spec(spec)
spec.loader.exec_module(target)


class PrepareBuilderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.project = self.root / 'project'
        shutil.copytree(PROJECT / 'packaging', self.project / 'packaging')
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.trace = self.root / 'trace'
        self.system_repo = self.root / 'system-repos/FreeBSD.conf'
        self.system_repo.parent.mkdir()
        self.system_repo.write_text('existing FreeBSD repository\n')
        recipe = target.enabled_targets(PROJECT)[0]
        self.env = dict(os.environ, PATH=str(self.bin) + ':' + os.environ['PATH'],
                        TARGET_ABI=recipe['abi'], TARGET_PRODUCT_ABI=recipe['product_abi'],
                        TARGET_PYTHON=recipe['python'], TARGET_PHP=recipe['php'],
                        TARGET_DEPENDENCY_REPOSITORY=recipe['dependency_repository'],
                        TARGET_DEPENDENCY_FINGERPRINT=recipe['dependency_fingerprint'],
                        NATIVE_ABI=recipe['abi'], TRACE=str(self.trace), FAIL_PHASE='')
        for name, code in {
            'uname': 'import sys; print("FreeBSD" if sys.argv[1] == "-s" else "amd64")',
            'pkg': '''import json,os,re,sys
from pathlib import Path
args=sys.argv[1:]
assert args[0] == "-4"
with open(os.environ["TRACE"],"a") as stream: stream.write(json.dumps(args)+"\\n")
if "config" in args:
 print(os.environ["NATIVE_ABI"])
else:
 assert "-R" in args and args[args.index("-r")+1] == "OPNsense"
 repos=Path(args[args.index("-R")+1]); assert [p.name for p in repos.iterdir()] == ["OPNsense.conf"]
 content=(repos / "OPNsense.conf").read_text()
 assert 'signature_type: "fingerprints"' in content
 assert os.environ["TARGET_DEPENDENCY_REPOSITORY"] in content
 fingerprints=Path(re.search(r'fingerprints: "([^\\"]+)"',content).group(1))
 trusted=list((fingerprints / "trusted").iterdir()); assert len(trusted)==1
 assert trusted[0].read_text() == 'function: "sha256"\\nfingerprint: "9f3b76ffef38fb6405595038b324b61043c9a2c375ae5c151d628508e9a845ce"\\n'
 if os.environ["FAIL_PHASE"] in args: sys.exit(1)
''',
        }.items():
            path = self.bin / name
            path.write_text('#!' + sys.executable + '\n' + code + '\n')
            path.chmod(0o755)

    def prepare(self):
        return subprocess.run(['sh', str(self.project / 'packaging/prepare-builder.sh')],
                              env=self.env, capture_output=True, text=True, timeout=15)

    def calls(self):
        return [json.loads(line) for line in self.trace.read_text().splitlines()] if self.trace.exists() else []

    def test_matched_official_repository_installs_every_versioned_dependency(self):
        result = self.prepare()
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        calls = self.calls()
        self.assertEqual(3, len(calls))
        self.assertIn('update', calls[1])
        self.assertIn('install', calls[2])
        self.assertEqual(
            ['curl', 'git', 'python313', 'py313-pyyaml', 'py313-requests',
             'py313-dnspython', 'py313-ujson', 'py313-Jinja2', 'py313-boto3',
             'php85', 'php85-dom', 'php85-filter', 'php85-gettext',
             'php85-simplexml', 'unbound'],
            calls[2][-15:])
        self.assertEqual('existing FreeBSD repository\n', self.system_repo.read_text())
        self.assertFalse(Path(calls[1][calls[1].index('-R') + 1]).exists())

    def test_bad_or_cross_series_inputs_are_rejected_before_package_operations(self):
        for field, value in [
            ('TARGET_DEPENDENCY_REPOSITORY', 'https://pkg.FreeBSD.org/FreeBSD:15:amd64/latest'),
            ('TARGET_DEPENDENCY_REPOSITORY', 'https://pkg.opnsense.org/FreeBSD:15:amd64/27.1/latest'),
            ('TARGET_DEPENDENCY_REPOSITORY', 'http://pkg.opnsense.org/FreeBSD:15:amd64/26.7/latest'),
            ('TARGET_DEPENDENCY_FINGERPRINT', 'packaging/OPNsense/trusted/../../key'),
            ('TARGET_PRODUCT_ABI', '26.10'), ('TARGET_ABI', 'FreeBSD:15;touch:amd64'),
            ('TARGET_PYTHON', '3.13;touch'), ('TARGET_PHP', '8.5/path'),
        ]:
            old = self.env[field]
            self.env[field] = value
            result = self.prepare()
            self.assertNotEqual(0, result.returncode, (field, value))
            self.assertEqual([], self.calls())
            self.env[field] = old

    def test_bad_fingerprint_or_foreign_native_abi_cannot_install_packages(self):
        self.env['NATIVE_ABI'] = 'FreeBSD:14:amd64'
        self.assertNotEqual(0, self.prepare().returncode)
        self.assertEqual(1, len(self.calls()))
        self.trace.unlink()
        self.env['NATIVE_ABI'] = 'FreeBSD:15:amd64'
        fingerprint = self.project / self.env['TARGET_DEPENDENCY_FINGERPRINT']
        fingerprint.write_text('function: "sha256"\nfingerprint: "bad"\n')
        self.assertNotEqual(0, self.prepare().returncode)
        self.assertEqual([], self.calls())

    def test_signature_update_failure_stops_before_dependency_installation(self):
        self.env['FAIL_PHASE'] = 'update'
        self.assertNotEqual(0, self.prepare().returncode)
        self.assertEqual(2, len(self.calls()))
        self.assertFalse(any('install' in call for call in self.calls()))
        self.assertEqual('existing FreeBSD repository\n', self.system_repo.read_text())

    def test_matrix_rejects_missing_or_mismatched_official_dependency_recipe(self):
        recipe_path = self.project / 'packaging/targets.json'
        original = json.loads(recipe_path.read_text())
        for field, value in [('dependency_repository', None),
                             ('dependency_repository', 'https://pkg.opnsense.org/FreeBSD:15:amd64/27.1/latest'),
                             ('dependency_fingerprint', 'packaging/OPNsense/trusted/../fingerprint')]:
            recipe = json.loads(json.dumps(original))
            recipe['targets']['26.7'][field] = value
            recipe_path.write_text(json.dumps(recipe))
            with self.assertRaisesRegex(ValueError, 'dependency'):
                target.enabled_targets(self.project)
        recipe_path.write_text(json.dumps(original))
        (self.project / original['targets']['26.7']['dependency_fingerprint']).unlink()
        with self.assertRaisesRegex(ValueError, 'dependency fingerprint'):
            target.enabled_targets(self.project)


if __name__ == '__main__':
    unittest.main()
