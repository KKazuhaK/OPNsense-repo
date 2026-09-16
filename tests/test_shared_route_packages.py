"""Verify that one native job binds all route-owning packages to shared bytes."""

import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


REPO = Path(__file__).resolve().parents[1]
CHECKER_PATH = REPO / 'tests/check-shared-route-packages.py'
spec = importlib.util.spec_from_file_location('shared_route_package_checker', CHECKER_PATH)
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)
verify = checker.load_verifier(REPO)
COMMIT = '1' * 40


def add(archive, name, content):
    member = tarfile.TarInfo(name)
    member.size = len(content)
    archive.addfile(member, io.BytesIO(content))


class SharedRoutePackageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def package(self, plugin, corrupt=None, modern=False, bad_sum=None):
        mappings = checker.shared_destinations(REPO, verify)[plugin]
        payloads = {}
        for relative, destination in mappings.items():
            payload = (REPO / relative).read_bytes()
            if corrupt == relative:
                payload += b'changed\n'
            payloads[destination] = payload
        if modern:
            files = {}
            for path, value in payloads.items():
                digest = '2$' + verify.zbase32(hashlib.blake2b(value).digest())
                if bad_sum == path:
                    digest = digest[:-1] + ('y' if digest[-1] != 'y' else 'z')
                files[path] = {'sum': digest, 'uname': 'root', 'gname': 'wheel',
                               'perm': '0755', 'mtime': 0}
        else:
            files = {path: '1$' + hashlib.sha256(value).hexdigest()
                     for path, value in payloads.items()}
        manifest = {
            'name': plugin,
            'version': {'os-mihomo': '1.2.8', 'os-sing-box': '1.1.3',
                        'os-easytier': '1.1.2'}[plugin],
            'abi': 'FreeBSD:15:amd64',
            'files': files,
        }
        package = self.root / (plugin + '.pkg')
        encoded = json.dumps(manifest).encode()
        with tarfile.open(package, 'w') as archive:
            add(archive, '+MANIFEST', encoded)
            add(archive, '+COMPACT_MANIFEST', encoded)
            for path, payload in payloads.items():
                add(archive, path.lstrip('/'), payload)
        return package

    def verifier_without_full_package_check(self):
        return SimpleNamespace(
            plugin_records=verify.plugin_records,
            target_module=verify.target_module,
            manifest_of=verify.manifest_of,
            archive_members=verify.archive_members,
            source_path=verify.source_path,
            file_checksum_matches=verify.file_checksum_matches,
            verify_source_package=lambda *_args, **_kwargs: None,
        )

    def committed_source(self, source, _commit, relative):
        return (Path(source) / relative).read_bytes()

    def test_three_candidates_embed_one_exact_route_control_hash(self):
        packages = [self.package(plugin) for plugin in checker.REQUIRED]
        with patch.object(checker, 'load_verifier',
                          return_value=self.verifier_without_full_package_check()), \
                patch.object(checker, 'committed_source_bytes',
                             side_effect=self.committed_source):
            report = checker.bind_packages(REPO, packages, COMMIT)
        route_source = hashlib.sha256((REPO / 'src/common/route_control.py').read_bytes()).hexdigest()
        tun_source = hashlib.sha256((REPO / 'src/common/tun_policy_routing.py').read_bytes()).hexdigest()
        self.assertEqual(route_source, report['source']['src/common/route_control.py'])
        self.assertEqual(tun_source, report['source']['src/common/tun_policy_routing.py'])
        self.assertEqual(set(checker.REQUIRED), {item['name'] for item in report['packages']})
        self.assertEqual(
            {route_source},
            {item['shared']['src/common/route_control.py']['sha256']
             for item in report['packages']},
        )
        self.assertEqual(
            {tun_source},
            {item['shared']['src/common/tun_policy_routing.py']['sha256']
             for item in report['packages'] if item['name'] != 'os-easytier'},
        )

    def test_one_different_shared_payload_is_rejected_even_with_matching_manifest(self):
        packages = [self.package(plugin, 'src/common/route_control.py'
                                 if plugin == 'os-easytier' else None)
                    for plugin in checker.REQUIRED]
        with patch.object(checker, 'load_verifier',
                          return_value=self.verifier_without_full_package_check()), \
                patch.object(checker, 'committed_source_bytes',
                             side_effect=self.committed_source), \
                self.assertRaisesRegex(ValueError, 'different source revision'):
            checker.bind_packages(REPO, packages, COMMIT)

    def test_worktree_shared_source_must_match_the_named_commit(self):
        packages = [self.package(plugin) for plugin in checker.REQUIRED]
        with patch.object(checker, 'load_verifier',
                          return_value=self.verifier_without_full_package_check()), \
                patch.object(checker, 'committed_source_bytes',
                             return_value=b'older committed bytes\n'), \
                self.assertRaisesRegex(ValueError, 'differs from the source commit'):
            checker.bind_packages(REPO, packages, COMMIT)

    def test_zbase32_matches_libpkg_reference_vector(self):
        content = (b'#!/bin/sh\n# Keep the historical CLI and cron entry point stable.\n'
                   b'exec /usr/local/bin/python3.13 '
                   b'/usr/local/opnsense/scripts/mihomo/mihomo.py sub-update "$@"\n')
        self.assertEqual(
            'a3dcfr6wkfa963qn8wwetde3feakuy1gwm1xfmkhsd6ju5igen11c5oy91txe5f9gyy88'
            'mfcmrazsrwoh7psbs68mzk1gj5bmkphd7n',
            verify.zbase32(hashlib.blake2b(content).digest()))

    def test_file_checksum_matches_both_pkg_manifest_shapes(self):
        content = b'payload\n'
        modern = '2$' + verify.zbase32(hashlib.blake2b(content).digest())
        self.assertTrue(verify.file_checksum_matches(
            '1$' + hashlib.sha256(content).hexdigest(), content))
        self.assertTrue(verify.file_checksum_matches(
            {'sum': modern, 'uname': 'root', 'gname': 'wheel', 'perm': '0755', 'mtime': 0},
            content))
        self.assertFalse(verify.file_checksum_matches({'sum': modern[:-1] + ('y' if modern[-1] != 'y' else 'z')}, content))
        self.assertFalse(verify.file_checksum_matches({'perm': '0755'}, content))
        self.assertFalse(verify.file_checksum_matches(None, content))

    def test_modern_manifest_shapes_bind_like_legacy_ones(self):
        packages = [self.package(plugin, modern=True) for plugin in checker.REQUIRED]
        with patch.object(checker, 'load_verifier',
                          return_value=self.verifier_without_full_package_check()), \
                patch.object(checker, 'committed_source_bytes',
                             side_effect=self.committed_source):
            report = checker.bind_packages(REPO, packages, COMMIT)
        self.assertEqual(set(checker.REQUIRED), {item['name'] for item in report['packages']})

    def test_modern_manifest_wrong_sum_is_rejected(self):
        mappings = checker.shared_destinations(REPO, verify)['os-mihomo']
        bad_install = mappings['src/common/route_control.py']
        packages = [self.package(plugin, modern=True,
                                 bad_sum=bad_install if plugin == 'os-mihomo' else None)
                    for plugin in checker.REQUIRED]
        with patch.object(checker, 'load_verifier',
                          return_value=self.verifier_without_full_package_check()), \
                patch.object(checker, 'committed_source_bytes',
                             side_effect=self.committed_source), \
                self.assertRaisesRegex(ValueError, 'manifest does not bind'):
            checker.bind_packages(REPO, packages, COMMIT)

    def test_native_workflow_builds_checks_and_archives_all_three_packages(self):
        workflow = (REPO / '.github/workflows/build-targets.yml').read_text()
        for plugin in checker.REQUIRED:
            with self.subTest(plugin=plugin):
                self.assertIn("- 'src/" + plugin + "/**'", workflow)
                self.assertIn('sh src/' + plugin + '/build.sh', workflow)
                self.assertIn('src/' + plugin + '/dist', workflow)
        self.assertIn('tests/check-shared-route-packages.py', workflow)
        self.assertIn("- 'tests/check-shared-route-packages.py'", workflow)
        self.assertIn("- 'tests/test_shared_route_packages.py'", workflow)
        self.assertIn("- 'packaging/plugins.json'", workflow)
        self.assertIn("- 'verify-repo.py'", workflow)
        for source in ('src/common/process_identity.py', 'src/common/route_control.py',
                       'src/common/tun_policy_routing.py'):
            self.assertIn("- '" + source + "'", workflow)
        self.assertIn("- 'src/common/tests/**'", workflow)
        for plugin in ('os-staticarp', 'os-lucky', 'os-ddns-go',
                       'os-ddclient-opnwall', 'os-unboundcustom'):
            with self.subTest(native_candidate=plugin):
                self.assertIn("- 'src/" + plugin + "/**'", workflow)
                self.assertIn('sh src/' + plugin + '/build.sh', workflow)
                self.assertIn('src/' + plugin + '/dist', workflow)
                self.assertIn('src/' + plugin + '/tests', workflow)
        self.assertIn("- 'src/common/process_control.py'", workflow)


if __name__ == '__main__':
    unittest.main()
