"""Verify native target attestations and signed release-to-catalog membership."""
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


REPO = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('release_verifier', REPO / 'verify-repo.py')
verify = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verify)
COMMIT = 'a' * 40


def target(major=15, product='26.7', python='3.13', native='15.1'):
    abi = f'FreeBSD:{major}:amd64'
    return {'abi': abi, 'arch': f'freebsd:{major}:x86:64', 'product_abi': product,
            'python': python, 'native_freebsd': native,
            'repository': f'repo/{abi}/{product}', 'profile': product}


def manifest(recipe):
    python = recipe['python'].replace('.', '')
    return {'name': 'os-mihomo', 'version': '1.1.2', 'abi': recipe['abi'],
            'arch': recipe['arch'], 'annotations': {'product_abi': recipe['product_abi']},
            'deps': {'python' + python: {'origin': 'lang/python' + python, 'version': recipe['python'] + '.15'},
                     'py' + python + '-pyyaml': {'origin': 'devel/py-pyyaml', 'version': '6.0.3'}},
            'files': {}, 'scripts': {}}


def attestation(recipe):
    major, minor = map(int, recipe['native_freebsd'].split('.'))
    return {'ok': True, 'checks': [f'Native lifecycle check {i}' for i in range(10)],
            'abi': recipe['abi'], 'native_abi': recipe['abi'],
            'native_release': recipe['native_freebsd'] + '-RELEASE-p3',
            'native_kernel_version': str(major * 100000 + minor * 1000),
            'native_product_abi': recipe['product_abi'],
            'python': recipe['python'], 'product_abi': recipe['product_abi'],
            'path': recipe['repository'] + '/All/os-mihomo-1.1.2.pkg'}


class AttestationTests(unittest.TestCase):
    def test_matching_native_targets_are_checked_individually(self):
        # The second tuple is synthetic test data, not a supported release claim.
        for recipe in (target(), target(16, '27.1', '3.14', '16.0')):
            verify.validate_attestation(attestation(recipe), manifest(recipe), recipe)

    def test_abi_and_native_environment_mismatches_are_rejected(self):
        recipe = target()
        for change in ({'abi': 'FreeBSD:16:amd64'}, {'native_abi': 'FreeBSD:16:amd64'},
                       {'native_release': '16.0-RELEASE'}, {'native_release': '15.10-RELEASE'},
                       {'native_release': '15.1evil'}, {'abi': 'FreeBSD:*:amd64'}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                verify.validate_attestation(dict(attestation(recipe), **change), manifest(recipe), recipe)
        changed = manifest(recipe)
        changed['abi'] = 'FreeBSD:16:amd64'
        with self.assertRaises(ValueError):
            verify.validate_attestation(attestation(recipe), changed, recipe)

    def test_python_product_and_repository_mismatches_are_rejected(self):
        recipe = target()
        for change in ({'python': '3.14'}, {'product_abi': '27.1'},
                       {'native_product_abi': '27.1'},
                       {'path': 'repo/FreeBSD:16:amd64/26.7/All/os-mihomo-1.1.2.pkg'},
                       {'path': 'repo/FreeBSD:15:amd64/27.1/All/os-mihomo-1.1.2.pkg'}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                verify.validate_attestation(dict(attestation(recipe), **change), manifest(recipe), recipe)
        changed = manifest(recipe)
        changed['annotations']['product_abi'] = '27.1'
        with self.assertRaises(ValueError):
            verify.validate_attestation(attestation(recipe), changed, recipe)
        changed = manifest(recipe)
        changed['deps'].pop('python313')
        with self.assertRaises(ValueError):
            verify.validate_attestation(attestation(recipe), changed, recipe)

    def test_missing_native_product_series_is_rejected(self):
        recipe = target()
        report = attestation(recipe)
        report.pop('native_product_abi')
        with self.assertRaises(ValueError):
            verify.validate_attestation(report, manifest(recipe), recipe)

    def test_missing_nonnumeric_and_foreign_kernel_versions_are_rejected(self):
        recipe = target()
        for kernel in (None, '', '15.1-RELEASE', '1600000', '1403000'):
            report = attestation(recipe)
            if kernel is None:
                report.pop('native_kernel_version')
            else:
                report['native_kernel_version'] = kernel
            with self.subTest(kernel=kernel), self.assertRaises(ValueError):
                verify.validate_attestation(report, manifest(recipe), recipe)

    def test_incomplete_or_unsuccessful_native_report_is_rejected(self):
        recipe = target()
        for change in ({'ok': False}, {'ok': 1}, {'checks': []},
                       {'checks': ['Only one native check']}, {'python': '3.13.15'}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                verify.validate_attestation(dict(attestation(recipe), **change), manifest(recipe), recipe)

    def test_native_checks_require_distinct_nonempty_labels(self):
        recipe = target()
        for checks in ('Not a native lifecycle check list', {'label' + str(i): True for i in range(10)},
                       ['Same label'] * 10, ['Valid ' + str(i) for i in range(9)] + [''],
                       ['Valid ' + str(i) for i in range(9)] + [True]):
            with self.subTest(checks=checks), self.assertRaisesRegex(ValueError, 'complete native lifecycle'):
                verify.validate_attestation(dict(attestation(recipe), checks=checks), manifest(recipe), recipe)


class ReleaseFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.site = self.root / 'site'
        self.site.mkdir()
        self.source = self.root / 'source'
        self.source.mkdir()
        self.recipes = [target()]

    def package(self, recipe, label=None, report_changes=None, manifest_changes=None):
        directory = self.root / 'build' / (label or recipe['profile'])
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / 'os-mihomo-1.1.2.pkg'
        value = manifest(recipe)
        if manifest_changes:
            value.update(manifest_changes)
        payload = json.dumps(value).encode()
        with tarfile.open(path, 'w:gz') as archive:
            for name in ('+MANIFEST', '+COMPACT_MANIFEST'):
                item = tarfile.TarInfo(name)
                item.size = len(payload)
                archive.addfile(item, io.BytesIO(payload))
        report = attestation(recipe)
        report['package_sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
        if report_changes:
            report.update(report_changes)
        (directory / 'test-report.json').write_text(json.dumps(report))
        return path

    def prepare(self, packages, commit=COMMIT):
        module = SimpleNamespace(enabled_targets=lambda project: self.recipes)
        with patch.object(verify, 'target_module', return_value=module), \
                patch.object(verify, 'verify_source_package') as source_check, \
                patch.dict(os.environ, {}, clear=False):
            previous = os.environ.pop('TEST_REPORT', None)
            try:
                value = verify.prepare_release(self.site, self.source, commit, packages)
            finally:
                if previous is not None:
                    os.environ['TEST_REPORT'] = previous
        self.assertEqual(len(packages), source_check.call_count)
        return value


class ReleasePreparationTests(ReleaseFixture):
    def test_two_native_targets_keep_separate_hashes_reports_and_destinations(self):
        self.recipes.append(target(16, '27.1', '3.14', '16.0'))
        packages = [self.package(recipe) for recipe in self.recipes]
        result = self.prepare(packages)
        self.assertEqual(2, result['schema_version'])
        self.assertEqual(COMMIT, result['source_commit'])
        self.assertEqual(2, len(result['packages']))
        self.assertEqual(2, len({entry['sha256'] for entry in result['packages']}))
        self.assertEqual(result, json.loads((self.site / 'release.json').read_text()))
        for package, recipe, entry in zip(packages, self.recipes, result['packages']):
            self.assertEqual(recipe['abi'], entry['native_abi'])
            self.assertEqual(recipe['python'], entry['python'])
            self.assertEqual(package.read_bytes(), (self.site / entry['path']).read_bytes())
            self.assertEqual(hashlib.sha256(package.read_bytes()).hexdigest(), entry['sha256'])

    def test_disabled_unknown_and_duplicate_package_targets_are_rejected(self):
        current = self.package(self.recipes[0])
        future = self.package(target(16, '27.1', '3.14', '16.0'))
        for packages in ([future], [current, current]):
            with self.subTest(packages=packages), self.assertRaisesRegex(ValueError, 'disabled or duplicate'):
                self.prepare(packages)

    def test_missing_enabled_target_and_missing_recipe_module_are_rejected(self):
        current = self.package(self.recipes[0])
        self.recipes.append(target(16, '27.1', '3.14', '16.0'))
        with self.assertRaisesRegex(ValueError, 'Every enabled target'):
            self.prepare([current])
        with patch.object(verify, 'target_module', return_value=None), \
                self.assertRaisesRegex(ValueError, 'target recipes'):
            verify.prepare_release(self.site, self.source, COMMIT, [current])

    def test_duplicate_recipe_tuple_and_shared_repository_are_rejected_before_copying(self):
        current = self.package(self.recipes[0])
        duplicate = dict(self.recipes[0], profile='duplicate-profile', python='3.14')
        collision = target(15, '27.1', '3.13', '15.1')
        collision['repository'] = self.recipes[0]['repository']
        for second in (duplicate, collision):
            self.recipes = [target(), second]
            with self.subTest(second=second), self.assertRaisesRegex(ValueError, 'distinct ABI/product'):
                self.prepare([current])
        self.assertFalse((self.site / 'repo').exists())

    def test_modified_package_and_mismatched_native_report_are_rejected(self):
        for changes in ({'package_sha256': '0' * 64}, {'native_abi': 'FreeBSD:16:amd64'},
                        {'python': '3.14'}, {'native_release': '15.2-RELEASE'},
                        {'product_abi': '27.1'}):
            with self.subTest(changes=changes):
                package = self.package(self.recipes[0], report_changes=changes)
                with self.assertRaises(ValueError):
                    self.prepare([package])

    def test_invalid_commit_is_rejected_before_staging(self):
        package = self.package(self.recipes[0])
        for commit in ('', 'a' * 39, 'G' * 40, COMMIT + '\n'):
            with self.subTest(commit=commit), self.assertRaisesRegex(ValueError, 'SOURCE_COMMIT'):
                self.prepare([package], commit)
        self.assertFalse((self.site / 'repo').exists())


class ReleasePathTests(ReleaseFixture):
    def test_flat_and_per_series_paths_are_accepted(self):
        for value in ('repo/FreeBSD:15:amd64/All/os-mihomo-1.1.2.pkg',
                      'repo/FreeBSD:16:amd64/27.1/All/os-mihomo-1.1.2_1.pkg'):
            self.assertEqual(self.site / value, verify.release_path(self.site, value))

    def test_unsafe_paths_and_symlink_escapes_are_rejected(self):
        for value in (None, '/repo/FreeBSD:15:amd64/All/evil.pkg',
                      'repo/FreeBSD:15:amd64/All/../../evil.pkg',
                      'repo/FreeBSD:15:amd64/All/evil.pkg\n',
                      'repo/FreeBSD:15:amd64/26.7/Other/evil.pkg',
                      'repo/FreeBSD:15:amd64/26.1/All/evil.txt',
                      'repo/FreeBSD:15:amd64/26.10/All/evil.pkg'):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'Unsafe'):
                verify.release_path(self.site, value)
        outside = self.root / 'outside'
        outside.mkdir()
        parent = self.site / 'repo/FreeBSD:15:amd64'
        parent.mkdir(parents=True)
        (parent / 'All').symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'Unsafe'):
            verify.release_path(self.site, 'repo/FreeBSD:15:amd64/All/evil.pkg')


class CatalogMembershipTests(ReleaseFixture):
    def site_report(self):
        package = self.package(self.recipes[0])
        report = self.prepare([package])
        (self.site / 'kazuha.pub').write_bytes(b'Isolated test trust anchor')
        (self.site / 'release.sig').write_bytes(b'Isolated test signature')
        repository = (self.site / report['packages'][0]['path']).parent.parent
        for name in ('meta.conf', 'data.pkg', 'packagesite.pkg'):
            (repository / name).write_bytes(b'Catalog fixture')
        return report, repository

    def checked_site(self, report, catalog, source=False):
        (self.site / 'release.json').write_text(json.dumps(report))
        fingerprint = hashlib.sha256((self.site / 'kazuha.pub').read_bytes()).hexdigest()
        module = SimpleNamespace(enabled_targets=lambda project: self.recipes)
        # Cryptography and source byte comparison have separate tests; this
        # boundary exercises report validation and real package/catalog hashes.
        with patch.object(verify, 'FINGERPRINT', fingerprint), \
                patch.object(verify, 'signature_check'), \
                patch.object(verify, 'verify_catalog', side_effect=lambda archive, member, key: b'{}' if member == 'data' else catalog), \
                patch.object(verify, 'target_module', return_value=module), \
                patch.object(verify, 'verify_source_package'), patch('builtins.print'):
            return verify.verify(self.site, self.source if source else None)

    def test_tested_package_must_be_listed_in_a_signed_catalog(self):
        report, repository = self.site_report()
        entry = report['packages'][0]
        catalog = json.dumps({'path': 'All/' + Path(entry['path']).name,
                              'abi': entry['abi'], 'sum': entry['sha256']}).encode()
        self.assertEqual(report, self.checked_site(report, catalog))
        with self.assertRaisesRegex(ValueError, 'missing from its catalog'):
            self.checked_site(report, b'')

    def test_duplicate_signed_targets_and_missing_committed_targets_are_rejected(self):
        report, repository = self.site_report()
        duplicate = copy.deepcopy(report)
        duplicate['packages'].append(copy.deepcopy(duplicate['packages'][0]))
        with self.assertRaisesRegex(ValueError, 'duplicate native release target'):
            self.checked_site(duplicate, b'')
        self.recipes.append(target(16, '27.1', '3.14', '16.0'))
        with self.assertRaisesRegex(ValueError, 'enabled target has no native release report'):
            self.checked_site(report, b'', source=True)

    def test_catalog_offers_only_the_newest_version_of_each_package(self):
        report, repository = self.site_report()
        entry = report['packages'][0]
        tested = json.dumps({'path': 'All/' + Path(entry['path']).name,
                             'abi': entry['abi'], 'sum': entry['sha256']})
        for version in ('1.2.9', '1.2.10'):
            (repository / 'All' / ('os-demo-' + version + '.pkg')).write_bytes(version.encode())

        def catalog(*versions):
            lines = [tested] + [json.dumps({'name': 'os-demo', 'version': version,
                                            'path': 'All/os-demo-' + version + '.pkg', 'abi': entry['abi'],
                                            'sum': hashlib.sha256(version.encode()).hexdigest()})
                                for version in versions]
            return '\n'.join(lines).encode()

        # Offered both, pkg picks by version text and 1.2.9 would win.
        with self.assertRaisesRegex(ValueError, 'offers os-demo more than once'):
            self.checked_site(report, catalog('1.2.10', '1.2.9'))
        with self.assertRaisesRegex(ValueError, 'offers os-demo 1.2.9 although os-demo-1.2.10.pkg is published'):
            self.checked_site(report, catalog('1.2.9'))
        # The older archive stays downloadable without being offered.
        self.assertEqual(report, self.checked_site(report, catalog('1.2.10')))

    def test_catalog_input_takes_the_numerically_newest_archive_of_each_package(self):
        all_dir = self.root / 'All'
        all_dir.mkdir()

        def archive(name, version):
            payload = json.dumps({'name': name, 'version': version}).encode()
            with tarfile.open(all_dir / (name + '-' + version + '.pkg'), 'w:gz') as stream:
                item = tarfile.TarInfo('+MANIFEST')
                item.size = len(payload)
                stream.addfile(item, io.BytesIO(payload))

        for version in ('1.0.2', '1.2.1', '1.2.9', '1.2.10'):
            archive('os-mihomo', version)
        for version in ('1.1.1', '1.1.1_2', '1.0.2'):
            archive('os-ttyd', version)
        self.assertEqual(['os-mihomo-1.2.10.pkg', 'os-ttyd-1.1.1_2.pkg'],
                         [path.name for path in verify.newest_archives(all_dir)])
        archive('os-ttyd', '1.1.1_02')
        with self.assertRaisesRegex(ValueError, 'Two archives carry os-ttyd'):
            verify.newest_archives(all_dir)

    def test_pkg_version_order_uses_numeric_parts_revisions_and_epochs(self):
        ordered = ['1.0.2', '1.2.9', '1.2.10', '1.3.0', '1.3.0_1', '1.3.1', '0.1,1']
        self.assertEqual(ordered, sorted(reversed(ordered), key=verify.pkg_version_key))

    def test_catalog_package_digest_mismatch_is_rejected(self):
        report, repository = self.site_report()
        entry = report['packages'][0]
        catalog = json.dumps({'path': 'All/' + Path(entry['path']).name,
                              'abi': entry['abi'], 'sum': '0' * 64}).encode()
        with self.assertRaisesRegex(ValueError, 'Package digest verification failed'):
            self.checked_site(report, catalog)
