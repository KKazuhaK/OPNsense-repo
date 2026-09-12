"""Exercise upgrade readiness using real signatures and a private HTTP fixture."""
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('upgrade_readiness', ROOT / 'check-upgrade.py')
readiness = importlib.util.module_from_spec(spec)
spec.loader.exec_module(readiness)
BASE = 'https://fixture.invalid/repository'
ABI = 'FreeBSD:15:amd64'
SERIES = '26.7'
REPOSITORY = 'repo/' + ABI
PACKAGE_PATH = REPOSITORY + '/All/os-mihomo-1.1.2.pkg'


def archive(members):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w:gz') as stream:
        for name, payload in members.items():
            member = tarfile.TarInfo(name)
            member.size = len(payload)
            stream.addfile(member, io.BytesIO(payload))
    return output.getvalue()


@unittest.skipUnless(shutil.which('openssl') and shutil.which('tar'), 'OpenSSL and tar are required.')
class UpgradeReadinessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.key = Path(cls.directory.name) / 'fixture.key'
        cls.public = Path(cls.directory.name) / 'fixture.pub'
        subprocess.run(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048',
                        '-out', str(cls.key)], check=True, capture_output=True)
        subprocess.run(['openssl', 'pkey', '-in', str(cls.key), '-pubout', '-out', str(cls.public)],
                       check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def sign(self, payload):
        return subprocess.run(['openssl', 'dgst', '-sha256', '-sign', str(self.key)],
                              input=payload, check=True, capture_output=True).stdout

    def signed_catalog(self, member, payload):
        return archive({member: payload, 'signature': self.sign(hashlib.sha256(payload).hexdigest().encode())})

    def setUp(self):
        self.manifest = {
            'name': 'os-mihomo', 'version': '1.1.2', 'abi': ABI, 'arch': 'freebsd:15:x86:64',
            'annotations': {'product_abi': SERIES, 'product_id': 'os-mihomo'},
            'deps': {'curl': {'origin': 'ftp/curl', 'version': '8.20.0'},
                     'python313': {'origin': 'lang/python313', 'version': '3.13.12'},
                     'py313-pyyaml': {'origin': 'devel/py-pyyaml', 'version': '6.0.3_1'}},
            'files': {'/usr/local/bin/mihomo': '1$' + hashlib.sha256(b'core fixture').hexdigest()},
        }
        self.entry = {'path': PACKAGE_PATH, 'abi': ABI, 'product_abi': SERIES, 'python': '3.13',
                      'native_abi': ABI, 'native_release': '15.1-RELEASE', 'native_product_abi': SERIES,
                      'native_kernel_version': '1501000',
                      'ok': True, 'checks': ['native lifecycle ' + str(i) for i in range(12)]}
        self.report = {'schema_version': 2, 'source_commit': 'a' * 40, 'packages': [self.entry]}
        self.assets = {'kazuha.pub': self.public.read_bytes(), REPOSITORY + '/meta.conf': b'version = 2;\n',
                       REPOSITORY + '/data.pkg': self.signed_catalog('data', b'{"version":2}\n')}
        self.publish_package()
        self.requests = []
        patch = mock.patch.object(readiness.verification, 'FINGERPRINT',
                                  hashlib.sha256(self.public.read_bytes()).hexdigest())
        patch.start()
        self.addCleanup(patch.stop)
        patch = mock.patch.object(readiness, 'urlopen', side_effect=self.response)
        patch.start()
        self.addCleanup(patch.stop)

    def response(self, url, timeout):
        self.assertTrue(url.startswith(BASE + '/'), 'The fixture must receive HTTPS repository requests only.')
        self.assertEqual(30, timeout)
        relative = url[len(BASE) + 1:]
        self.requests.append(relative)
        if relative not in self.assets:
            raise FileNotFoundError('Missing fixture asset: ' + relative)
        return io.BytesIO(self.assets[relative])

    def resign_report(self):
        payload = (json.dumps(self.report, sort_keys=True) + '\n').encode()
        self.assets['release.json'] = payload
        self.assets['release.sig'] = self.sign(payload)

    def publish_package(self):
        manifest = json.dumps(self.manifest).encode()
        self.assets[PACKAGE_PATH] = archive({'+MANIFEST': manifest, '+COMPACT_MANIFEST': manifest,
                                             'usr/local/bin/mihomo': b'core fixture'})
        digest = hashlib.sha256(self.assets[PACKAGE_PATH]).hexdigest()
        self.entry['sha256'] = digest
        self.catalog_entry = {'name': 'os-mihomo', 'version': '1.1.2', 'abi': ABI,
                              'path': 'All/os-mihomo-1.1.2.pkg', 'sum': digest}
        self.resign_catalog()
        self.resign_report()

    def resign_catalog(self):
        payload = (json.dumps(self.catalog_entry) + '\n').encode()
        self.assets[REPOSITORY + '/packagesite.pkg'] = self.signed_catalog('packagesite.yaml', payload)

    def check(self, abi=ABI, series=SERIES):
        return readiness.check(BASE, abi, series)

    def test_matching_signed_native_target_is_ready(self):
        self.assertEqual(self.entry, self.check())
        self.assertEqual(['kazuha.pub', 'release.json', 'release.sig', REPOSITORY + '/meta.conf',
                          REPOSITORY + '/data.pkg', REPOSITORY + '/packagesite.pkg', PACKAGE_PATH], self.requests)

    def test_two_series_on_one_abi_keep_distinct_signed_packages(self):
        current = copy.deepcopy(self.entry)
        original_assets = dict(self.assets)
        next_repository = REPOSITORY + '/27.1'
        next_package = next_repository + '/All/os-mihomo-1.1.2.pkg'
        self.entry.update(path=next_package, product_abi='27.1', native_product_abi='27.1')
        self.manifest['annotations']['product_abi'] = '27.1'
        self.publish_package()
        next_assets = {next_package: self.assets[PACKAGE_PATH]}
        for filename in ('meta.conf', 'data.pkg', 'packagesite.pkg'):
            next_assets[next_repository + '/' + filename] = self.assets[REPOSITORY + '/' + filename]
        self.assets = original_assets | next_assets
        self.report['packages'] = [current, self.entry]
        self.resign_report()
        self.assertEqual(current, self.check())
        self.assertEqual(self.entry, self.check(series='27.1'))
        self.assertIn(PACKAGE_PATH, self.requests)
        self.assertIn(next_package, self.requests)

    def test_unsigned_or_tampered_report_is_rejected(self):
        original_payload = self.assets['release.json']
        original_signature = self.assets['release.sig']
        for payload, signature in ((original_payload, b''), (original_payload + b' ', original_signature)):
            with self.subTest(unsigned=not signature):
                self.assets['release.json'] = payload
                self.assets['release.sig'] = signature
                with self.assertRaisesRegex(ValueError, 'Signature verification failed'):
                    self.check()

    def test_unsigned_or_tampered_package_catalog_is_rejected(self):
        payload = (json.dumps(self.catalog_entry) + '\n').encode()
        original_signature = self.sign(hashlib.sha256(payload).hexdigest().encode())
        for changed, signature in ((payload, b''), (payload + b' ', original_signature)):
            with self.subTest(unsigned=not signature):
                self.assets[REPOSITORY + '/packagesite.pkg'] = archive({'packagesite.yaml': changed,
                                                                       'signature': signature})
                with self.assertRaisesRegex(ValueError, 'Signature verification failed'):
                    self.check()

    def test_tampered_data_catalog_is_rejected(self):
        self.assets[REPOSITORY + '/data.pkg'] = archive({'data': b'{"changed":true}\n',
                                                        'signature': self.sign(hashlib.sha256(b'{}\n').hexdigest().encode())})
        with self.assertRaisesRegex(ValueError, 'Signature verification failed'):
            self.check()

    def test_tampered_package_is_rejected(self):
        self.assets[PACKAGE_PATH] += b'changed package bytes'
        with self.assertRaisesRegex(ValueError, 'target package digest differs'):
            self.check()

    def test_next_unpublished_target_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'target has no signed native-tested package'):
            self.check('FreeBSD:16:amd64', '27.1')
        self.assertNotIn(PACKAGE_PATH, self.requests)

    def test_duplicate_target_does_not_count_as_ready(self):
        self.report['packages'].append(copy.deepcopy(self.entry))
        self.resign_report()
        with self.assertRaisesRegex(ValueError, 'target has no signed native-tested package'):
            self.check()

    def test_native_report_abi_mismatch_is_rejected(self):
        self.entry['native_abi'] = 'FreeBSD:14:amd64'
        self.resign_report()
        with self.assertRaisesRegex(ValueError, 'Package ABI differs'):
            self.check()

    def test_native_kernel_major_mismatch_is_rejected(self):
        self.entry['native_kernel_version'] = '1600000'
        self.resign_report()
        with self.assertRaises(ValueError):
            self.check()

    def test_package_abi_mismatch_is_rejected_despite_valid_signatures(self):
        self.manifest['abi'] = 'FreeBSD:14:amd64'
        self.publish_package()
        with self.assertRaisesRegex(ValueError, 'Package ABI differs'):
            self.check()

    def test_python_dependency_mismatch_is_rejected(self):
        self.manifest['deps'].pop('python313')
        self.manifest['deps']['python314'] = {'origin': 'lang/python314', 'version': '3.14.3'}
        self.publish_package()
        with self.assertRaisesRegex(ValueError, 'Python dependency differs'):
            self.check()

    def test_native_product_series_mismatch_is_rejected(self):
        self.entry['native_product_abi'] = '26.1'
        self.resign_report()
        with self.assertRaisesRegex(ValueError, 'Product ABI differs'):
            self.check()

    def test_package_missing_from_signed_catalog_is_rejected(self):
        self.catalog_entry['path'] = 'All/os-mihomo-1.1.0.pkg'
        self.resign_catalog()
        with self.assertRaisesRegex(ValueError, 'missing from its signed catalog'):
            self.check()

    def test_invalid_target_series_or_abi_is_rejected(self):
        for abi, series in ((ABI, '26.10'), (ABI, '26.4'), (ABI, '26.07'),
                            ('FreeBSD:16:arm64', '27.1'), ('../FreeBSD:15:amd64', SERIES)):
            with self.subTest(abi=abi, series=series):
                with self.assertRaisesRegex(ValueError, 'official target ABI and OPNsense series'):
                    self.check(abi, series)

    def test_unsigned_http_transport_and_wrong_trust_anchor_are_rejected(self):
        with self.assertRaisesRegex(ValueError, 'must use HTTPS'):
            readiness.check(BASE.replace('https://', 'http://'), ABI, SERIES)
        self.assets['kazuha.pub'] += b'changed trust anchor'
        with self.assertRaisesRegex(ValueError, 'Incorrect repository trust anchor'):
            self.check()
