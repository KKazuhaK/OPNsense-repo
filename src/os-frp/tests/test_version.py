"""Keep the package, archive, and installed frp version pins aligned."""
import hashlib
import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]


class VersionTests(unittest.TestCase):
    def test_official_archive_and_installed_version_match(self):
        version = (ROOT / 'FRP_VERSION').read_text().strip()
        self.assertEqual((ROOT / 'src/usr/local/share/frp/FRP_VERSION').read_text().strip(), version)
        script = (ROOT / 'build.sh').read_text()
        self.assertIn('FRP_VERSION="${FRP_VERSION:-' + version + '}"', script)
        registry = json.loads((ROOT.parents[1] / 'packaging/plugins.json').read_text())['plugins']['os-frp']
        entry = registry['vendored'][0]
        archive = ROOT / entry['artifact']
        self.assertIn('frp_' + version + '_freebsd_amd64', archive.name)
        self.assertEqual(hashlib.sha256(archive.read_bytes()).hexdigest(), entry['sha256'])
        self.assertEqual((ROOT / entry['sha256_file']).read_text().split()[0], entry['sha256'])
        sums = dict((line.split()[1], line.split()[0]) for line in (ROOT / entry['checksums_file']).read_text().splitlines())
        self.assertEqual(sums[archive.name], entry['sha256'])
