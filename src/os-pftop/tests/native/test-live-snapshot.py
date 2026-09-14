"""Take a bounded native pfTop read snapshot without changing PF configuration."""
import base64
import json
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import unittest


@unittest.skipUnless(platform.system() == 'FreeBSD' and shutil.which('pftop'), 'Requires native FreeBSD pfTop and read access to /dev/pf')
class LiveSnapshotTests(unittest.TestCase):
    def test_native_batch_snapshot_reads_states_and_uses_the_filter_parser(self):
        source = Path(__file__).resolve().parents[2] / 'src/usr/local/opnsense/scripts/pftop/snapshot.py'
        given = {'view': 'default', 'sort': 'bytes', 'count': '20', 'filter': 'host 192.0.2.10'}
        payload = base64.b64encode(json.dumps(given).encode()).decode()
        process = subprocess.run([sys.executable, str(source), payload], capture_output=True, text=True, timeout=20)
        self.assertEqual(process.returncode, 0, process.stderr)
        result = json.loads(process.stdout)
        self.assertEqual(result['status'], 'ok', result.get('error'))
        self.assertTrue(result['output'])
        self.assertLessEqual(len(result['output']), 524288)
        self.assertEqual(result['error'], '')


if __name__ == '__main__':
    unittest.main()
