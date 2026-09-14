"""Opt-in Internet bandwidth test using the bundled FreeBSD engine and private state."""
import fcntl
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

PACKAGE = Path(__file__).resolve().parents[2]


@unittest.skipUnless(sys.platform.startswith('freebsd'), 'Requires native FreeBSD and Internet access')
class LiveSpeedtest(unittest.TestCase):
    def test_real_engine_produces_finished_progress_and_private_result(self):
        spec = importlib.util.spec_from_file_location('live_speedtest',
            PACKAGE / 'src/usr/local/opnsense/scripts/speedtest/speedtest.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory(prefix='speedtest-live-') as directory:
            root = Path(directory)
            archive = PACKAGE / 'src/usr/local/bin/speedtest-go_1.7.10_Freebsd_x86_64.tar.gz'
            subprocess.run(['tar', '-xzf', str(archive), '-C', str(root)],
                           check=True, capture_output=True, timeout=10)
            engines = list(root.rglob('speedtest-go'))
            self.assertEqual(1, len(engines))
            engines[0].chmod(0o700)
            module.BINARY = str(engines[0])
            module.STATE = str(root / 'state')
            module.RESULT = module.STATE + '/result.json'
            module.PROGRESS = module.STATE + '/progress.json'
            module.LOCK = module.STATE + '/run.lock'
            module.TIMEOUT = 120
            self.assertEqual(0, module.main(['speedtest']))
            progress = json.loads(Path(module.PROGRESS).read_text())
            result = json.loads(Path(module.RESULT).read_text())
            self.assertEqual('done', progress['state'])
            self.assertEqual('', progress['error'])
            self.assertTrue({'server', 'download'}.issubset({entry['stage'] for entry in progress['stages']}))
            self.assertEqual(1, len(result['servers']))
            server = result['servers'][0]
            self.assertGreater(server['dl_speed'], 0)
            self.assertGreaterEqual(server['ul_speed'], 0)
            self.assertTrue(server['id'].isdigit())
            self.assertEqual(0o600, Path(module.RESULT).stat().st_mode & 0o777)
            self.assertEqual(0o644, Path(module.PROGRESS).stat().st_mode & 0o777)
            with open(module.LOCK) as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            print('Native bandwidth result: %.2f Mbps down, %.2f Mbps up; %d stages' %
                  (server['dl_speed'] * 8 / 1e6, server['ul_speed'] * 8 / 1e6, len(progress['stages'])))


if __name__ == '__main__':
    unittest.main()
