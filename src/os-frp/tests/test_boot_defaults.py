"""Exercise OPNsense's broad rc.conf.d discovery against the package tree."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class BootDefaultsTests(unittest.TestCase):
    def test_samples_cannot_override_enabled_live_services(self):
        with tempfile.TemporaryDirectory() as directory:
            stage = Path(directory)
            shutil.copytree(ROOT / 'src', stage, dirs_exist_ok=True)
            fragments = stage / 'etc/rc.conf.d'
            fragments.mkdir(parents=True, exist_ok=True)
            for side in ['frpc', 'frps']:
                sample = stage / ('usr/local/share/frp/' + side + '.rc.conf.sample')
                self.assertTrue(sample.is_file())
                (fragments / side).write_text(side + '_enable="YES"\n')
            # rc.freebsd sources every fragment, including files named *.sample.
            result = subprocess.run(['sh', '-c',
                'for file in "$1"/*; do . "$file"; done; '
                'printf "%s %s" "$frpc_enable" "$frps_enable"',
                'sh', str(fragments)], capture_output=True, text=True, check=True)
            self.assertEqual(result.stdout, 'YES YES')
            self.assertEqual(sorted(p.name for p in fragments.iterdir()), ['frpc', 'frps'])
