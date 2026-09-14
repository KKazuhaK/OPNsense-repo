"""Run native PHP controller contracts without framework or installed services."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


@unittest.skipUnless(shutil.which('php'), 'requires PHP CLI')
class ControllerContractTests(unittest.TestCase):
    def test_configd_results_permissions_private_transport_and_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(__file__).parent / 'native/test-controller.php'
            result = subprocess.run(['php', str(source), directory], capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, 'controller contract passed\n')
            self.assertEqual(list(Path(directory).iterdir()), [])


if __name__ == '__main__':
    unittest.main()
