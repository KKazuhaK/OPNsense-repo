"""Run the actual API controller with a bounded PHP backend stand-in."""
from pathlib import Path
import shutil
import subprocess
import unittest

PACKAGE = Path(__file__).resolve().parents[1]


class ApiTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('php'), 'Requires PHP for the actual controller contract')
    def test_controller_permissions_and_apply_result_contract(self):
        result = subprocess.run(['php', str(PACKAGE / 'tests/php/test-api.php'), str(PACKAGE)],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn('Unboundcustom API contract passed', result.stdout)


if __name__ == '__main__':
    unittest.main()
