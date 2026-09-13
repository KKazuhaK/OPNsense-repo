"""Exercise provider validation and controller delegation with actual PHP classes."""
from pathlib import Path
import shutil
import subprocess
import unittest

PACKAGE = Path(__file__).resolve().parents[1]


class PhpTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('php'), 'Requires PHP for model validation and API contracts')
    def test_validation_and_api_contracts(self):
        result = subprocess.run(['php', str(PACKAGE / 'tests/php/test-model-api.php'), str(PACKAGE)],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn('DynDNS model/API contract passed', result.stdout)


if __name__ == '__main__':
    unittest.main()
