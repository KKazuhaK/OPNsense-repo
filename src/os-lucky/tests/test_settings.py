"""Regression checks for rc.conf quoting and port validation."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('lucky_settings', Path(__file__).parents[1] /
                                            'src/usr/local/opnsense/scripts/lucky/settings.py')
settings = importlib.util.module_from_spec(spec)
spec.loader.exec_module(settings)


class SettingsTests(unittest.TestCase):
    def test_shell_characters_remain_literal_and_zero_port_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            settings.CONFIG = Path(directory) / 'rc.conf'
            config_directory = str(Path(directory) / 'lucky $literal `literal` "quoted"')
            given = {'enabled': 0, 'conf_dir': config_directory, 'web_port': 16602}
            original_argv = sys.argv
            try:
                payload_file = Path(directory) / 'payload.json'
                payload_file.write_text(json.dumps(given))
                sys.argv = ['settings.py', 'set', str(payload_file)]
                self.assertEqual(settings.main()['status'], 'ok')
                self.assertEqual(settings.read_settings(), {'enabled': False, 'conf_dir': config_directory, 'web_port': 16602})
                previous = settings.CONFIG.read_bytes()
                given['web_port'] = 0
                payload_file.write_text(json.dumps(given))
                with self.assertRaises(ValueError):
                    settings.main()
                self.assertEqual(settings.CONFIG.read_bytes(), previous)
            finally:
                sys.argv = original_argv


if __name__ == '__main__':
    unittest.main()
