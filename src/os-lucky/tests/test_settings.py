"""Regression checks for rc.conf quoting and port validation."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[2] / 'common'))

spec = importlib.util.spec_from_file_location('lucky_settings', Path(__file__).parents[1] /
                                            'src/usr/local/opnsense/scripts/lucky/settings.py')
settings = importlib.util.module_from_spec(spec)
spec.loader.exec_module(settings)


class SettingsTests(unittest.TestCase):
    def setUp(self):
        mirror = patch.object(settings, 'mirror_settings', return_value=True)
        self.mirror = mirror.start()
        self.addCleanup(mirror.stop)

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
                self.mirror.assert_called_once_with()
                self.assertEqual(settings.read_settings(), {'enabled': False, 'conf_dir': config_directory, 'web_port': 16602})
                previous = settings.CONFIG.read_bytes()
                given['web_port'] = 0
                payload_file.write_text(json.dumps(given))
                with self.assertRaises(ValueError):
                    settings.main()
                self.assertEqual(settings.CONFIG.read_bytes(), previous)
                self.mirror.assert_called_once_with()
            finally:
                sys.argv = original_argv

    def test_backup_failure_is_reported_after_the_settings_are_saved(self):
        with tempfile.TemporaryDirectory() as directory:
            settings.CONFIG = Path(directory) / 'rc.conf'
            expected = {'enabled': False, 'conf_dir': str(Path(directory) / 'lucky'), 'web_port': 16603}
            payload = Path(directory) / 'payload.json'
            payload.write_text(json.dumps(expected))
            original_argv = sys.argv
            def fail_backup():
                self.assertEqual(settings.read_settings(), expected)
                return False
            self.mirror.side_effect = fail_backup
            try:
                sys.argv = ['settings.py', 'set', str(payload)]
                result = settings.main()
                self.assertEqual(result['status'], 'failed')
                self.assertTrue(result['saved'])
                self.mirror.assert_called_once_with()
            finally:
                sys.argv = original_argv


if __name__ == '__main__':
    unittest.main()
