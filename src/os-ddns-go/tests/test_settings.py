"""Regression checks for credential masking, round trips, and stale saves."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[2] / 'common'))

spec = importlib.util.spec_from_file_location('ddnsgo_settings', Path(__file__).parents[1] /
                                            'src/usr/local/opnsense/scripts/ddnsgo/settings.py')
settings = importlib.util.module_from_spec(spec)
spec.loader.exec_module(settings)


class SettingsTests(unittest.TestCase):
    def setUp(self):
        mirror = patch.object(settings, 'mirror_settings', return_value=True)
        self.mirror = mirror.start()
        self.addCleanup(mirror.stop)

    def test_credentials_round_trip_and_stale_save(self):
        with tempfile.TemporaryDirectory() as directory:
            settings.CONFIG = Path(directory) / 'config.yaml'
            settings.RC_CONFIG = Path(directory) / 'ddnsgo'
            settings.CONFIG.write_text('dns:\n  - token: secret-value\n    username: admin\n    userid: 123456\n    id: 987654321\n    domain: example.net\n    enabled: true\n')
            original_argv = sys.argv
            try:
                sys.argv = ['settings.py', 'get']
                response = settings.main()
                self.mirror.assert_not_called()
                payload = json.dumps(response)
                for secret in ('secret-value', 'admin', '123456', '987654321', 'example.net'):
                    self.assertNotIn(secret, payload)
                given = response['settings']
                given['config_content'] = given['config_content'].replace('enabled: true', 'enabled: false')
                payload_file = Path(directory) / 'payload.json'
                payload_file.write_text(json.dumps(given))
                sys.argv = ['settings.py', 'set', str(payload_file)]
                self.assertEqual(settings.main()['status'], 'ok')
                self.mirror.assert_called_once_with()
                stored = settings.yaml.safe_load(settings.CONFIG.read_text())['dns'][0]
                self.assertEqual(stored['token'], 'secret-value')
                self.assertEqual(stored['userid'], 123456)
                self.assertFalse(stored['enabled'])
                self.assertEqual(settings.CONFIG.stat().st_mode & 0o777, 0o600)
                with self.assertRaisesRegex(ValueError, 'configuration changed'):
                    settings.main()
                self.mirror.assert_called_once_with()
            finally:
                sys.argv = original_argv

    def test_backup_failure_is_visible_without_exposing_saved_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            settings.CONFIG = Path(directory) / 'config.yaml'
            settings.RC_CONFIG = Path(directory) / 'ddnsgo'
            settings.CONFIG.write_text('token: SENTINEL_CREDENTIAL\nenabled: true\n')
            original_argv = sys.argv
            def fail_backup():
                saved = settings.yaml.safe_load(settings.CONFIG.read_text())
                self.assertEqual(saved, {'token': 'SENTINEL_CREDENTIAL', 'enabled': False})
                return False
            self.mirror.side_effect = fail_backup
            try:
                sys.argv = ['settings.py', 'get']
                given = settings.main()['settings']
                given['config_content'] = given['config_content'].replace('enabled: true', 'enabled: false')
                payload = Path(directory) / 'payload.json'
                payload.write_text(json.dumps(given))
                sys.argv = ['settings.py', 'set', str(payload)]
                result = settings.main()
                self.assertEqual(result['status'], 'failed')
                self.assertTrue(result['saved'])
                self.assertNotIn('SENTINEL_CREDENTIAL', json.dumps(result))
                self.mirror.assert_called_once_with()
            finally:
                sys.argv = original_argv

    def test_moving_masked_credentials_is_rejected(self):
        value = {'dns': [{'token': 'one'}, {'token': 'two'}]}
        redacted = settings.transform(value)
        redacted['dns'].reverse()
        with self.assertRaisesRegex(ValueError, 'masked value was moved'):
            settings.transform(redacted, restore=settings.stored_scalars(value))

    def test_log_masks_provider_values_and_arrows_survive(self):
        with tempfile.TemporaryDirectory() as directory:
            settings.CONFIG = Path(directory) / 'config.yaml'
            settings.LOG = Path(directory) / 'ddnsgo.log'
            settings.CONFIG.write_text('dns:\n  token: secret-value\n')
            settings.LOG.write_text('provider --> response token=secret-value\n')
            original_argv = sys.argv
            try:
                sys.argv = ['settings.py', 'log']
                text = settings.main()['log']
                self.assertNotIn('secret-value', text)
                self.assertIn('-->', text)
            finally:
                sys.argv = original_argv


if __name__ == '__main__':
    unittest.main()
