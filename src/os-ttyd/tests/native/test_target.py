#!/usr/local/bin/python3
"""Check the terminal target follows OPNsense SSH settings and overrides."""
import importlib.util
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[2] / 'src/usr/local/opnsense/scripts/ttyd/manage.py'
spec = importlib.util.spec_from_file_location('ttyd_mvc', SOURCE)
manager = importlib.util.module_from_spec(spec)
spec.loader.exec_module(manager)


class TargetTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.config = Path(self.directory.name) / 'config.xml'
        self.rc_config = Path(self.directory.name) / 'ttyd'
        self.config.write_text('<opnsense><system><ssh><port>10511</port></ssh></system></opnsense>')
        self.rc_config.write_text('ttyd_enable="NO"\nttyd_interface="127.0.0.1"\n')
        self.addCleanup(patch.stopall)
        patch.object(manager, 'CONFIG', self.config).start()
        patch.object(manager, 'RC_CONFIG', self.rc_config).start()
        patch.object(manager, 'run', return_value=SimpleNamespace(returncode=0)).start()
        patch.object(manager, 'mirror_configuration', return_value=True).start()

    def test_target_uses_configured_native_ssh_port(self):
        self.assertEqual(manager.dispatch('status')['target'], '127.0.0.1:10511')

    def test_legacy_default_command_follows_current_ssh_port(self):
        self.rc_config.write_text("ttyd_command='" + manager.LEGACY_COMMAND + "'\n")
        self.assertEqual(manager.dispatch('status')['target'], '127.0.0.1:10511')

    def test_custom_command_is_preserved_and_never_returned(self):
        self.rc_config.write_text("ttyd_command='ssh user:private-credential@example.test'\n")
        result = manager.dispatch('status')
        self.assertEqual(result['target'], 'Custom command')
        self.assertNotIn('private-credential', str(result))
        self.assertNotIn('user:', str(result))

    def test_invalid_ssh_port_falls_back_to_default(self):
        self.config.write_text('<opnsense><system><ssh><port>invalid</port></ssh></system></opnsense>')
        self.assertEqual(manager.ssh_port(), 22)

    def test_successful_service_operation_reports_backup_warning(self):
        with patch.object(manager, 'mirror_configuration', return_value=False) as mirror:
            result = manager.dispatch('stop')
        self.assertEqual(result['status'], 'ok')
        self.assertIn('configuration backup could not be updated', result['warning'])
        mirror.assert_called_once()

    def test_failed_service_operation_never_mirrors(self):
        with patch.object(manager, 'run', return_value=SimpleNamespace(returncode=1)):
            with patch.object(manager, 'mirror_configuration') as mirror:
                self.assertEqual(manager.dispatch('start')['status'], 'failed')
        mirror.assert_not_called()


if __name__ == '__main__':
    unittest.main()
