"""Exercise the shared process identity helpers without a live kernel."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / 'process_identity.py'
spec = importlib.util.spec_from_file_location('shared_process_identity', SCRIPT)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class BirthTests(unittest.TestCase):
    def test_parse_boot_accepts_sysctl_text_and_canonical_tokens(self):
        self.assertEqual((1780000000, 12345),
                         m.parse_boot('{ sec = 1780000000, usec = 12345 } Wed Sep 16 2026'))
        self.assertEqual((1780000000, 1), m.parse_boot('1780000000:1'))
        for value in ('', 'not a boot', '{ sec = 1 }', '1:1000000'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                m.parse_boot(value)

    def test_relative_birth_cancels_the_same_clock_step(self):
        self.assertEqual(m.relative_birth('1780000010:5', '1780000000:0'),
                         m.relative_birth('1780000310:5', '1780000300:0'))

    def test_rebase_birth_moves_and_reencodes_without_padding(self):
        self.assertEqual('1780000300:5', m.rebase_birth('1780000000:5', 300 * 1000000))
        self.assertEqual('1780000000:6', m.rebase_birth('1780000000:5', 1))
        self.assertEqual('1779999999:999999', m.rebase_birth('1780000000:0', -1))
        self.assertIsNone(m.rebase_birth('bad', 1))
        self.assertIsNone(m.rebase_birth('1780000000:0', -2000000000000000))

    def test_birth_frame_shift_reports_delta_and_current_token(self):
        with patch.object(m, 'boot_time', return_value=(1780000300, 5)):
            self.assertEqual((300 * 1000000, '1780000300:5'),
                             m.birth_frame_shift('{ sec = 1780000000, usec = 5 }'))
        with patch.object(m, 'boot_time', return_value=None):
            self.assertIsNone(m.birth_frame_shift('1780000000:5'))
        self.assertIsNone(m.birth_frame_shift('garbage'))


if __name__ == '__main__':
    unittest.main()
