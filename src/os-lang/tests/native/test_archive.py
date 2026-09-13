#!/usr/local/bin/python3
"""Check ZIP traversal and link rejection on the router runtime."""
import importlib.util
from pathlib import Path
import stat
import tempfile
import unittest
import zipfile

SOURCE = Path(__file__).resolve().parents[2] / 'src/usr/local/opnsense/scripts/langtool/validate_archive.py'
spec = importlib.util.spec_from_file_location('langtool_archive', SOURCE)
validator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validator)


class ArchiveTest(unittest.TestCase):
    def test_safe_archive_and_unsafe_names(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'lang.zip'
            for name, safe in [('share/locale/zh_CN/messages.mo', True), ('../etc/passwd', False), ('/etc/passwd', False), ('etc/../../passwd', False), ('etc\\passwd', False), ('etc/file\nname', False)]:
                with zipfile.ZipFile(path, 'w') as archive:
                    archive.writestr(name, b'example')
                self.assertEqual(validator.validate(path), safe, name)

    def test_symlink_is_rejected_before_extraction(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'lang.zip'
            link = zipfile.ZipInfo('etc/redirect')
            link.create_system = 3
            link.external_attr = (stat.S_IFLNK | 0o777) << 16
            with zipfile.ZipFile(path, 'w') as archive:
                archive.writestr(link, '/etc')
                archive.writestr('etc/redirect/passwd', 'replacement')
            self.assertFalse(validator.validate(path))


if __name__ == '__main__':
    unittest.main()
