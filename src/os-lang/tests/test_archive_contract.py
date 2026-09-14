"""Reject malformed and special ZIP entries before any extraction."""
import importlib.util
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
import zipfile

SOURCE = Path(__file__).parents[1] / 'src/usr/local/opnsense/scripts/langtool/validate_archive.py'
spec = importlib.util.spec_from_file_location('private_lang_archive', SOURCE)
validator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validator)


class ArchiveContractTests(unittest.TestCase):
    def test_empty_corrupt_and_special_archives_are_rejected_by_cli(self):
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / 'archive.zip'
            for kind in ['empty', 'corrupt', 'symlink', 'fifo', 'socket']:
                with self.subTest(kind=kind):
                    if kind == 'corrupt':
                        archive.write_bytes(b'not a zip archive')
                    else:
                        with zipfile.ZipFile(archive, 'w') as handle:
                            if kind != 'empty':
                                entry = zipfile.ZipInfo('share/locale/messages.mo')
                                entry.create_system = 3
                                mode = {'symlink': stat.S_IFLNK, 'fifo': stat.S_IFIFO, 'socket': stat.S_IFSOCK}[kind]
                                entry.external_attr = (mode | 0o600) << 16
                                handle.writestr(entry, 'PRIVATE_ARCHIVE_CONTENT')
                    result = subprocess.run([sys.executable, str(SOURCE), str(archive)], capture_output=True, text=True)
                    self.assertEqual(result.returncode, 1)
                    self.assertNotIn('PRIVATE_ARCHIVE_CONTENT', result.stdout + result.stderr)

    def test_explicit_directories_and_regular_files_are_supported(self):
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / 'archive.zip'
            with zipfile.ZipFile(archive, 'w') as handle:
                directory = zipfile.ZipInfo('share/locale/')
                directory.create_system = 3
                directory.external_attr = (stat.S_IFDIR | 0o755) << 16
                handle.writestr(directory, '')
                handle.writestr('share/locale/中文.mo', b'exact binary')
            self.assertTrue(validator.validate(str(archive)))


if __name__ == '__main__':
    unittest.main()
