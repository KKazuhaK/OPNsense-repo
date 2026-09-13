#!/usr/local/bin/python3
"""Reject ZIP links and traversal before the privileged extractor runs."""
from pathlib import PurePosixPath
import stat
import sys
import zipfile


def validate(path):
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        if not entries:
            return False
        for entry in entries:
            name = entry.filename
            mode = entry.external_attr >> 16
            kind = stat.S_IFMT(mode)
            if (not name or name.startswith('/') or '\\' in name or
                    any(character in name for character in '\0\n\r') or
                    '..' in PurePosixPath(name).parts or
                    kind not in (0, stat.S_IFREG, stat.S_IFDIR)):
                return False
    return True


if __name__ == '__main__':
    try:
        valid = validate(sys.argv[1])
    except (OSError, ValueError, IndexError, zipfile.BadZipFile):
        valid = False
    if not valid:
        print('Archive contains invalid paths, links or unsupported entries.')
    sys.exit(0 if valid else 1)
