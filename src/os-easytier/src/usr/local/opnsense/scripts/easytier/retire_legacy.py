#!/usr/local/bin/python3
"""Retire only the exact former EasyTier blanket rule and its generated file."""
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

RULEFILE = Path('/var/run/easytier.rules')
GENERATED = (b'pass in quick on easytier0 inet from any to any flags S/SA keep state '
             b'label "easytier_any_to_any_pass"\n')
KNOWN = {
    GENERATED.decode().strip(),
    'pass in quick on easytier0 inet all flags S/SA keep state label "easytier_any_to_any_pass"',
}


def command(arguments):
    return subprocess.run(arguments, capture_output=True, text=True, timeout=5, check=False)


def snapshot(path, owner_uid):
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    with os.fdopen(descriptor, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != owner_uid or info.st_size > 1024:
            return None
        data = stream.read(1025)
        if data != GENERATED:
            return None
        return (info.st_dev, info.st_ino, info.st_mtime_ns, info.st_ctime_ns, data)


def retire(rulefile=RULEFILE, runner=command, owner_uid=0):
    result = runner(['/sbin/pfctl', '-a', 'easytier', '-sr'])
    if result.returncode:
        return 'The legacy EasyTier anchor could not be inspected and was preserved.'
    lines = [re.sub(r'\s+', ' ', line).strip()
             for line in result.stdout.splitlines() if line.strip()]
    if lines and (len(lines) != 1 or lines[0] not in KNOWN):
        return 'The EasyTier anchor contains other rules and was preserved.'
    before = snapshot(rulefile, owner_uid)
    if lines:
        result = runner(['/sbin/pfctl', '-a', 'easytier', '-F', 'rules'])
        if result.returncode:
            return 'The verified legacy EasyTier rule could not be retired.'
    if before is not None and snapshot(rulefile, owner_uid) == before:
        rulefile.unlink()
    return ''


def main():
    try:
        warning = retire()
    except (OSError, subprocess.SubprocessError):
        warning = 'Legacy EasyTier cleanup could not be completed safely; unverified resources were preserved.'
    if warning:
        print('Warning: ' + warning, file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
