#!/usr/local/bin/python3
"""Validate both runtime modes with the actual packaged FreeBSD Core parser."""
import argparse
import importlib.util
import json
from pathlib import Path
import os
import subprocess
import sys
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--helpers', default='/usr/local/opnsense/scripts/singbox')
parser.add_argument('--core', default='/usr/local/bin/sing-box')
parser.add_argument('--sample', default='/usr/local/etc/sing-box/config.json.sample')
args = parser.parse_args()
if not sys.platform.startswith('freebsd'):
    raise SystemExit('This parser check requires the actual FreeBSD binary.')
sys.path.insert(0, args.helpers)
spec = importlib.util.spec_from_file_location('native_singbox_integration', Path(args.helpers) / 'integration.py')
integration = importlib.util.module_from_spec(spec)
spec.loader.exec_module(integration)
original = json.loads(Path(args.sample).read_bytes())
for transparent in (False, True):
    rendered = integration.render(original, {'transparent': transparent, 'transparent_consent': transparent})
    fd, path = tempfile.mkstemp(prefix='singbox-runtime-parser-')
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'w') as stream: json.dump(rendered, stream)
        result = subprocess.run([args.core, 'check', '-c', path], capture_output=True, timeout=20)
        if result.returncode:
            raise RuntimeError('The actual packaged Core rejected the isolated runtime mode.')
    finally:
        os.unlink(path)
print('Actual Core accepts proxy-only and controlled transparent runtime JSON; no service was started.')
