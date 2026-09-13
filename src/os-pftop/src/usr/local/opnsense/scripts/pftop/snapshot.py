#!/usr/local/bin/python3
"""Run a pfTop snapshot with validated arguments and no shell evaluation."""
import base64
import json
import os
import subprocess
import sys

VIEWS = ('default', 'label', 'long', 'queue', 'rules', 'size', 'speed', 'state', 'time')
SORTS = ('age', 'bytes', 'dest', 'dport', 'exp', 'none', 'pkt', 'sport', 'src')
COUNTS = ('20', '30', '40', '55', '100', 'all')


def main():
    given = json.loads(base64.b64decode(sys.argv[1], validate=True))
    view, sort, count = given.get('view', 'default'), given.get('sort', 'bytes'), given.get('count', '100')
    if view not in VIEWS or sort not in SORTS or count not in COUNTS:
        raise ValueError('Invalid snapshot options.')
    filter_value = str(given.get('filter', '')).strip()
    if len(filter_value) > 160 or any(ord(char) < 32 for char in filter_value):
        raise ValueError('The filter must contain at most 160 characters without control characters.')
    binary = next((path for path in ('/usr/local/sbin/pftop', '/usr/sbin/pftop', '/usr/bin/pftop')
                   if os.access(path, os.X_OK)), None)
    if binary is None:
        raise ValueError('pftop was not found on this system.')
    args = [binary, '-b', '-w', '135', '-v', view]
    if filter_value:
        args += ['-f', filter_value]
    if view not in ('queue', 'label', 'rules'):
        args += ['-o', sort]
    args += ['-a' if count == 'all' else count]
    process = subprocess.run(args, capture_output=True, text=True, errors='replace', timeout=15)
    output = process.stdout + process.stderr
    return {'status': 'ok' if process.returncode == 0 else 'failed', 'output': output[:524288],
            'error': '' if process.returncode == 0 else 'pftop returned an error.'}


if __name__ == '__main__':
    try:
        result = main()
    except (ValueError, OSError, KeyError, TypeError, subprocess.TimeoutExpired) as exception:
        result = {'status': 'failed', 'error': str(exception), 'output': ''}
    print(json.dumps(result))
