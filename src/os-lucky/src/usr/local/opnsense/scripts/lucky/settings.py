#!/usr/local/bin/python3
"""Read and update Lucky's existing rc.conf state without executing shell text."""
import json
import os
from pathlib import Path
import re
import sys
import tempfile

CONFIG = Path('/etc/rc.conf.d/lucky')
DEFAULTS = {'lucky_enable': 'YES', 'lucky_conf_dir': '/usr/local/etc/lucky', 'lucky_http_port': '16601'}


def read_settings():
    values = DEFAULTS.copy()
    if CONFIG.exists():
        for key, value in re.findall(r'^([a-z_]+)="((?:\\.|[^"\\])*)"\s*$', CONFIG.read_text(), re.M):
            if key in values:
                values[key] = re.sub(r'\\([\\"$`])', r'\1', value)
    return {'enabled': values['lucky_enable'] != 'NO', 'conf_dir': values['lucky_conf_dir'],
            'web_port': int(values['lucky_http_port'])}


def main():
    if sys.argv[1] == 'get':
        return {'settings': read_settings()}
    if sys.argv[1] != 'set':
        raise ValueError('Unknown action.')
    given = json.loads(Path(sys.argv[2]).read_text())
    current = read_settings()
    directory = str(given.get('conf_dir', current['conf_dir'])).strip() or DEFAULTS['lucky_conf_dir']
    if not directory.startswith('/') or any(ord(char) < 32 for char in directory):
        raise ValueError('The configuration directory must be an absolute path without control characters.')
    port = int(given.get('web_port', current['web_port']))
    if not 1 <= port <= 65535:
        raise ValueError('The port must be between 1 and 65535.')
    enabled = given.get('enabled', current['enabled']) in (True, 1, '1', 'yes')
    Path(directory).mkdir(parents=True, exist_ok=True)
    escaped = re.sub(r'([\\"$`])', r'\\\1', directory)
    content = f'lucky_enable="{"YES" if enabled else "NO"}"\nlucky_conf_dir="{escaped}"\nlucky_http_port="{port}"\n'
    CONFIG.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix='.lucky-', dir=CONFIG.parent)
    try:
        with os.fdopen(descriptor, 'w') as handle:
            handle.write(content)
        os.chmod(temporary, 0o644)
        os.replace(temporary, CONFIG)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return {'status': 'ok'}


if __name__ == '__main__':
    try:
        result = main()
    except (ValueError, OSError, KeyError, TypeError) as exception:
        result = {'status': 'failed', 'error': str(exception)}
    print(json.dumps(result))
