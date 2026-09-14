#!/usr/local/bin/python3
"""Read and update Lucky's existing rc.conf state without executing shell text."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from config_backup import BackupError, rc_value

CONFIG = Path('/etc/rc.conf.d/lucky')
DEFAULTS = {'lucky_enable': 'YES', 'lucky_conf_dir': '/usr/local/etc/lucky', 'lucky_http_port': '16601'}


def mirror_settings():
    try:
        return subprocess.run([sys.executable, str(Path(__file__).with_name('config_mirror.py')), 'mirror'],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
    except OSError:
        return False


def read_settings():
    # Share the literal parser used by the backup profile and preserve valid
    # single-quoted and unquoted settings accepted by the native rc framework.
    raw = CONFIG.read_bytes() if CONFIG.exists() else b''
    values = {key: rc_value(raw, key, default) for key, default in DEFAULTS.items()}
    return {'enabled': values['lucky_enable'] != 'NO', 'conf_dir': values['lucky_conf_dir'],
            'web_port': int(values['lucky_http_port'])}


def main():
    if sys.argv[1] == 'get':
        return {'settings': read_settings()}
    if sys.argv[1] != 'set':
        raise ValueError('Unknown action.')
    given = json.loads(Path(sys.argv[2]).read_text())
    if not isinstance(given, dict):
        raise ValueError('The settings must be a JSON object.')
    current = read_settings()
    directory = str(given.get('conf_dir', current['conf_dir']))
    if any(ord(char) < 32 or ord(char) == 127 for char in directory):
        raise ValueError('The configuration directory must be an absolute path without control characters.')
    directory = directory.strip() or DEFAULTS['lucky_conf_dir']
    if not directory.startswith('/') or directory.startswith('//') or directory == '/' or '..' in Path(directory).parts:
        raise ValueError('The configuration directory must be an absolute application path without parent traversal.')
    port = given.get('web_port', current['web_port'])
    if isinstance(port, bool) or not isinstance(port, (str, int)) or not re.fullmatch(r'[0-9]+', str(port).strip()):
        raise ValueError('The port must be a whole number between 1 and 65535.')
    port = int(port)
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
    if not mirror_settings():
        return {'status': 'failed', 'saved': True, 'error': 'Settings were saved, but the configuration backup failed.'}
    return {'status': 'ok'}


if __name__ == '__main__':
    try:
        result = main()
    except (BackupError, ValueError, OSError, KeyError, TypeError) as exception:
        result = {'status': 'failed', 'error': str(exception)}
    print(json.dumps(result))
