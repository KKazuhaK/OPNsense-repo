#!/usr/local/bin/python3
"""Expose EasyTier's existing file store and rc service through configd."""
import datetime
import fcntl
import hashlib
import hmac
import json
import math
import os
import pwd
import stat
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
import tomllib
from urllib.parse import urlsplit

CONFIG = Path('/usr/local/etc/easytier/config.toml')
LOG = Path('/var/log/easytier.log')
RC = '/usr/local/etc/rc.d/easytier'
SAVE_LOCK = Path('/var/run/easytier-config.lock')
OPERATION_LOCK = Path('/var/run/easytier-mvc.lock')
PID = Path('/var/run/easytier.pid')
SYSTEM_CONFIG = Path('/conf/config.xml')
MARKER = '__EASYTIER_KEEP_'
REQUEST_ROOT = Path('/tmp')
REQUEST_PREFIX = 'easytier_mvc_'

# Load the adjacent helper when tests import this script without changing sys.path.
import importlib.util
_network_spec = importlib.util.spec_from_file_location('easytier_network', Path(__file__).with_name('network.py'))
network = importlib.util.module_from_spec(_network_spec)
_network_spec.loader.exec_module(network)
SENSITIVE = re.compile(r'(secret|password|passwd|token|credential|private.?key|api.?key|authorization|username)', re.I)


def run(arguments, timeout=30):
    return subprocess.run(arguments, capture_output=True, text=True, timeout=timeout)


def mirror_configuration():
    try:
        result = run([sys.executable, str(Path(__file__).with_name('config_mirror.py')), 'mirror'])
        data = json.loads(result.stdout) if result.returncode == 0 else None
        return isinstance(data, dict) and data.get('ok') is True
    except (OSError, ValueError, TypeError, subprocess.SubprocessError):
        return False


def mirrored_result(result):
    if result.get('status') == 'ok' and not mirror_configuration():
        result['warning'] = 'The operation completed, but its configuration backup could not be updated.'
    return result


def stored():
    return tomllib.loads(CONFIG.read_text()) if CONFIG.exists() else {}


def confidential(key, value):
    if not isinstance(value, str) or not value:
        return False
    if SENSITIVE.search(str(key)):
        return True
    try:
        uri = urlsplit(value)
        return bool(uri.scheme and (uri.username or uri.password or uri.query or uri.fragment))
    except ValueError:
        return True


def masking_key():
    # A private key prevents masked low-entropy secrets from becoming guessable
    # hashes. It also invalidates stale placeholders when credentials change.
    key_path = CONFIG.parent / '.mvc-mask-key'
    CONFIG.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not key_path.exists():
        fd, temporary = tempfile.mkstemp(prefix='.mvc-key.', dir=CONFIG.parent)
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(os.urandom(32))
                stream.flush()
                os.fsync(stream.fileno())
            try:
                os.link(temporary, key_path)
            except FileExistsError:
                pass
        finally:
            os.unlink(temporary)
    key = key_path.read_bytes()
    if len(key) != 32:
        raise ValueError('Invalid masking key.')
    return key


def masking_marker(path, value, key=None):
    key = masking_key() if key is None else key
    identity = json.dumps([path, value], ensure_ascii=False).encode()
    return MARKER + hmac.new(key, identity, hashlib.sha256).hexdigest()[:32] + '__'


def redact(data, replacements=None, path=(), key=None):
    replacements = {} if replacements is None else replacements
    if isinstance(data, dict):
        return {name: redact(value, replacements, path + (name,), key) for name, value in data.items()}
    if isinstance(data, list):
        return [redact(value, replacements, path + (index,), key) for index, value in enumerate(data)]
    field = ' '.join(str(name) for name in path if isinstance(name, str))
    if confidential(field, data):
        marker = masking_marker(path, data, key)
        replacements[marker] = data
        return marker
    return data


def restore(value, replacements, path=()):
    if isinstance(value, dict):
        return {key: restore(item, replacements, path + (key,)) for key, item in value.items()}
    if isinstance(value, list):
        return [restore(item, replacements, path + (index,)) for index, item in enumerate(value)]
    if isinstance(value, str) and value.startswith(MARKER):
        if value not in replacements or not hmac.compare_digest(value, masking_marker(path, replacements[value])):
            raise ValueError('Unknown, stale or relocated secret placeholder.')
        return replacements[value]
    return value


def scalar(value):
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, bool):
        return 'true' if value else 'false'
    if isinstance(value, (datetime.datetime, datetime.date, datetime.time)):
        return value.isoformat()
    if isinstance(value, float) and not math.isfinite(value):
        return 'nan' if math.isnan(value) else ('inf' if value > 0 else '-inf')
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, list):
        return '[' + ', '.join(scalar(item) for item in value) + ']'
    if isinstance(value, dict):
        return '{ ' + ', '.join(json.dumps(key) + ' = ' + scalar(item) for key, item in value.items()) + ' }'
    raise ValueError('Unsupported configuration value.')


def render(data, path=()):
    lines = []
    for key, value in data.items():
        if not isinstance(value, dict) and not (isinstance(value, list) and value and all(isinstance(x, dict) for x in value)):
            lines.append(json.dumps(key) + ' = ' + scalar(value))
    for key, value in data.items():
        section = '.'.join(json.dumps(item) for item in path + (key,))
        if isinstance(value, dict):
            lines.extend(['', '[' + section + ']', render(value, path + (key,))])
        elif isinstance(value, list) and value and all(isinstance(x, dict) for x in value):
            for item in value:
                # Inline nested tables keep array-table paths unambiguous.
                lines.extend(['', '[[' + section + ']]'])
                lines.extend(json.dumps(k) + ' = ' + scalar(v) for k, v in item.items())
    return '\n'.join(lines).rstrip() + '\n'


def scrub(text, data):
    replacements = {}
    redact(data, replacements)
    for value in sorted(set(replacements.values()), key=len, reverse=True):
        text = text.replace(value, '********')
    text = re.sub(r'(?i)([a-z0-9_-]*(?:secret|password|passwd|token|credential|private_key|api_key|authorization|username)[a-z0-9_-]*)([\"\']?\s*[=:]\s*)("[^"]*"|\'[^\']*\'|\S+)', r'\1\2********', text)
    text = re.sub(r'(?i)([a-z][a-z0-9+.-]*://)[^\s"<>]+', lambda m: m.group(1) + '[redacted]' if confidential('', m.group(0)) else m.group(0), text)
    return text


def running():
    return run([RC, 'onestatus'], 5).returncode == 0


def rpc_portal(for_connection=True):
    value = stored().get('rpc_portal', 0)
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ValueError('Invalid RPC portal.')
    value = str(value)
    if value.isdigit():
        host, port = '127.0.0.1', int(value) or 15888
    else:
        match = re.fullmatch(r'(\[[0-9a-fA-F:.]+\]|[a-zA-Z0-9_.-]+):(\d+)', value)
        if match is None:
            raise ValueError('Invalid RPC portal.')
        host, port = match[1], int(match[2])
        if for_connection:
            host = {'0.0.0.0': '127.0.0.1', '[::]': '[::1]'}.get(host, host)
    if not 1 <= port <= 65535:
        raise ValueError('Invalid RPC portal.')
    return f'{host}:{port}'


def language():
    try:
        return ET.parse(SYSTEM_CONFIG).findtext('system/language', default='en_US')
    except (OSError, ET.ParseError):
        return 'en_US'


def status():
    data = stored()
    identity = data.get('network_identity', {})
    if not isinstance(identity, dict):
        raise ValueError('Invalid network identity.')
    version = run(['/usr/local/sbin/easytier-core', '--version'], 5).stdout.strip()
    return {'status': 'ok', 'running': running(), 'version': scrub(version, data), 'language': language(),
            'pid': PID.read_text().strip() if PID.exists() else '',
            'hostname': scrub(str(data.get('hostname', '')), data),
            'ipv4': scrub(str(data.get('ipv4', '')), data),
            'network_name': scrub(str(identity.get('network_name', '')), data), **network.public_status()}


def request_text(argument):
    path = Path(argument)
    if path.parent != REQUEST_ROOT or not path.name.startswith(REQUEST_PREFIX):
        raise ValueError('Invalid request path.')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        metadata = os.fstat(stream.fileno())
        owners = {0, pwd.getpwnam('www').pw_uid}
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o777 != 0o600 or metadata.st_uid not in owners:
            raise ValueError('Invalid request file.')
        content = stream.read(1048577)
    if len(content) > 1048576:
        raise ValueError('Request exceeds size limit.')
    return content.decode('utf-8')


def save_configuration(text):
    if not text.strip() or '\0' in text or len(text.encode()) > 1048576:
        return {'status': 'failed', 'error': 'The configuration is empty or invalid.'}
    replacements = {}
    redact(stored(), replacements)
    # Parse before and after restoring masked values. Never send parser errors
    # back because they may include credentials from the submitted document.
    parsed = restore(tomllib.loads(text), replacements)
    network.validate_live_configuration(parsed)
    output = render(parsed)
    tomllib.loads(output)
    CONFIG.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.config.', dir=CONFIG.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(output)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, CONFIG)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return {'status': 'ok'}


def dispatch(action, argument=None):
    if action == 'settings':
        data = stored()
        replacements = {}
        public = redact(data, replacements)
        return {'status': 'ok', 'config': render(public), 'has_secret': bool(replacements)}
    if action == 'save':
        text = request_text(argument)
        CONFIG.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        SAVE_LOCK.parent.mkdir(parents=True, exist_ok=True)
        with SAVE_LOCK.open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            result = save_configuration(text)
        # The archive takes the same lock after the save releases it.
        return mirrored_result(result)
    if action == 'status':
        return status()
    if action == 'peers':
        if not running():
            return {'status': 'ok', 'running': False, 'rows': []}
        result = run(['/usr/local/sbin/easytier-cli', '-p', rpc_portal(), 'peer'], 5)
        if result.returncode:
            return {'status': 'failed', 'error': 'Unable to query peers. Check the configured RPC portal.'}
        rows = []
        data = stored()
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith('|') and '---' not in line and 'ipv4' not in line:
                columns = [scrub(x.strip(), data) for x in line.strip('|').split('|')]
                if len(columns) >= 10:
                    rows.append(columns[:10])
        return {'status': 'ok', 'running': True, 'rows': rows}
    if action == 'log':
        # Read backwards so the polling endpoint does not load an unbounded log.
        content = b''
        if LOG.exists():
            with LOG.open('rb') as stream:
                position = stream.seek(0, os.SEEK_END)
                while position > 0 and content.count(b'\n') <= 100 and len(content) < 1048576:
                    size = min(8192, position)
                    position -= size
                    stream.seek(position)
                    content = stream.read(size) + content
        text = '\n'.join(content.decode('utf-8', errors='replace').splitlines()[-100:])
        return {'status': 'ok', 'log': scrub(text, stored())}
    if action == 'clear_log':
        LOG.touch(mode=0o600, exist_ok=True)
        with LOG.open('w'):
            pass
        return {'status': 'ok'}
    if action in {'start', 'stop', 'restart'}:
        if action == 'restart':
            enabled = run(['/usr/sbin/sysrc', '-n', '-f', '/etc/rc.conf.d/easytier', 'easytier_enable'], 5)
            if enabled.returncode or enabled.stdout.strip().upper() not in {'YES', 'TRUE', 'ON', '1'} or not running():
                return {'status': 'failed', 'error': 'EasyTier is stopped or disabled. Use Start to enable it explicitly.'}
        if action in {'start', 'restart'}:
            network.validate_live_configuration(stored())
        if action in {'start', 'stop'}:
            enabled = 'YES' if action == 'start' else 'NO'
            SAVE_LOCK.parent.mkdir(parents=True, exist_ok=True)
            with SAVE_LOCK.open('a') as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                result = run(['/usr/sbin/sysrc', '-f', '/etc/rc.conf.d/easytier', 'easytier_enable=' + enabled])
            if result.returncode:
                return {'status': 'failed', 'error': 'Unable to update service startup settings.'}
        result = run([RC, 'one' + action], 60)
        return mirrored_result({'status': 'ok' if result.returncode == 0 else 'failed',
                                'error': '' if result.returncode == 0 else 'Service operation failed. Check the EasyTier log.'})
    return {'status': 'failed', 'error': 'Unknown action.'}


def main():
    try:
        if len(sys.argv) < 2:
            raise ValueError('Missing action.')
        action = sys.argv[1]
        if action == 'rpc-portal':
            print(rpc_portal(for_connection=False))
            return 0
        argument = sys.argv[2] if len(sys.argv) > 2 else None
        if action in {'start', 'stop', 'restart'}:
            with OPERATION_LOCK.open('a') as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                result = dispatch(action, argument)
        else:
            result = dispatch(action, argument)
        print(json.dumps(result, ensure_ascii=False))
    except network.PolicyError as error:
        print(json.dumps({'status': 'failed', 'error': str(error)}))
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
        if len(sys.argv) > 1 and sys.argv[1] == 'rpc-portal':
            print('Unable to read the EasyTier RPC portal.', file=sys.stderr)
            return 1
        print(json.dumps({'status': 'failed', 'error': 'Unable to read, validate or update EasyTier configuration.'}))
    return 0


if __name__ == '__main__':
    sys.exit(main())
