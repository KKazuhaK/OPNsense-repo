#!/usr/local/bin/python3
"""Keep DDNS-Go YAML in its existing store and mask stored credentials in APIs."""
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import yaml

CONFIG = Path('/usr/local/etc/ddns-go/config.yaml')
RC_CONFIG = Path('/etc/rc.conf.d/ddnsgo')
LOG = Path('/var/log/ddnsgo.log')
PRIVATE_KEY = re.compile(r'password|passwd|secret|token|credential|key|userid|username|webhook|authorization', re.I)
MARKER_PREFIX = '__DDNSGO_KEEP_'


def marker(path):
    return MARKER_PREFIX + hashlib.sha256(json.dumps(path).encode()).hexdigest()[:16] + '__'


def transform(value, path=(), restore=None, private=False):
    if isinstance(value, dict):
        return {key: transform(item, path + (str(key),), restore,
                               private or bool(PRIVATE_KEY.search(str(key)))) for key, item in value.items()}
    if isinstance(value, list):
        return [transform(item, path + (index,), restore, private) for index, item in enumerate(value)]
    if restore is not None:
        if isinstance(value, str) and value.startswith(MARKER_PREFIX):
            if value != marker(path) or path not in restore:
                raise ValueError('A masked value was moved or is no longer stored. Reload the configuration.')
            return restore[path]
        return value
    # Providers use arbitrary field names and can encode account IDs as
    # numbers. Mask every non-boolean scalar, plus private boolean fields.
    return marker(path) if value is not None and (not isinstance(value, bool) or private) else value


def stored_scalars(value, path=(), private=False):
    result = {}
    if isinstance(value, dict):
        for key, item in value.items():
            result.update(stored_scalars(item, path + (str(key),), private or bool(PRIVATE_KEY.search(str(key)))))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            result.update(stored_scalars(item, path + (index,), private))
    elif value is not None and (not isinstance(value, bool) or private):
        result[path] = value
    return result


def read_config():
    raw = CONFIG.read_bytes() if CONFIG.exists() else b''
    value = yaml.safe_load(raw) if raw.strip() else {}
    if not isinstance(value, dict):
        raise ValueError('The configuration must be a YAML mapping.')
    return raw, value


def listen_address():
    raw = RC_CONFIG.read_text() if RC_CONFIG.exists() else ''
    found = re.search(r'^ddnsgo_listen="([^"\r\n]*)"', raw, re.M)
    return found.group(1) if found else ':9876'


def main():
    action = sys.argv[1]
    raw, current = read_config()
    revision = hashlib.sha256(raw).hexdigest()
    if action == 'get':
        return {'settings': {'config_content': yaml.safe_dump(transform(current), allow_unicode=True, sort_keys=False),
                             'revision': revision, 'listen': listen_address()}, 'has_config': bool(raw.strip())}
    if action == 'log':
        if not LOG.exists():
            return {'log': ''}
        with LOG.open('rb') as handle:
            handle.seek(max(0, LOG.stat().st_size - 64000))
            text = handle.read().decode(errors='replace')
        # Mask all stored string values, including provider-specific secrets.
        for secret in sorted({str(value) for value in stored_scalars(current).values() if str(value)}, key=len, reverse=True):
            text = text.replace(secret, '[redacted]')
        text = re.sub(r'(?i)(password|secret|token|credential|authorization|api[_-]?key)(\s*[:=]\s*)\S+', r'\1\2[redacted]', text)
        return {'log': '\n'.join(text.splitlines()[-200:])}
    if action != 'set':
        raise ValueError('Unknown action.')
    given = json.loads(Path(sys.argv[2]).read_text())
    content = str(given.get('config_content', ''))
    if not content.strip():
        raise ValueError('The configuration content cannot be empty.')
    if len(content.encode()) > 1048576:
        raise ValueError('The configuration exceeds the 1 MiB limit.')
    if given.get('revision') != revision:
        raise ValueError('The configuration changed. Reload it before saving.')
    document = yaml.safe_load(content)
    if not isinstance(document, dict):
        raise ValueError('The configuration must be a YAML mapping.')
    restored = transform(document, restore=stored_scalars(current))
    CONFIG.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix='.ddnsgo-', dir=CONFIG.parent)
    try:
        with os.fdopen(descriptor, 'w') as handle:
            yaml.safe_dump(restored, handle, allow_unicode=True, sort_keys=False)
        os.chmod(temporary, 0o600)
        os.replace(temporary, CONFIG)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return {'status': 'ok'}


if __name__ == '__main__':
    try:
        result = main()
    except yaml.YAMLError:
        # Parser diagnostics include configuration lines and can expose secrets.
        result = {'status': 'failed', 'error': 'The configuration contains invalid YAML.'}
    except (ValueError, OSError, KeyError, TypeError, RecursionError) as exception:
        result = {'status': 'failed', 'error': str(exception)}
    print(json.dumps(result))
