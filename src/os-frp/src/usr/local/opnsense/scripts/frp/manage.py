#!/usr/local/bin/python3
"""Drive the frps and frpc daemons, their TOML documents and their logs for configd."""
import argparse
import datetime
import fcntl
import json
import math
import os
import pwd
import re
import stat
import subprocess
import sys
import tempfile
import time
import tomllib
from pathlib import Path

KEEP = '__KEEP__'
# What the shipped sample files carry where a field has no safe default. Both rc
# scripts refuse to start while one is still in place, so it is not a value.
PLACEHOLDER = 'CHANGE_ME'
STATE = Path('/var/db/os-frp')
CONFIG_DIR = Path('/usr/local/etc/frp')
REQUEST_ROOT = Path('/tmp')
REQUEST_PREFIX = 'frp_'
MAX_DOCUMENT = 1048576
LOG_LINES = 200
SERVICE = '/usr/sbin/service'
SYSRC = '/usr/sbin/sysrc'

SIDES = {
    'frps': {
        'binary': '/usr/local/sbin/frps',
        'config': CONFIG_DIR / 'frps.toml',
        'pidfile': Path('/var/run/frps.pid'),
        'log': Path('/var/log/frps.log'),
        'rcconf': Path('/etc/rc.conf.d/frps'),
        'rcvar': 'frps_enable',
        'label': 'frp server',
    },
    'frpc': {
        'binary': '/usr/local/sbin/frpc',
        'config': CONFIG_DIR / 'frpc.toml',
        'pidfile': Path('/var/run/frpc.pid'),
        'log': Path('/var/log/frpc.log'),
        'rcconf': Path('/etc/rc.conf.d/frpc'),
        'rcvar': 'frpc_enable',
        'label': 'frp client',
    },
}

# Keys whose string value is a credential.  frp spells every one of these as a
# leaf json tag: auth.token, webServer.password, the shared secretKey of an
# stcp/sudp/xtcp proxy or visitor, loadBalancer.groupKey, the httpPassword of an
# http or tcpmux proxy, and the password of a client plugin.
CREDENTIAL_NAMES = frozenset({'token', 'password', 'secretkey', 'groupkey', 'httppassword', 'apikey', 'authorization'})
CREDENTIAL_SUFFIXES = ('password', 'secretkey', 'token')

# Top-level keys frp declares as an array of tables.  Every other list of
# tables is emitted inline, which is what allowPorts needs.
ARRAY_TABLES = frozenset({'proxies', 'visitors', 'httpPlugins'})

BARE_KEY = re.compile(r'^[A-Za-z0-9_-]+$')
POSITION = re.compile(r'(?:at )?line (\d+),? column (\d+)')
SENSITIVE_ASSIGNMENT = re.compile(
    r'(?i)([a-z0-9_-]*(?:secret|password|passwd|token|credential|api[_-]?key|authorization)[a-z0-9_-]*)'
    r'(["\']?\s*[=:]\s*)("[^"]*"|\'[^\']*\'|\S+)')
URL_CREDENTIALS = re.compile(r'(?i)([a-z][a-z0-9+.-]*://)[^/\s"\']*@')


class Error(Exception):
    """A failure whose message is safe to show in the web interface."""


def run(arguments, timeout=30):
    return subprocess.run(arguments, capture_output=True, text=True, timeout=timeout)


def table(data, name):
    value = data.get(name) if isinstance(data, dict) else None
    return value if isinstance(value, dict) else {}


def text_of(value):
    return value.strip() if isinstance(value, str) else ''


def port_of(value):
    # TOML booleans are integers in Python; a bool is never a port number.
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else 0


# --- TOML emitting -----------------------------------------------------------

def key_token(name):
    name = str(name)
    return name if BARE_KEY.match(name) else json.dumps(name, ensure_ascii=False)


def scalar(value):
    if isinstance(value, bool):
        return 'true' if value else 'false'
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, (datetime.datetime, datetime.date, datetime.time)):
        return value.isoformat()
    if isinstance(value, float) and not math.isfinite(value):
        return 'nan' if math.isnan(value) else ('inf' if value > 0 else '-inf')
    if isinstance(value, (int, float)):
        return repr(value) if isinstance(value, float) else str(value)
    if isinstance(value, list):
        return '[' + ', '.join(scalar(item) for item in value) + ']'
    if isinstance(value, dict):
        if not value:
            return '{}'
        return '{ ' + ', '.join(key_token(key) + ' = ' + scalar(item) for key, item in value.items()) + ' }'
    if value is None:
        raise Error('A configuration value is empty where frp expects a value.')
    raise Error('The configuration contains a value frp cannot express in TOML.')


def is_table_array(path, key, value):
    # Only the documented top-level arrays become [[key]] blocks.  Everything
    # else, allowPorts above all, stays an inline array of inline tables.
    return (not path and key in ARRAY_TABLES and isinstance(value, list)
            and bool(value) and all(isinstance(item, dict) for item in value))


def render(data, path=()):
    lines = []
    for key, value in data.items():
        if isinstance(value, dict) or is_table_array(path, key, value):
            continue
        lines.append(key_token(key) + ' = ' + scalar(value))
    for key, value in data.items():
        header = '.'.join(key_token(name) for name in path + (key,))
        if isinstance(value, dict):
            body = render(value, path + (key,))
            # A table that holds nothing but sub-tables needs no header of its
            # own: [transport.tls] alone re-reads as transport.tls.
            if not value or any(not isinstance(item, dict) for item in value.values()):
                lines.extend(['', '[' + header + ']'])
                if body:
                    lines.append(body)
            elif body:
                lines.extend(['', body])
        elif is_table_array(path, key, value):
            for item in value:
                # Nested tables inside an array element are inlined so the
                # array-of-tables path can never become ambiguous.
                lines.extend(['', '[[' + header + ']]'])
                lines.extend(key_token(name) + ' = ' + scalar(entry) for name, entry in item.items())
    return '\n'.join(lines).strip('\n')


def document(data):
    if not isinstance(data, dict):
        raise Error('The configuration must be a table of keys.')
    body = re.sub(r'\n{3,}', '\n\n', render(data))
    header = '# Managed by the OPNsense os-frp plugin.\n# Every key is an frp configuration field; unknown keys stop the daemon.\n'
    return header + (body + '\n' if body else '')


def jsonable(value):
    """Make a parsed TOML document safe for json.dumps without losing meaning."""
    if isinstance(value, dict):
        return {str(key): jsonable(item) for key, item in value.items()}
    if isinstance(value, list):
        return [jsonable(item) for item in value]
    if isinstance(value, (datetime.datetime, datetime.date, datetime.time)):
        return value.isoformat()
    if isinstance(value, float) and not math.isfinite(value):
        return 'nan' if math.isnan(value) else ('inf' if value > 0 else '-inf')
    return value


# --- credential masking ------------------------------------------------------

def item_key(item, index):
    """Address a list element by its frp name so reordering keeps credentials."""
    if isinstance(item, dict):
        name = item.get('name')
        if isinstance(name, str) and name:
            return ('#', name)
    return ('#', index)


def is_credential(name, value):
    if not isinstance(value, str) or not value:
        return False
    lowered = str(name).lower()
    return lowered in CREDENTIAL_NAMES or lowered.endswith(CREDENTIAL_SUFFIXES)


def dotted(path):
    rendered = ''
    for item in path:
        if isinstance(item, tuple):
            rendered += '[' + str(item[1]) + ']'
        else:
            rendered += ('.' if rendered else '') + str(item)
    return rendered


def collect(value, store=None, path=()):
    """Map every stored credential to the path it lives at."""
    store = {} if store is None else store
    if isinstance(value, dict):
        for name, item in value.items():
            collect(item, store, path + (name,))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            collect(item, store, path + (item_key(item, index),))
    elif path and isinstance(path[-1], str) and is_credential(path[-1], value):
        store[path] = value
    return store


def mask(value, path=()):
    if isinstance(value, dict):
        return {name: mask(item, path + (name,)) for name, item in value.items()}
    if isinstance(value, list):
        return [mask(item, path + (item_key(item, index),)) for index, item in enumerate(value)]
    if path and isinstance(path[-1], str) and is_credential(path[-1], value):
        return KEEP
    return value


def restore(value, store, path=()):
    if isinstance(value, dict):
        return {name: restore(item, store, path + (name,)) for name, item in value.items()}
    if isinstance(value, list):
        return [restore(item, store, path + (item_key(item, index),)) for index, item in enumerate(value)]
    if isinstance(value, str) and value == KEEP:
        if path not in store:
            raise Error('No credential is stored at ' + dotted(path) + ', so the "' + KEEP + '" placeholder there '
                        'cannot be resolved. Renaming a proxy or a visitor moves its credential path; enter the '
                        'value again instead of keeping it.')
        return store[path]
    return value


def scrub(text, secrets=()):
    for secret in sorted({item for item in secrets if isinstance(item, str) and len(item) > 2}, key=len, reverse=True):
        text = text.replace(secret, '********')
    text = SENSITIVE_ASSIGNMENT.sub(r'\1\2"********"', text)
    text = URL_CREDENTIALS.sub(r'\1[redacted]@', text)
    return text


# --- stored document ---------------------------------------------------------

def read_document(path):
    if not path.exists():
        return {}
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        content = stream.read(MAX_DOCUMENT + 1)
    if len(content) > MAX_DOCUMENT:
        raise Error('The stored configuration is larger than the 1 MiB this plugin handles.')
    try:
        return jsonable(tomllib.loads(content.decode('utf-8')))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as failure:
        raise Error('The stored configuration is not valid TOML' + position(failure) + '.') from None


def position(failure):
    found = POSITION.search(str(failure))
    return ' (line ' + found.group(1) + ', column ' + found.group(2) + ')' if found else ''


def parse_request(text):
    """Accept the settings object, or raw TOML from the advanced editor."""
    if not text.strip():
        raise Error('The submitted configuration is empty.')
    if '\0' in text:
        raise Error('The submitted configuration contains a null byte.')
    stripped = text.lstrip()
    if stripped.startswith('{') or stripped.startswith('['):
        try:
            parsed = json.loads(text)
        except ValueError as failure:
            if stripped.startswith('{'):
                raise Error('The submitted configuration is not valid JSON' + position(failure) + '.') from None
            parsed = None
        if isinstance(parsed, dict):
            return jsonable(parsed)
        if parsed is not None:
            raise Error('The submitted configuration must be a table of keys.')
    try:
        return jsonable(tomllib.loads(text))
    except tomllib.TOMLDecodeError as failure:
        raise Error('The submitted configuration is not valid TOML' + position(failure) + '.') from None


def request_text(argument):
    """Read a credential-bearing request the controller left in a private file."""
    if not argument:
        raise Error('This action needs the path of the request file.')
    path = Path(argument)
    if path.parent != REQUEST_ROOT or not path.name.startswith(REQUEST_PREFIX):
        raise Error('The request file must live in ' + str(REQUEST_ROOT) + ' and start with "' + REQUEST_PREFIX + '".')
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        raise Error('The request file is missing or unreadable.') from None
    with os.fdopen(fd, 'rb') as stream:
        metadata = os.fstat(stream.fileno())
        try:
            owners = {0, pwd.getpwnam('www').pw_uid}
        except KeyError:
            owners = {0}
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o777 != 0o600 or metadata.st_uid not in owners:
            raise Error('The request file must be a private regular file owned by root or www.')
        content = stream.read(MAX_DOCUMENT + 1)
    if len(content) > MAX_DOCUMENT:
        raise Error('The request is larger than the 1 MiB this plugin handles.')
    try:
        return content.decode('utf-8')
    except UnicodeDecodeError:
        raise Error('The request is not UTF-8 text.') from None


# --- the fields with no safe default -----------------------------------------

def unset_placeholders(value, found=None, path=()):
    """Every path still holding the sample's placeholder instead of a value."""
    found = [] if found is None else found
    if isinstance(value, dict):
        for name, item in value.items():
            unset_placeholders(item, found, path + (name,))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            unset_placeholders(item, found, path + (item_key(item, index),))
    elif isinstance(value, str) and value.strip() == PLACEHOLDER:
        found.append(dotted(path))
    return found


def guards(side, data):
    """Settings that are dangerous or inert when left as the sample ships them."""
    # A placeholder is what the sample writes where there is no safe default, and
    # both rc scripts refuse to start while one is in place. Catching it here is
    # what keeps a start from enabling the service at boot and then failing.
    issues = [{'field': path, 'message':
               'The placeholder "' + PLACEHOLDER + '" is still in place at ' + path + '. '
               + SIDES[side]['label'] + ' refuses to start until it is replaced with a real value.'}
              for path in unset_placeholders(data)]
    if side != 'frps':
        return issues
    auth = table(data, 'auth')
    method = text_of(auth.get('method')).lower() or 'token'
    if method == 'oidc':
        oidc = table(auth, 'oidc')
        if not text_of(oidc.get('issuer')) or not text_of(oidc.get('audience')):
            issues.append({'field': 'auth.oidc', 'message':
                           'auth.method is "oidc" but auth.oidc.issuer or auth.oidc.audience is empty, so no client '
                           'token would ever be checked against an identity provider.'})
    else:
        source = auth.get('tokenSource')
        if not text_of(auth.get('token')) and not (isinstance(source, dict) and source):
            issues.append({'field': 'auth.token', 'message':
                           'auth.token is empty. frps compares the client token against that empty string, so any '
                           'client that sends an empty token authenticates. Set a token, or point auth.tokenSource '
                           'at a file that holds one.'})
    web = table(data, 'webServer')
    if port_of(web.get('port')):
        if not text_of(web.get('user')) or not text_of(web.get('password')):
            issues.append({'field': 'webServer.password', 'message':
                           'webServer.port is set while webServer.user or webServer.password is empty. frps skips '
                           'the dashboard authentication middleware when both are empty, which leaves the admin API '
                           'open to anyone who reaches that port, including the call that deletes proxies.'})
    allowed = data.get('allowPorts')
    if not isinstance(allowed, list) or not allowed:
        issues.append({'field': 'allowPorts', 'message':
                       'allowPorts is not set, so a connected client may bind any remote port on this firewall. '
                       'List the ranges you accept, for example allowPorts = [{ start = 20000, end = 25000 }].'})
    return issues


# --- validation --------------------------------------------------------------

def verify_file(side, path, secrets=()):
    """Ask the daemon itself whether a candidate file is acceptable."""
    binary = SIDES[side]['binary']
    if not Path(binary).exists():
        return {'valid': None, 'method': 'none', 'message': 'The ' + side + ' binary is not installed.'}
    try:
        # frp v0.71.0 ships "frps verify" and "frpc verify"; --strict_config is a
        # persistent flag and defaults to true, which is what the daemon runs with.
        result = run([binary, 'verify', '-c', str(path), '--strict_config=true'], 20)
    except subprocess.SubprocessError:
        return {'valid': None, 'method': 'verify', 'message': 'The ' + side + ' verifier did not answer in time.'}
    output = scrub((result.stdout + result.stderr).strip(), secrets)
    if result.returncode != 0 and re.search(r'unknown command|unknown flag|unknown shorthand', output, re.I):
        return dry_run(side, path, secrets)
    if result.returncode == 0:
        return {'valid': True, 'method': 'verify', 'message': output or 'The configuration syntax is ok.'}
    return {'valid': False, 'method': 'verify', 'message': output or 'The configuration was rejected.'}


def dry_run(side, path, secrets=()):
    """Fallback for a build without the verify subcommand: run it briefly.

    This binds the ports the candidate asks for, so it can fail against a
    running daemon; it is only reached when verify is genuinely absent.
    """
    binary = SIDES[side]['binary']
    try:
        child = subprocess.Popen([binary, '-c', str(path), '--strict_config=true'],
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    except OSError:
        return {'valid': None, 'method': 'dry-run', 'message': 'The ' + side + ' binary could not be started.'}
    try:
        output = child.communicate(timeout=3)[0] or ''
        code = child.returncode
    except subprocess.TimeoutExpired:
        child.kill()
        output = child.communicate()[0] or ''
        # Still alive after three seconds means it accepted the document.
        return {'valid': True, 'method': 'dry-run', 'message': 'The daemon accepted the configuration and was stopped again.'}
    message = scrub(output.strip(), secrets) or 'The daemon exited with status ' + str(code) + '.'
    return {'valid': code == 0, 'method': 'dry-run', 'message': message}


# --- service state -----------------------------------------------------------

def running_pid(side):
    pidfile = SIDES[side]['pidfile']
    try:
        value = int(pidfile.read_text(encoding='utf-8', errors='replace').split()[0])
    except (OSError, ValueError, IndexError):
        return 0
    if value <= 0:
        return 0
    try:
        os.kill(value, 0)
    except ProcessLookupError:
        return 0
    except PermissionError:
        return value
    except OSError:
        return 0
    return value


def is_running(side):
    if running_pid(side):
        return True
    try:
        return run([SERVICE, side, 'onestatus'], 10).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def wait_for(side, expected, timeout=10.0):
    deadline = time.monotonic() + timeout
    while True:
        if is_running(side) == expected:
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.25)


def is_enabled(side):
    config = SIDES[side]
    try:
        result = run([SYSRC, '-f', str(config['rcconf']), '-n', config['rcvar']], 10)
        if result.returncode == 0:
            return result.stdout.strip().upper() in {'YES', 'TRUE', 'ON', '1'}
    except (OSError, subprocess.SubprocessError):
        pass
    try:
        content = config['rcconf'].read_text(encoding='utf-8', errors='replace')
    except OSError:
        return False
    found = re.search(r'^\s*' + config['rcvar'] + r'\s*=\s*"?([A-Za-z0-9]+)"?', content, re.M)
    return bool(found) and found.group(1).upper() in {'YES', 'TRUE', 'ON', '1'}


def set_enabled(side, enabled):
    config = SIDES[side]
    config['rcconf'].parent.mkdir(parents=True, exist_ok=True)
    result = run([SYSRC, '-f', str(config['rcconf']), config['rcvar'] + '=' + ('YES' if enabled else 'NO')], 20)
    if result.returncode != 0:
        raise Error('Unable to record the ' + side + ' startup setting in ' + str(config['rcconf']) + '.')


def recent_log(side, data, lines=20):
    text = tail(log_path(side, data), lines)
    return scrub(text, collect(data).values()).strip()


# --- log ---------------------------------------------------------------------

def log_path(side, data):
    target = text_of(table(data, 'log').get('to'))
    if target and target not in {'console', '-'} and target.startswith('/'):
        return Path(target)
    return SIDES[side]['log']


def tail(path, lines):
    """Read backwards so a polled endpoint never loads an unbounded log."""
    content = b''
    try:
        with path.open('rb') as stream:
            offset = stream.seek(0, os.SEEK_END)
            while offset > 0 and content.count(b'\n') <= lines and len(content) < MAX_DOCUMENT:
                size = min(8192, offset)
                offset -= size
                stream.seek(offset)
                content = stream.read(size) + content
    except OSError:
        return ''
    return '\n'.join(content.decode('utf-8', errors='replace').splitlines()[-lines:])


# --- reporting ---------------------------------------------------------------

def version_of(side):
    binary = SIDES[side]['binary']
    if not Path(binary).exists():
        return ''
    try:
        result = run([binary, '-v'], 10)
    except (OSError, subprocess.SubprocessError):
        return ''
    return result.stdout.strip().splitlines()[0] if result.stdout.strip() else ''


def endpoint_of(item, server):
    kind = text_of(item.get('type')).lower()
    if kind in {'tcp', 'udp'}:
        port = port_of(item.get('remotePort'))
        return (server + ':' + str(port)) if server and port else (str(port) if port else '')
    if kind in {'http', 'https', 'tcpmux'}:
        domains = [text_of(name) for name in item.get('customDomains') or [] if text_of(name)]
        subdomain = text_of(item.get('subdomain'))
        if subdomain:
            domains.append(subdomain + '.<subDomainHost>')
        return ', '.join(domains)
    if kind in {'stcp', 'sudp', 'xtcp'}:
        return 'reachable through a visitor only'
    return ''


def local_of(item):
    plugin = table(item, 'plugin')
    if plugin:
        return 'plugin ' + (text_of(plugin.get('type')) or 'unknown')
    address = text_of(item.get('localIP')) or '127.0.0.1'
    port = port_of(item.get('localPort'))
    return address + ':' + str(port) if port else address


def proxy_rows(data):
    rows = []
    server = text_of(data.get('serverAddr'))
    for index, item in enumerate(data.get('proxies') or []):
        if not isinstance(item, dict):
            continue
        rows.append({
            'name': text_of(item.get('name')) or 'proxy ' + str(index + 1),
            'type': text_of(item.get('type')).lower(),
            'enabled': item.get('enabled') is not False,
            'local': local_of(item),
            'endpoint': endpoint_of(item, server),
        })
    return rows


def visitor_rows(data):
    rows = []
    for index, item in enumerate(data.get('visitors') or []):
        if not isinstance(item, dict):
            continue
        port = port_of(item.get('bindPort'))
        rows.append({
            'name': text_of(item.get('name')) or 'visitor ' + str(index + 1),
            'type': text_of(item.get('type')).lower(),
            'enabled': item.get('enabled') is not False,
            'server_name': text_of(item.get('serverName')),
            'bind': (text_of(item.get('bindAddr')) or '127.0.0.1') + ':' + str(port) if port else '',
        })
    return rows


def status(side):
    config = SIDES[side]
    data = read_document(config['config'])
    exists = config['config'].exists()
    checked = verify_file(side, config['config'], collect(data).values()) if exists else {
        'valid': False, 'method': 'none', 'message': 'The configuration file has not been written yet.'}
    issues = guards(side, data)
    report = {
        'side': side,
        'label': config['label'],
        'running': is_running(side),
        'enabled': is_enabled(side),
        'pid': str(running_pid(side) or ''),
        'version': version_of(side),
        'installed': Path(config['binary']).exists(),
        'config_path': str(config['config']),
        'config_exists': exists,
        'config_valid': checked['valid'],
        'config_message': checked['message'],
        'log_path': str(log_path(side, data)),
        'guards': issues,
        'can_start': exists and checked['valid'] is not False and not issues,
    }
    if side == 'frps':
        report['bind'] = (text_of(data.get('bindAddr')) or '0.0.0.0') + ':' + str(port_of(data.get('bindPort')) or 7000)
        report['vhost_http'] = port_of(data.get('vhostHTTPPort'))
        report['vhost_https'] = port_of(data.get('vhostHTTPSPort'))
        report['dashboard'] = port_of(table(data, 'webServer').get('port'))
        report['allow_ports'] = describe_ports(data.get('allowPorts'))
    else:
        server = text_of(data.get('serverAddr'))
        report['server'] = (server + ':' + str(port_of(data.get('serverPort')) or 7000)) if server else ''
        report['admin'] = port_of(table(data, 'webServer').get('port'))
        report['proxies'] = proxy_rows(data)
        report['visitors'] = visitor_rows(data)
    return report


def describe_ports(allowed):
    if not isinstance(allowed, list):
        return ''
    parts = []
    for item in allowed:
        if not isinstance(item, dict):
            continue
        single, start, end = port_of(item.get('single')), port_of(item.get('start')), port_of(item.get('end'))
        if single:
            parts.append(str(single))
        elif start and end:
            parts.append(str(start) + '-' + str(end))
        elif start:
            parts.append(str(start) + '-')
    return ', '.join(parts)


# --- mutations ---------------------------------------------------------------

def prepare(side, argument):
    """Turn a request into the TOML text that would replace the live file."""
    config = SIDES[side]
    candidate = parse_request(request_text(argument))
    stored = collect(read_document(config['config']))
    merged = restore(candidate, stored)
    output = document(merged)
    if len(output.encode('utf-8')) > MAX_DOCUMENT:
        raise Error('The configuration is larger than the 1 MiB this plugin handles.')
    # Re-read what the emitter produced: a document this plugin cannot parse
    # back is never handed to the daemon.
    try:
        tomllib.loads(output)
    except tomllib.TOMLDecodeError:
        raise Error('The configuration could not be written back as valid TOML.') from None
    return merged, output


def name_candidate(checked, temporary, side):
    """The daemon echoes the file it read; show the live path instead."""
    checked['message'] = checked['message'].replace(str(temporary), str(SIDES[side]['config']))
    return checked


def candidate_file(side, output):
    CONFIG_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.' + side + '.', suffix='.toml', dir=CONFIG_DIR)
    with os.fdopen(fd, 'w', encoding='utf-8') as stream:
        stream.write(output)
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(temporary, 0o600)
    return temporary


def set_settings(side, argument):
    merged, output = prepare(side, argument)
    secrets = collect(merged).values()
    temporary = candidate_file(side, output)
    try:
        checked = name_candidate(verify_file(side, Path(temporary), secrets), temporary, side)
        if checked['valid'] is False:
            raise Error(SIDES[side]['label'] + ' rejected the configuration, so the live file was left alone: '
                        + checked['message'])
        os.replace(temporary, SIDES[side]['config'])
        temporary = None
    finally:
        if temporary is not None and os.path.exists(temporary):
            os.unlink(temporary)
    issues = guards(side, merged)
    return {'saved': True, 'valid': checked['valid'], 'method': checked['method'],
            'message': checked['message'], 'guards': issues,
            'restart_required': is_running(side)}


def verify_settings(side, argument):
    merged, output = prepare(side, argument)
    secrets = collect(merged).values()
    temporary = candidate_file(side, output)
    try:
        checked = name_candidate(verify_file(side, Path(temporary), secrets), temporary, side)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return {'saved': False, 'valid': checked['valid'], 'method': checked['method'],
            'message': checked['message'], 'guards': guards(side, merged)}


def settings(side):
    config = SIDES[side]
    data = read_document(config['config'])
    stored = collect(data)
    public = mask(data)
    return {'side': side, 'config': public, 'toml': document(public),
            'config_path': str(config['config']), 'config_exists': config['config'].exists(),
            'credentials': sorted(dotted(path) for path in stored),
            'guards': guards(side, data)}


def start(side):
    config = SIDES[side]
    if not Path(config['binary']).exists():
        raise Error('The ' + side + ' binary is not installed at ' + config['binary'] + '.')
    data = read_document(config['config'])
    if not config['config'].exists():
        raise Error('The configuration file ' + str(config['config']) + ' does not exist yet.')
    issues = guards(side, data)
    if issues:
        raise Error(SIDES[side]['label'] + ' was not started. ' + ' '.join(item['message'] for item in issues))
    checked = verify_file(side, config['config'], collect(data).values())
    if checked['valid'] is False:
        raise Error(SIDES[side]['label'] + ' was not started because its configuration is invalid: ' + checked['message'])
    set_enabled(side, True)
    started = run([SERVICE, side, 'onestart'], 60)
    if not wait_for(side, True):
        # The rc script refuses to start on its own account -- placeholders
        # still in the file, a missing binary -- and says why on the way out.
        # Reporting only that nothing is running would throw that away and
        # leave the operator with a page that cannot explain itself.
        reason = scrub((started.stdout + started.stderr).strip(), collect(data).values())
        raise Error(SIDES[side]['label'] + ' did not start. '
                    + (reason or recent_log(side, data) or 'Nothing was written to its log.'))
    return {'running': True, 'enabled': True, 'pid': str(running_pid(side) or '')}


def stop(side):
    set_enabled(side, False)
    run([SERVICE, side, 'onestop'], 60)
    if not wait_for(side, False):
        raise Error(SIDES[side]['label'] + ' is still running after the stop request.')
    return {'running': False, 'enabled': False, 'pid': ''}


def restart(side):
    if is_running(side):
        run([SERVICE, side, 'onestop'], 60)
        wait_for(side, False)
    return start(side)


def log(side, argument=None):
    data = read_document(SIDES[side]['config'])
    lines = LOG_LINES
    if argument:
        try:
            lines = max(1, min(1000, int(argument)))
        except ValueError:
            lines = LOG_LINES
    path = log_path(side, data)
    return {'side': side, 'path': str(path), 'lines': lines,
            'log': scrub(tail(path, lines), collect(data).values())}


# --- entry point -------------------------------------------------------------

READ_ONLY = {'status', 'settings', 'log'}


def dispatch(side, action, argument):
    if action == 'status':
        return status(side)
    if action == 'settings':
        return settings(side)
    if action == 'log':
        return log(side, argument)
    if action == 'set-settings':
        return set_settings(side, argument)
    if action == 'verify':
        return verify_settings(side, argument)
    if action == 'start':
        return start(side)
    if action == 'stop':
        return stop(side)
    if action == 'restart':
        return restart(side)
    raise Error('Unknown action.')


def locked(side):
    """Serialise the actions that change the live file or the service."""
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    lock = (STATE / (side + '.lock')).open('a')
    fcntl.flock(lock, fcntl.LOCK_EX)
    return lock


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--json', action='store_true', help='Return structured action results for configd.')
    parser.add_argument('side', choices=sorted(SIDES))
    parser.add_argument('action', choices=sorted(READ_ONLY | {'start', 'stop', 'restart', 'set-settings', 'verify'}))
    parser.add_argument('argument', nargs='?')
    arguments = parser.parse_args()
    try:
        if arguments.action in READ_ONLY:
            result = dispatch(arguments.side, arguments.action, arguments.argument)
        else:
            if os.geteuid() != 0:
                raise Error('Changing ' + arguments.side + ' state requires root privileges.')
            lock = locked(arguments.side)
            try:
                result = dispatch(arguments.side, arguments.action, arguments.argument)
            finally:
                lock.close()
        if arguments.json:
            print(json.dumps({'ok': True, 'result': result}, ensure_ascii=False))
        else:
            print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except (Error, OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as failure:
        message = str(failure) if isinstance(failure, Error) else (
            'Unable to read, validate or update the ' + arguments.side + ' configuration.')
        if arguments.json:
            print(json.dumps({'ok': False, 'error': message}, ensure_ascii=False))
            return 0
        print(message, file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
