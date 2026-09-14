#!/usr/local/bin/python3
"""Carry Sing-box configuration files and explicit dependencies in config.xml."""
import json
from pathlib import Path
import posixpath
import sys

try:
    from config_backup import ConfigBackup, rc_value, run
except ImportError:
    for parent in Path(__file__).resolve().parents:
        if (parent / 'common/config_backup.py').is_file():
            sys.path.insert(0, str(parent / 'common'))
            break
    from config_backup import ConfigBackup, rc_value, run


STATE = '/usr/local/etc/sing-box'
RC = '/etc/rc.conf.d/sing_box'
CONFIG = STATE + '/config.json'
GLOBAL_STORES = ('/etc/ssl', '/usr/share/certs', '/usr/local/share/certs',
                 '/usr/local/share/certificates', '/var/etc/ssl')
TLS_FILES = ('certificate_path', 'key_path', 'client_certificate_path', 'client_key_path',
             'certificate_authority_path', 'mca_certificate_path', 'mca_key_path')


def configured_path(files):
    """Read a literal RC override without executing shell configuration."""
    return rc_value(files.get(RC, b''), 'config', CONFIG)


def references(files):
    """Derive permitted external paths from saved configuration bytes only.

    Inline keys, URLs, logs, caches and built-in system trust stores are not
    dependencies to restore. Unsupported relative paths make the mirror fail
    visibly instead of producing a backup that silently loses required files.
    """
    found = {}

    def add(value, kind='file'):
        for path in value if isinstance(value, list) else [value]:
            if path in (None, ''):
                continue
            if not isinstance(path, str) or not path.startswith('/') or '\x00' in path:
                raise ValueError('The configuration contains an unsupported file reference.')
            normalized = posixpath.normpath(path)
            if normalized != path or '..' in path.split('/'):
                raise ValueError('The configuration contains an unsupported file reference.')
            if path == '/etc/hosts' or any(path == base or path.startswith(base + '/') for base in GLOBAL_STORES):
                continue
            found[(path, kind)] = {'path': path, 'kind': kind}

    def tls(value):
        if not isinstance(value, dict):
            return
        for name in TLS_FILES:
            add(value.get(name))
        ech = value.get('ech', {})
        if isinstance(ech, dict):
            add(ech.get('key_path'))
            add(ech.get('config_path'))
        acme = value.get('acme', {})
        if isinstance(acme, dict):
            add(acme.get('data_directory'), 'tree')

    def walk(value):
        if isinstance(value, dict):
            tls(value.get('tls'))
            if value.get('type') == 'ssh':
                add(value.get('private_key_path'))
            if value.get('type') == 'acme':
                add(value.get('data_directory'), 'tree')
            if value.get('type') == 'openconnect':
                token = value.get('token', {})
                if isinstance(token, dict):
                    add(token.get('secret_path'))
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    effective = configured_path(files)
    add(effective)
    for path in sorted({CONFIG, effective, STATE + '/sub/template.json'}):
        if path not in files:
            continue
        value = json.loads(files[path])
        if not isinstance(value, dict):
            raise ValueError('The configuration document is not a JSON object.')
        walk(value)
        certificate = value.get('certificate', {})
        if isinstance(certificate, dict):
            add(certificate.get('certificate_path'))
            add(certificate.get('certificate_directory_path'), 'tree')
        route = value.get('route', {})
        if isinstance(route, dict):
            for rule in route.get('rule_set', []):
                if isinstance(rule, dict):
                    name = 'path' if rule.get('type') == 'local' else 'initial_path'
                    reference = rule.get(name)
                    tags = rule.get('tag', [])
                    if isinstance(reference, str) and '{tag}' in reference:
                        tags = tags if isinstance(tags, list) else [tags]
                        if not tags or any(not isinstance(tag, str) for tag in tags):
                            raise ValueError('The configuration contains an unsupported rule reference.')
                        for tag in tags:
                            add(reference.replace('{tag}', tag))
                    elif rule.get('type') in ('local', 'remote'):
                        add(reference)
            for name in ('geoip', 'geosite'):
                if isinstance(route.get(name), dict):
                    add(route[name].get('path'))
        dns = value.get('dns', {})
        if isinstance(dns, dict):
            for server in dns.get('servers', []):
                if isinstance(server, dict) and server.get('type') == 'hosts':
                    add(server.get('path'))
    return [found[key] for key in sorted(found)]


PROFILE = {
    'module': 'SingBox',
    'root_env': 'OS_SINGBOX_BACKUP_ROOT',
    'script_dir': Path(__file__).resolve().parent,
    'trees': [STATE],
    'files': [RC],
    'rc_paths': [{'file': RC, 'variable': 'config', 'kind': 'file', 'default': CONFIG}],
    'excludes': ['.mvc-*', '*.log', '*.pid', '*.lock', '*.sample', 'sub.sh', 'cache.db', 'cache.db-*'],
    'references': references,
    'data_lock': '/var/run/sing-box-config.lock',
}


if __name__ == '__main__':
    sys.exit(run(PROFILE))
