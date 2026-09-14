#!/usr/local/bin/python3
"""Decide what of the speed test survives a rebuild, and put it back.

An OPNsense backup is /conf/config.xml and nothing else. The page keeps its
state in /var/db/speedtest, so a restored box comes up with none of it: the
three choices an operator actually made -- which interface to leave from, which
server to ask, how many connections to open -- are gone, while everything else
in that directory (the last result, a run's progress, the cached server lists,
the run lock) is a measurement the plugin makes again on first use and would be
wrong to carry anyway. Only the three are mirrored.

The file stays the source of truth that api.php reads and writes; config.xml is
a one-directional copy that the native backup then carries for free. The two
functions below are the whole policy, which is why they are here and not in
config_mirror.php: they read and write nothing but this plugin's own files and
can therefore be tested without a router.
"""
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile

# Rooted for the suite; empty on a router, where these are absolute paths.
STATE = '/var/db/speedtest'
SETTINGS = STATE + '/settings.json'
SHIM = '/usr/local/opnsense/scripts/speedtest/config_mirror.php'
MARKER = '/conf/os-config-backup/Speedtest/applied.sha256'
PHP = '/usr/local/bin/php'
# The shim loads the OPNsense model stack, so it is slow rather than quick to
# fail; long enough for that, short enough that a settings save never hangs.
TIMEOUT = 20

FIELDS = ('interface', 'server_id', 'threads')
# The same defaults api.php answers with when the file is absent. A restore has
# to produce the settings the page would have shown, not an empty form.
DEFAULTS = {'interface': 'auto', 'server_id': '', 'threads': '4'}
# What api.php would accept from the page, applied in both directions: nothing
# this plugin would refuse is written to the configuration, and nothing the
# configuration carries is written to disk unless the page could have set it.
INTERFACE = re.compile(r'^[A-Za-z0-9_.:-]{1,32}$')
SERVER_ID = re.compile(r'^[0-9]{0,12}$')
THREADS = (1, 16)


class MirrorError(Exception):
    """The configuration could not be reached. Never the caller's problem."""


def root():
    return os.environ.get('OS_SPEEDTEST_ROOT', '')


def state_dir():
    return root() + STATE


def settings_file():
    return root() + SETTINGS


def shim():
    return root() + SHIM


def field_value(name, raw):
    """The value as this version would store it, or None if it would not."""
    if isinstance(raw, bool) or raw is None or isinstance(raw, (dict, list)):
        return None
    if name == 'threads':
        try:
            number = int(str(raw).strip())
        except (TypeError, ValueError):
            return None
        return str(number) if THREADS[0] <= number <= THREADS[1] else None
    text = str(raw).strip()
    if name == 'interface':
        return text if INTERFACE.match(text) else None
    return text if SERVER_ID.match(text) else None


def read_settings():
    """What the page last wrote, or nothing at all if it never did."""
    try:
        with open(settings_file()) as handle:
            stored = json.load(handle)
    except (OSError, ValueError):
        return {}
    return {str(name): value for name, value in stored.items()} if isinstance(stored, dict) else {}


def write_settings(settings):
    """Replace the file the way api.php does, so the page never reads a half."""
    directory = state_dir()
    os.makedirs(directory, mode=0o700, exist_ok=True)
    os.chmod(directory, 0o700)
    handle, temporary = tempfile.mkstemp(dir=directory, prefix='.settings.')
    try:
        with os.fdopen(handle, 'w') as out:
            json.dump(settings, out, separators=(',', ':'))
        os.chmod(temporary, 0o600)
        os.replace(temporary, settings_file())
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def mirror_payload():
    """The three settings, as the configuration should carry them.

    A value the page could not have produced is replaced by the default rather
    than copied: the configuration is what a rebuilt box will be given back, so
    it may only ever hold something this plugin would accept.
    """
    stored = read_settings()
    payload = {}
    for name in FIELDS:
        value = field_value(name, stored.get(name))
        payload[name] = DEFAULTS[name] if value is None else value
    return payload


def adopt_payload(payload):
    """Write the on-disk settings a restored configuration asked for.

    Only names this version knows and values it would accept are taken, so a
    section that is absent, half written, newer than this plugin or simply
    wrong leaves the rest of the file as it was. Nothing is written when
    nothing moved, which is what makes running this on every boot harmless.
    """
    if not isinstance(payload, dict):
        payload = {}
    stored = read_settings()
    wanted = dict(stored)
    for name in FIELDS:
        value = field_value(name, payload.get(name))
        if value is not None:
            wanted[name] = value
    if wanted == stored:
        return False
    write_settings(wanted)
    return True


def run_shim(verb, payload=None):
    """Hand the configuration half to the one language that can do it."""
    try:
        done = subprocess.run([PHP, shim(), verb],
                              input='' if payload is None else json.dumps(payload),
                              capture_output=True, text=True, timeout=TIMEOUT)
    except (OSError, subprocess.SubprocessError) as error:
        raise MirrorError('%s %s: %s' % (PHP, verb, error))
    if done.returncode != 0:
        raise MirrorError('%s exited %d: %s' % (verb, done.returncode,
                                                (done.stdout + done.stderr).strip()))
    try:
        answer = json.loads(done.stdout or '{}')
    except ValueError:
        raise MirrorError('%s answered with something other than JSON' % verb)
    if not isinstance(answer, dict):
        raise MirrorError('%s answered with something other than an object' % verb)
    return answer


def mirror():
    """Copy the settings on disk into the configuration."""
    stored = run_shim('import')
    marker = applied_backup()
    if any(name in stored for name in FIELDS) and marker and marker != revision_token(stored):
        raise MirrorError('A restored Speedtest configuration is pending; import it before saving settings.')
    payload = mirror_payload()
    payload['_expected'] = revision_token(stored)
    result = run_shim('export', payload)
    confirmed = run_shim('import')
    expected = dict(stored, **{name: payload[name] for name in FIELDS})
    if confirmed != expected:
        raise MirrorError('The Speedtest backup changed before its update could be confirmed.')
    mark_backup(confirmed)
    return result


def revision_token(fields):
    return hashlib.sha256(json.dumps(fields, ensure_ascii=True, sort_keys=True,
                                    separators=(',', ':')).encode()).hexdigest()


def applied_backup():
    try:
        with open(root() + MARKER, encoding='ascii') as handle:
            value = handle.read(65).strip()
        return value if re.fullmatch(r'[a-f0-9]{64}', value) else None
    except (OSError, UnicodeError):
        return None


def mark_backup(fields):
    path = root() + MARKER
    directory = os.path.dirname(path)
    os.makedirs(directory, mode=0o700, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.backup-applied.', dir=directory)
    try:
        with os.fdopen(fd, 'w', encoding='ascii') as handle:
            handle.write(revision_token(fields) + '\n')
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def import_config():
    """Take the settings a restored configuration carries back to disk."""
    payload = run_shim('import')
    if not any(payload.get(name, '') != '' for name in FIELDS):
        return False
    if not any(field_value(name, payload.get(name)) is not None for name in FIELDS):
        return False
    # Failed mirror writes leave the last XML revision marked as applied. A
    # routine boot must keep the newer file; an erased settings store still
    # needs to be reconstructed after a rebuild or a /var reset.
    if applied_backup() == revision_token(payload) and os.path.isfile(settings_file()):
        return False
    changed = adopt_payload(payload)
    if run_shim('import') != payload:
        raise MirrorError('The Speedtest backup changed during restoration; retry the import.')
    mark_backup(payload)
    return changed


def main(argv):
    verb = argv[0] if argv else ''
    try:
        if verb == 'mirror':
            print(json.dumps(mirror()))
        elif verb == 'import-config':
            print(json.dumps({'changed': import_config()}))
        else:
            sys.stderr.write('usage: config_mirror.py mirror|import-config\n')
            return 2
    except (MirrorError, OSError) as error:
        # The settings are on disk either way, so this is reported and not
        # raised; both callers treat the exit status as a warning.
        sys.stderr.write('%s\n' % error)
        print(json.dumps({'changed': False, 'error': str(error)}))
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
