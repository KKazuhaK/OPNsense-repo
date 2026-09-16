#!/usr/local/bin/python3
"""Run Sing-box with explicit, recoverable LAN capture and native router egress."""
import argparse
import contextlib
import copy
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time

from routing import Routing, RoutingError
from process_identity import birth_frame_shift, boot_token, process, rebase_birth

STATE = Path('/var/db/os-sing-box')
POLICY = Path('/usr/local/etc/sing-box/integration.json')
CONFIG = Path('/usr/local/etc/sing-box/config.json')
CORE = '/usr/local/bin/sing-box'
SETFIB = '/usr/sbin/setfib'
PIDFILE = Path('/var/run/sing-box.pid')
TUN = 'tun_singbox'
DEFAULTS = {'schema': 1, 'transparent': False, 'transparent_consent': False,
            'device_mode': 'off', 'device_list': [], 'ipv6': False}
LIMIT = 16 * 1024 * 1024
ROUTING_DIAGNOSTIC_LIMIT = 512
ROUTING_DIAGNOSTIC_FILE_LIMIT = 4096


class IntegrationError(Exception):
    pass


def bounded_routing_diagnostic(value):
    """Return one bounded line from a routing exception or helper message."""
    text = ' '.join(''.join(character if character.isprintable() else ' '
                            for character in str(value)).split())
    return text.encode('utf-8', errors='replace')[:ROUTING_DIAGNOSTIC_LIMIT].decode('utf-8', errors='ignore')


def private_json(path, default=None):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return copy.deepcopy(default)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                or before.st_size > LIMIT or before.st_mode & 0o077):
            raise IntegrationError('An integration file is not private.')
        raw = stream.read(LIMIT + 1)
        after = os.fstat(stream.fileno())
    fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    if (len(raw) > LIMIT
            or any(getattr(before, field) != getattr(after, field) for field in fields)):
        raise IntegrationError('An integration file changed while it was read.')
    return json.loads(raw)


def write_json(path, value):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.parent.is_symlink() or path.is_symlink():
        raise IntegrationError('An integration directory is invalid.')
    parent = os.lstat(path.parent)
    if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.geteuid()
            or parent.st_mode & 0o022):
        raise IntegrationError('An integration directory is invalid.')
    fd, name = tempfile.mkstemp(prefix='.singbox-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            os.fchmod(stream.fileno(), 0o600)
            json.dump(value, stream, sort_keys=True, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(name)


def service_pidfile(path):
    """Read one owned numeric PID file without following or blocking on names."""
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        raise
    except OSError as error:
        raise IntegrationError('The service pidfile is unavailable and was preserved.') from error
    with os.fdopen(descriptor, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_mode & 0o022 or info.st_size > 64):
            raise IntegrationError('The service pidfile has invalid ownership or size.')
        raw = stream.read(65)
    try:
        text = raw.decode('ascii')
    except UnicodeError:
        raise IntegrationError('The service pidfile is invalid.') from None
    if (len(raw) > 64 or not re.fullmatch(r'[1-9][0-9]{0,9}\n?', text)
            or not 1 < int(text) < 2147483648):
        raise IntegrationError('The service pidfile is invalid.')
    return int(text), (raw, info.st_dev, info.st_ino)


def fsync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def append_log(path):
    """Open one root-owned regular log without following a blocking object."""
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT
                             | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    except OSError as error:
        raise IntegrationError('The private service log could not be opened.') from error
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_mode & 0o022):
            raise IntegrationError('The private service log has invalid ownership.')
        os.set_blocking(descriptor, True)
        return os.fdopen(descriptor, 'ab', buffering=0)
    except Exception:
        os.close(descriptor)
        raise


def policy(value):
    if not isinstance(value, dict) or value.get('schema', 1) != 1:
        raise IntegrationError('The integration settings are invalid.')
    result = dict(DEFAULTS, **value)
    for name in ('transparent', 'transparent_consent', 'ipv6'):
        if not isinstance(result[name], bool):
            raise IntegrationError('The integration settings are invalid.')
    if result['transparent'] and not result['transparent_consent']:
        raise IntegrationError('Confirm LAN capture before enabling transparent routing.')
    if result['device_mode'] not in ('off', 'blacklist', 'whitelist') or not isinstance(result['device_list'], list) or len(result['device_list']) > 128:
        raise IntegrationError('The device policy is invalid.')
    try:
        result['device_list'] = [str(ipaddress.ip_network(item, strict=False)) for item in result['device_list']]
    except (TypeError, ValueError):
        raise IntegrationError('The device policy contains an invalid IP or CIDR.') from None
    return result


def tun_addresses(tun):
    addresses = tun.get('address', tun.get('inet4_address', []))
    if isinstance(addresses, str):
        addresses = [addresses]
    if not isinstance(addresses, list):
        raise IntegrationError('The TUN address is invalid.')
    if 'address' not in tun:
        legacy6 = tun.get('inet6_address', [])
        if isinstance(legacy6, str):
            legacy6 = [legacy6]
        if not isinstance(legacy6, list):
            raise IntegrationError('The TUN address is invalid.')
        addresses = addresses + legacy6
    if any(not isinstance(address, str) for address in addresses):
        raise IntegrationError('The TUN address is invalid.')
    return addresses


def render(configuration, settings):
    """Override capture mechanics in a private copy; never rewrite user JSON."""
    if not isinstance(configuration, dict) or not isinstance(configuration.get('inbounds', []), list):
        raise IntegrationError('A JSON configuration object with valid inbounds is required.')
    settings = policy(settings)
    data = copy.deepcopy(configuration)
    tuns = [item for item in data.get('inbounds', []) if isinstance(item, dict) and item.get('type') == 'tun']
    if not settings['transparent']:
        data['inbounds'] = [item for item in data.get('inbounds', []) if item not in tuns]
        # Rules referring to a removed inbound are harmless and stay intact.
        return data
    if len(tuns) != 1:
        raise IntegrationError('Transparent routing requires exactly one saved TUN inbound.')
    dns = data.get('dns', {})
    servers = dns.get('servers', []) if isinstance(dns, dict) else None
    if (not isinstance(dns, dict) or not isinstance(servers, list)
            or any(isinstance(item, dict) and item.get('type') == 'fakeip' for item in servers)
            or isinstance(dns.get('fakeip'), dict) and dns['fakeip'].get('enabled')):
        raise IntegrationError('Transparent device routing requires real-address DNS; disable fake IP.')
    tun = tuns[0]
    if tun.get('stack', 'gvisor') != 'gvisor':
        raise IntegrationError('The packaged FreeBSD core requires the gVisor TUN stack.')
    if tun.get('file_descriptor', 0):
        raise IntegrationError('An externally owned TUN descriptor cannot be captured.')
    tun.update(interface_name=TUN, auto_route=False, strict_route=False, stack='gvisor')
    addresses = tun_addresses(tun)
    try:
        networks = [ipaddress.ip_interface(item).network for item in addresses]
    except (TypeError, ValueError):
        raise IntegrationError('The TUN address is invalid.') from None
    if settings['ipv6'] and not any(net.version == 6 for net in networks):
        raise IntegrationError('IPv6 capture requires an IPv6 TUN address.')
    if not networks or any(not net.is_private or net.prefixlen == 0 for net in networks):
        raise IntegrationError('The TUN requires a specific private address prefix.')
    # In this BSD fork auto_route=false returns before DNS/FIB/tunable setup.
    # Both automatic and explicit route ranges are removed from the runtime
    # inbound: BuildAutoRouteRanges must never install routes in FIB 0.
    for key in ('route_address', 'route_address_set', 'route_exclude_address',
                'route_exclude_address_set', 'inet4_route_address', 'inet6_route_address',
                'inet4_route_exclude_address', 'inet6_route_exclude_address',
                'include_interface', 'exclude_interface', 'include_uid', 'exclude_uid',
                'include_android_user', 'include_package', 'exclude_package', 'auto_redirect'):
        tun.pop(key, None)
    return data


def command(args, check=True):
    result = subprocess.run(args, capture_output=True, timeout=20)
    if check and result.returncode:
        raise IntegrationError('A native integration operation failed. Check the service log.')
    return result


def configuration_changed(args):
    """Run the native XML helper and accept only its exact change result."""
    result = command(args)
    if result.stdout == b'changed\n':
        return True
    if result.stdout == b'unchanged\n':
        return False
    raise IntegrationError('The native configuration helper returned an invalid result.')


def identity(pid):
    if type(pid) is not int or not 1 < pid < 2147483648:
        return None
    try:
        value = process(pid)
    except RuntimeError as error:
        raise IntegrationError('The exact process identity could not be read.') from error
    if value is None:
        return None
    # Health and parentage can change without transferring PID ownership.
    return snapshot_identity(value)


def snapshot_identity(value):
    return {key: value[key] for key in ('pid', 'birth', 'uid', 'executable')} | {'arguments': value['argv']}


def rebase_record_births(record):
    """Move recorded births into the live clock frame after a wall-clock step."""
    token = record.get('boot') if isinstance(record, dict) else None
    if not isinstance(token, str):
        return
    shift = birth_frame_shift(token)
    if shift is None:
        return
    delta, current = shift
    for identity in (record.get('core'), record.get('watcher'), record.get('launcher')):
        if isinstance(identity, dict) and isinstance(identity.get('birth'), str):
            moved = rebase_birth(identity['birth'], delta)
            if moved is not None:
                identity['birth'] = moved
    record['boot'] = current


def core_arguments():
    return [CORE, 'run', '-c', str(STATE / 'runtime.json')]


def watcher_arguments():
    return [sys.executable, str(Path(__file__).resolve()), 'watch']


def launcher_arguments(descriptor=None, value=None):
    """Build or validate the exact pre-exec Core launcher arguments."""
    if value is None:
        return [sys.executable, str(Path(__file__).resolve()), 'launch', str(descriptor)]
    arguments = value.get('arguments') if isinstance(value, dict) else None
    if (not isinstance(arguments, list) or len(arguments) != 4
            or arguments[:3] != [sys.executable, str(Path(__file__).resolve()), 'launch']
            or not re.fullmatch(r'[0-9]{1,9}', str(arguments[3]))):
        return None
    descriptor = int(arguments[3])
    return arguments if 2 < descriptor < 2147483648 else None


def setfib_arguments():
    return [SETFIB, '0', *core_arguments()]


def same_execution(left, right):
    return (isinstance(left, dict) and isinstance(right, dict)
            and all(left.get(key) == right.get(key) for key in ('pid', 'birth', 'uid')))


def core_health(record):
    if not owned(record):
        return {'process_alive': False, 'healthy': False, 'paused': False}
    try:
        value = process(record['core']['pid'])
    except RuntimeError as error:
        raise IntegrationError('The Core health could not be established.') from error
    alive = value is not None and snapshot_identity(value) == record['core']
    return {'process_alive': alive, 'healthy': alive and not value['stopped'],
            'paused': alive and bool(value['stopped'])}


def owned(record, kind='core'):
    value = record.get(kind) if isinstance(record, dict) else None
    if kind == 'core':
        expected = core_arguments()
    elif kind == 'watcher':
        expected = watcher_arguments()
    elif kind == 'launcher':
        expected = launcher_arguments(value=value)
    else:
        return False
    return (isinstance(value, dict) and value.get('uid') == os.geteuid()
            and expected is not None
            and value.get('executable') == os.path.realpath(expected[0])
            and value.get('arguments') == expected and identity(value.get('pid')) == value)


def signal_owned(record, kind, sig):
    if owned(record, kind):
        os.kill(record[kind]['pid'], sig)
        return True
    return False


class Manager:
    def __init__(self, state=STATE, routing=None, pidfile=PIDFILE, configuration=CONFIG,
                 log=Path('/var/log/sing-box.log')):
        self.state = Path(state)
        self.pidfile = Path(pidfile)
        self.configuration = Path(configuration)
        self.runtime = self.state / 'runtime.json'
        self.record_path = self.state / 'service-state.json'
        self.routing_error_path = self.state / 'routing-error.json'
        self.filter_reload_path = self.state / 'filter-reload-pending.json'
        self.filter_reload_lock_path = self.state / 'filter-reload.lock'
        self.log_path = Path(log)
        self.routing = routing or Routing()

    def prepare_state(self):
        self.state.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = os.lstat(self.state)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o700):
            raise IntegrationError('The private integration state directory is invalid.')

    def routing_error(self):
        try:
            descriptor = os.open(self.routing_error_path, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            return ''
        except OSError:
            return 'The private routing diagnostic could not be read.'
        try:
            with os.fdopen(descriptor, 'rb') as stream:
                before = os.fstat(stream.fileno())
                if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                        or stat.S_IMODE(before.st_mode) != 0o600
                        or before.st_size > ROUTING_DIAGNOSTIC_FILE_LIMIT):
                    return 'The private routing diagnostic is invalid.'
                raw = stream.read(ROUTING_DIAGNOSTIC_FILE_LIMIT + 1)
                after = os.fstat(stream.fileno())
            if (len(raw) > ROUTING_DIAGNOSTIC_FILE_LIMIT
                    or any(getattr(before, key) != getattr(after, key) for key in
                           ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))):
                return 'The private routing diagnostic changed while being read.'
            value = json.loads(raw)
            if (not isinstance(value, dict) or value.get('schema') != 1
                    or not isinstance(value.get('error'), str)
                    or not isinstance(value.get('updated'), (int, float))):
                raise ValueError
            return bounded_routing_diagnostic(value['error'])
        except (OSError, ValueError, TypeError, UnicodeError):
            return 'The private routing diagnostic is invalid.'

    def remember_routing_error(self, error, log=False):
        detail = bounded_routing_diagnostic(error) or 'No native routing diagnostic was returned.'
        try:
            write_json(self.routing_error_path, {'schema': 1, 'error': detail, 'updated': time.time()})
        except (IntegrationError, OSError):
            pass
        if log:
            self.log_routing_error(detail)
        return detail

    def clear_routing_error(self):
        try:
            self.routing_error_path.unlink()
            fsync_directory(self.routing_error_path.parent)
        except FileNotFoundError:
            pass
        except OSError:
            pass

    def log_routing_error(self, detail):
        message = ('[%s] Scoped Sing-box routing recovery is pending; retrying. %s\n'
                   % (time.strftime('%Y-%m-%d %H:%M:%S'), bounded_routing_diagnostic(detail)))
        try:
            with append_log(self.log_path) as stream:
                stream.write(message.encode())
        except (IntegrationError, OSError):
            pass

    def read_record(self):
        value = private_json(self.record_path, {})
        if (not isinstance(value, dict) or value.get('schema', 1) != 1
                or any(value.get(key) is not None and not isinstance(value.get(key), dict)
                       for key in ('core', 'watcher', 'launcher'))):
            raise IntegrationError('The service ownership record is invalid.')
        rebase_record_births(value)
        return value

    def capture_launcher(self, pid, arguments):
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            current = identity(pid)
            if current is not None:
                if (current.get('arguments') != arguments
                        or current.get('executable') != os.path.realpath(arguments[0])
                        or current.get('uid') != os.geteuid()):
                    raise IntegrationError('The Core launcher has an unexpected process identity.')
                return current
            time.sleep(0.02)
        raise IntegrationError('The Core launcher identity could not be verified.')

    def capture_core_transition(self, launcher, child):
        """Accept only the launcher's same execution becoming the expected Core."""
        deadline = time.monotonic() + 3
        allowed = (launcher.get('arguments'), setfib_arguments())
        while time.monotonic() < deadline:
            current = identity(launcher.get('pid'))
            if current is None:
                if child.poll() is not None:
                    raise IntegrationError('Sing-box exited during startup.')
                time.sleep(0.02)
                continue
            if not same_execution(launcher, current):
                raise IntegrationError('The Core launcher process identity changed unexpectedly.')
            if (current.get('arguments') == core_arguments()
                    and current.get('executable') == os.path.realpath(CORE)):
                return current
            if not any(current.get('arguments') == arguments
                       and current.get('executable') == os.path.realpath(arguments[0])
                       for arguments in allowed):
                raise IntegrationError('The Core launcher executed an unexpected process.')
            time.sleep(0.02)
        raise IntegrationError('The Core process identity could not be verified.')

    def recover_launcher(self, record):
        """Retire or promote one durable pre-exec launcher ownership receipt."""
        launcher = record.get('launcher')
        if launcher is None:
            return
        arguments = launcher_arguments(value=launcher)
        if (arguments is None or launcher.get('uid') != os.geteuid()
                or launcher.get('executable') != os.path.realpath(sys.executable)):
            raise IntegrationError('The Core launcher ownership receipt is invalid.')
        current = identity(launcher.get('pid'))
        if current is None or not same_execution(launcher, current):
            record.pop('launcher', None)
            write_json(self.record_path, record)
            return
        if (current.get('arguments') == core_arguments()
                and current.get('executable') == os.path.realpath(CORE)):
            record['core'] = current
            record.pop('launcher', None)
            write_json(self.record_path, record)
            return
        allowed = (arguments, setfib_arguments())
        if not any(current.get('arguments') == expected
                   and current.get('executable') == os.path.realpath(expected[0])
                   for expected in allowed):
            raise IntegrationError('The Core launcher executed an unexpected process and was preserved.')
        os.kill(current['pid'], signal.SIGTERM)
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            latest = identity(launcher['pid'])
            if latest is None or not same_execution(launcher, latest):
                break
            if not any(latest.get('arguments') == expected
                       and latest.get('executable') == os.path.realpath(expected[0])
                       for expected in (*allowed, core_arguments())):
                raise IntegrationError('The Core launcher executed an unexpected process and was preserved.')
            time.sleep(0.05)
        else:
            latest = identity(launcher['pid'])
            if latest is not None and same_execution(launcher, latest):
                os.kill(latest['pid'], signal.SIGKILL)
                deadline = time.monotonic() + 2
                while time.monotonic() < deadline:
                    latest = identity(launcher['pid'])
                    if latest is None or not same_execution(launcher, latest):
                        break
                    time.sleep(0.05)
                if latest is not None and same_execution(launcher, latest):
                    raise IntegrationError('The owned Core launcher did not stop.')
        record.pop('launcher', None)
        write_json(self.record_path, record)

    def lock(self):
        self.prepare_state()
        fd = os.open(self.state / 'service.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        stream = os.fdopen(fd, 'w')
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600):
            stream.close()
            raise IntegrationError('The service lock has invalid ownership.')
        fcntl.flock(fd, fcntl.LOCK_EX)
        return stream

    def routing_cleanup(self):
        return self.routing.execute('disable')

    def routing_context_missing(self):
        try:
            descriptor = os.open(self.state / 'routing-context.json', os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            return True
        except OSError as error:
            raise IntegrationError('The firewall routing context could not be inspected.') from error
        else:
            os.close(descriptor)
            return False

    @contextlib.contextmanager
    def filter_reload_lock(self):
        self.prepare_state()
        descriptor = os.open(self.filter_reload_lock_path,
                             os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'a') as lock:
            info = os.fstat(lock.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) != 0o600):
                raise IntegrationError('The filter reload lock has invalid ownership.')
            deadline = time.monotonic() + 5
            while True:
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError as error:
                    if time.monotonic() >= deadline:
                        raise IntegrationError('The filter reload operation is busy.') from error
                    time.sleep(0.02)
            yield

    def complete_filter_reload(self, force=False):
        """Complete one journalled native XML change before clearing its receipt."""
        with self.filter_reload_lock():
            pending = private_json(self.filter_reload_path, None)
            if pending is not None and pending != {'schema': 1, 'pending': True}:
                raise IntegrationError('The filter reload receipt is invalid.')
            if pending is None and not force:
                return False
            if pending is None:
                write_json(self.filter_reload_path, {'schema': 1, 'pending': True})
            command(['/usr/local/sbin/configctl', 'filter', 'reload'])
            self.filter_reload_path.unlink()
            fsync_directory(self.filter_reload_path.parent)
            return True

    def sync_filter_configuration(self):
        """Reload PF only for a saved XML change or an interrupted prior change."""
        pending = private_json(self.filter_reload_path, None)
        if pending is not None and pending != {'schema': 1, 'pending': True}:
            raise IntegrationError('The filter reload receipt is invalid.')
        changed = configuration_changed(
            ['/usr/local/bin/php', '/usr/local/opnsense/scripts/singbox/config_setup.php', 'enable'])
        self.complete_filter_reload(force=changed or self.routing_context_missing())

    def tun_snapshot(self):
        value = command(['/sbin/ifconfig', '-v', TUN], check=False)
        if value.returncode:
            return None
        text = value.stdout.decode(errors='strict')
        flags = re.match(re.escape(TUN) + r': flags=([0-9a-fA-F]+)\b.*\bmetric (\d+) mtu (\d+)', text)
        driver = re.search(r'^\s*drivername: (tun\d+)\s*$', text, re.M)
        description = re.search(r'^\s*description: (.*)$', text, re.M)
        opener = re.search(r'^\s*Opened by PID (\d+)\s*$', text, re.M)
        if flags is None or driver is None:
            raise IntegrationError('The exact TUN interface identity could not be read.')
        try:
            index = socket.if_nametoindex(TUN)
        except OSError as error:
            raise IntegrationError('The TUN interface changed during inspection.') from error
        return {'name': TUN, 'index': index, 'driver': driver.group(1),
                'metric': int(flags.group(2)), 'mtu': int(flags.group(3)),
                'description': description.group(1) if description else '',
                'opened_by': int(opener.group(1)) if opener else None,
                'closed': not (int(flags.group(1), 16) & 0x41) and opener is None
                          and re.search(r'^\s*inet6?\s', text, re.M) is None}

    def claim_tun(self, record):
        current = self.tun_snapshot()
        if current is None or current['opened_by'] != record['core']['pid'] or not owned(record):
            raise IntegrationError('The TUN was not opened by the verified Core.')
        stable = ('name', 'index', 'driver', 'metric', 'mtu')
        receipt = {key: current[key] for key in stable}
        receipt['description'] = 'Singbox owner ' + os.urandom(16).hex()
        receipt['phase'] = 'claiming'
        receipt['preclaim'] = {key: current[key] for key in (*stable, 'description', 'opened_by')}
        record['tun'] = receipt
        # Journal both the exact opener and the unmarked identity before changing
        # the interface. Cleanup can then recover either side of this mutation.
        write_json(self.record_path, record)
        if self.tun_snapshot() != current or not owned(record):
            raise IntegrationError('The TUN interface changed before ownership was marked.')
        command(['/sbin/ifconfig', TUN, 'description', receipt['description']])
        verified = self.tun_snapshot()
        if (verified is None or any(verified.get(key) != receipt[key] for key in (*stable, 'description'))
                or verified['opened_by'] != record['core']['pid']):
            raise IntegrationError('The TUN ownership marker could not be verified.')
        receipt['phase'] = 'owned'
        receipt.pop('preclaim', None)
        write_json(self.record_path, record)

    def cleanup_tun(self, record):
        receipt = record.get('tun')
        if receipt is None:
            return
        phase = receipt.get('phase', 'owned') if isinstance(receipt, dict) else None
        preclaim = receipt.get('preclaim') if isinstance(receipt, dict) else None
        stable = ('name', 'index', 'driver', 'metric', 'mtu')
        if (not isinstance(receipt, dict) or receipt.get('name') != TUN
                or type(receipt.get('index')) is not int or receipt['index'] <= 0
                or not re.fullmatch(r'tun[0-9]+', str(receipt.get('driver', '')))
                or type(receipt.get('metric')) is not int or receipt['metric'] < 0
                or type(receipt.get('mtu')) is not int or receipt['mtu'] <= 0
                or not re.fullmatch(r'Singbox owner [0-9a-f]{32}', str(receipt.get('description', '')))
                or phase not in ('claiming', 'owned')):
            raise IntegrationError('The TUN ownership receipt is invalid; the interface was preserved.')
        if phase == 'claiming' and (not isinstance(preclaim, dict)
                or any(preclaim.get(key) != receipt.get(key) for key in stable)
                or not isinstance(preclaim.get('description'), str)
                or type(preclaim.get('opened_by')) is not int
                or preclaim['opened_by'] != (record.get('core') or {}).get('pid')):
            raise IntegrationError('The pending TUN ownership receipt is invalid; the interface was preserved.')
        self.prepare_state()
        fd = os.open(self.state / 'tun-cleanup.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'a') as lock:
            info = os.fstat(lock.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600:
                raise IntegrationError('The TUN cleanup lock has invalid ownership.')
            deadline = time.monotonic() + 2
            while True:
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError as error:
                    if time.monotonic() >= deadline:
                        raise IntegrationError('Owned TUN cleanup is busy and will be retried.') from error
                    time.sleep(.02)
            current = self.tun_snapshot()
            if current is None:
                return
            exact_identity = all(current.get(key) == receipt[key] for key in stable)
            marked = current.get('description') == receipt['description']
            unmarked = phase == 'claiming' and current.get('description') == preclaim['description']
            if not exact_identity or not (marked or unmarked) or not current['closed']:
                raise IntegrationError('The TUN is open or its ownership changed; the interface was preserved.')
            if self.tun_snapshot() != current:
                raise IntegrationError('The TUN changed during cleanup; the interface was preserved.')
            command(['/sbin/ifconfig', TUN, 'destroy'], check=False)
            remaining = self.tun_snapshot()
            if (remaining is not None
                    and all(remaining.get(key) == receipt[key] for key in stable)
                    and remaining.get('description') in (receipt['description'],
                                                         preclaim['description'] if unmarked else None)
                    and remaining['closed']):
                raise IntegrationError('Owned TUN destruction failed and will be retried.')

    def status(self):
        record = self.read_record()
        health = core_health(record)
        diagnostic = self.routing_error()
        try:
            routing = self.routing.execute('status')
        except (RoutingError, OSError, UnicodeError) as error:
            routing = {'active': False, 'pending': True}
            diagnostic = bounded_routing_diagnostic(error) or 'The routing state could not be inspected.'
        active, pending = bool(routing.get('active')), bool(routing.get('pending'))
        pending = pending or bool(diagnostic)
        fallback = bool(record.get('transparent') and not active and not pending)
        return {'running': health['healthy'], **health, 'transparent': health['healthy'] and active,
                'routing_active': active, 'recovery_pending': pending, 'routing_fallback': fallback,
                'restart_required': fallback and health['process_alive'], 'routing_error': diagnostic}

    def stop(self):
        # Remove capture first, even with a stale PID or partial startup.
        recovery_error = None
        try:
            self.routing_cleanup()
            self.clear_routing_error()
        except (RoutingError, OSError, UnicodeError) as error:
            self.remember_routing_error(error, log=True)
            recovery_error = error
        record = self.read_record()
        try:
            self.recover_launcher(record)
        except IntegrationError as error:
            recovery_error = recovery_error or error
        legacy = None
        if not record.get('core') and not record.get('launcher'):
            try:
                legacy_pid, _ = service_pidfile(self.pidfile)
            except (FileNotFoundError, IntegrationError, OSError):
                legacy_pid = None
            if legacy_pid is not None:
                legacy = identity(legacy_pid)
                if (legacy and legacy.get('uid') == os.geteuid() and legacy.get('executable') == os.path.realpath(CORE)
                        and legacy['arguments'] == [CORE, 'run', '-c', str(self.configuration)]):
                    # Graceful legacy Close restores its in-memory DNS backup.
                    # Resume a paused exact process so it can handle TERM, then
                    # recheck the complete identity before the terminating signal.
                    if identity(legacy['pid']) == legacy:
                        os.kill(legacy['pid'], signal.SIGCONT)
                        if identity(legacy['pid']) == legacy:
                            os.kill(legacy['pid'], signal.SIGTERM)
                else:
                    legacy = None
        signal_owned(record, 'core', signal.SIGTERM)
        until = time.monotonic() + 10
        while (owned(record) or legacy and identity(legacy['pid']) == legacy) and time.monotonic() < until:
            time.sleep(0.1)
        if legacy and identity(legacy['pid']) == legacy:
            raise IntegrationError('The legacy Core did not stop gracefully; its DNS cleanup could not be verified.')
        if owned(record):
            signal_owned(record, 'core', signal.SIGKILL)
            until = time.monotonic() + 3
            while owned(record) and time.monotonic() < until:
                time.sleep(0.1)
        if owned(record):
            raise IntegrationError('The owned Core did not stop.')
        try:
            self.cleanup_tun(record)
        except IntegrationError as error:
            recovery_error = recovery_error or error
        if recovery_error is None:
            signal_owned(record, 'watcher', signal.SIGTERM)
        # A foreign pidfile remains untouched, even if our journal is stale.
        try:
            pid, snapshot = service_pidfile(self.pidfile)
        except (FileNotFoundError, IntegrationError, OSError):
            pid, snapshot = None, None
        if (pid is not None and identity(pid) is None
                and (pid == (record.get('core') or {}).get('pid')
                     or legacy and pid == legacy['pid'])):
            try:
                current = service_pidfile(self.pidfile)
            except (FileNotFoundError, IntegrationError, OSError):
                current = None
            if current == (pid, snapshot) and identity(pid) is None:
                self.pidfile.unlink()
                fsync_directory(self.pidfile.parent)
        if recovery_error is None:
            try:
                self.record_path.unlink()
            except FileNotFoundError:
                pass
            else:
                fsync_directory(self.record_path.parent)
            self.clear_routing_error()
            return {'running': False}
        raise IntegrationError('Scoped routing recovery is pending and will be retried.') from recovery_error

    def start(self, configuration=CONFIG):
        record = self.read_record()
        if owned(record) or owned(record, 'launcher'):
            raise IntegrationError('Sing-box is already running.')
        try:
            pid, snapshot = service_pidfile(self.pidfile)
        except FileNotFoundError:
            pid, snapshot = None, None
        if pid is not None:
            if identity(pid) is not None:
                raise IntegrationError('The service pidfile belongs to another process; it was preserved.')
            if service_pidfile(self.pidfile) != (pid, snapshot) or identity(pid) is not None:
                raise IntegrationError('The service pidfile changed concurrently; it was preserved.')
            self.pidfile.unlink()
            fsync_directory(self.pidfile.parent)
        self.stop()
        settings = policy(private_json(POLICY, DEFAULTS))
        # Legacy installations acquire no automatic consent. Store the explicit
        # default separately while retaining every byte of their saved JSON.
        if not POLICY.exists():
            write_json(POLICY, settings)
        runtime = render(private_json(Path(configuration)), settings)
        if settings['transparent']:
            if command(['/usr/sbin/service', 'mihomo', 'onestatus'], check=False).returncode == 0:
                raise IntegrationError('Mihomo is running; disable its capture before starting this TUN.')
            if command(['/sbin/ifconfig', TUN], check=False).returncode == 0:
                raise IntegrationError('The TUN interface is already owned elsewhere.')
            native = self.routing.routes(0)
            tun = next(item for item in runtime['inbounds'] if item.get('type') == 'tun')
            for address in tun_addresses(tun):
                net = ipaddress.ip_interface(address).network
                if any(route['family'] == net.version and ipaddress.ip_network(route['destination']).prefixlen and net.overlaps(ipaddress.ip_network(route['destination'])) for route in native.values()):
                    raise IntegrationError('The TUN address overlaps an existing native route.')
        write_json(self.runtime, runtime)
        command([CORE, 'check', '-c', str(self.runtime)])
        if settings['transparent']:
            self.sync_filter_configuration()
        record = {'schema': 1, 'core': None, 'watcher': None, 'launcher': None,
                  'transparent': settings['transparent'], 'boot': boot_token()}
        child = None
        watcher = None
        read_descriptor = None
        release_descriptor = None
        launcher_recorded = False
        try:
            read_descriptor, release_descriptor = os.pipe()
            launch = launcher_arguments(descriptor=read_descriptor)
            with append_log(self.log_path) as log:
                child = subprocess.Popen(
                    launch, stdout=log, stderr=log, stdin=subprocess.DEVNULL,
                    start_new_session=True, pass_fds=(read_descriptor,), close_fds=True)
            os.close(read_descriptor)
            read_descriptor = None
            record['launcher'] = self.capture_launcher(child.pid, launch)
            write_json(self.record_path, record)
            launcher_recorded = True
            if os.write(release_descriptor, b'1') != 1:
                raise IntegrationError('The Core launch handshake was incomplete.')
            os.close(release_descriptor)
            release_descriptor = None
            record['core'] = self.capture_core_transition(record['launcher'], child)
            record['launcher'] = None
            write_json(self.record_path, record)
            launcher_recorded = False
            descriptor = os.open(self.pidfile,
                                 os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o600)
            with os.fdopen(descriptor, 'w') as stream:
                stream.write(str(child.pid) + '\n')
                stream.flush()
                os.fsync(stream.fileno())
            fsync_directory(self.pidfile.parent)
            if settings['transparent']:
                until = time.monotonic() + 20
                while command(['/sbin/ifconfig', TUN], check=False).returncode:
                    if not owned(record) or time.monotonic() >= until:
                        raise IntegrationError('The Core did not create the TUN within 20 seconds.')
                    time.sleep(0.2)
                self.claim_tun(record)
                # Persist watcher identity before activating capture. This keeps
                # a startup failure from leaving a live Core or capture behind.
                with append_log(self.log_path) as log:
                    watcher = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), 'watch'],
                                               stdout=log, stderr=log, stdin=subprocess.DEVNULL, start_new_session=True)
                until = time.monotonic() + 3
                while time.monotonic() < until:
                    current = identity(watcher.pid)
                    if current and current['arguments'] == [sys.executable, str(Path(__file__).resolve()), 'watch']:
                        record['watcher'] = current
                        break
                    time.sleep(0.05)
                if record['watcher'] is None:
                    raise IntegrationError('The routing watcher could not be verified.')
                write_json(self.record_path, record)
                self.routing.execute('enable')
                if not self.routing.execute('status').get('active'):
                    raise IntegrationError('No supported LAN source is available for capture.')
            if not owned(record):
                raise IntegrationError('The Core exited before startup completed.')
            self.clear_routing_error()
            return {'running': True, 'transparent': settings['transparent']}
        except Exception as error:
            if watcher is not None and record['watcher'] is None and watcher.poll() is None:
                watcher.terminate()
                try:
                    watcher.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    watcher.kill()
                    watcher.wait(timeout=3)
            if record['core'] is None and child is not None and not launcher_recorded:
                # Popen created this exact child; it cannot be a reused pid.
                if child.poll() is None:
                    child.terminate()
                    try:
                        child.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        child.wait(timeout=3)
            with contextlib.suppress(IntegrationError, RoutingError):
                self.stop()
            if isinstance(error, RoutingError):
                self.remember_routing_error(error, log=True)
            raise
        finally:
            for descriptor in (read_descriptor, release_descriptor):
                if descriptor is not None:
                    with contextlib.suppress(OSError):
                        os.close(descriptor)

    def watch(self):
        # Do not take the service lock: a starter holds it while the watcher
        # becomes ready. The routing lock serializes each ownership mutation.
        deadline = time.monotonic() + 4
        while time.monotonic() < deadline:
            record = self.read_record()
            if (record.get('watcher') or {}).get('pid') == os.getpid():
                break
            time.sleep(0.1)
        else:
            return
        while True:
            current = self.read_record()
            if current.get('watcher') != record.get('watcher'):
                return
            try:
                result = self.routing.execute('refresh')
                if not result.get('busy'):
                    self.clear_routing_error()
                # Routing health handles pauses without changing PID ownership.
                # A dead Core can leave a closed cloned interface on FreeBSD.
                if not result.get('busy') and not result.get('active') and not result.get('pending') and not owned(current):
                    self.cleanup_tun(current)
            except (IntegrationError, RoutingError, OSError, UnicodeError) as error:
                detail = self.remember_routing_error(error)
                print('Scoped Sing-box routing recovery is pending; retrying. ' + detail,
                      file=sys.stderr, flush=True)
            time.sleep(2)


def launch_core(descriptor):
    """Wait until the parent durably records this process, then enter FIB 0."""
    if not re.fullmatch(r'[0-9]{1,9}', str(descriptor)):
        raise IntegrationError('The Core launch handshake is invalid.')
    descriptor = int(descriptor)
    if not 2 < descriptor < 2147483648:
        raise IntegrationError('The Core launch handshake is invalid.')
    try:
        release = os.read(descriptor, 2)
    finally:
        os.close(descriptor)
    if release != b'1':
        return
    os.execv(SETFIB, setfib_arguments())


def main():
    if sys.argv[1:2] == ['launch']:
        if len(sys.argv) != 3 or not sys.platform.startswith('freebsd') or os.geteuid() != 0:
            raise IntegrationError('The Core launch handshake is invalid.')
        launch_core(sys.argv[2])
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('start', 'stop', 'status', 'watch', 'init',
                                           'set-policy', 'reload-filter'))
    parser.add_argument('--config', default=str(CONFIG))
    parser.add_argument('--pidfile', default=str(PIDFILE))
    args = parser.parse_args()
    if not sys.platform.startswith('freebsd') or os.geteuid() != 0:
        raise IntegrationError('Native service integration requires FreeBSD root.')
    manager = Manager(pidfile=args.pidfile, configuration=args.config)
    if args.action == 'watch':
        manager.watch()
        return
    if args.action == 'reload-filter':
        result = {'reloaded': manager.complete_filter_reload()}
    elif args.action == 'status':
        result = manager.status()
    elif args.action == 'init':
        result = policy(private_json(POLICY, DEFAULTS))
        if not POLICY.exists():
            write_json(POLICY, result)
    elif args.action == 'set-policy':
        # Configd passes a private request over stdin, never as logged arguments.
        content = sys.stdin.buffer.read(65537)
        if len(content) > 65536:
            raise IntegrationError('The integration request is too large.')
        given = json.loads(content)
        if not isinstance(given, dict):
            raise IntegrationError('The integration settings are invalid.')
        with manager.lock():
            result = policy(dict(private_json(POLICY, DEFAULTS), **given))
            write_json(POLICY, result)
    else:
        with manager.lock():
            result = manager.stop() if args.action == 'stop' else manager.start(args.config)
    print(json.dumps({'ok': True, **result}))
    if args.action == 'status' and not result['running']:
        raise SystemExit(1)


if __name__ == '__main__':
    try:
        main()
    except (IntegrationError, RoutingError, OSError, ValueError, TypeError, KeyError,
            UnicodeError, subprocess.SubprocessError):
        # Native diagnostics and user JSON may contain credentials.
        print(json.dumps({'ok': False, 'error': 'Sing-box integration failed safely. Check the private service log.'}))
        raise SystemExit(1)
