#!/usr/local/bin/python3
"""Supervise one Core and import only bounded, non-conflicting VPN routes."""
import copy
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
import tomllib

from process_identity import birth_frame_shift, boot_token, process, rebase_birth

ROOT = Path('/var/run/easytier-network')
JOURNAL = ROOT / 'owner.json'
RUNTIME = ROOT / 'config.toml'
CORE_PID = Path('/var/run/easytier.pid')
CORE = '/usr/local/sbin/easytier-core'
CLI = '/usr/local/sbin/easytier-cli'
CONFIG = Path('/usr/local/etc/easytier/config.toml')
PRIVATE = tuple(ipaddress.ip_network(x) for x in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'))
ULA = ipaddress.ip_network('fc00::/7')
IFNAME = re.compile(r'[A-Za-z][A-Za-z0-9_]{0,14}')
LIMIT = 1048576
ROUTING_DIAGNOSTIC_LIMIT = 512
PORTAL = re.compile(r'(?:\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9_.-]+):[1-9][0-9]{0,4}\Z')
ROUTE_FIELDS = frozenset(('destination', 'gateway', 'interface', 'flags'))


class PolicyError(ValueError):
    """A public, credential-free configuration diagnostic."""


class RouteMutationError(PolicyError):
    """A bounded diagnostic from the numeric native route adapter."""


def bounded_routing_diagnostic(value):
    text = ' '.join(''.join(character if character.isprintable() else ' '
                            for character in str(value)).split())
    return text.encode('utf-8', errors='replace')[:ROUTING_DIAGNOSTIC_LIMIT].decode('utf-8', errors='ignore')


def route_status_error(message, error):
    detail = bounded_routing_diagnostic(error)
    return bounded_routing_diagnostic(message + (' ' + detail if detail else ''))


def run(args, timeout=5):
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)


def private_network(value):
    try:
        network = ipaddress.ip_network(value, strict=False)
    except (TypeError, ValueError):
        raise PolicyError('VPN routes must be valid IPv4 private CIDRs.') from None
    if network.version != 4 or not any(network.subnet_of(x) for x in PRIVATE):
        raise PolicyError('Public and default VPN routes are not supported on the system routing table. Use private IPv4 subnet routes.')
    return network


def validate_configuration(data):
    flags = data.get('flags', {})
    if not isinstance(flags, dict):
        raise PolicyError('EasyTier flags must be a TOML table.')
    name = flags.get('dev_name') or 'easytier0'
    if not isinstance(name, str) or not IFNAME.fullmatch(name):
        raise PolicyError('The TUN device name must be 1–15 letters, digits or underscores, starting with a letter.')
    for key in ('ipv6_public_addr_auto', 'ipv6_public_addr_provider', 'ipv6_public_addr_prefix'):
        if data.get(key):
            raise PolicyError('Public IPv6 overlay address and automatic default-route modes are not supported. Native IPv6 remains available.')
    if not flags.get('no_tun', False):
        if data.get('dhcp', False):
            raise PolicyError('Configure a fixed private overlay IPv4 address; automatic overlay DHCP cannot be validated before TUN creation.')
        if data.get('ipv4'):
            try:
                address = ipaddress.ip_interface(data['ipv4'])
            except (TypeError, ValueError):
                raise PolicyError('The overlay IPv4 address must be a valid private CIDR.') from None
            private_network(str(address.network))
        if data.get('ipv6'):
            try:
                address = ipaddress.ip_interface(data['ipv6'])
            except (TypeError, ValueError):
                raise PolicyError('The overlay IPv6 address must be a valid ULA CIDR.') from None
            if address.version != 6 or not address.network.subnet_of(ULA):
                raise PolicyError('The overlay IPv6 address must use a ULA subnet. Native public IPv6 remains available.')
    routes = data.get('routes')
    if routes is not None:
        if not isinstance(routes, list) or len(routes) > 1024:
            raise PolicyError('VPN routes must be an array with at most 1024 private IPv4 CIDRs.')
        for route in routes:
            private_network(route)
    return name



def validate_live_configuration(data, table=None):
    name = validate_configuration(data)
    table = routing_table() if table is None else table
    record = load_record()
    own = ({**record.get('routes', {}), **record.get('overlay_routes', {})}
           if owns_running_interface(record) else {})
    if not data.get('flags', {}).get('no_tun', False):
        for key in ('ipv4', 'ipv6'):
            if data.get(key) and protected(ipaddress.ip_interface(data[key]).network, table, own):
                raise PolicyError('The overlay address subnet overlaps a native system route. Choose a distinct private overlay subnet.')
    for route in data.get('routes') or []:
        if protected(private_network(route), table, own):
            raise PolicyError('An explicit VPN route overlaps a native system route. Remove that route or choose a distinct remote private subnet.')
    return name

def fsync_directory(path):
    flags = os.O_RDONLY
    if hasattr(os, 'O_DIRECTORY'):
        flags |= os.O_DIRECTORY
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def atomic(path, content):
    ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.owner.', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        fsync_directory(path.parent)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def write_journal(record):
    atomic(JOURNAL, json.dumps(record))


def create_pidfile(pid):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    descriptor = os.open(CORE_PID, flags, 0o600)
    try:
        stream = os.fdopen(descriptor, 'w')
        descriptor = -1
        with stream:
            stream.write(str(pid) + '\n')
            stream.flush()
            os.fsync(stream.fileno())
        fsync_directory(CORE_PID.parent)
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def read_pidfile():
    descriptor = os.open(CORE_PID, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, 'r') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_mode & 0o022):
            raise PolicyError('The EasyTier PID file has foreign ownership or writers.')
        text = stream.read(65)
    if len(text) > 64 or not re.fullmatch(r'[1-9][0-9]{0,9}\n?', text) or int(text) >= 2147483648:
        raise PolicyError('The EasyTier PID file is invalid and was preserved.')
    return int(text)


def identity(pid, parent=None):
    if type(pid) is not int or not 1 < pid < 2147483648:
        return None
    try:
        value = process(pid)
    except RuntimeError as error:
        raise PolicyError('Unable to establish exact EasyTier process ownership.') from error
    if value is None:
        return None
    try:
        if parent is not None and value['ppid'] != parent:
            raise PolicyError('The new EasyTier process has an unexpected parent identity.')
        # Parentage and stopped state can change without transferring PID
        # ownership. The remaining values are the immutable ownership receipt.
        return {key: value[key] for key in ('pid', 'birth', 'uid', 'executable')} | {
            'argv': list(value['argv'])}
    except (KeyError, TypeError):
        raise PolicyError('The exact EasyTier process identity is invalid.') from None


def same_process(record):
    return isinstance(record, dict) and identity(record.get('pid')) == record


def rebase_record_births(record):
    """Move recorded births into the live clock frame after a wall-clock step."""
    token = record.get('boot') if isinstance(record, dict) else None
    if not isinstance(token, str):
        return
    shift = birth_frame_shift(token)
    if shift is None:
        return
    delta, current = shift
    for identity in (record.get('core'), record.get('supervisor'), record.get('launcher')):
        if isinstance(identity, dict) and isinstance(identity.get('birth'), str):
            moved = rebase_birth(identity['birth'], delta)
            if moved is not None:
                identity['birth'] = moved
    record['boot'] = current


def exact_command(record, arguments):
    return (isinstance(record, dict) and isinstance(arguments, list) and arguments
            and record.get('uid') == os.geteuid()
            and record.get('executable') == os.path.realpath(arguments[0])
            and record.get('argv') == arguments)


def supervisor_arguments(record=None):
    if record is None:
        return [sys.executable, os.path.abspath(__file__), 'run']
    arguments = record.get('argv') if isinstance(record, dict) else None
    if (not isinstance(arguments, list) or len(arguments) != 3
            or arguments[1:] != [os.path.abspath(__file__), 'run']
            or not os.path.isabs(arguments[0])
            or os.path.realpath(arguments[0]) != os.path.realpath(sys.executable)
            or not exact_command(record, arguments)):
        return None
    return arguments


def core_arguments(record, legacy=False):
    if not isinstance(record, dict):
        return None
    arguments = record.get('argv')
    config = CONFIG if legacy else RUNTIME
    if (not isinstance(arguments, list) or len(arguments) != 5
            or arguments[:4] != [CORE, '--config-file', str(config), '--rpc-portal']
            or not isinstance(arguments[4], str) or len(arguments[4]) > 255
            or PORTAL.fullmatch(arguments[4]) is None
            or not exact_command(record, arguments)):
        return None
    try:
        port = int(arguments[4].rsplit(':', 1)[1])
    except (ValueError, IndexError):
        return None
    return arguments if port <= 65535 else None


def launcher_arguments(record=None, descriptor=None, portal=None):
    if record is None:
        return [sys.executable, os.path.abspath(__file__), 'launch',
                str(descriptor), portal]
    arguments = record.get('argv') if isinstance(record, dict) else None
    if (not isinstance(arguments, list) or len(arguments) != 5
            or arguments[1:3] != [os.path.abspath(__file__), 'launch']
            or not os.path.isabs(arguments[0])
            or os.path.realpath(arguments[0]) != os.path.realpath(sys.executable)
            or not re.fullmatch(r'[0-9]{1,9}', str(arguments[3]))
            or not isinstance(arguments[4], str) or len(arguments[4]) > 255
            or PORTAL.fullmatch(arguments[4]) is None
            or not exact_command(record, arguments)):
        return None
    try:
        fd, port = int(arguments[3]), int(arguments[4].rsplit(':', 1)[1])
    except (ValueError, IndexError):
        return None
    return arguments if 2 < fd < 2147483648 and port <= 65535 else None


def launcher_core_arguments(record):
    arguments = launcher_arguments(record)
    if arguments is None:
        return None
    return [CORE, '--config-file', str(RUNTIME), '--rpc-portal', arguments[4]]


def same_execution(left, right):
    return (isinstance(left, dict) and isinstance(right, dict)
            and all(left.get(key) == right.get(key)
                    for key in ('pid', 'birth', 'uid')))


def owned_supervisor(record):
    return supervisor_arguments(record) is not None


def owned_core(record, legacy=False):
    return core_arguments(record, legacy) is not None


def owned_launcher(record):
    return launcher_arguments(record) is not None


def signal_process(record, number, arguments=None):
    # Re-read the complete kernel identity immediately before every signal.
    if arguments is not None and not exact_command(record, arguments):
        return False
    if not same_process(record):
        return False
    try:
        os.kill(record['pid'], number)
        return True
    except ProcessLookupError:
        return False


def capture_process(pid, arguments, parent=None):
    for _ in range(50):
        current = identity(pid, parent)
        if current is not None:
            if not exact_command(current, arguments):
                raise PolicyError('The new EasyTier process has an unexpected exact command identity.')
            return current
        time.sleep(.01)
    raise PolicyError('Unable to establish exact ownership of the new EasyTier process.')


def capture_supervisor(pid):
    for _ in range(50):
        current = identity(pid)
        if current is not None:
            if not owned_supervisor(current):
                raise PolicyError('The EasyTier supervisor has an unexpected exact command identity.')
            return current
        time.sleep(.01)
    raise PolicyError('Unable to establish exact ownership of the EasyTier supervisor.')


def capture_core_transition(launcher, arguments):
    for _ in range(100):
        current = identity(launcher.get('pid'))
        if current is None:
            time.sleep(.01)
            continue
        if not same_execution(launcher, current):
            raise PolicyError('The EasyTier launcher process identity changed unexpectedly.')
        if exact_command(current, arguments):
            return current
        if not (owned_launcher(current) and current == launcher):
            raise PolicyError('The EasyTier launcher executed an unexpected process.')
        time.sleep(.01)
    raise PolicyError('Unable to establish the launched EasyTier Core identity.')


def stop_launcher(record):
    launcher = record.get('launcher')
    if launcher is None:
        return
    expected_core = launcher_core_arguments(launcher)
    if expected_core is None:
        raise PolicyError('The EasyTier launcher ownership receipt is invalid.')
    arguments = launcher_arguments(launcher)
    if arguments is None:
        raise PolicyError('The EasyTier launcher ownership receipt is invalid.')

    def inspect():
        current = identity(launcher.get('pid'))
        if current is None or not same_execution(launcher, current):
            record.pop('launcher', None)
            write_journal(record)
            return 'gone'
        if exact_command(current, expected_core):
            # exec(2) retains the PID and birth identity. Persist the new exact
            # command before callers decide whether to terminate the Core.
            record['core'] = current
            record.pop('launcher', None)
            write_journal(record)
            return 'core'
        if current != launcher:
            raise PolicyError('The EasyTier launcher executed an unexpected process and was preserved.')
        return 'launcher'

    if inspect() != 'launcher':
        return
    # The release byte and a stop request can cross. A failed exact-launcher
    # signal therefore requires another exec-transition inspection instead of
    # retiring the only durable receipt for a newly running Core.
    if not signal_process(launcher, signal.SIGTERM, arguments):
        if inspect() != 'launcher':
            return
    for _ in range(20):
        state = inspect()
        if state != 'launcher':
            return
        time.sleep(.05)
    if not signal_process(launcher, signal.SIGKILL, arguments):
        if inspect() != 'launcher':
            return
        raise PolicyError('The owned EasyTier launcher could not be stopped.')
    for _ in range(20):
        state = inspect()
        if state != 'launcher':
            return
        time.sleep(.05)
    raise PolicyError('The owned EasyTier launcher could not be stopped.')


def launcher(descriptor, portal):
    if (not sys.platform.startswith('freebsd') or os.geteuid() != 0
            or not re.fullmatch(r'[0-9]{1,9}', descriptor)
            or PORTAL.fullmatch(portal or '') is None):
        raise PolicyError('The EasyTier launch handshake is invalid.')
    fd = int(descriptor)
    try:
        port = int(portal.rsplit(':', 1)[1])
    except (ValueError, IndexError):
        raise PolicyError('The EasyTier launch handshake is invalid.') from None
    if not 2 < fd < 2147483648 or port > 65535:
        raise PolicyError('The EasyTier launch handshake is invalid.')
    try:
        release = os.read(fd, 2)
    finally:
        os.close(fd)
    if release != b'1':
        return 0
    os.execv(CORE, [CORE, '--config-file', str(RUNTIME), '--rpc-portal', portal])


def parse_routes(text, family):
    if len(text.encode()) > LIMIT:
        raise PolicyError('The system routing table exceeds the supported size.')
    columns, values = None, {}
    for line in text.splitlines():
        words = line.split()
        if not words:
            continue
        if words[0] == 'Destination':
            if not all(x in words for x in ('Gateway', 'Flags', 'Netif')):
                raise PolicyError('The numeric system routing table format is unsupported.')
            columns = {x: words.index(x) for x in ('Destination', 'Gateway', 'Flags', 'Netif')}
            continue
        if columns is None:
            continue
        if len(words) <= max(columns.values()):
            raise PolicyError('The numeric system routing table contains an incomplete route.')
        destination = words[columns['Destination']]
        gateway, flags, interface = (words[columns[x]] for x in ('Gateway', 'Flags', 'Netif'))
        if 'L' in flags:
            continue
        if destination == 'default':
            destination = '0.0.0.0/0' if family == 4 else '::/0'
        else:
            addr, _, prefix = destination.partition('/')
            addr = addr.split('%')[0]
            if family == 4 and addr.count('.') < 3:
                addr += '.0' * (3 - addr.count('.'))
            destination = addr + '/' + (prefix or ('32' if family == 4 else '128'))
        try:
            network = ipaddress.ip_network(destination, strict=False)
            if network.version != family:
                raise ValueError
        except ValueError:
            raise PolicyError('A numeric route destination is invalid.') from None
        # ULA overlay prefixes cannot overlap scoped link-local or multicast
        # destinations. Omit these from protection rather than merge zone keys.
        if family == 6 and (network.is_link_local or network.is_multicast):
            continue
        route = {'destination': str(network), 'gateway': gateway, 'interface': interface, 'flags': flags}
        key = str(network)
        if key in values and values[key] != route:
            raise PolicyError('Duplicate system route destinations are unsupported.')
        values[key] = route
    if columns is None:
        raise PolicyError('The numeric system routing table is unavailable.')
    return values


def routing_table():
    values = {}
    for family, selector in ((4, 'inet'), (6, 'inet6')):
        result = run(['/usr/bin/netstat', '-rnW', '-F', '0', '-f', selector])
        if result.returncode:
            # FreeBSD netstat rejects an explicit -F 0 on a single-FIB VNET.
            # Reading its default table is safe only after proving that the
            # sole table and this process are both FIB0.
            count = run(['/sbin/sysctl', '-n', 'net.fibs'])
            current = run(['/sbin/sysctl', '-n', 'net.my_fibnum'])
            if count.returncode == current.returncode == 0 and count.stdout.strip() == '1' and current.stdout.strip() == '0':
                result = run(['/usr/bin/netstat', '-rnW', '-f', selector])
        if result.returncode:
            raise PolicyError('Unable to inspect the native system routing table.')
        values.update(parse_routes(result.stdout, family))
    return values


def protected(candidate, table, own=None):
    own = {} if own is None else own
    for key, route in table.items():
        network = ipaddress.ip_network(key)
        if network.version != candidate.version or network.prefixlen == 0 or own.get(key) == route:
            continue
        if candidate.overlaps(network):
            return True
    return False


def interface_identity(name):
    try:
        index = socket.if_nametoindex(name)
    except OSError:
        return None
    result = run(['/sbin/ifconfig', '-v', name])
    if result.returncode:
        return None
    description = re.search(r'^\s*description: (.*)$', result.stdout, re.M)
    origin = re.search(r'^\s*Opened by PID (\d+)', result.stdout, re.M)
    # The kernel records the original TUN clone name even after a rename.
    tun = re.search(r'^\s*drivername: (tun\d+)\b', result.stdout, re.M)
    return {'name': name, 'index': index, 'description': description[1] if description else '',
            'opened_by': int(origin[1]) if origin else None, 'original': tun[1] if tun else ''}


def owns_interface(record):
    expected = record.get('interface')
    current = interface_identity(expected['name']) if isinstance(expected, dict) else None
    core_pid = (record.get('core') or {}).get('pid')
    return (isinstance(expected, dict) and type(core_pid) is int
            and expected.get('opened_by') == core_pid
            and expected.get('phase', 'owned') == 'owned'
            and same_interface(record, current, core_pid))


def owns_running_interface(record):
    core = record.get('core')
    supervisor = record.get('supervisor')
    return bool(record.get('mode') == 'supervised'
                and owned_supervisor(supervisor) and same_process(supervisor)
                and owned_core(core) and same_process(core)
                and owns_interface(record))


def same_interface(record, current, opener, allow_preclaim=False):
    expected = record.get('interface')
    marker = 'EasyTier owner ' + str(record.get('token', ''))
    descriptions = {marker}
    if allow_preclaim and isinstance(expected, dict) and expected.get('phase') == 'claiming':
        preclaim = expected.get('preclaim')
        if (isinstance(preclaim, dict)
                and all(preclaim.get(key) == expected.get(key)
                        for key in ('name', 'index', 'original'))
                and preclaim.get('opened_by') == (record.get('core') or {}).get('pid')
                and isinstance(preclaim.get('description'), str)):
            descriptions.add(preclaim['description'])
    return bool(isinstance(expected, dict) and isinstance(current, dict)
                and current.get('name') == expected.get('name')
                and current.get('index') == expected.get('index')
                and current.get('description') in descriptions
                and current.get('original') == expected.get('original')
                and str(current.get('original', '')).startswith('tun')
                and current.get('opened_by') == opener)



def mutate_route(action, destination, interface, owner=None):
    from native_route import mutate, RouteError
    try:
        if action == 'add':
            if owner is None:
                raise PolicyError('An exact VPN interface owner is required to add a route.')
            def exact_index(name):
                expected = owner.get('interface', {})
                if (name != interface or expected.get('name') != interface
                        or not owns_running_interface(owner)):
                    raise PolicyError('VPN interface ownership changed during route installation.')
                return expected['index']
            mutate(action, destination, interface, index=exact_index)
        else:
            mutate(action, destination, interface)
        return True
    except (RouteError, OSError, ValueError) as error:
        raise RouteMutationError(bounded_routing_diagnostic(error)
                                 or 'No native routing diagnostic was returned.') from None


def route_receipt(record, destination):
    interface = record.get('interface')
    core = record.get('core')
    try:
        network = private_network(destination)
        name, index = interface['name'], interface['index']
    except (KeyError, TypeError):
        raise PolicyError('The VPN route ownership receipt is invalid.') from None
    marker = 'EasyTier owner ' + str(record.get('token', ''))
    if (not IFNAME.fullmatch(str(name)) or type(index) is not int
            or not 1 <= index <= 0xffffffff
            or not owned_core(core, legacy=record.get('mode') == 'legacy')
            or interface.get('phase', 'owned') != 'owned'
            or interface.get('description') != marker
            or interface.get('opened_by') != core.get('pid')
            or not str(interface.get('original', '')).startswith('tun')):
        raise PolicyError('The VPN route ownership receipt is invalid.')
    flags = 'UHS' if network.prefixlen == 32 else 'US'
    return {'schema': 1, 'action': 'add', 'destination': str(network),
            'interface': name, 'interface_index': index, 'flags': flags}


def validate_route_receipt(record, receipt):
    if not isinstance(receipt, dict) or set(receipt) != {
            'schema', 'action', 'destination', 'interface', 'interface_index', 'flags'}:
        raise PolicyError('The pending VPN route receipt is invalid; the route was preserved.')
    try:
        expected = route_receipt(record, receipt['destination'])
    except PolicyError:
        raise PolicyError('The pending VPN route receipt is invalid; the route was preserved.') from None
    if receipt != expected:
        raise PolicyError('The pending VPN route receipt is invalid; the route was preserved.')
    return expected


def matches_route_receipt(route, receipt):
    return bool(isinstance(route, dict) and set(route) == ROUTE_FIELDS
                and route.get('destination') == receipt['destination']
                and route.get('interface') == receipt['interface']
                and route.get('gateway') == 'link#' + str(receipt['interface_index'])
                and set(str(route.get('flags', ''))) == set(receipt['flags'])
                and len(str(route.get('flags', ''))) == len(receipt['flags']))


def recover_pending_route(record, wanted=None, table=None):
    receipt = record.get('pending_route')
    if receipt is None:
        return routing_table() if table is None else table
    receipt = validate_route_receipt(record, receipt)
    table = routing_table() if table is None else table
    destination = receipt['destination']
    current = table.get(destination)
    if matches_route_receipt(current, receipt):
        # The receipt precedes the native add. An equal route after a crash can
        # be either our result or an administrator's concurrent route, so exact
        # equality is insufficient authority to adopt or delete it.
        record['route_recovery_ambiguous'] = True
        write_journal(record)
        raise PolicyError(
            'A pending VPN route has ambiguous ownership and was preserved.')
    # An absent route means the add never settled. A different route is a
    # concurrent owner's route and must survive with only our stale intent retired.
    record.pop('pending_route', None)
    record.pop('route_recovery_ambiguous', None)
    record['imported_route_count'] = len(record.get('routes', {}))
    write_journal(record)
    return table

def remove_routes(record):
    table = recover_pending_route(record)
    for destination, expected in list(record.get('routes', {}).items()):
        diagnostic = ''
        removed = True
        if table.get(destination) == expected:
            try:
                removed = mutate_route('delete', destination, expected['interface'])
            except RouteMutationError as error:
                removed, diagnostic = False, str(error)
        latest = routing_table()
        if latest.get(destination) == expected:
            raise PolicyError(route_status_error(
                'An owned VPN route could not be removed. Its ownership journal was retained.', diagnostic))
        table = latest
        record['routes'].pop(destination, None)
    record['imported_route_count'] = len(record.get('routes', {}))
    write_journal(record)


def cleanup_interface(record):
    expected = record.get('interface')
    if expected is None:
        return
    if not isinstance(expected, dict) or not IFNAME.fullmatch(str(expected.get('name', ''))):
        raise PolicyError('The VPN TUN ownership journal is invalid; the interface was preserved.')
    core_pid = (record.get('core') or {}).get('pid')
    if type(core_pid) is not int or expected.get('opened_by') != core_pid:
        raise PolicyError('The VPN TUN opener receipt is invalid; the interface was preserved.')
    name = expected['name']
    current = interface_identity(name)
    if current is None:
        try:
            socket.if_nametoindex(name)
        except OSError:
            record.pop('interface', None)
            record.pop('overlay_routes', None)
            return
        raise PolicyError('The VPN TUN interface could not be inspected; cleanup will be retried.')
    if not same_interface(record, current, None, allow_preclaim=True):
        # The name was reused or changed by an administrator. Retire only our
        # stale receipt and leave the foreign interface untouched.
        record.pop('interface', None)
        record.pop('overlay_routes', None)
        return
    try:
        result = run(['/sbin/ifconfig', name, 'destroy'])
        detail = getattr(result, 'stderr', '') or getattr(result, 'stdout', '')
    except (OSError, subprocess.SubprocessError) as error:
        result, detail = None, str(error)
    after = interface_identity(name)
    if after is None:
        try:
            socket.if_nametoindex(name)
        except OSError:
            record.pop('interface', None)
            record.pop('overlay_routes', None)
            return
        raise PolicyError('The VPN TUN interface could not be verified after destruction; cleanup will be retried.')
    if same_interface(record, after, None, allow_preclaim=True):
        diagnostic = bounded_routing_diagnostic(detail)
        raise PolicyError(route_status_error(
            'The owned VPN TUN interface could not be destroyed; its ownership journal was retained.', diagnostic))
    # A concurrent foreign replacement is never removed. Its different exact
    # identity proves that our ownership receipt is stale.
    record.pop('interface', None)
    record.pop('overlay_routes', None)


def cleanup(record):
    # Never flush PF states, reload global PF, or alter routes changed by an administrator.
    failures = []
    try:
        remove_routes(record)
    except (PolicyError, OSError, ValueError, subprocess.SubprocessError) as error:
        failures.append(error)
    try:
        cleanup_interface(record)
    except (PolicyError, OSError, ValueError, subprocess.SubprocessError) as error:
        failures.append(error)
    try:
        expected = record.get('core')
        if CORE_PID.exists() or CORE_PID.is_symlink():
            pid = read_pidfile()
            current = identity(pid)
            # Remove only the PID file we wrote for this exact process, after
            # that process has exited. Reused or foreign PIDs keep their file.
            if (isinstance(expected, dict) and pid == expected.get('pid')
                    and current is None and (owned_core(expected)
                                             or owned_core(expected, legacy=True))):
                CORE_PID.unlink()
                fsync_directory(CORE_PID.parent)
    except (OSError, PolicyError) as error:
        failures.append(error)
    try:
        if RUNTIME.exists():
            RUNTIME.unlink()
    except OSError as error:
        failures.append(error)
    record['active'] = False
    if failures:
        record['cleanup_pending'] = True
        record['cleanup_error'] = route_status_error(
            'Owned EasyTier network cleanup is incomplete and will be retried.', failures[0])
    else:
        record.pop('cleanup_pending', None)
        record.pop('cleanup_error', None)
    write_journal(record)
    if failures:
        raise PolicyError(record['cleanup_error']) from failures[0]


def learned_routes(text):
    if len(text.encode()) > LIMIT:
        raise PolicyError('The learned VPN route response exceeds the supported size.')
    data = json.loads(text)
    if not isinstance(data, list) or len(data) > 1024:
        raise PolicyError('The learned VPN route response format is unsupported.')
    result = []
    for row in data:
        if not isinstance(row, dict) or not isinstance(row.get('proxy_cidrs'), str):
            raise PolicyError('The learned VPN route response format is unsupported.')
        if row.get('next_hop_hostname') == 'Local' and row.get('next_hop_ipv4') == '-':
            continue
        result.extend(x.strip() for x in row['proxy_cidrs'].split(',') if x.strip())
    if len(result) > 1024:
        raise PolicyError('The learned VPN route response exceeds the supported route count.')
    return result


def sync_routes(record, candidates, table=None):
    table = routing_table() if table is None else table
    candidates_valid, wanted = set(), set()
    rejected = {'public_or_invalid': 0, 'native_conflict': 0}
    own = record['routes']
    previous_error = record.get('error', '')
    diagnostics = []
    for value in set(candidates):
        try:
            candidate = private_network(value)
        except PolicyError:
            rejected['public_or_invalid'] += 1
            continue
        candidates_valid.add(str(candidate))
    table = recover_pending_route(record, candidates_valid, table)
    own = record['routes']
    for value in candidates_valid:
        candidate = private_network(value)
        if protected(candidate, table, own):
            rejected['native_conflict'] += 1
        else:
            wanted.add(str(candidate))
    # A newly added native route wins over an overlapping imported VPN route.
    for destination, expected in list(own.items()):
        if destination not in wanted or table.get(destination) != expected:
            diagnostic = ''
            withdrawn = True
            if table.get(destination) == expected:
                try:
                    withdrawn = mutate_route('delete', destination, expected['interface'])
                except RouteMutationError as error:
                    withdrawn, diagnostic = False, str(error)
            latest = routing_table()
            if latest.get(destination) == expected:
                raise PolicyError(route_status_error(
                    'An owned VPN route could not be withdrawn. Its ownership journal was retained.', diagnostic))
            table = latest
            own.pop(destination, None)
    for destination in sorted(wanted - own.keys()):
        latest = routing_table()
        candidate = ipaddress.ip_network(destination)
        if protected(candidate, latest, own) or destination in latest:
            rejected['native_conflict'] += 1
            continue
        receipt = route_receipt(record, destination)
        record['pending_route'] = receipt
        record.pop('route_recovery_ambiguous', None)
        write_journal(record)
        # EXCL prevents replacement, while this second inspection closes the
        # interval between the first absence check and the durable intent.
        latest = routing_table()
        if (protected(candidate, latest, own) or destination in latest
                or not owns_running_interface(record)):
            record.pop('pending_route', None)
            write_journal(record)
            if destination in latest:
                rejected['native_conflict'] += 1
                continue
            raise PolicyError('VPN interface ownership changed before a route could be installed.')
        try:
            inserted_ok = mutate_route('add', destination, record['interface']['name'], record)
        except RouteMutationError as error:
            inserted_ok = False
            diagnostics.append(str(error))
        inserted = routing_table().get(destination)
        if inserted_ok and matches_route_receipt(inserted, receipt):
            own[destination] = inserted
        elif not inserted_ok and matches_route_receipt(inserted, receipt):
            record['route_recovery_ambiguous'] = True
            write_journal(record)
            raise PolicyError(
                'A failed VPN route add left an equal route with ambiguous ownership; it was preserved.')
        else:
            rejected['installation_failure'] = rejected.get('installation_failure', 0) + 1
        record.pop('pending_route', None)
        record.pop('route_recovery_ambiguous', None)
        record['imported_route_count'] = len(own)
        write_journal(record)
    if rejected.get('installation_failure'):
        details = ' '.join(dict.fromkeys(diagnostics))
        record['error'] = route_status_error(
            'Some private VPN routes could not be installed.', details or 'Check the private EasyTier log.')
        if record['error'] != previous_error:
            print(record['error'], file=sys.stderr, flush=True)
    else:
        record['error'] = ''
    record['rejected_routes'] = rejected
    record['imported_route_count'] = len(own)
    write_journal(record)


def load_record():
    try:
        descriptor = os.open(JOURNAL, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return {}
    with os.fdopen(descriptor, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_mode & 0o022):
            raise PolicyError('The EasyTier ownership journal has foreign ownership or writers.')
        content = stream.read(LIMIT + 1)
    if len(content) > LIMIT:
        raise PolicyError('The EasyTier ownership journal exceeds its supported size.')
    try:
        record = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise PolicyError('The EasyTier ownership journal is invalid.') from None
    if not isinstance(record, dict):
        raise PolicyError('The EasyTier ownership journal is invalid.')
    rebase_record_births(record)
    return record


def public_status():
    try:
        record = load_record()
        error = record.get('cleanup_error') or record.get('error', '')
        if not isinstance(error, str):
            raise TypeError
        error = bounded_routing_diagnostic(error)
        core = record.get('core')
        supervisor = record.get('supervisor')
        if (record.get('active') and owned_core(core) and same_process(core)
                and not (owned_supervisor(supervisor) and same_process(supervisor))):
            error = 'The VPN supervisor is not running. Stop the service and restart it explicitly.'
        return {'imported_routes': record.get('imported_route_count', 0),
                'rejected_routes': record.get('rejected_routes', {}), 'network_error': error}
    except (OSError, ValueError, TypeError):
        return {'imported_routes': 0, 'rejected_routes': {}, 'network_error': 'Unable to inspect VPN route supervision.'}




def terminate_core(record):
    core = record.get('core')
    arguments = core_arguments(core, legacy=record.get('mode') == 'legacy')
    if arguments is None:
        return 1 if same_process(core) else 0
    if not same_process(core):
        return 0
    if not signal_process(core, signal.SIGTERM, arguments):
        return 1 if same_process(core) else 0
    for _ in range(50):
        if not same_process(core):
            return 0
        time.sleep(.1)
    if same_process(core):
        if not signal_process(core, signal.SIGKILL, arguments):
            return 1 if same_process(core) else 0
    for _ in range(20):
        if not same_process(core):
            return 0
        time.sleep(.1)
    return 1

def stop_legacy():
    if not CORE_PID.exists() and not CORE_PID.is_symlink():
        return 0
    pid = read_pidfile()
    core = identity(pid)
    if core is None:
        # A dead process cannot own the legacy PID file. Remove only the same
        # still-stale numeric file so a crash does not block every later start.
        if read_pidfile() == pid and identity(pid) is None:
            CORE_PID.unlink()
            fsync_directory(CORE_PID.parent)
            return 0
        return 1
    # The administrator may have saved a new RPC portal while the legacy Core
    # is still using the old one.  The immutable process receipt already proves
    # the fixed binary and config path; requiring today's config value would
    # make an ordinary restart or package upgrade unable to stop that Core.
    arguments = core_arguments(core, legacy=True)
    if arguments is None:
        return 1
    try:
        flags = tomllib.loads(CONFIG.read_text()).get('flags', {})
        name = flags.get('dev_name') or 'easytier0'
    except (OSError, ValueError, AttributeError):
        name = ''
    current = interface_identity(name) if isinstance(name, str) and IFNAME.fullmatch(name) else None
    record = {'schema': 1, 'mode': 'legacy', 'token': secrets.token_hex(16),
              'core': core, 'routes': {}, 'active': False, 'boot': boot_token(),
              'rejected_routes': {}, 'imported_route_count': 0, 'error': ''}
    if current and current['opened_by'] == core['pid'] and current['original'].startswith('tun'):
        receipt = {**current, 'phase': 'claiming', 'preclaim': dict(current)}
        record['interface'] = receipt
        write_journal(record)
        if interface_identity(name) != current or not same_process(core):
            return 1
        if run(['/sbin/ifconfig', name, 'description', 'EasyTier owner ' + record['token']]).returncode:
            return 1
        claimed = interface_identity(name)
        if isinstance(claimed, dict):
            record['interface'] = {**claimed, 'phase': 'owned'}
        if not same_interface(record, claimed, core['pid']):
            record['interface'] = receipt
            write_journal(record)
            return 1
    write_journal(record)
    if terminate_core(record):
        return 1
    cleanup(record)
    return 0


def stop():
    record = load_record()
    if not record:
        return stop_legacy()
    owner = record.get('supervisor')
    if not (owned_supervisor(owner) and same_process(owner)):
        # A stale journal cannot authorize killing a reused PID.
        stop_launcher(record)
        core = record.get('core')
        if record and owned_core(core, legacy=record.get('mode') == 'legacy') and same_process(core):
            remove_routes(record)
            if terminate_core(record):
                raise PolicyError('The owned EasyTier Core could not be stopped; cleanup will be retried.')
        if record:
            cleanup(record)
        return stop_legacy()
    if not signal_process(owner, signal.SIGTERM, supervisor_arguments(owner)):
        raise PolicyError('EasyTier supervision changed before shutdown; owned network state was preserved.')
    for _ in range(80):
        if not same_process(owner):
            current = load_record()
            # Never let an old stop request tear down a replacement supervisor.
            if current.get('supervisor') not in (None, owner):
                raise PolicyError('EasyTier supervision changed during shutdown; cleanup was preserved.')
            if current:
                stop_launcher(current)
            core = current.get('core') if current else None
            if (current and owned_core(core, legacy=current.get('mode') == 'legacy')
                    and same_process(core)):
                remove_routes(current)
                if terminate_core(current):
                    raise PolicyError('The owned EasyTier Core could not be stopped; cleanup will be retried.')
            if current:
                cleanup(current)
                verified = load_record()
                if (verified.get('routes') or verified.get('interface')
                        or verified.get('cleanup_pending')):
                    raise PolicyError('Owned EasyTier network cleanup is incomplete and will be retried.')
            return stop_legacy()
        time.sleep(.1)
    return 1


def supervise():
    from manage import render, rpc_portal
    ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    root_info = ROOT.stat()
    if (not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != os.geteuid()
            or root_info.st_mode & 0o077):
        raise PolicyError('The EasyTier runtime directory has unsafe ownership or permissions.')
    descriptor = os.open(ROOT / 'lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'a') as lock:
        lock_info = os.fstat(lock.fileno())
        if (not stat.S_ISREG(lock_info.st_mode) or lock_info.st_uid != os.geteuid()
                or lock_info.st_mode & 0o022):
            raise PolicyError('The EasyTier runtime lock has foreign ownership or writers.')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        previous = load_record()
        if previous:
            stop_launcher(previous)
            core = previous.get('core')
            if (owned_core(core, legacy=previous.get('mode') == 'legacy')
                    and same_process(core)):
                raise PolicyError('An existing EasyTier Core is still running.')
            cleanup(previous)
        if CORE_PID.exists() or CORE_PID.is_symlink():
            if stop_legacy():
                raise PolicyError('An existing EasyTier PID file is not owned by this service and was preserved.')
        data = tomllib.loads(CONFIG.read_text())
        portal = rpc_portal(for_connection=False)
        name = validate_live_configuration(data)
        no_tun = data.get('flags', {}).get('no_tun', False)
        if not no_tun and interface_identity(name):
            raise PolicyError('The configured TUN name already belongs to an existing interface. Choose an unused device name.')
        runtime = copy.deepcopy(data)
        runtime['routes'] = []
        runtime.setdefault('flags', {})['dev_name'] = name
        atomic(RUNTIME, render(runtime))
        supervisor = capture_supervisor(os.getpid())
        record = {'schema': 1, 'mode': 'supervised', 'token': secrets.token_hex(16),
                  'supervisor': supervisor, 'active': False, 'boot': boot_token(),
                  'routes': {}, 'rejected_routes': {}, 'imported_route_count': 0, 'error': ''}
        interrupted = False
        def terminate(_number, _frame):
            nonlocal interrupted
            interrupted = True
        signal.signal(signal.SIGTERM, terminate)
        signal.signal(signal.SIGINT, terminate)
        child_arguments = [CORE, '--config-file', str(RUNTIME), '--rpc-portal', portal]
        child = None
        read_descriptor = None
        release_descriptor = None
        try:
            read_descriptor, release_descriptor = os.pipe()
            launch_arguments = launcher_arguments(
                descriptor=read_descriptor, portal=portal)
            child = subprocess.Popen(
                launch_arguments, pass_fds=(read_descriptor,), close_fds=True)
            os.close(read_descriptor)
            read_descriptor = None
            record['launcher'] = capture_process(
                child.pid, launch_arguments, os.getpid())
            write_journal(record)
            if interrupted:
                raise PolicyError('EasyTier launch was interrupted before Core execution.')
            if os.write(release_descriptor, b'1') != 1:
                raise PolicyError('The EasyTier launch handshake was incomplete.')
            os.close(release_descriptor)
            release_descriptor = None
            record['core'] = capture_core_transition(
                record['launcher'], child_arguments)
            record.pop('launcher', None)
            write_journal(record)
            create_pidfile(child.pid)
            if not no_tun:
                for _ in range(150):
                    current = interface_identity(name)
                    if current:
                        # Reject a clone demonstrably opened by a different process.
                        if current['opened_by'] != child.pid or not current['original'].startswith('tun'):
                            raise PolicyError('The new TUN interface is opened by another process.')
                        receipt = dict(current)
                        receipt['phase'] = 'claiming'
                        receipt['preclaim'] = dict(current)
                        record['interface'] = receipt
                        # Persist the exact unmarked interface before mutation.
                        # Recovery can then match either side if this process dies.
                        write_journal(record)
                        if interface_identity(name) != current or not same_process(record.get('core')):
                            raise PolicyError('The VPN TUN interface changed before ownership was marked.')
                        result = run(['/sbin/ifconfig', name, 'description', 'EasyTier owner ' + record['token']])
                        if result.returncode:
                            raise PolicyError('Unable to record ownership of the VPN TUN interface.')
                        claimed = interface_identity(name)
                        if isinstance(claimed, dict):
                            record['interface'] = {**claimed, 'phase': 'owned'}
                        if not owns_running_interface(record):
                            # Keep the durable preclaim receipt when post-mark
                            # inspection fails. Cleanup can match either the
                            # unmarked or marked side after the Core closes it.
                            record['interface'] = receipt
                            raise PolicyError('Unable to verify ownership of the VPN TUN interface.')
                        write_journal(record)
                        break
                    if interrupted or child.poll() is not None:
                        raise PolicyError('EasyTier Core exited before creating its TUN interface.')
                    time.sleep(.1)
                else:
                    raise PolicyError('EasyTier Core did not create its configured TUN interface.')
            if not no_tun:
                expected = set()
                for key in ('ipv4', 'ipv6'):
                    if data.get(key):
                        address = ipaddress.ip_interface(data[key])
                        expected.update((str(address.network), str(ipaddress.ip_network(str(address.ip)))))
                record['overlay_routes'] = {key: route for key, route in routing_table().items() if key in expected}
            record['active'] = True
            write_journal(record)
            failures = 0
            while not interrupted and child.poll() is None:
                enabled = run(['/usr/sbin/sysrc', '-n', '-f', '/etc/rc.conf.d/easytier', 'easytier_enable'])
                if enabled.returncode:
                    raise PolicyError('Unable to read the service enable state. VPN routes were withdrawn.')
                if enabled.stdout.strip().upper() not in ('YES', 'TRUE', 'ON', '1'):
                    break
                try:
                    result = run([CLI, '-p', rpc_portal(), '-o', 'json', 'route'], timeout=3)
                except subprocess.TimeoutExpired:
                    result = subprocess.CompletedProcess([], 1, '', '')
                if result.returncode:
                    failures += 1
                    if failures >= 3:
                        raise PolicyError('Core RPC stopped responding. VPN routes were withdrawn; restart the service after checking its log.')
                else:
                    failures = 0
                    candidates = data['routes'] if 'routes' in data else learned_routes(result.stdout)
                    if not no_tun:
                        if not owns_running_interface(record):
                            raise PolicyError('VPN interface ownership changed. Imported VPN routes were withdrawn.')
                        sync_routes(record, candidates)
                for _ in range(20):
                    if interrupted or child.poll() is not None:
                        break
                    time.sleep(.1)
        except (PolicyError, OSError, ValueError, subprocess.SubprocessError) as error:
            record['error'] = bounded_routing_diagnostic(str(error)) if isinstance(error, PolicyError) else 'VPN route supervision stopped. Check the private EasyTier log and configuration.'
            raise
        finally:
            for descriptor in (read_descriptor, release_descriptor):
                if descriptor is not None:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
            try:
                stop_launcher(record)
                remove_routes(record)
            finally:
                if child is not None and child.poll() is None:
                    if terminate_core(record):
                        raise PolicyError('The owned EasyTier Core could not be stopped; cleanup will be retried.')
                cleanup(record)
    return 0


def main():
    try:
        action = sys.argv[1]
        if action == 'launch':
            if len(sys.argv) != 4:
                raise PolicyError('The EasyTier launch handshake is invalid.')
            return launcher(sys.argv[2], sys.argv[3])
        if action == 'run':
            return supervise()
        if action == 'stop':
            return stop()
        if action == 'status':
            record = load_record()
            core = record.get('core')
            supervisor = record.get('supervisor')
            return 0 if (record.get('active') and owned_core(core) and same_process(core)
                         and owned_supervisor(supervisor) and same_process(supervisor)) else 1
        if action == 'enabled':
            result = run(['/usr/sbin/sysrc', '-n', '-f', '/etc/rc.conf.d/easytier', 'easytier_enable'])
            return 0 if result.returncode == 0 and result.stdout.strip().upper() in ('YES', 'TRUE', 'ON', '1') else 1
        if action == 'check':
            from manage import rpc_portal
            rpc_portal(for_connection=False)
            data = tomllib.loads(CONFIG.read_text())
            validate_live_configuration(data)
            return 0
        raise PolicyError('Unknown networking action.')
    except (OSError, ValueError, KeyError, IndexError, subprocess.SubprocessError) as error:
        print(bounded_routing_diagnostic(error) if isinstance(error, PolicyError)
              else 'Unable to supervise EasyTier networking.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
