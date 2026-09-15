"""Safely own FreeBSD routes shared by network plugins."""

import argparse
import contextlib
import ctypes
import errno
import fcntl
import ipaddress
import json
import os
import re
import socket
import stat
import struct
import sys
import time


# FreeBSD 14/15 netlink headers use fixed-width fields and four-byte alignment.
HEADER = struct.Struct('=IHHII')
ROUTE = struct.Struct('=BBBBBBBBI')
ATTRIBUTE = struct.Struct('=HH')
U32 = struct.Struct('=I')
AF_NETLINK = 38
NETLINK_ROUTE = 0
REQUEST, ACK, EXCL, CREATE = 1, 4, 0x200, 0x400
NEWROUTE, DELROUTE, GETROUTE, ERROR = 24, 25, 26, 2
DST, OIF, GATEWAY, RTFLAGS, TABLE = 1, 4, 5, 14, 15
PREFIX = 0x800
UP, GW, HOST, REJECT, LLDATA, STATIC, BLACKHOLE = 1, 2, 4, 8, 0x400, 0x800, 0x1000
TIMEOUT = 5
LIMIT = 1024 * 1024
RESERVE_ATTEMPTS = 3
RESERVE_BACKOFF = 0.5
IFNAME = re.compile(r'[A-Za-z0-9_.-]{1,15}\Z')
ROUTE_IDENTITY = ('family', 'destination', 'scope', 'gateway', 'interface', 'flags')
ROUTE_SEMANTIC = ('family', 'destination', 'scope', 'gateway', 'interface', 'discard')
__all__ = [
    'ACK', 'AF_NETLINK', 'ATTRIBUTE', 'BLACKHOLE', 'CREATE', 'DELROUTE', 'DST', 'ERROR',
    'EXCL', 'GATEWAY', 'GETROUTE', 'GW', 'HEADER', 'HOST', 'IFNAME', 'LIMIT',
    'LLDATA', 'NETLINK_ROUTE', 'NEWROUTE', 'OIF', 'PREFIX', 'REJECT',
    'REQUEST', 'RESERVE_ATTEMPTS', 'RESERVE_BACKOFF', 'ROUTE', 'RTFLAGS',
    'RouteAmbiguous', 'RouteError', 'RouteRejected', 'STATIC', 'TABLE', 'TIMEOUT', 'U32', 'UP',
    'add', 'align', 'attribute', 'attributes', 'check_direct', 'check_source',
    'direct_identity', 'direct_payload', 'direct_state', 'exchange',
    'fib_reservation_lock', 'format_command_failure', 'installed', 'main', 'mutate', 'open_socket',
    'parse_network', 'parse_route_table', 'payload', 'private_fib_occupied',
    'reserve_private_fib', 'route_identity', 'route_key', 'route_semantic',
    'scoped_address', 'validate',
]


class RouteError(Exception):
    pass


class RouteRejected(OSError):
    """The kernel answered with an errno, so its verdict on the request is final."""


class RouteAmbiguous(RouteError):
    """Readback matches after transport failure, without proving who added it."""


def format_command_failure(args, value, limit=512):
    """Return one bounded line while retaining a helper's own diagnosis."""
    name = os.path.basename(args[0])
    if name.startswith('python') and len(args) > 1:
        name = os.path.basename(args[1])
    detail = ' '.join((value.stderr or b'').decode(errors='replace').split())[:limit]
    return 'The %s operation failed with status %d.%s' % (
        name, value.returncode, ' ' + detail if detail else '')


def parse_network(value, family=None):
    """Decode netstat's shortened IPv4 destinations and scoped IPv6 prefixes."""
    if value == 'default':
        return ipaddress.ip_network('0.0.0.0/0' if family == 4 else '::/0'), ''
    address, slash, length = value.partition('/')
    address, scoped, scope = address.partition('%')
    if scoped and not IFNAME.fullmatch(scope):
        raise RouteError('An interface scope is invalid.')
    if ':' not in address:
        parts = address.split('.')
        if not all(part.isdecimal() for part in parts) or not 1 <= len(parts) <= 4:
            raise RouteError('A routing destination is invalid.')
        if not slash:
            length = str(32 if len(parts) == 4 else len(parts) * 8)
        address = '.'.join(parts + ['0'] * (4 - len(parts)))
    elif not slash:
        length = '128'
    try:
        result = ipaddress.ip_network(address + '/' + length, strict=False)
    except ValueError:
        raise RouteError('A routing destination is invalid.') from None
    if family and result.version != family:
        raise RouteError('A routing address family is inconsistent.')
    return result, scope


def route_key(route):
    return '%d:%s%%%s' % (route['family'], route['destination'], route['scope'])


def parse_route_table(text, family, limit=4 * 1024 * 1024, route_limit=8192):
    """Read numeric routes and reject ambiguous destinations before mutation."""
    if len(text.encode()) > limit:
        raise RouteError('The routing table exceeds the supported limit.')
    columns, routes = None, {}
    for line in text.splitlines():
        words = line.split()
        if not words:
            continue
        if words[0] == 'Destination':
            if 'Gateway' not in words or 'Flags' not in words or 'Netif' not in words:
                raise RouteError('The routing table format is unsupported.')
            columns = {name: words.index(name) for name in ('Destination', 'Gateway', 'Flags', 'Netif')}
            continue
        if columns is None:
            continue
        if len(words) <= max(columns.values()):
            raise RouteError('A routing table entry is incomplete.')
        destination, scope = parse_network(words[columns['Destination']], family)
        gateway = words[columns['Gateway']]
        interface, flags = words[columns['Netif']], words[columns['Flags']]
        if not IFNAME.fullmatch(interface) or not re.fullmatch(r'[A-Za-z0-9!]+', flags):
            raise RouteError('A routing table entry is invalid.')
        if gateway.startswith('link#'):
            if not re.fullmatch(r'link#[0-9]+', gateway):
                raise RouteError('A link gateway is invalid.')
            gateway = 'interface'
        else:
            address, _, zone = gateway.partition('%')
            try:
                if ipaddress.ip_address(address).version != family:
                    raise ValueError
            except ValueError:
                # Link-layer neighbour entries are not forwarding routes.
                if 'L' in flags or re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', gateway):
                    continue
                raise RouteError('A numeric gateway is required.') from None
            if zone and not IFNAME.fullmatch(zone):
                raise RouteError('A gateway scope is invalid.')
        if 'L' in flags:
            continue
        candidate = {
            'family': family, 'destination': str(destination), 'scope': scope,
            'gateway': gateway, 'interface': interface, 'flags': flags,
            'discard': 'blackhole' if 'B' in flags else 'reject' if 'R' in flags else '',
        }
        key = route_key(candidate)
        if key in routes and route_identity(routes[key]) != route_identity(candidate):
            raise RouteError('Multiple routes to one destination are unsupported.')
        routes[key] = candidate
        if len(routes) > route_limit:
            raise RouteError('The routing table exceeds the supported route count.')
    if columns is None:
        # netstat omits the column header for a genuinely empty FIB.
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        label = 'Internet:' if family == 4 else 'Internet6:'
        if (not 1 <= len(lines) <= 2
                or not re.fullmatch(r'Routing tables(?:\s*\(fib:\s*[0-9]+\))?', lines[0])
                or (len(lines) == 2 and lines[1] != label)):
            raise RouteError('The routing table has no recognized header.')
    return routes


def route_identity(route):
    return {key: route[key] for key in ROUTE_IDENTITY}


def route_semantic(route):
    """Return the forwarding identity without kernel-generated display flags."""
    return {key: route[key] for key in ROUTE_SEMANTIC}


def private_fib_occupied(native, private):
    """Accept only interface routes cloned unchanged from the main table."""
    for key, route in private.items():
        if (not ipaddress.ip_network(route['destination']).prefixlen
                or route.get('gateway') != 'interface' or route.get('discard')
                or 'G' in str(route.get('flags', '')) or key not in native
                or route_identity(route) != route_identity(native[key])):
            return True
    return False


@contextlib.contextmanager
def fib_reservation_lock(path):
    """Serialize irreversible net.fibs reservations across all plugins."""
    flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW
    if hasattr(os, 'O_CLOEXEC'):
        flags |= os.O_CLOEXEC
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, 'a') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600):
            raise RouteError('The global routing reservation lock is unsafe.')
        fcntl.flock(stream, fcntl.LOCK_EX)
        yield


def reserve_private_fib(record, get_count, set_count, occupied, save,
                        pause=time.sleep, attempts=RESERVE_ATTEMPTS,
                        backoff=RESERVE_BACKOFF, lock_path=None):
    """Reserve once, journal before inspection, and retry the same FIB."""
    if lock_path is not None:
        with fib_reservation_lock(lock_path):
            return reserve_private_fib(record, get_count, set_count, occupied, save,
                                       pause, attempts, backoff)
    count = get_count()
    if type(count) is not int or not 1 <= count <= 65535:
        raise RouteError('No supported private routing table is available.')
    if record.get('fib') is not None and record['fib'] < count:
        return record['fib']
    reserved = record.get('reserved')
    if type(reserved) is not int or not 1 <= reserved <= count:
        if count == 65535:
            raise RouteError('No supported private routing table is available.')
        reserved = count
        # net.fibs cannot be lowered. Journal the candidate before the
        # irreversible mutation so a timeout or crash reuses this exact FIB.
        record['reserved'] = reserved
        save(record)
    if reserved == count:
        if count == 65535:
            raise RouteError('No supported private routing table is available.')
        set_count(reserved + 1)
        if get_count() != reserved + 1:
            raise RouteError('The private routing table allocation could not be verified.')
    for attempt in range(attempts):
        if not occupied(reserved):
            break
        if attempt + 1 == attempts:
            raise RouteError('Private routing table ' + str(reserved)
                             + ' is occupied by routes this plugin does not own.')
        pause(backoff)
    record.update(fib=reserved, routes={}, active=False, reserved=None)
    save(record)
    return reserved


def align(length):
    return (length + 3) & ~3


def attribute(kind, data):
    length = ATTRIBUTE.size + len(data)
    return ATTRIBUTE.pack(length, kind) + data + bytes(align(length) - length)


def attributes(data):
    result, offset = {}, 0
    while offset < len(data):
        if len(data) - offset < ATTRIBUTE.size:
            raise RouteError('A native routing attribute is truncated.')
        length, kind = ATTRIBUTE.unpack_from(data, offset)
        if length < ATTRIBUTE.size or offset + align(length) > len(data) or kind in result:
            raise RouteError('A native routing attribute is invalid.')
        result[kind] = data[offset + ATTRIBUTE.size:offset + length]
        offset += align(length)
    return result


def validate(fib, wanted, index=socket.if_nametoindex):
    if type(fib) is not int or not 1 <= fib <= 65534 or not isinstance(wanted, dict):
        raise RouteError('A private routing table is required.')
    try:
        net = ipaddress.ip_network(wanted['destination'], strict=True)
        interface, scope = wanted['interface'], wanted['scope']
        gateway, separator, zone = wanted['gateway'].partition('%')
        gw = ipaddress.ip_address(gateway)
        if wanted['family'] != net.version or gw.version != net.version:
            raise ValueError
        if not IFNAME.fullmatch(interface) or (scope and scope != interface) or (separator and zone != interface):
            raise ValueError
        if wanted['discard'] not in ('', 'blackhole', 'reject'):
            raise ValueError
        if scope and net.version != 6:
            raise ValueError
        if separator and gw.version != 6:
            raise ValueError
        if gw.version == 6 and gw.is_link_local and not separator:
            raise ValueError
        if not isinstance(wanted['flags'], str) or not re.fullmatch(r'[A-Za-z0-9!]*', wanted['flags']) or 'L' in wanted['flags']:
            raise ValueError
        ifindex = index(interface)
        if not 1 <= ifindex <= 0xffffffff:
            raise ValueError
    except (KeyError, TypeError, ValueError, OSError):
        raise RouteError('The numeric routing identity is invalid.') from None
    return net, gw, ifindex


def payload(fib, wanted, net, gw, ifindex, get=False):
    family = 2 if net.version == 4 else 28
    route_type = {'': 1, 'blackhole': 6, 'reject': 8}[wanted['discard']]
    result = ROUTE.pack(family, net.prefixlen, 0, 0, 0, 4, 0, route_type, PREFIX if get else 0)
    for kind, data in ((DST, scoped_address(net.network_address, wanted['scope'], ifindex)), (OIF, U32.pack(ifindex)),
                       (TABLE, U32.pack(fib)), (GATEWAY, scoped_address(gw, '%' in wanted['gateway'], ifindex))):
        result += attribute(kind, data)
    if not get:
        flags = UP | GW | STATIC | (HOST if net.prefixlen == net.max_prefixlen else 0)
        flags |= BLACKHOLE if wanted['discard'] == 'blackhole' else REJECT if wanted['discard'] == 'reject' else 0
        result += attribute(RTFLAGS, U32.pack(flags))
    return result


def scoped_address(address, scoped, ifindex):
    raw = address.packed
    # The netlink parser embeds unicast link scope from OIF, but does not
    # embed interface/link-local multicast scope. Preserve that native key.
    if scoped and address.version == 6 and address.is_multicast and (raw[1] & 15) in (1, 2):
        if ifindex > 65535:
            raise RouteError('The multicast routing interface index is unsupported.')
        raw = raw[:2] + struct.pack('!H', ifindex) + raw[4:]
    return raw


def check_source(data, wanted, net, gw, ifindex, fib=0):
    if len(data) < ROUTE.size:
        raise RouteError('The native source route is incomplete.')
    family, prefix, _, _, _, _, _, route_type, _ = ROUTE.unpack_from(data)
    attrs = attributes(data[ROUTE.size:])
    expected_type = {'': 1, 'blackhole': 6, 'reject': 8}[wanted['discard']]
    destination = net.network_address.packed
    # IPv6 prefix export clears link-local multicast scope, while interface
    # scope remains embedded in the exported interface-local multicast key.
    if net.version == 6 and net.network_address.is_multicast and (destination[1] & 15) == 1:
        destination = scoped_address(net.network_address, wanted['scope'], ifindex)
    expected = {DST: destination, GATEWAY: gw.packed,
                OIF: U32.pack(ifindex), TABLE: U32.pack(fib)}
    if family != (2 if net.version == 4 else 28) or prefix != net.prefixlen or route_type != expected_type:
        raise RouteError('The system route changed before it could be copied.')
    if any(attrs.get(key) != value for key, value in expected.items()):
        raise RouteError('The system routing gateway or interface changed.')
    flags = attrs.get(RTFLAGS)
    if flags is None or len(flags) != U32.size or U32.unpack(flags)[0] & LLDATA:
        raise RouteError('The system route is not a forwarding route.')


def open_socket():
    if not sys.platform.startswith('freebsd'):
        raise RouteError('Native routing requires FreeBSD.')
    sock = socket.socket(AF_NETLINK, socket.SOCK_RAW, NETLINK_ROUTE)
    try:
        # CPython's address conversion varies by FreeBSD port. Bind the native
        # sockaddr directly; subsequent send/recv need no address conversion.
        libc = ctypes.CDLL(None, use_errno=True)
        libc.bind.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
        libc.bind.restype = ctypes.c_int
        libc.getsockname.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
        libc.getsockname.restype = ctypes.c_int
        address = ctypes.create_string_buffer(struct.pack('=BBHII', 12, AF_NETLINK, 0, 0, 0), 12)
        if libc.bind(sock.fileno(), address, 12):
            raise OSError(ctypes.get_errno(), 'Native routing bind failed')
        length = ctypes.c_uint32(12)
        if libc.getsockname(sock.fileno(), address, ctypes.byref(length)) or length.value != 12:
            raise RouteError('The native routing socket identity is unavailable.')
        size, family, _, pid, groups = struct.unpack('=BBHII', address.raw)
        if size != 12 or family != AF_NETLINK or not pid or groups:
            raise RouteError('The native routing socket identity is invalid.')
        return sock, pid
    except BaseException:
        sock.close()
        raise


def exchange(sock, pid, sequence, kind, flags, data, clock=time.monotonic):
    message = HEADER.pack(HEADER.size + len(data), kind, flags | REQUEST | ACK, sequence, pid) + data
    deadline = clock() + TIMEOUT
    sock.settimeout(TIMEOUT)
    if sock.send(message) != len(message):
        raise RouteError('The native routing request was incomplete.')
    received, response, acknowledged = 0, None, False
    while not acknowledged or (kind == GETROUTE and response is None):
        remaining = deadline - clock()
        if remaining <= 0:
            raise RouteError('The native routing acknowledgement timed out.')
        sock.settimeout(remaining)
        packet = sock.recv(65536)
        received += len(packet)
        if not packet or received > LIMIT:
            raise RouteError('The native routing response exceeded its limit.')
        offset = 0
        while offset < len(packet):
            if len(packet) - offset < HEADER.size:
                raise RouteError('The native routing response is truncated.')
            length, response_kind, _, seq, port = HEADER.unpack_from(packet, offset)
            if length < HEADER.size or offset + align(length) > len(packet):
                raise RouteError('The native routing message length is invalid.')
            body = packet[offset + HEADER.size:offset + length]
            offset += align(length)
            if seq != sequence or port != pid:
                continue
            if response_kind == ERROR:
                if len(body) < 4 + HEADER.size:
                    raise RouteError('The native routing acknowledgement is truncated.')
                error = struct.unpack_from('=i', body)[0]
                original = HEADER.unpack_from(body, 4)
                expected = HEADER.unpack_from(message)
                # FreeBSD's successful GET handler changes the request type
                # to NEWROUTE before constructing its ACK. All other fields
                # still identify our request, and the route reply is required.
                if kind == GETROUTE and error == 0 and original[1] == NEWROUTE:
                    expected = (expected[0], NEWROUTE, *expected[2:])
                if original != expected:
                    raise RouteError('The native routing acknowledgement identity is invalid.')
                if error:
                    raise RouteRejected(abs(error), os.strerror(abs(error)))
                acknowledged = True
            elif kind == GETROUTE and response_kind == NEWROUTE and response is None:
                response = body
            else:
                raise RouteError('The native routing reply type is invalid.')
    return response


def installed(sock, pid, fib, wanted, net, gw, ifindex):
    """Ask the kernel what the destination holds now. The question travels the
    socket that carried the add, so the answer describes the settled table."""
    try:
        body = exchange(sock, pid, 3, GETROUTE, 0, payload(fib, wanted, net, gw, ifindex, get=True))
        check_source(body, wanted, net, gw, ifindex, fib)
    except (RouteError, OSError):
        return False
    return True


def direct_identity(destination, interface, index=socket.if_nametoindex):
    if not isinstance(interface, str) or not IFNAME.fullmatch(interface):
        raise RouteError('The direct VPN route identity is invalid.')
    try:
        net = ipaddress.ip_network(destination, strict=True)
        if net.version != 4:
            raise ValueError
        ifindex = index(interface)
        if not 1 <= ifindex <= 0xffffffff:
            raise ValueError
    except (TypeError, ValueError, OSError):
        raise RouteError('The direct VPN route identity is invalid.') from None
    return net, ifindex


def direct_payload(net, ifindex, add=False, get=False):
    result = ROUTE.pack(2, net.prefixlen, 0, 0, 0, 4, 0, 1, PREFIX if get else 0)
    result += attribute(DST, net.network_address.packed)
    result += attribute(OIF, U32.pack(ifindex))
    result += attribute(TABLE, U32.pack(0))
    if add:
        flags = UP | STATIC | (HOST if net.prefixlen == 32 else 0)
        result += attribute(RTFLAGS, U32.pack(flags))
    return result


def check_direct(data, net, ifindex):
    """Recognize only the exact direct route requested by EasyTier."""
    if len(data) < ROUTE.size:
        return False
    family, prefix, _, _, _, _, _, route_type, _ = ROUTE.unpack_from(data)
    attrs = attributes(data[ROUTE.size:])
    if (family, prefix, route_type) != (2, net.prefixlen, 1):
        return False
    expected = {DST: net.network_address.packed, OIF: U32.pack(ifindex), TABLE: U32.pack(0)}
    if any(attrs.get(key) != value for key, value in expected.items()):
        return False
    flags = attrs.get(RTFLAGS)
    if flags is None or len(flags) != U32.size:
        return False
    flags = U32.unpack(flags)[0]
    return flags & (UP | STATIC) == (UP | STATIC) and not flags & (GW | LLDATA | REJECT | BLACKHOLE)


def direct_state(sock, pid, net, ifindex):
    """Return whether the exact direct route exists after an ambiguous reply."""
    try:
        body = exchange(sock, pid, 3, GETROUTE, 0, direct_payload(net, ifindex, get=True))
    except RouteRejected as error:
        if error.errno in (errno.ENOENT, errno.ESRCH):
            return False
        raise
    return check_direct(body, net, ifindex)


def mutate(action, destination, interface, connector=open_socket,
           index=socket.if_nametoindex):
    """Add or delete one exact direct-interface route in FIB 0."""
    if action not in ('add', 'delete'):
        raise RouteError('The direct VPN route identity is invalid.')
    net, ifindex = direct_identity(destination, interface, index)
    sock, pid = connector()
    with sock:
        try:
            exchange(sock, pid, 1, NEWROUTE if action == 'add' else DELROUTE,
                     CREATE | EXCL if action == 'add' else 0,
                     direct_payload(net, ifindex, add=action == 'add'))
        except RouteRejected:
            raise
        except (RouteError, OSError) as error:
            # The request may have reached the kernel before the reply failed.
            # Absence safely settles deletion. An equal route after an add can
            # also be a concurrent EXCL winner, so report it as unowned.
            current = direct_state(sock, pid, net, ifindex)
            if current is not (action == 'add'):
                raise
            if action == 'add':
                raise RouteAmbiguous(
                    'The direct route exists after an ambiguous add; ownership was not established.') from error


def add(fib, wanted, connector=open_socket, index=socket.if_nametoindex):
    net, gw, ifindex = validate(fib, wanted, index)
    sock, pid = connector()
    with sock:
        source = exchange(sock, pid, 1, GETROUTE, 0, payload(0, wanted, net, gw, ifindex, get=True))
        check_source(source, wanted, net, gw, ifindex)
        # EXCL prevents both replacing a concurrent owner's destination and
        # appending an ECMP path. Never use APPEND, REPLACE or RTF_PINNED.
        # It promises nothing about the source: a unicast reply describes only
        # the selected path, so routing.py refuses a table that answers one
        # destination twice before any copy is asked for.
        try:
            exchange(sock, pid, 2, NEWROUTE, CREATE | EXCL, payload(fib, wanted, net, gw, ifindex))
        except RouteRejected:
            raise
        except (RouteError, OSError) as error:
            # The request may already have reached the kernel, so this failure
            # says nothing about which EXCL writer installed an equal route.
            # Readback bounds the result but cannot establish provenance.
            if not installed(sock, pid, fib, wanted, net, gw, ifindex):
                raise
            raise RouteAmbiguous(
                'The private route exists after an ambiguous add; ownership was not established.') from error


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['add'])
    parser.add_argument('--fib', type=int, required=True)
    parser.add_argument('--route', required=True)
    args = parser.parse_args(argv)
    try:
        if len(args.route) > 4096:
            raise RouteError('The routing identity exceeds its supported limit.')
        add(args.fib, json.loads(args.route))
    except (RouteError, OSError, ValueError) as error:
        print('Native routing operation failed: ' + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
