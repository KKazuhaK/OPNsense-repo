#!/usr/local/bin/python3
"""Add numeric gateway routes with an explicit interface and exclusive ownership."""

import argparse
import ctypes
import ipaddress
import json
import os
import re
import socket
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
NEWROUTE, GETROUTE, ERROR = 24, 26, 2
DST, OIF, GATEWAY, RTFLAGS, TABLE = 1, 4, 5, 14, 15
PREFIX = 0x800
UP, GW, HOST, REJECT, LLDATA, STATIC, BLACKHOLE = 1, 2, 4, 8, 0x400, 0x800, 0x1000
TIMEOUT = 5
LIMIT = 1024 * 1024
IFNAME = re.compile(r'[A-Za-z0-9_.-]{1,15}\Z')


class RouteError(Exception):
    pass


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


def check_source(data, wanted, net, gw, ifindex):
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
                OIF: U32.pack(ifindex), TABLE: U32.pack(0)}
    if family != (2 if net.version == 4 else 28) or prefix != net.prefixlen or route_type != expected_type:
        raise RouteError('The system route changed before it could be copied.')
    if any(attrs.get(key) != value for key, value in expected.items()) or 9 in attrs:
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
                    raise OSError(abs(error), os.strerror(abs(error)))
                acknowledged = True
            elif kind == GETROUTE and response_kind == NEWROUTE and response is None:
                response = body
            else:
                raise RouteError('The native routing reply type is invalid.')
    return response


def add(fib, wanted, connector=open_socket, index=socket.if_nametoindex):
    net, gw, ifindex = validate(fib, wanted, index)
    sock, pid = connector()
    with sock:
        source = exchange(sock, pid, 1, GETROUTE, 0, payload(0, wanted, net, gw, ifindex, get=True))
        check_source(source, wanted, net, gw, ifindex)
        # EXCL prevents both replacing a concurrent owner's destination and
        # appending an ECMP path. Never use APPEND, REPLACE or RTF_PINNED.
        exchange(sock, pid, 2, NEWROUTE, CREATE | EXCL, payload(fib, wanted, net, gw, ifindex))


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
