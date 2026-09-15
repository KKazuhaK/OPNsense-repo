"""Check native netlink ownership and forwarding identity without changing routes."""

import errno
import importlib.util
import ipaddress
from pathlib import Path
import socket
import struct
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / 'src/usr/local/opnsense/scripts/mihomo/native_route.py'
spec = importlib.util.spec_from_file_location('mihomo_native_route', SCRIPT)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def route(destination='10.0.0.1/32', gateway='10.255.255.1', interface='wg0', scope='', discard=''):
    net = ipaddress.ip_network(destination)
    return dict(family=net.version, destination=str(net), gateway=gateway,
                interface=interface, scope=scope, discard=discard, flags='UGHS')


def reply(kind, sequence, body, pid=1234):
    raw = m.HEADER.pack(m.HEADER.size + len(body), kind, 0, sequence, pid) + body
    return raw + bytes(m.align(len(raw)) - len(raw))


def acknowledgement(message, error=0):
    _, _, _, sequence, pid = m.HEADER.unpack_from(message)
    return reply(m.ERROR, sequence, struct.pack('=i', error) + message[:m.HEADER.size], pid)


def source(wanted, index=4, table=0):
    net, gw, index = m.validate(1, wanted, lambda _: index)
    return m.payload(table, wanted, net, gw, index)


class Socket:
    def __init__(self, wanted=None, error=0):
        self.wanted = wanted or route()
        self.error, self.sent, self.packets = error, [], []
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.closed = True

    def settimeout(self, value):
        self.timeout = value

    def send(self, message):
        self.sent.append(message)
        _, kind, _, sequence, pid = m.HEADER.unpack_from(message)
        if kind == m.GETROUTE:
            self.packets.append(reply(m.NEWROUTE, sequence, source(self.wanted), pid) + acknowledgement(message))
        else:
            self.packets.append(acknowledgement(message, self.error))
        return len(message)

    def recv(self, size):
        if not self.packets:
            raise socket.timeout('synthetic timeout')
        return self.packets.pop(0)


class LostAcknowledgement(Socket):
    """Deliver the add to the kernel, then never answer it."""
    def __init__(self, wanted=None, present=None, fib=None):
        super().__init__(wanted)
        self.present, self.fib = present, fib

    def send(self, message):
        self.sent.append(message)
        _, kind, _, sequence, pid = m.HEADER.unpack_from(message)
        if kind == m.NEWROUTE:
            return len(message)
        if sequence == 1:
            body = source(self.wanted)
        elif self.fib is None:
            return len(message)
        else:
            body = source(self.present or self.wanted, table=self.fib)
        self.packets.append(reply(m.NEWROUTE, sequence, body, pid) + acknowledgement(message))
        return len(message)


class ExtraAttribute(Socket):
    """Answer the source query with one more attribute than the plugin sends."""
    def __init__(self, wanted, extra):
        super().__init__(wanted)
        self.extra = extra

    def send(self, message):
        self.sent.append(message)
        _, kind, _, sequence, pid = m.HEADER.unpack_from(message)
        if kind == m.GETROUTE:
            self.packets.append(reply(m.NEWROUTE, sequence, source(self.wanted) + self.extra, pid) + acknowledgement(message))
        else:
            self.packets.append(acknowledgement(message, self.error))
        return len(message)


class NativeRouteTests(unittest.TestCase):
    def test_cyclic_gateway_add_does_not_depend_on_target_gateway_route(self):
        wanted = route()
        sock = Socket(wanted)
        m.add(2023, wanted, lambda: (sock, 1234), lambda _: 4)
        self.assertTrue(sock.closed)
        self.assertEqual(len(sock.sent), 2)
        get, add = sock.sent
        self.assertEqual(m.HEADER.unpack_from(get)[1], m.GETROUTE)
        header = m.HEADER.unpack_from(add)
        self.assertEqual(header[1:3], (m.NEWROUTE, m.REQUEST | m.ACK | m.CREATE | m.EXCL))
        attrs = m.attributes(add[m.HEADER.size + m.ROUTE.size:])
        self.assertEqual(attrs[m.OIF], m.U32.pack(4))
        self.assertEqual(attrs[m.TABLE], m.U32.pack(2023))
        self.assertEqual(attrs[m.GATEWAY], ipaddress.ip_address('10.255.255.1').packed)
        flags = m.U32.unpack(attrs[m.RTFLAGS])[0]
        self.assertEqual(flags, m.UP | m.GW | m.STATIC | m.HOST)
        self.assertEqual(set(attrs), {m.DST, m.OIF, m.TABLE, m.GATEWAY, m.RTFLAGS})

    def test_existing_destination_errno_is_preserved_and_no_retry_overwrites(self):
        sock = Socket(error=errno.EEXIST)
        with self.assertRaises(OSError) as raised:
            m.add(3, route(), lambda: (sock, 1234), lambda _: 4)
        self.assertEqual(raised.exception.errno, errno.EEXIST)
        self.assertEqual(len(sock.sent), 2)
        self.assertTrue(sock.closed)

    def test_source_gateway_interface_prefix_and_discard_changes_prevent_add(self):
        for change in ({'gateway': '10.255.255.9'}, {'interface': 'wg1'},
                       {'destination': '10.0.0.0/24'}, {'discard': 'reject'}):
            with self.subTest(change=change):
                sock = Socket(route(**change))
                if 'interface' in change:
                    # The source's native OIF is a different interface index.
                    original = sock.recv
                    def recv(size):
                        packet = original(size)
                        old = m.attribute(m.OIF, m.U32.pack(4))
                        return packet.replace(old, m.attribute(m.OIF, m.U32.pack(5)))
                    sock.recv = recv
                with self.assertRaises(m.RouteError):
                    m.add(3, route(), lambda: (sock, 1234), lambda _: 4)
                self.assertEqual(len(sock.sent), 1)

    def test_ipv6_scopes_are_carried_by_explicit_interface(self):
        wanted = route('fe80::/64', 'fe80::1%wg0', scope='wg0')
        sock = Socket(wanted)
        m.add(3, wanted, lambda: (sock, 1234), lambda _: 4)
        attrs = m.attributes(sock.sent[-1][m.HEADER.size + m.ROUTE.size:])
        self.assertEqual(attrs[m.GATEWAY], ipaddress.ip_address('fe80::1').packed)
        self.assertEqual(m.ROUTE.unpack_from(sock.sent[-1], m.HEADER.size)[0], 28)
        self.assertEqual(attrs[m.OIF], m.U32.pack(4))

    def test_scoped_multicast_prefix_preserves_native_embedded_interface_key(self):
        wanted = route('ff02::/64', 'fe80::1%wg0', scope='wg0')
        net, gw, index = m.validate(3, wanted, lambda _: 4)
        data = m.payload(3, wanted, net, gw, index)
        attrs = m.attributes(data[m.ROUTE.size:])
        self.assertEqual(attrs[m.DST], bytes.fromhex('ff020004000000000000000000000000'))
        self.assertEqual(attrs[m.OIF], m.U32.pack(4))

    def test_reject_and_blackhole_remain_distinct(self):
        for discard, kind, flag in [('reject', 8, m.REJECT), ('blackhole', 6, m.BLACKHOLE)]:
            with self.subTest(discard=discard):
                wanted = route(discard=discard)
                sock = Socket(wanted)
                m.add(3, wanted, lambda: (sock, 1234), lambda _: 4)
                self.assertEqual(m.ROUTE.unpack_from(sock.sent[-1], m.HEADER.size)[7], kind)
                attrs = m.attributes(sock.sent[-1][m.HEADER.size + m.ROUTE.size:])
                self.assertTrue(m.U32.unpack(attrs[m.RTFLAGS])[0] & flag)

    def test_lost_acknowledgement_adopts_the_route_the_kernel_installed(self):
        wanted = route()
        sock = LostAcknowledgement(wanted, fib=2023)
        m.add(2023, wanted, lambda: (sock, 1234), lambda _: 4)
        self.assertEqual(len(sock.sent), 3)
        readback = sock.sent[2]
        self.assertEqual(m.HEADER.unpack_from(readback)[1], m.GETROUTE)
        attrs = m.attributes(readback[m.HEADER.size + m.ROUTE.size:])
        self.assertEqual(attrs[m.TABLE], m.U32.pack(2023))
        self.assertTrue(sock.closed)

    def test_lost_acknowledgement_reports_failure_when_no_route_was_installed(self):
        for present in (None, route(gateway='10.255.255.9')):
            with self.subTest(present=present):
                fib = None if present is None else 2023
                sock = LostAcknowledgement(route(), present=present, fib=fib)
                with self.assertRaises(OSError):
                    m.add(2023, route(), lambda: (sock, 1234), lambda _: 4)
                self.assertEqual(len(sock.sent), 3)
                self.assertTrue(sock.closed)

    def test_source_multipath_attribute_is_not_the_kernel_signal(self):
        # FreeBSD 15.1 answers a unicast query with the selected path and, for
        # a weighted or grouped nexthop, NL_RTA_WEIGHT. It never sends
        # NL_RTA_MULTIPATH, so neither attribute may decide a copy here.
        for kind in (13, 9):
            with self.subTest(kind=kind):
                wanted = route()
                sock = ExtraAttribute(wanted, m.attribute(kind, m.U32.pack(0)))
                m.add(3, wanted, lambda: (sock, 1234), lambda _: 4)
                self.assertEqual(len(sock.sent), 2)

    def test_invalid_identity_never_opens_socket(self):
        def forbidden():
            self.fail('An invalid identity opened a native routing socket.')
        for fib, wanted in [(0, route()), (True, route()), (65535, route()),
                            (1, route(interface='wg0;id')), (1, route(scope='wg1')),
                            (1, route(gateway='10.0.0.1%wg0')),
                            (1, route('::/0', 'fe80::1')),
                            (1, route('::/0', 'fe80::1%wg1')),
                            (1, {**route(), 'flags': 'UGHL'})]:
            with self.subTest(fib=fib, wanted=wanted), self.assertRaises(m.RouteError):
                m.add(fib, wanted, forbidden, lambda _: 4)

    def test_acknowledgement_requires_embedded_request_identity(self):
        sock = Socket()
        original = sock.recv
        def recv(size):
            packet = bytearray(original(size))
            # The embedded request sequence differs from its envelope.
            struct.pack_into('=I', packet, m.HEADER.size + 4 + 8, 99)
            return bytes(packet)
        sock.recv = recv
        with self.assertRaises(m.RouteError):
            m.exchange(sock, 1234, 2, m.NEWROUTE, m.CREATE | m.EXCL, b'')

    def test_wrong_sequence_and_port_are_ignored_until_matching_ack(self):
        sock = Socket()
        original = sock.recv
        def recv(size):
            packet = original(size)
            wrong_sequence = bytearray(packet)
            struct.pack_into('=I', wrong_sequence, 8, 99)
            wrong_port = bytearray(packet)
            struct.pack_into('=I', wrong_port, 12, 99)
            return bytes(wrong_sequence) + bytes(wrong_port) + packet
        sock.recv = recv
        self.assertIsNone(m.exchange(sock, 1234, 2, m.NEWROUTE, m.CREATE | m.EXCL, b''))

    def test_ack_before_source_reply_is_supported(self):
        sock = Socket()
        original = sock.recv
        def recv(size):
            packet = original(size)
            first_length = m.HEADER.unpack_from(packet)[0]
            return packet[m.align(first_length):] + packet[:m.align(first_length)]
        sock.recv = recv
        self.assertEqual(m.exchange(sock, 1234, 1, m.GETROUTE, 0, b''), source(route()))

    def test_native_get_ack_changes_only_request_type_after_success(self):
        sock = Socket()
        original = sock.recv
        def recv(size):
            packet = bytearray(original(size))
            first_length = m.HEADER.unpack_from(packet)[0]
            struct.pack_into('=H', packet, m.align(first_length) + m.HEADER.size + 4 + 4, m.NEWROUTE)
            return bytes(packet)
        sock.recv = recv
        self.assertEqual(m.exchange(sock, 1234, 1, m.GETROUTE, 0, b''), source(route()))

    def test_native_get_error_cannot_use_successful_ack_type_transition(self):
        sock = Socket()
        def recv(size):
            message = bytearray(sock.sent[-1])
            struct.pack_into('=H', message, 4, m.NEWROUTE)
            return acknowledgement(bytes(message), errno.ESRCH)
        sock.recv = recv
        with self.assertRaises(m.RouteError):
            m.exchange(sock, 1234, 1, m.GETROUTE, 0, b'')

    def test_ack_timeout_and_response_limits_are_bounded(self):
        sock = Socket()
        sock.recv = lambda _: reply(m.ERROR, 999, bytes(20))
        ticks = iter([0, 0, 6])
        with self.assertRaises(m.RouteError):
            m.exchange(sock, 1234, 2, m.NEWROUTE, m.CREATE | m.EXCL, b'', lambda: next(ticks))

        limit = m.LIMIT
        try:
            m.LIMIT = 64
            sock = Socket()
            sock.recv = lambda _: reply(m.ERROR, 999, bytes(64))
            with self.assertRaises(m.RouteError):
                m.exchange(sock, 1234, 2, m.NEWROUTE, m.CREATE | m.EXCL, b'')
        finally:
            m.LIMIT = limit

    def test_truncated_messages_and_duplicate_attributes_are_rejected(self):
        for packet in [b'x', m.HEADER.pack(15, m.ERROR, 0, 2, 1234),
                       reply(m.ERROR, 2, b'\0' * 4)]:
            with self.subTest(packet=packet):
                sock = Socket()
                sock.recv = lambda _: packet
                with self.assertRaises(m.RouteError):
                    m.exchange(sock, 1234, 2, m.NEWROUTE, m.CREATE | m.EXCL, b'')
        value = m.attribute(m.OIF, m.U32.pack(4))
        for data in (value + value, b'x', m.ATTRIBUTE.pack(3, 4), m.ATTRIBUTE.pack(8, 4)):
            with self.subTest(data=data), self.assertRaises(m.RouteError):
                m.attributes(data)


if __name__ == '__main__':
    unittest.main()
