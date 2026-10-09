"""Release the fast TCP path's connections the core keeps after their client has gone."""
import copy
import itertools
import json
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest import mock
from urllib import parse as urlparse

from test_mihomo import Clock, SUBSCRIPTION, m
from test_core_recovery import RecoveryCase, RecoverySystem

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'src'
PORT = m.REDIRECT_PORT

# What `netstat -an -p tcp` prints on FreeBSD 15: an IPv4 endpoint is
# a.b.c.d.port, the protocol carries its family, and the state is padded to
# eleven columns. The core's own outbound sockets, the controller's, IPv6 and
# listeners on other addresses and ports are all in the same list.
NETSTAT = '''Active Internet connections (including servers)
Proto Recv-Q Send-Q Local Address          Foreign Address        (state)
tcp4       0      0 127.0.0.1.7894         192.168.3.25.52114     ESTABLISHED
tcp4       0      0 127.0.0.1.7894         192.168.3.40.40812     CLOSED
tcp4       0      0 127.0.0.1.7894         192.168.3.41.51234     FIN_WAIT_2
tcp4       0      0 127.0.0.1.7894         192.168.3.42.60001     CLOSE_WAIT
tcp4       0      0 127.0.0.1.7894         192.168.3.43.1025      TIME_WAIT
tcp4       0  32768 127.0.0.1.7894         10.0.0.7.65535         ESTABLISHED
tcp4       0      0 127.0.0.1.7894         192.168.3.40.40812     ESTABLISHED
tcp4       0      0 127.0.0.1.7894         *.*                    LISTEN
tcp4       0      0 192.168.3.1.43210      142.250.1.188.5228     FIN_WAIT_2
tcp4       0      0 203.0.113.2.38811      198.51.100.9.28256     FIN_WAIT_2
tcp4       0      0 127.0.0.1.9090         127.0.0.1.31544        TIME_WAIT
tcp4       0      0 127.0.0.1.17894        192.168.3.9.1234       CLOSED
tcp4       0      0 127.0.0.10.7894        192.168.3.9.1235       CLOSED
tcp4       0      0 192.168.3.1.7894         192.168.3.9.1236     CLOSED
tcp6       0      0 ::1.7894               ::1.40000              CLOSED
tcp6       0      0 *.22                   *.*                    LISTEN
tcp46      0      0 *.443                  *.*                    LISTEN
udp4       0      0 127.0.0.1.7894         192.168.3.9.1237
tcp4       0      0 127.0.0.1.7894         192.168.3.250.7        12
tcp4       0      0 127.0.0.1.7894         192.168.3.251.8
tcp4       0      0 127.0.0.1.7894         192.168.3.256.9        CLOSED
tcp4       0      0 127.0.0.1.7894         192.168.3.9.0          CLOSED
tcp4       0      0 127.0.0.1.7894         192.168.3.9.65536      CLOSED
tcp4       0      0 127.0.0.1.7894         192.168.003.9.4000     CLOSED
tcp4       x      0 127.0.0.1.7894         192.168.3.9.4001       CLOSED
tcp4       0      0 127.0.0.1.7894
garbage
'''


def netstat(rows, port=PORT, others=()):
    """netstat's text for the listener and the given (endpoint, state) client sockets.

    others are (local endpoint, foreign endpoint, state) rows of sockets that
    are not the listener's, in netstat's own a.b.c.d.port notation.
    """
    lines = ['Active Internet connections (including servers)',
             'Proto Recv-Q Send-Q Local Address          Foreign Address        (state)    ',
             'tcp4       0      0 %-22s %-22s %-11s' % ('127.0.0.1.%d' % port, '*.*', 'LISTEN')]
    for (address, client), state in rows:
        lines.append('tcp4       0      0 %-22s %-22s %-11s' % ('127.0.0.1.%d' % port,
                                                              '%s.%d' % (address, client), state))
    for local, foreign, state in others:
        lines.append('tcp4       0      0 %-22s %-22s %-11s' % (local, foreign, state))
    return '\n'.join(lines) + '\n'


def endpoint(entry):
    """The client endpoint of one entry of GET /connections."""
    return entry['metadata']['sourceIP'], int(entry['metadata']['sourcePort'])


def connection(ident, address, port, kind='Redir', network='tcp', upload=517, download=4410, inbound=PORT):
    """One entry of GET /connections as Mihomo 1.19 answers it."""
    return {'id': ident,
            'metadata': {'network': network, 'type': kind, 'sourceIP': address, 'destinationIP': '142.250.1.188',
                         'sourceGeoIP': None, 'destinationGeoIP': None, 'sourceIPASN': '',
                         'destinationIPASN': '', 'sourcePort': str(port), 'destinationPort': '5228',
                         'inboundIP': '127.0.0.1', 'inboundPort': str(inbound),
                         'inboundName': m.REDIRECT_LISTENER if kind == 'Redir' else 'DEFAULT-TUN',
                         'inboundUser': '', 'host': 'mtalk.google.com', 'dnsMode': 'normal', 'uid': 0,
                         'process': '', 'processPath': '', 'specialProxy': '', 'specialRules': '',
                         'remoteDestination': '142.250.1.188', 'dscp': 0, 'sniffHost': ''},
            'upload': upload, 'download': download, 'start': '2026-10-01T08:00:00.123456789-07:00',
            'chains': ['DIRECT'], 'providerChains': [], 'rule': 'DomainSuffix', 'rulePayload': 'google.com'}


class ReaperSystem(RecoverySystem):
    """A core with a controller and client sockets on the fast TCP path's listener."""

    def __init__(self):
        super().__init__()
        # Whether the routing adapter loads the redirect when it enables.
        self.fast = True
        # The core's connections by id, and the state of each one's client
        # socket on the listener; None for a connection without one.
        self.connections = {}
        self.states = {}
        # Client sockets on the listener no core connection owns any more,
        # as (endpoint, state).
        self.orphans = []
        # Sockets netstat lists that are not the listener's, as netstat()'s
        # others.
        self.others = []
        # Client endpoints whose FIN_WAIT_2 socket ends between netstat and
        # tcpdrop, as when its client finally sends its FIN or a reset; and
        # those the kernel's lookup never finds although netstat lists them.
        self.vanishing = set()
        self.unfound = set()
        self.calls = []
        # Failures to inject, by 'list', 'netstat', 'close' and 'drop'.
        self.failures = {}
        # Seconds every close and every drop takes on the test clock, and
        # that clock.
        self.close_cost = 0
        self.drop_cost = 0
        self.clock = None
        # The options the last list was read with.
        self.options = None
        # Whether the list hands out copies; a long list's test reads the
        # entries themselves, which the scan never changes.
        self.copies = True

    def routing(self, action):
        super().routing(action)
        if action == 'enable' and self.fast:
            m.atomic_write(self.state / 'routing-state.json',
                           json.dumps({'active': True, 'tcp_redirect_port': PORT}).encode())

    def start(self, config, transparent):
        super().start(config, transparent)
        # A new core holds nothing of the old one's.
        self.connections.clear()
        self.states.clear()

    def stop(self):
        super().stop()
        self.connections.clear()
        self.states.clear()

    def add(self, ident, address, port, state, **fields):
        self.connections[ident] = connection(ident, address, port, **fields)
        self.states[ident] = state

    def sockets(self):
        """Every client socket on the listener, as (endpoint, state)."""
        return [(endpoint(entry), self.states[ident]) for ident, entry in self.connections.items()
                if self.states[ident] is not None and entry['metadata']['network'] == 'tcp'] + self.orphans

    def redirect_sockets(self, port):
        self.calls.append('netstat')
        if 'netstat' in self.failures:
            raise self.failures['netstat']
        return m.listener_sockets(netstat(self.sockets(), port, self.others), port)

    def drop_redirect_socket(self, port, client):
        self.calls.append(('tcpdrop', port, client))
        if 'drop' in self.failures:
            raise self.failures['drop']
        if self.clock is not None:
            self.clock.now += self.drop_cost
        if client in self.vanishing:
            self.vanishing.discard(client)
            self.release(client)
        # The kernel looks the four-tuple up among the sockets it has not
        # dropped yet, so a CLOSED one is never reached; it drops the one it
        # finds, and the relay reading that socket ends, with the connection
        # the core may still list for it. tcpdrop reports a four-tuple it
        # finds nothing for as ESRCH.
        reached = [state for found, state in self.sockets() if found == client and state != 'CLOSED']
        if not reached or client in self.unfound:
            raise m.NoSuchSocketError('tcpdrop exited with status 1: No such process')
        # Whatever a scan decided, it never drops anything else.
        if port != PORT or reached != ['FIN_WAIT_2']:
            raise AssertionError('dropped %r on port %d' % (reached, port))
        self.release(client)
        return None

    def release(self, client):
        """The FIN_WAIT_2 socket of a client endpoint ends, and with it the relay and any connection listed for it."""
        for ident in [ident for ident, entry in self.connections.items()
                      if endpoint(entry) == client and self.states[ident] == 'FIN_WAIT_2']:
            del self.connections[ident], self.states[ident]
        self.orphans = [(found, state) for found, state in self.orphans
                        if found != client or state != 'FIN_WAIT_2']

    def controller(self, method, path, payload=None, **options):
        self.calls.append((method, path))
        if (method, path) == ('GET', '/proxies'):
            return {'proxies': {}}
        if (method, path) == ('GET', '/connections'):
            self.options = options
            if 'list' in self.failures:
                raise self.failures['list']
            # Mihomo answers null, not an empty list, when it holds none.
            listed = [copy.deepcopy(entry) if self.copies else entry
                      for entry in self.connections.values()] or None
            return {'downloadTotal': 123456, 'uploadTotal': 6543, 'connections': listed, 'memory': 52000000}
        if method == 'DELETE' and path.startswith('/connections/'):
            if 'close' in self.failures:
                raise self.failures['close']
            if self.clock is not None:
                self.clock.now += self.close_cost
            ident = urlparse.unquote(path[len('/connections/'):])
            # Closing the outbound ends a relay waiting on the server, which
            # closes the client socket; an unknown id is answered the same
            # way. A relay reading a FIN_WAIT_2 client socket goes on reading
            # it: the core only stops listing the connection, whose client
            # socket stays held.
            if self.states.get(ident) == 'FIN_WAIT_2':
                self.orphans.append((endpoint(self.connections[ident]), 'FIN_WAIT_2'))
            self.connections.pop(ident, None)
            self.states.pop(ident, None)
            return {}
        raise AssertionError((method, path))

    def deletes(self):
        """The ids closed through the controller, in order."""
        return [urlparse.unquote(call[1][len('/connections/'):]) for call in self.calls
                if isinstance(call, tuple) and call[0] == 'DELETE']

    def drops(self):
        """The client endpoints tcpdrop was run for, in order."""
        return [call[2] for call in self.calls if isinstance(call, tuple) and call[0] == 'tcpdrop']

    def scans(self):
        return sum(1 for call in self.calls if call == ('GET', '/connections'))


class ReaperCase(RecoveryCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.clock = Clock()
        self.system = ReaperSystem()
        self.system.clock = self.clock
        self.manager = m.Manager(Path(self.temp.name), self.system, proxy_api=self.system.controller)
        self.manager.clock = self.clock
        self.system.state = self.manager.state
        self.manager.initialize()
        self.manager.write_settings(dict(self.manager.settings(), dns_scope='all', tcp_redirect=True))
        self.manager.dispatch('start')
        self.manager.apply(SUBSCRIPTION)
        self.manager.dispatch('enable-transparent')
        self.assertTrue(self.status()['tcp_redirect'])
        self.system.events.clear()
        self.system.calls.clear()

    def minutes(self, count):
        """count watchdog ticks a minute apart, each of which scans; the last tick's status."""
        status = None
        for _ in range(count):
            status = self.tick(60)
        return status


class ParseTests(unittest.TestCase):
    def test_netstat_lines_are_read_by_client_endpoint(self):
        self.assertEqual({('192.168.3.25', 52114): {'ESTABLISHED'},
                          # An old socket the core still holds beside a new
                          # one from the same client port.
                          ('192.168.3.40', 40812): {'CLOSED', 'ESTABLISHED'},
                          ('192.168.3.41', 51234): {'FIN_WAIT_2'},
                          ('192.168.3.42', 60001): {'CLOSE_WAIT'},
                          ('192.168.3.43', 1025): {'TIME_WAIT'},
                          ('10.0.0.7', 65535): {'ESTABLISHED'},
                          # A state netstat prints as a number, or not at
                          # all, is kept, so it holds its endpoint back.
                          ('192.168.3.250', 7): {'12'},
                          ('192.168.3.251', 8): {''}},
                         m.listener_sockets(NETSTAT, PORT))

    def test_only_the_listeners_own_port_counts(self):
        self.assertEqual({('192.168.3.9', 1234): {'CLOSED'}}, m.listener_sockets(NETSTAT, 17894))
        self.assertEqual({}, m.listener_sockets(NETSTAT, 9091))
        self.assertEqual({}, m.listener_sockets('', PORT))

    def test_the_system_runs_netstat_once_and_never_reads_a_failure_as_empty(self):
        system = m.System()
        with mock.patch.object(system, 'run', return_value=subprocess.CompletedProcess(
                [], 0, NETSTAT.encode(), b'')) as run:
            self.assertEqual(m.listener_sockets(NETSTAT, PORT), system.redirect_sockets(PORT))
        run.assert_called_once_with(['/usr/bin/netstat', '-an', '-p', 'tcp'], timeout=30, check=False)
        with mock.patch.object(system, 'run', return_value=subprocess.CompletedProcess([], 1, b'', b'')):
            with self.assertRaisesRegex(m.Error, 'status 1'):
                system.redirect_sockets(PORT)
        with mock.patch.object(system, 'run', side_effect=m.Error('A system operation failed or timed out.')):
            with self.assertRaises(m.Error):
                system.redirect_sockets(PORT)
        with mock.patch.object(m, 'NETSTAT_LIMIT', 64), mock.patch.object(
                system, 'run', return_value=subprocess.CompletedProcess([], 0, NETSTAT.encode(), b'')):
            with self.assertRaisesRegex(m.Error, 'more than'):
                system.redirect_sockets(PORT)

    def test_a_listing_without_the_listeners_own_line_is_a_failure_not_an_empty_list(self):
        # netstat -p tcp exits 0 when the kernel's socket list cannot be read,
        # with only a warning on stderr and not even the header on stdout.
        system = m.System()
        header = NETSTAT.splitlines(keepends=True)[:2]
        clients = [line for line in NETSTAT.splitlines(keepends=True) if 'LISTEN' not in line]
        for stdout, stderr, detail in (
                ('', 'netstat: sysctl: net.inet.tcp.pcblist: Cannot allocate memory\n',
                 ': netstat: sysctl: net.inet.tcp.pcblist: Cannot allocate memory'),
                ('', 'netstat: malloc 2621440 bytes\n', ': netstat: malloc 2621440 bytes'),
                (''.join(header), '', ''),
                (''.join(clients), '', ''),
                # Another port's listener, or one on every address, is not this one.
                (netstat([], 17894), '', ''),
                (''.join(header) + 'tcp4       0      0 *.%d                 *.*                    LISTEN     \n'
                 % PORT, '', '')):
            with self.subTest(stdout=stdout, stderr=stderr), mock.patch.object(
                    system, 'run', return_value=subprocess.CompletedProcess([], 0, stdout.encode(), stderr.encode())):
                with self.assertRaises(m.Error) as raised:
                    system.redirect_sockets(PORT)
                self.assertEqual('netstat listed no listener on 127.0.0.1.%d%s' % (PORT, detail), str(raised.exception))
        # The listener's own line alone is a complete list of no client.
        with mock.patch.object(system, 'run', return_value=subprocess.CompletedProcess(
                [], 0, netstat([]).encode(), b'')):
            self.assertEqual({}, system.redirect_sockets(PORT))
        self.assertTrue(m.listener_listed(NETSTAT, PORT))
        self.assertTrue(m.listener_listed(netstat([], 17894), 17894))
        self.assertFalse(m.listener_listed(NETSTAT, 17894))
        self.assertFalse(m.listener_listed('', PORT))

    def test_the_system_drops_one_socket_with_tcpdrop_and_requires_its_report(self):
        system = m.System()
        client = ('192.168.3.2', 57846)
        argv = ['/usr/sbin/tcpdrop', '127.0.0.1', '7894', '192.168.3.2', '57846']
        # What FreeBSD 15.1's tcpdrop printed for one of the held sockets on a router.
        with mock.patch.object(system, 'run', return_value=subprocess.CompletedProcess(
                argv, 0, b'127.0.0.1 7894 192.168.3.2 57846: dropped\n', b'')) as run:
            self.assertIsNone(system.drop_redirect_socket(PORT, client))
        run.assert_called_once_with(argv, timeout=m.STALE_DROP_TIMEOUT, check=False)
        self.assertEqual('/usr/sbin/tcpdrop', m.TCPDROP)
        for returncode, stdout, stderr, message, gone in (
                # The kernel no longer finds the socket (ESRCH): it ended after
                # netstat listed it, which alone is told apart.
                (1, b'', b'tcpdrop: 127.0.0.1 7894 192.168.3.2 57846: No such process\n',
                 'tcpdrop exited with status 1: No such process', True),
                (1, b'', b'tcpdrop: 127.0.0.1 7894 192.168.3.2 57846: Operation not permitted\n',
                 'tcpdrop exited with status 1: Operation not permitted', False),
                (1, b'', b'', 'tcpdrop exited with status 1', False),
                # Only this very socket's ESRCH counts as its end.
                (1, b'', b'tcpdrop: 127.0.0.1 7894 192.168.3.2 57847: No such process\n',
                 'tcpdrop exited with status 1: 127.0.0.1 7894 192.168.3.2 57847: No such process', False),
                (1, b'', b'tcpdrop: getaddrinfo: No such process\n',
                 'tcpdrop exited with status 1: getaddrinfo: No such process', False),
                (1, b'', b'tcpdrop: No such process\n', 'tcpdrop exited with status 1: No such process', False),
                (2, b'', b'tcpdrop: 127.0.0.1 7894 192.168.3.2 57846: No such process\n',
                 'tcpdrop exited with status 2: No such process', False),
                # A report of this socket does not outweigh a failing status.
                (1, b'127.0.0.1 7894 192.168.3.2 57846: dropped\n',
                 b'tcpdrop: 127.0.0.1 7894 192.168.3.2 57846: Operation not permitted\n',
                 'tcpdrop exited with status 1: Operation not permitted', False),
                (0, b'', b'', 'tcpdrop did not report the socket dropped', False),
                # Another socket's report is not this one's.
                (0, b'127.0.0.1 7894 192.168.3.2 57847: dropped\n', b'', 'tcpdrop did not report the socket dropped',
                 False),
                (0, b'127.0.0.1 7894 192.168.3.20 57846: dropped\n', b'',
                 'tcpdrop did not report the socket dropped', False)):
            with self.subTest(stdout=stdout, stderr=stderr), mock.patch.object(
                    system, 'run', return_value=subprocess.CompletedProcess(argv, returncode, stdout, stderr)):
                with self.assertRaises(m.Error) as raised:
                    system.drop_redirect_socket(PORT, client)
                # The socket is not named, so one failure reads the same for every socket.
                self.assertEqual(message, str(raised.exception))
                self.assertEqual(gone, isinstance(raised.exception, m.NoSuchSocketError))
        with mock.patch.object(system, 'run', side_effect=m.Error('A system operation failed or timed out.')):
            with self.assertRaisesRegex(m.Error, 'timed out') as raised:
                system.drop_redirect_socket(PORT, client)
            self.assertNotIsInstance(raised.exception, m.NoSuchSocketError)
        # Only an IPv4 client endpoint on a real port reaches tcpdrop, never
        # anything it could read as an option or a host name.
        for port, endpoint_ in ((PORT, ('-a', 1)), (PORT, ('::1', 1)), (PORT, ('192.168.003.2', 1)),
                                (PORT, ('192.168.3.2', 0)), (PORT, ('192.168.3.2', '57846')),
                                (PORT, ('192.168.3.2', 65536)), (0, client), ('7894', client)):
            with self.subTest(port=port, endpoint=endpoint_), mock.patch.object(system, 'run') as run:
                with self.assertRaisesRegex(m.Error, 'IPv4 client endpoint'):
                    system.drop_redirect_socket(port, endpoint_)
                run.assert_not_called()

    def test_only_tcp_from_the_redirect_listener_is_taken_from_the_controllers_list(self):
        listed = {'connections': [
            connection('a', '192.168.3.40', 40812),
            connection('tun', '192.168.3.40', 40813, kind='Tun', inbound=0),
            connection('udp', '192.168.3.40', 40814, network='udp'),
            connection('http', '192.168.3.40', 40815, kind='HTTP', inbound=7890),
            # An administrator's own redir listener is not the plugin's.
            connection('own', '192.168.3.40', 40816, inbound=7892),
            # A core that does not name the inbound port.
            connection('unnamed', '192.168.3.40', 40817, inbound=0),
            connection('mapped', '::ffff:192.168.3.41', '51234'),
            connection('v6', '2001:db8::5', 51235),
            connection('bad port', '192.168.3.40', 0),
            connection('bad bytes', '192.168.3.40', 40818, upload=True),
            connection('negative', '192.168.3.40', 40819, download=-1),
            connection('../escape', '192.168.3.40', 40820),
            dict(connection('no id', '192.168.3.40', 40821), id=None),
            {'id': 'no metadata'}, 'nonsense', None]}
        self.assertEqual([('a', ('192.168.3.40', 40812), 517 + 4410),
                          ('unnamed', ('192.168.3.40', 40817), 517 + 4410),
                          ('mapped', ('192.168.3.41', 51234), 517 + 4410)],
                         m.fast_path_connections(listed, PORT))
        self.assertEqual([], m.fast_path_connections({'connections': None}, PORT))
        self.assertEqual([], m.fast_path_connections({'connections': []}, PORT))
        for broken in ({}, {'proxies': {}}, {'connections': {}}, [], None, 'connections'):
            with self.subTest(broken=broken), self.assertRaises(ValueError):
                m.fast_path_connections(broken, PORT)

    def test_the_controller_client_reads_a_long_list_keeping_only_what_the_scan_uses(self):
        manager = m.Manager(Path('/'), mock.Mock())
        body = json.dumps({'downloadTotal': 1, 'uploadTotal': 2, 'memory': 3,
                           'connections': [connection('a', '192.168.3.40', 40812)]}).encode()
        settings = {'controller': '0.0.0.0:9191', 'secret': 'private'}
        with mock.patch.object(manager, 'settings', return_value=settings), \
                mock.patch.object(m.urlrequest, 'build_opener') as build:
            response = build.return_value.open.return_value.__enter__.return_value
            response.read.return_value = body
            listed = manager._proxy_api('GET', '/connections', limit=m.STALE_LIST_LIMIT,
                                        timeout=m.STALE_LIST_TIMEOUT, fields=m.CONNECTION_FIELDS)
            request = build.return_value.open.call_args.args[0]
            self.assertEqual('http://127.0.0.1:9191/connections', request.full_url)
            self.assertEqual('Bearer private', request.get_header('Authorization'))
            self.assertEqual({'timeout': m.STALE_LIST_TIMEOUT}, build.return_value.open.call_args.kwargs)
            response.read.assert_called_once_with(m.STALE_LIST_LIMIT + 1)
            self.assertEqual({'connections': [{
                'id': 'a', 'upload': 517, 'download': 4410,
                'metadata': {'network': 'tcp', 'type': 'Redir', 'sourceIP': '192.168.3.40',
                             'sourcePort': '40812', 'inboundPort': str(PORT)}}]}, listed)
            # Every other caller reads as before: the whole answer, up to 2 MB.
            self.assertEqual(json.loads(body), manager._proxy_api('GET', '/connections'))
            self.assertEqual(2 * 1024 * 1024 + 1, response.read.call_args.args[0])
            self.assertEqual({'timeout': 2}, build.return_value.open.call_args.kwargs)
            with self.assertRaisesRegex(ValueError, 'larger than'):
                manager._proxy_api('GET', '/connections', limit=len(body) - 1)
            response.read.return_value = b''
            self.assertEqual({}, manager._proxy_api('DELETE', '/connections/a'))


class DecisionTests(unittest.TestCase):
    def test_a_closed_endpoint_is_closed_at_once_and_a_close_wait_one_after_five_idle_minutes(self):
        connections = [('closed', ('10.0.0.1', 1), 10), ('half', ('10.0.0.2', 2), 10),
                       ('wait', ('10.0.0.3', 3), 10), ('live', ('10.0.0.4', 4), 10),
                       ('gone', ('10.0.0.5', 5), 10), ('held', ('10.0.0.6', 6), 10),
                       ('held-beside-closed', ('10.0.0.7', 7), 10)]
        sockets = {('10.0.0.1', 1): {'CLOSED'}, ('10.0.0.2', 2): {'CLOSE_WAIT'},
                   ('10.0.0.3', 3): {'CLOSE_WAIT', 'CLOSED'}, ('10.0.0.4', 4): {'ESTABLISHED'},
                   # The core finished toward these clients: closing their
                   # connections would only hide the sockets they hold.
                   ('10.0.0.6', 6): {'FIN_WAIT_2'}, ('10.0.0.7', 7): {'FIN_WAIT_2', 'CLOSED'}}
        due, seen = m.stale_connections(connections, sockets, {}, 1000)
        self.assertEqual([('closed', 'closed')], due)
        self.assertEqual({'half': (1000, 10), 'wait': (1000, 10)}, seen)
        due, seen = m.stale_connections(connections, sockets, seen, 1000 + m.STALE_IDLE - 1)
        self.assertEqual([('closed', 'closed')], due)
        due, seen = m.stale_connections(connections, sockets, seen, 1000 + m.STALE_IDLE)
        self.assertEqual([('closed', 'closed'), ('half', 'idle'), ('wait', 'idle')], due)
        due, seen = m.stale_connections(connections, sockets, seen, 1000 + 100 * m.STALE_IDLE)
        self.assertNotIn('held', [ident for ident, _ in due])
        self.assertEqual({'half', 'wait'}, set(seen))

    def test_moving_bytes_restart_the_wait_and_any_other_state_holds_an_endpoint_back(self):
        sockets = {('10.0.0.2', 2): {'CLOSE_WAIT'}}
        due, seen = m.stale_connections([('half', ('10.0.0.2', 2), 10)], sockets, {}, 0)
        due, seen = m.stale_connections([('half', ('10.0.0.2', 2), 11)], sockets, seen, 200)
        self.assertEqual(([], {'half': (200, 11)}), (due, seen))
        due, seen = m.stale_connections([('half', ('10.0.0.2', 2), 11)], sockets, seen, 499)
        self.assertEqual([], due)
        self.assertEqual([('half', 'idle')], m.stale_connections(
            [('half', ('10.0.0.2', 2), 11)], sockets, seen, 500)[0])
        for states in ({'CLOSED', 'ESTABLISHED'}, {'CLOSE_WAIT', 'SYN_RCVD'}, {'TIME_WAIT'}, {'LAST_ACK'},
                       {'FIN_WAIT_1'}, {'CLOSING'}, {'LISTEN'}, {'12'}, {''}, set(), {'FIN_WAIT_2'},
                       {'FIN_WAIT_2', 'CLOSED'}, {'FIN_WAIT_2', 'CLOSE_WAIT'}):
            with self.subTest(states=states):
                self.assertEqual(([], {}), m.stale_connections(
                    [('x', ('10.0.0.2', 2), 10)], {('10.0.0.2', 2): states}, {'x': (0, 10)}, 10000))

    def test_a_fin_wait_2_socket_is_dropped_after_five_minutes_whether_listed_or_not(self):
        sockets = {('10.0.0.1', 1): {'FIN_WAIT_2'}, ('10.0.0.2', 2): {'FIN_WAIT_2'},
                   # Beside an older socket of the same client port, which the
                   # kernel no longer looks up and tcpdrop cannot reach.
                   ('10.0.0.3', 3): {'FIN_WAIT_2', 'CLOSED'}}
        # Only the first one's connection is still listed by the controller.
        connections = [('listed', ('10.0.0.1', 1), 10)]
        due, held = m.held_sockets(connections, sockets, {}, 1000)
        self.assertEqual([], due)
        self.assertEqual({('10.0.0.1', 1): (1000, 10), ('10.0.0.2', 2): (1000, None),
                          ('10.0.0.3', 3): (1000, None)}, held)
        due, held = m.held_sockets(connections, sockets, held, 1000 + m.STALE_IDLE - 1)
        self.assertEqual([], due)
        due, held = m.held_sockets(connections, sockets, held, 1000 + m.STALE_IDLE)
        self.assertEqual([('10.0.0.1', 1), ('10.0.0.2', 2), ('10.0.0.3', 3)], due)
        # A scan whose drops did not all happen finds them due again at once.
        self.assertEqual(due, m.held_sockets(connections, sockets, held, 1000 + m.STALE_IDLE + 60)[0])

    def test_moving_bytes_restart_a_held_sockets_wait_and_a_connection_no_longer_listed_keeps_it(self):
        client = ('10.0.0.1', 1)
        sockets = {client: {'FIN_WAIT_2'}}
        due, held = m.held_sockets([('a', client, 10)], sockets, {}, 0)
        # Still uploading after the core finished: the wait starts again.
        due, held = m.held_sockets([('a', client, 15)], sockets, held, 200)
        self.assertEqual(([], {client: (200, 15)}), (due, held))
        # Every connection listed for the endpoint counts.
        due, held = m.held_sockets([('a', client, 15), ('b', client, 1)], sockets, held, 300)
        self.assertEqual(([], {client: (300, 16)}), (due, held))
        # The core stops listing it, as after a close through the controller:
        # nothing moves on it any more, and the wait goes on.
        due, held = m.held_sockets([], sockets, held, 599)
        self.assertEqual(([], {client: (300, 16)}), (due, held))
        self.assertEqual([client], m.held_sockets([], sockets, held, 600)[0])
        # Listed again with the bytes it had, the wait still goes on.
        self.assertEqual([client], m.held_sockets([('a', client, 15), ('b', client, 1)], sockets, held, 600)[0])
        # One that is listed only after it was first seen starts again: what
        # moved before is not known.
        other = ('10.0.0.2', 2)
        due, held = m.held_sockets([], {other: {'FIN_WAIT_2'}}, {}, 0)
        due, held = m.held_sockets([('c', other, 7)], {other: {'FIN_WAIT_2'}}, held, 250)
        self.assertEqual(([], {other: (250, 7)}), (due, held))

    def test_only_fin_wait_2_is_ever_dropped_and_an_endpoint_that_leaves_it_is_forgotten(self):
        client = ('10.0.0.2', 2)
        for states in ({'ESTABLISHED'}, {'CLOSED'}, {'CLOSE_WAIT'}, {'CLOSE_WAIT', 'CLOSED'}, {'TIME_WAIT'},
                       {'FIN_WAIT_1'}, {'CLOSING'}, {'LAST_ACK'}, {'SYN_RCVD'}, {'LISTEN'}, {'12'}, {''}, set(),
                       # Two sockets the kernel both looks up cannot share a
                       # four-tuple; netstat listing one beside the other means
                       # it changed while it was read, so nothing is dropped.
                       {'FIN_WAIT_2', 'ESTABLISHED'}, {'FIN_WAIT_2', 'CLOSE_WAIT'}, {'FIN_WAIT_2', 'TIME_WAIT'},
                       {'FIN_WAIT_2', 'CLOSED', 'ESTABLISHED'}, {'FIN_WAIT_2', ''}):
            with self.subTest(states=states):
                self.assertEqual(([], {}), m.held_sockets([('x', client, 10)], {client: states},
                                                          {client: (0, 10)}, 10000))
        # Gone from netstat, it is forgotten; back again, it waits from scratch.
        self.assertEqual(([], {}), m.held_sockets([], {}, {client: (0, None)}, 10000))
        self.assertEqual(([], {client: (10000, None)}), m.held_sockets([], {client: {'FIN_WAIT_2'}}, {}, 10000))

    def test_an_endpoint_is_never_both_closed_through_the_controller_and_dropped(self):
        client = ('10.0.0.2', 2)
        states = ('CLOSED', 'CLOSE_WAIT', 'FIN_WAIT_2', 'ESTABLISHED', 'TIME_WAIT', 'LAST_ACK', '')
        for size in range(1, len(states) + 1):
            for combination in itertools.combinations(states, size):
                with self.subTest(states=combination):
                    sockets = {client: set(combination)}
                    connections = [('x', client, 10)]
                    closed = m.stale_connections(connections, sockets, {'x': (0, 10)}, 10000)[0]
                    dropped = m.held_sockets(connections, sockets, {client: (0, 10)}, 10000)[0]
                    self.assertFalse(closed and dropped)
                    self.assertEqual(set(combination) <= {'CLOSED', 'CLOSE_WAIT'}, bool(closed))
                    self.assertEqual('FIN_WAIT_2' in combination and set(combination) <= {'FIN_WAIT_2', 'CLOSED'},
                                     bool(dropped))

    def test_a_list_of_sixty_thousand_connections_is_decided_in_one_linear_pass(self):
        count = 60000
        connections = [('id-%d' % index, ('10.%d.%d.%d' % (index >> 16, (index >> 8) & 255, index & 255),
                                          1024 + index % 60000), index) for index in range(count)]
        states = ('CLOSED', 'ESTABLISHED', 'CLOSE_WAIT', 'FIN_WAIT_2')
        sockets = {endpoint: {states[index % 4]} for index, (_, endpoint, _) in enumerate(connections)}
        # And held sockets the core no longer lists.
        sockets.update({('172.16.%d.%d' % (index >> 8, index & 255), 2000): {'FIN_WAIT_2'}
                        for index in range(20000)})
        started = time.process_time()
        due, seen = m.stale_connections(connections, sockets, {}, 0)
        drops, held = m.held_sockets(connections, sockets, {}, 0)
        due, seen = m.stale_connections(connections, sockets, seen, m.STALE_IDLE)
        drops, held = m.held_sockets(connections, sockets, held, m.STALE_IDLE)
        self.assertLess(time.process_time() - started, 5)
        self.assertEqual(count // 4, sum(1 for _, reason in due if reason == 'closed'))
        self.assertEqual(count // 4, sum(1 for _, reason in due if reason == 'idle'))
        self.assertEqual(count // 4, len(seen))
        self.assertEqual(count // 4 + 20000, len(drops))
        self.assertEqual(count // 4 + 20000, len(held))


class ReaperTests(ReaperCase):
    def test_a_connection_whose_client_socket_is_closed_is_closed_at_the_next_scan(self):
        self.system.add('stale', '192.168.3.40', 40812, 'CLOSED')
        self.system.add('live', '192.168.3.25', 52114, 'ESTABLISHED')
        lines = len(self.log())
        status = self.tick()
        self.assertEqual(['stale'], self.system.deletes())
        self.assertEqual(['live'], list(self.system.connections))
        self.assertEqual([m.STALE_LOG % (1, 1, 0, 0)], self.logged(lines))
        self.assertEqual('Closed 1 stale connections of the fast TCP path (1 whose client had closed, '
                         '0 half-closed and idle for 5 minutes, 0 held open by a client that never closed).',
                         self.logged(lines)[0])
        self.assertTrue(status['running'] and status['tcp_redirect'], status)
        self.assertEqual(1, status['stale_connections_closed'])
        # The list is read before netstat, and only once per scan, with the
        # size and wait a long list needs and only the fields used.
        reads = [call for call in self.system.calls if call in ('netstat', ('GET', '/connections'))]
        self.assertEqual([('GET', '/connections'), 'netstat'], reads)
        self.assertEqual({'limit': m.STALE_LIST_LIMIT, 'timeout': m.STALE_LIST_TIMEOUT,
                          'fields': m.CONNECTION_FIELDS}, self.system.options)

    def test_a_half_closed_connection_is_released_after_five_minutes_without_a_byte(self):
        self.system.add('close-wait', '192.168.3.42', 60001, 'CLOSE_WAIT')
        self.system.add('fin-wait', '192.168.3.41', 51234, 'FIN_WAIT_2')
        self.system.add('busy', '192.168.3.44', 50000, 'CLOSE_WAIT')
        lines = len(self.log())
        self.tick()
        for _ in range(4):
            self.minutes(1)
            # Still answering a request the client half-closed after.
            self.system.connections['busy']['download'] += 1000
        self.assertEqual(([], []), (self.system.deletes(), self.system.drops()))
        self.minutes(1)
        # The client finished first on one, the core on the other: the
        # controller closes the first, tcpdrop releases the second.
        self.assertEqual(['close-wait'], self.system.deletes())
        self.assertEqual([('192.168.3.41', 51234)], self.system.drops())
        self.assertEqual(['busy'], list(self.system.connections))
        self.assertEqual([m.STALE_LOG % (2, 0, 1, 1)], self.logged(lines))
        # Five minutes after its bytes last moved, the busy one goes too.
        self.minutes(4)
        self.assertEqual(['close-wait'], self.system.deletes())
        self.minutes(1)
        self.assertEqual(['close-wait', 'busy'], self.system.deletes())
        self.assertEqual(3, self.status()['stale_connections_closed'])

    def test_a_fin_wait_2_client_socket_is_dropped_never_closed_through_the_controller(self):
        self.system.add('held', '192.168.3.2', 57846, 'FIN_WAIT_2')
        self.system.add('live', '192.168.3.25', 52114, 'ESTABLISHED')
        lines = len(self.log())
        self.tick()
        self.minutes(4)
        self.assertEqual(([], []), (self.system.deletes(), self.system.drops()))
        self.assertEqual({('192.168.3.2', 57846)}, set(self.manager._stale['held']))
        status = self.minutes(1)
        # The four-tuple of the client socket on the listener, as tcpdrop takes it.
        self.assertIn(('tcpdrop', PORT, ('192.168.3.2', 57846)), self.system.calls)
        self.assertEqual([('192.168.3.2', 57846)], self.system.drops())
        self.assertEqual(['live'], list(self.system.connections))
        self.assertEqual([], self.system.orphans)
        self.assertEqual({}, self.manager._stale['held'])
        self.assertEqual([m.STALE_LOG % (1, 0, 0, 1)], self.logged(lines))
        self.assertEqual('Closed 1 stale connections of the fast TCP path (0 whose client had closed, 0 half-closed '
                         'and idle for 5 minutes, 1 held open by a client that never closed).', self.logged(lines)[0])
        # It counts like a connection closed through the controller.
        self.assertEqual(1, status['stale_connections_closed'])
        self.minutes(30)
        self.assertEqual(([], [('192.168.3.2', 57846)]), (self.system.deletes(), self.system.drops()))

    def test_a_held_socket_the_controller_no_longer_lists_is_dropped_too(self):
        # Closing it through the controller, as a manual cleanup did on a
        # router: the close succeeds and the core stops listing it, but its
        # relay goes on reading the client socket, which stays held.
        self.system.add('held', '192.168.3.2', 57846, 'FIN_WAIT_2')
        self.assertEqual({}, self.system.controller('DELETE', '/connections/held'))
        self.assertEqual({}, self.system.connections)
        self.assertEqual([(('192.168.3.2', 57846), 'FIN_WAIT_2')], self.system.orphans)
        # And one already held before this watchdog started.
        self.system.orphans.append((('192.168.3.2', 57847), 'FIN_WAIT_2'))
        self.system.calls.clear()
        lines = len(self.log())
        self.tick()
        self.minutes(4)
        self.assertEqual([], self.system.drops())
        self.minutes(1)
        self.assertEqual([('192.168.3.2', 57846), ('192.168.3.2', 57847)], self.system.drops())
        self.assertEqual([], self.system.orphans)
        self.assertEqual([], self.system.deletes())
        self.assertEqual([m.STALE_LOG % (2, 0, 0, 2)], self.logged(lines))
        self.assertEqual(2, self.status()['stale_connections_closed'])

    def test_moving_bytes_keep_a_fin_wait_2_connection_until_they_stop_for_five_minutes(self):
        self.system.add('upload', '192.168.3.2', 57846, 'FIN_WAIT_2')
        self.tick()
        for _ in range(9):
            self.minutes(1)
            # The client is still sending after the core finished toward it.
            self.system.connections['upload']['upload'] += 1000
        self.assertEqual([], self.system.drops())
        # The last change is seen at the next scan, and the wait starts there.
        self.minutes(5)
        self.assertEqual([], self.system.drops())
        self.minutes(1)
        self.assertEqual([('192.168.3.2', 57846)], self.system.drops())
        self.assertEqual([], self.system.deletes())

    def test_a_socket_that_leaves_fin_wait_2_is_forgotten_and_waits_from_scratch_when_back(self):
        client = ('192.168.3.2', 57846)
        self.system.orphans.append((client, 'FIN_WAIT_2'))
        self.tick()
        self.minutes(3)
        # netstat no longer lists it.
        self.system.orphans.clear()
        self.minutes(1)
        self.assertNotIn(client, self.manager._stale['held'])
        self.system.orphans.append((client, 'FIN_WAIT_2'))
        self.minutes(3)
        # Listed beside a live socket, as when netstat read a changing
        # table: nothing on it is dropped, and it is forgotten.
        self.system.orphans.append((client, 'ESTABLISHED'))
        self.minutes(3)
        self.assertNotIn(client, self.manager._stale['held'])
        self.assertEqual([], self.system.drops())
        # Alone again, it is first seen at the next scan.
        self.system.orphans.remove((client, 'ESTABLISHED'))
        self.minutes(5)
        self.assertEqual([], self.system.drops())
        self.minutes(1)
        self.assertEqual([client], self.system.drops())

    def test_a_held_socket_beside_an_old_closed_one_is_dropped_before_the_closed_ones_connection_closes(self):
        # The client reused the port of a socket it had reset earlier, which
        # the core still holds as CLOSED.
        self.system.add('old', '192.168.3.2', 57846, 'CLOSED')
        self.system.orphans.append((('192.168.3.2', 57846), 'FIN_WAIT_2'))
        self.tick()
        self.minutes(4)
        self.assertEqual(([], []), (self.system.deletes(), self.system.drops()))
        self.minutes(1)
        self.assertEqual([('192.168.3.2', 57846)], self.system.drops())
        self.assertEqual([], self.system.deletes())
        self.assertEqual(['old'], list(self.system.connections))
        # Once only the CLOSED socket is left, its connection is closed.
        self.minutes(1)
        self.assertEqual(['old'], self.system.deletes())
        self.assertEqual({}, self.system.connections)

    def test_a_half_closed_connection_that_becomes_established_again_waits_from_scratch(self):
        self.system.add('flapping', '192.168.3.42', 60001, 'CLOSE_WAIT')
        self.tick()
        self.minutes(3)
        # The endpoint now also holds a live socket: nothing on it is touched,
        # and the connection is forgotten.
        self.system.orphans.append((('192.168.3.42', 60001), 'ESTABLISHED'))
        self.minutes(3)
        self.assertNotIn('flapping', self.manager._stale['seen'])
        self.system.orphans.clear()
        self.minutes(4)
        self.assertEqual([], self.system.deletes())
        self.minutes(2)
        self.assertEqual(['flapping'], self.system.deletes())

    def test_established_tun_and_udp_connections_are_never_closed(self):
        self.system.add('established', '192.168.3.25', 52114, 'ESTABLISHED')
        self.system.add('time-wait', '192.168.3.26', 52115, 'TIME_WAIT')
        # TUN and UDP connections whose endpoints have a CLOSED client socket
        # on the listener all the same.
        self.system.add('tun', '192.168.3.40', 40812, None, kind='Tun', inbound=0)
        self.system.add('udp', '192.168.3.40', 40813, None, network='udp')
        self.system.add('own-redir', '192.168.3.40', 40814, None, inbound=7892)
        self.system.orphans += [(('192.168.3.40', 40812), 'CLOSED'), (('192.168.3.40', 40813), 'CLOSED'),
                                (('192.168.3.40', 40814), 'CLOSED')]
        # An old CLOSED socket beside a new live one from the same client port.
        self.system.add('reused', '192.168.3.50', 41000, 'ESTABLISHED')
        self.system.orphans.append((('192.168.3.50', 41000), 'CLOSED'))
        # A connection whose client socket netstat no longer lists.
        self.system.add('unlisted', '192.168.3.51', 41001, None)
        self.minutes(60)
        self.assertEqual(([], []), (self.system.deletes(), self.system.drops()))
        self.assertEqual(60, self.system.scans())
        self.assertEqual(0, self.status()['stale_connections_closed'])

    def test_only_the_listeners_own_fin_wait_2_sockets_are_ever_dropped(self):
        # Client sockets on the listener in every state but FIN_WAIT_2.
        for index, state in enumerate(('ESTABLISHED', 'TIME_WAIT', 'FIN_WAIT_1', 'CLOSING', 'LAST_ACK',
                                       'SYN_RCVD', 'CLOSE_WAIT', 'CLOSED', '12', '')):
            self.system.orphans.append((('192.168.3.60', 42000 + index), state))
        self.system.add('established', '192.168.3.25', 52114, 'ESTABLISHED')
        # FIN_WAIT_2 beside a socket the kernel also looks up: netstat read a
        # table that changed meanwhile.
        for index, state in enumerate(('ESTABLISHED', 'CLOSE_WAIT', 'TIME_WAIT')):
            self.system.orphans += [(('192.168.3.61', 43000 + index), 'FIN_WAIT_2'),
                                    (('192.168.3.61', 43000 + index), state)]
        # FIN_WAIT_2 everywhere but on the listener itself: another port, the
        # same port on other addresses, the router's own and the core's own
        # outbound connections.
        self.system.others += [('127.0.0.1.17894', '192.168.3.9.1234', 'FIN_WAIT_2'),
                               ('127.0.0.10.7894', '192.168.3.9.1235', 'FIN_WAIT_2'),
                               ('192.168.3.1.7894', '192.168.3.9.1236', 'FIN_WAIT_2'),
                               ('192.168.3.1.43210', '142.250.1.188.5228', 'FIN_WAIT_2'),
                               ('203.0.113.2.38811', '198.51.100.9.28256', 'FIN_WAIT_2')]
        self.minutes(60)
        self.assertEqual(([], []), (self.system.deletes(), self.system.drops()))
        self.assertEqual({}, self.manager._stale['held'])
        self.assertEqual(0, self.status()['stale_connections_closed'])

    def test_every_connection_on_an_endpoint_whose_sockets_are_all_closed_is_closed(self):
        self.system.add('first', '192.168.3.40', 40812, 'CLOSED')
        self.system.add('second', '192.168.3.40', 40812, 'CLOSED')
        self.tick()
        self.assertEqual(['first', 'second'], self.system.deletes())

    def test_scans_run_at_most_once_a_minute(self):
        self.system.add('live', '192.168.3.25', 52114, 'ESTABLISHED')
        self.tick()
        self.assertEqual((1, 1), (self.system.scans(), self.system.calls.count('netstat')))
        for _ in range(11):
            self.tick()
        self.assertEqual(1, self.system.scans(), 'scanned again within 60 seconds')
        self.tick()
        self.assertEqual((2, 2), (self.system.scans(), self.system.calls.count('netstat')))
        self.minutes(10)
        self.assertEqual((12, 12), (self.system.scans(), self.system.calls.count('netstat')))
        # The cadence is kept by the watchdog, on the clock it shares.
        self.assertIs(time.monotonic, m.Manager(Path(self.temp.name), self.system).clock)

    def test_nothing_is_scanned_without_the_fast_tcp_path(self):
        self.system.add('stale', '192.168.3.40', 40812, 'CLOSED')
        # The redirect is not loaded, so captured TCP rides the TUN, which
        # gives the kernel no socket per connection to ask about.
        m.atomic_write(self.manager.state / 'routing-state.json', json.dumps({'active': True}).encode())
        status = self.minutes(3)
        self.assertFalse(status['tcp_redirect'])
        # The setting off, with a routing state that still names the port.
        m.atomic_write(self.manager.state / 'routing-state.json',
                       json.dumps({'active': True, 'tcp_redirect_port': PORT}).encode())
        self.manager.write_settings(dict(self.manager.settings(), tcp_redirect=False))
        self.minutes(3)
        # Transparent routing off.
        self.manager.write_settings(dict(self.manager.settings(), tcp_redirect=True, transparent=False))
        self.minutes(3)
        # A core whose ownership cannot be proven.
        self.manager.write_settings(dict(self.manager.settings(), transparent=True))
        with mock.patch.object(self.system, 'core_usage', return_value=None):
            self.minutes(3)
        self.assertEqual((0, 0), (self.system.scans(), self.system.calls.count('netstat')))
        self.assertEqual([], self.system.deletes())
        # Turned on again, the next tick scans.
        self.tick()
        self.assertEqual(['stale'], self.system.deletes())

    def test_a_pause_of_the_fast_tcp_path_makes_a_held_socket_wait_from_scratch(self):
        client = ('192.168.3.2', 57846)
        self.system.orphans.append((client, 'FIN_WAIT_2'))
        self.tick()
        self.minutes(4)
        self.manager.write_settings(dict(self.manager.settings(), tcp_redirect=False))
        self.minutes(1)
        self.assertEqual({}, self.manager._stale['held'])
        self.manager.write_settings(dict(self.manager.settings(), tcp_redirect=True))
        self.minutes(5)
        self.assertEqual([], self.system.drops())
        self.minutes(1)
        self.assertEqual([client], self.system.drops())

    def test_a_pause_of_the_fast_tcp_path_makes_a_half_closed_connection_wait_from_scratch(self):
        self.system.add('half', '192.168.3.42', 60001, 'CLOSE_WAIT')
        self.tick()
        self.minutes(1)
        self.manager.write_settings(dict(self.manager.settings(), tcp_redirect=False))
        self.minutes(10)
        self.assertEqual({}, self.manager._stale['seen'])
        self.manager.write_settings(dict(self.manager.settings(), tcp_redirect=True))
        # Its bytes did not move, but the pause was not watched: the wait
        # starts again at the first scan after it.
        self.minutes(5)
        self.assertEqual([], self.system.deletes())
        self.minutes(1)
        self.assertEqual(['half'], self.system.deletes())

    def test_a_system_without_netstat_or_tcpdrop_scans_nothing(self):
        self.system.add('stale', '192.168.3.40', 40812, 'CLOSED')
        for name in ('redirect_sockets', 'drop_redirect_socket'):
            with self.subTest(name=name), mock.patch.object(ReaperSystem, name, None):
                self.minutes(2)
            self.assertEqual(0, self.system.scans())

    def test_failures_never_break_the_tick_and_are_logged_once(self):
        self.system.add('stale', '192.168.3.40', 40812, 'CLOSED')
        lines = len(self.log())
        failures = (('list', OSError('<urlopen error [Errno 61] Connection refused>'),
                     'the controller did not list the connections: <urlopen error [Errno 61] Connection refused>'),
                    ('list', ValueError('Expecting value: line 1 column 1 (char 0)'),
                     'the controller did not list the connections: Expecting value: line 1 column 1 (char 0)'),
                    ('netstat', m.Error('netstat exited with status 1'),
                     'netstat did not list the sockets: netstat exited with status 1'),
                    ('close', m.http.client.RemoteDisconnected('Remote end closed connection without response'),
                     'the controller did not close a connection: Remote end closed connection without response'))
        for kind, error, reason in failures:
            with self.subTest(kind=kind, error=error):
                self.system.failures = {kind: error}
                for _ in range(3):
                    status = self.minutes(1)
                    self.assertTrue(status['running'] and status['routing_active'] and status['tcp_redirect'])
                    self.assertEqual('', status['error'])
                self.assertEqual([m.STALE_FAILED_LOG % reason], self.logged(lines))
                self.assertEqual(['stale'], list(self.system.connections))
                lines = len(self.log())
        # An answer that is no connection list fails the scan the same way.
        self.system.failures = {}
        self.manager.proxy_api = lambda method, path, payload=None, **options: {'proxies': {}}
        self.minutes(2)
        self.assertEqual([m.STALE_FAILED_LOG % 'the controller did not list the connections: the answer holds '
                                               'no connection list'], self.logged(lines))
        self.manager.proxy_api = self.system.controller
        # The next good scan closes what the failed ones could not.
        lines = len(self.log())
        self.minutes(1)
        self.assertEqual({}, self.system.connections)
        self.assertEqual([m.STALE_LOG % (1, 1, 0, 0)], self.logged(lines))
        # A failure after a success is logged again, the very one logged last
        # before it included, and again only once.
        self.manager.proxy_api = lambda method, path, payload=None, **options: {'proxies': {}}
        lines = len(self.log())
        self.minutes(3)
        self.assertEqual([m.STALE_FAILED_LOG % 'the controller did not list the connections: the answer holds '
                                               'no connection list'], self.logged(lines))
        self.manager.proxy_api = self.system.controller
        # So is a different one.
        self.system.add('stale-2', '192.168.3.41', 40813, 'CLOSED')
        self.system.failures = {'netstat': m.Error('netstat exited with status 1')}
        lines = len(self.log())
        self.minutes(1)
        self.assertEqual([m.STALE_FAILED_LOG % 'netstat did not list the sockets: netstat exited with status 1'],
                         self.logged(lines))

    def test_a_netstat_that_lists_nothing_fails_the_scan_instead_of_finding_no_socket(self):
        self.system.add('stale', '192.168.3.40', 40812, 'CLOSED')
        native = m.System()
        printed = {'stdout': b'', 'stderr': b'netstat: sysctl: net.inet.tcp.pcblist: Cannot allocate memory\n'}

        def redirect_sockets(system, port):
            # The installed netstat call and its checks, over this output.
            system.calls.append('netstat')
            with mock.patch.object(native, 'run', return_value=subprocess.CompletedProcess(
                    [], 0, printed['stdout'], printed['stderr'])):
                return native.redirect_sockets(port)

        lines = len(self.log())
        with mock.patch.object(ReaperSystem, 'redirect_sockets', redirect_sockets):
            for _ in range(3):
                status = self.minutes(1)
                self.assertTrue(status['running'] and status['tcp_redirect'])
                self.assertEqual('', status['error'])
            self.assertEqual([m.STALE_FAILED_LOG % ('netstat did not list the sockets: netstat listed no listener on '
                                                    '127.0.0.1.%d: netstat: sysctl: net.inet.tcp.pcblist: Cannot '
                                                    'allocate memory' % PORT)], self.logged(lines))
            self.assertEqual(['stale'], list(self.system.connections))
            # A complete list closes it at the next scan.
            printed.update(stdout=netstat([(('192.168.3.40', 40812), 'CLOSED')]).encode(), stderr=b'')
            lines = len(self.log())
            self.minutes(1)
        self.assertEqual({}, self.system.connections)
        self.assertEqual([m.STALE_LOG % (1, 1, 0, 0)], self.logged(lines))

    def test_a_failing_scan_leaves_the_crash_rescue_and_the_memory_guard_alone(self):
        self.system.add('stale', '192.168.3.40', 40812, 'CLOSED')
        self.system.failures = {'list': OSError('timed out')}
        lines = len(self.log())
        self.minutes(2)
        self.assertEqual([m.STALE_FAILED_LOG % 'the controller did not list the connections: timed out'],
                         self.logged(lines))
        identity = self.system.identity
        self.system.resident = 3 * 1024 ** 3
        status = self.tick()
        self.assertNotEqual(identity, self.system.identity, 'the memory guard restarted the core')
        self.assertEqual(m.MEMORY_RESTART_REASON % ('3.0 GB', '2.0 GB'), status['last_restart']['reason'])
        self.system.resident = 150 * 1024 ** 2
        self.crash()
        self.restart_after(60)
        self.assertTrue(self.status()['running'])

    def test_a_close_that_fails_stops_the_scan_and_the_rest_wait_for_the_next(self):
        for index in range(3):
            self.system.add('stale-%d' % index, '192.168.3.40', 40000 + index, 'CLOSED')
        original = self.system.controller
        answered = []

        def flaky(method, path, payload=None, **options):
            if method == 'DELETE':
                answered.append(path)
                if len(answered) == 2:
                    raise OSError('timed out')
            return original(method, path, payload, **options)

        self.manager.proxy_api = flaky
        lines = len(self.log())
        status = self.tick()
        self.assertEqual(['stale-1', 'stale-2'], sorted(self.system.connections))
        self.assertEqual([m.STALE_LOG % (1, 1, 0, 0) + m.STALE_DEFERRED_LOG % 2,
                          m.STALE_FAILED_LOG % 'the controller did not close a connection: timed out'],
                         self.logged(lines))
        self.assertEqual('', status['error'])
        self.minutes(1)
        self.assertEqual([], list(self.system.connections))
        self.assertEqual(3, self.status()['stale_connections_closed'])

    def held(self, count, port=57846):
        """count FIN_WAIT_2 client sockets the core no longer lists, watched until they are due."""
        clients = [('192.168.3.2', port + index) for index in range(count)]
        self.system.orphans += [(client, 'FIN_WAIT_2') for client in clients]
        self.tick()
        self.minutes(4)
        self.assertEqual([], self.system.drops())
        return clients

    def test_a_tcpdrop_failure_is_logged_once_never_breaks_the_tick_and_never_stops_the_closes(self):
        clients = self.held(2)
        self.system.add('stale', '192.168.3.40', 40812, 'CLOSED')
        self.system.failures = {'drop': m.Error('tcpdrop exited with status 1: Operation not permitted')}
        lines = len(self.log())
        for _ in range(3):
            status = self.minutes(1)
            self.assertTrue(status['running'] and status['routing_active'] and status['tcp_redirect'])
            self.assertEqual('', status['error'])
        # The first failure ends that scan's drops; the closes go on.
        self.assertEqual([clients[0]] * 3, self.system.drops())
        self.assertEqual(['stale'], self.system.deletes())
        self.assertEqual([m.STALE_LOG % (1, 1, 0, 0) + m.STALE_DEFERRED_LOG % 2,
                          m.STALE_FAILED_LOG % ('tcpdrop did not drop a socket: tcpdrop exited with status 1: '
                                                'Operation not permitted')], self.logged(lines))
        self.assertEqual(sorted(clients), sorted(found for found, _ in self.system.orphans))
        # Both are dropped at the next scan that can, without waiting again.
        self.system.failures = {}
        lines = len(self.log())
        self.minutes(1)
        self.assertEqual([], self.system.orphans)
        self.assertEqual([m.STALE_LOG % (2, 0, 0, 2)], self.logged(lines))
        self.assertEqual(3, self.status()['stale_connections_closed'])

    def test_a_failure_of_tcpdrop_and_of_the_controller_in_one_scan_are_logged_together_once(self):
        self.held(1)
        self.system.add('stale', '192.168.3.40', 40812, 'CLOSED')
        self.system.failures = {'drop': m.Error('A system operation failed or timed out.'),
                                'close': OSError('timed out')}
        lines = len(self.log())
        self.minutes(3)
        self.assertEqual([m.STALE_FAILED_LOG % ('tcpdrop did not drop a socket: A system operation failed or timed '
                                                'out.; the controller did not close a connection: timed out')],
                         self.logged(lines))
        # One of them recovered is a different failure, logged once.
        del self.system.failures['close']
        lines = len(self.log())
        self.minutes(2)
        self.assertEqual([m.STALE_LOG % (1, 1, 0, 0) + m.STALE_DEFERRED_LOG % 1,
                          m.STALE_FAILED_LOG % ('tcpdrop did not drop a socket: A system operation failed or timed '
                                                'out.')], self.logged(lines))

    def test_a_real_tcpdrop_failure_reads_the_same_for_every_socket_and_is_logged_once(self):
        native = m.System()

        def drop_redirect_socket(system, port, client):
            # The installed tcpdrop call and its checks, over what tcpdrop
            # prints when the kernel refuses: the socket's own name included.
            system.calls.append(('tcpdrop', port, client))
            warning = 'tcpdrop: 127.0.0.1 %d %s %d: Operation not permitted\n' % (port, client[0], client[1])
            with mock.patch.object(native, 'run', return_value=subprocess.CompletedProcess(
                    [], 1, b'', warning.encode())):
                return native.drop_redirect_socket(port, client)

        clients = self.held(3)
        lines = len(self.log())
        with mock.patch.object(ReaperSystem, 'drop_redirect_socket', drop_redirect_socket):
            for _ in range(3):
                # Another socket comes first at every scan.
                self.system.orphans.append(self.system.orphans.pop(0))
                self.minutes(1)
        self.assertEqual(clients[1:] + clients[:1], self.system.drops())
        self.assertEqual([m.STALE_FAILED_LOG % ('tcpdrop did not drop a socket: tcpdrop exited with status 1: '
                                                'Operation not permitted')], self.logged(lines))

    def test_a_socket_that_ends_before_tcpdrop_reaches_it_is_skipped_and_the_others_are_still_dropped(self):
        clients = self.held(3)
        # The second one's client sends its FIN or a reset in the seconds
        # between netstat and its drop, so the kernel no longer finds it.
        self.system.vanishing.add(clients[1])
        lines = len(self.log())
        status = self.minutes(1)
        self.assertEqual(clients, self.system.drops())
        self.assertEqual([], self.system.orphans)
        # Nothing failed: only the two drops are logged and counted.
        self.assertEqual([m.STALE_LOG % (2, 0, 0, 2)], self.logged(lines))
        self.assertEqual(2, status['stale_connections_closed'])
        self.assertEqual({}, self.manager._stale['held'])
        self.assertIsNone(self.manager._stale['failure'])
        # Its client reuses the port and the core finishes toward it again:
        # a new socket, which waits from the start and is then dropped.
        self.system.orphans.append((clients[1], 'FIN_WAIT_2'))
        self.minutes(5)
        self.assertEqual(clients, self.system.drops())
        self.minutes(1)
        self.assertEqual(clients + [clients[1]], self.system.drops())
        self.assertEqual([], self.system.orphans)
        self.assertEqual(set(), self.manager._stale['vanished'])
        self.assertEqual([m.STALE_LOG % (2, 0, 0, 2), m.STALE_LOG % (1, 0, 0, 1)], self.logged(lines))

    def test_a_socket_the_kernel_never_finds_while_netstat_keeps_listing_it_is_a_failure(self):
        clients = self.held(2)
        # netstat lists the first in FIN_WAIT_2 at every scan, but tcpdrop's
        # lookup never finds it: the two disagree, which must not pass unseen.
        self.system.unfound.add(clients[0])
        lines = len(self.log())
        self.minutes(1)
        # A first miss reads as a socket that ended meanwhile.
        self.assertEqual(clients, self.system.drops())
        self.assertEqual([m.STALE_LOG % (1, 0, 0, 1)], self.logged(lines))
        # Still listed, it waits from the start; missed again, it is a
        # failure, logged once and tried again at every scan.
        self.minutes(5)
        self.assertEqual(clients, self.system.drops())
        lines = len(self.log())
        for _ in range(3):
            status = self.minutes(1)
            self.assertTrue(status['running'] and status['tcp_redirect'])
            self.assertEqual('', status['error'])
        self.assertEqual(clients + [clients[0]] * 3, self.system.drops())
        self.assertEqual([m.STALE_FAILED_LOG % ('tcpdrop did not drop a socket: tcpdrop exited with status 1: '
                                                'No such process')], self.logged(lines))
        # Once netstat no longer lists it, it is forgotten.
        self.system.orphans.clear()
        self.minutes(2)
        self.assertEqual(clients + [clients[0]] * 3, self.system.drops())
        self.assertIsNone(self.manager._stale['failure'])
        self.assertEqual(({}, set()), (self.manager._stale['held'], self.manager._stale['vanished']))

    def test_a_new_core_and_a_pause_of_the_fast_tcp_path_forget_the_sockets_tcpdrop_missed(self):
        client = self.held(1)[0]
        self.system.unfound.add(client)
        lines = len(self.log())
        self.minutes(1)
        self.assertEqual({client}, self.manager._stale['vanished'])
        # The socket on that endpoint is now the new core's, so a miss on it
        # after its own wait is a first one again.
        self.manager.dispatch('restart')
        self.minutes(6)
        self.assertEqual([client] * 2, self.system.drops())
        self.assertEqual({client}, self.manager._stale['vanished'])
        # So is one after a pause, which was not watched.
        self.manager.write_settings(dict(self.manager.settings(), tcp_redirect=False))
        self.minutes(1)
        self.assertEqual(set(), self.manager._stale['vanished'])
        self.manager.write_settings(dict(self.manager.settings(), tcp_redirect=True))
        self.minutes(6)
        self.assertEqual([client] * 3, self.system.drops())
        self.assertEqual([], [line for line in self.logged(lines) if 'stale connections' in line])

    def test_closing_stops_after_its_time_budget_and_continues_at_the_next_scan(self):
        for index in range(8):
            self.system.add('stale-%d' % index, '192.168.3.40', 40000 + index, 'CLOSED')
        self.system.close_cost = 1
        lines = len(self.log())
        self.tick()
        self.assertEqual(m.STALE_CLOSE_BUDGET, len(self.system.deletes()))
        self.assertEqual([m.STALE_LOG % (5, 5, 0, 0) + m.STALE_DEFERRED_LOG % 3], self.logged(lines))
        self.assertEqual('Closed 5 stale connections of the fast TCP path (5 whose client had closed, 0 '
                         'half-closed and idle for 5 minutes, 0 held open by a client that never closed). '
                         '3 more are closed at the next scan.', self.logged(lines)[0])
        self.minutes(1)
        self.assertEqual([], list(self.system.connections))
        self.assertEqual([m.STALE_LOG % (3, 3, 0, 0)], self.logged(lines)[1:])

    def test_one_time_budget_covers_the_drops_and_the_closes_and_drops_go_first(self):
        clients = self.held(4)
        for index in range(4):
            self.system.add('stale-%d' % index, '192.168.3.40', 40000 + index, 'CLOSED')
        self.system.close_cost = self.system.drop_cost = 1
        self.system.calls.clear()
        lines = len(self.log())
        self.minutes(1)
        # Five seconds' worth: every drop, then one close.
        self.assertEqual(clients, self.system.drops())
        self.assertEqual(['stale-0'], self.system.deletes())
        self.assertEqual([m.STALE_LOG % (5, 1, 0, 4) + m.STALE_DEFERRED_LOG % 3], self.logged(lines))
        # Netstat right before the drops, the closes after them.
        order = [call if call == 'netstat' else call[0] for call in self.system.calls
                 if call == 'netstat' or call[0] in ('tcpdrop', 'DELETE')]
        self.assertEqual(['netstat'] + ['tcpdrop'] * 4 + ['DELETE'], order)
        self.minutes(1)
        self.assertEqual({}, self.system.connections)
        self.assertEqual([m.STALE_LOG % (3, 3, 0, 0)], self.logged(lines)[1:])

    def test_drops_beyond_the_budget_are_made_at_the_next_scan_without_waiting_again(self):
        clients = self.held(8)
        self.system.drop_cost = 1
        lines = len(self.log())
        self.minutes(1)
        self.assertEqual(clients[:m.STALE_CLOSE_BUDGET], self.system.drops())
        self.assertEqual([m.STALE_LOG % (5, 0, 0, 5) + m.STALE_DEFERRED_LOG % 3], self.logged(lines))
        self.minutes(1)
        self.assertEqual(clients, self.system.drops())
        self.assertEqual([], self.system.orphans)
        self.assertEqual([m.STALE_LOG % (3, 0, 0, 3)], self.logged(lines)[1:])
        self.assertEqual(8, self.status()['stale_connections_closed'])

    def test_the_count_is_kept_for_the_running_core_and_starts_again_with_a_new_one(self):
        self.system.add('a', '192.168.3.40', 40812, 'CLOSED')
        self.system.add('b', '192.168.3.41', 40813, 'CLOSED')
        self.tick()
        self.assertEqual(2, self.status()['stale_connections_closed'])
        # Every other publisher reads the same count.
        self.assertEqual(2, self.manager.dispatch('status')['stale_connections_closed'])
        self.assertEqual(0o600, self.manager.stale_file.stat().st_mode & 0o777)
        self.assertTrue(str(self.manager.stale_file).endswith('/var/run/mihomo-stale-connections.json'))
        # A watchdog that starts again counts on for the same core.
        restarted = m.Manager(Path(self.temp.name), self.system, proxy_api=self.system.controller)
        restarted.clock = self.clock
        self.manager = restarted
        self.system.add('c', '192.168.3.42', 40814, 'CLOSED')
        self.assertEqual(3, self.tick()['stale_connections_closed'])
        # A new core starts from zero, whoever publishes.
        self.manager.dispatch('restart')
        self.assertEqual(0, self.status()['stale_connections_closed'])
        self.assertEqual(0, self.tick()['stale_connections_closed'])
        self.system.add('d', '192.168.3.43', 40815, 'CLOSED')
        self.assertEqual(1, self.minutes(1)['stale_connections_closed'])
        # A stopped core has no count; a record that is not ours reads as 0.
        self.manager.dispatch('stop')
        self.assertIsNone(self.status()['stale_connections_closed'])
        self.manager.dispatch('start')
        for broken in ('nonsense', '[]', json.dumps({'version': 1, 'core': self.system.identity, 'closed': -1}),
                       json.dumps({'version': 1, 'core': self.system.identity, 'closed': True}),
                       json.dumps({'version': 2, 'core': self.system.identity, 'closed': 5}),
                       json.dumps({'version': 1, 'core': self.system.identity, 'closed': 5, 'extra': 1})):
            with self.subTest(broken=broken):
                self.manager.stale_file.write_text(broken)
                self.assertEqual(0, self.manager.publish_status()['stale_connections_closed'])
        self.manager.stale_file.write_text(json.dumps({'version': 1, 'core': self.system.identity, 'closed': 5}))
        self.assertEqual(5, self.manager.publish_status()['stale_connections_closed'])

    def test_a_new_core_forgets_the_old_ones_half_closed_connections_and_held_sockets(self):
        client = ('192.168.3.2', 57846)
        self.system.add('half', '192.168.3.42', 60001, 'CLOSE_WAIT')
        self.system.orphans.append((client, 'FIN_WAIT_2'))
        self.tick()
        self.assertIn('half', self.manager._stale['seen'])
        self.assertIn(client, self.manager._stale['held'])
        self.minutes(3)
        self.manager.dispatch('restart')
        # What the new core lists, even under an id the old one used, and a
        # socket on the same endpoint now are the new core's, first seen now.
        self.system.add('half', '192.168.3.42', 60001, 'CLOSE_WAIT')
        self.minutes(1)
        self.assertEqual({'half': (self.clock.now, 517 + 4410)}, self.manager._stale['seen'])
        self.assertEqual({client: (self.clock.now, None)}, self.manager._stale['held'])
        # Five minutes after the old core first saw them, nothing is due yet.
        self.minutes(4)
        self.assertEqual(([], []), (self.system.deletes(), self.system.drops()))
        self.minutes(1)
        self.assertEqual((['half'], [client]), (self.system.deletes(), self.system.drops()))

    def test_the_backup_guard_branch_scans_nothing(self):
        self.system.add('stale', '192.168.3.40', 40812, 'CLOSED')
        with mock.patch.object(self.manager, '_guard_backup', side_effect=m.Error('A restored backup is pending.')):
            self.minutes(3)
        self.assertEqual(0, self.system.scans())
        self.tick()
        self.assertEqual(['stale'], self.system.deletes())

    def test_a_list_longer_than_fifty_thousand_is_scanned_whole(self):
        # More than any router keeps alive; every entry is still read, and
        # each is looked at once.
        count = 50002
        for index in range(count):
            address = '10.%d.%d.%d' % (index >> 16, (index >> 8) & 255, index & 255)
            self.system.add('id-%d' % index, address, 1024 + index % 60000,
                            'CLOSED' if index % 2 else 'ESTABLISHED')
        self.system.copies = False
        started = time.process_time()
        status = self.tick()
        self.assertLess(time.process_time() - started, 30)
        self.assertEqual(count // 2, len(self.system.deletes()))
        self.assertEqual(count // 2, len(self.system.connections))
        self.assertEqual(count // 2, status['stale_connections_closed'])
        self.assertTrue(all(int(ident[3:]) % 2 == 0 for ident in self.system.connections))


class StatusViewTests(unittest.TestCase):
    VIEW = SOURCE / 'usr/local/opnsense/mvc/app/views/OPNsense/Mihomo/index.volt'

    def test_the_status_area_shows_the_count_beside_core_memory(self):
        view = self.VIEW.read_text()
        self.assertIn("{{ lang._('Stale connections closed: %s') }}", view)
        notes = view[view.index("{{ lang._('Core memory: %s') }}"):view.index('state.restart_note')]
        self.assertIn('state.stale_connections_closed', notes)
        self.assertIn('"stale_connections_closed": stale_closed',
                      (SOURCE / 'usr/local/opnsense/scripts/mihomo/mihomo.py').read_text())

    def test_both_readmes_explain_the_cleanup_its_cause_and_its_limit(self):
        # Each README quotes the status label and the log line as written.
        quoted = ('`Stale connections closed: 7684`', '`%s`' % (m.STALE_LOG % (14, 11, 1, 2)), 'tcpdrop')
        for path, terms in ((ROOT / 'README.US.md', quoted + ('half-close', 'fast TCP path', 'TUN', 'CLOSED',
                                                             'FIN_WAIT_2', 'CLOSE_WAIT', 'five minutes')),
                            (ROOT / 'README.md', quoted + ('半关闭', '快速 TCP 路径', 'TUN', 'CLOSED', 'FIN_WAIT_2',
                                                           'CLOSE_WAIT', '5 分钟')),
                            (ROOT / 'DESIGN.md', ('STALE_IDLE', 'netstat', 'DELETE /connections/', 'Redir',
                                                  'common/net/sing.go', 'tcpdrop', 'held_sockets()',
                                                  'FIN_WAIT_2', 'CLOSE_WAIT', 'STALE_HELD_STATES', 'NoSuchSocketError',
                                                  'No such process'))):
            with self.subTest(path=path.name):
                text = path.read_text()
                for term in terms:
                    self.assertIn(term, text)


if __name__ == '__main__':
    unittest.main()
