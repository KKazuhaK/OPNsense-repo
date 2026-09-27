"""Exercise the DNS probe and the verdict that arms or withdraws the captured-device redirect."""
import ast
import importlib.util
import ipaddress
import socket
import struct
import sys
import threading
import time
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / 'src/usr/local/opnsense/scripts/mihomo/dns_probe.py'
spec = importlib.util.spec_from_file_location('dns_probe_under_test', SCRIPT)
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)

CORE = {'pid': 4242, 'birth': '1700000000:123456'}
OTHER = {'pid': 4243, 'birth': '1700000001:5'}


def reply(query, rcode, identifier=None, flags=0x8180, question=None):
    """A reply to query with the given response code, or with a forged identifier or question."""
    head = struct.pack('!HHHHHH', struct.unpack('!H', query[:2])[0] if identifier is None else identifier,
                       (flags & 0xFFF0) | rcode, 1, 0, 0, 0)
    return head + (query[12:] if question is None else question)


class Server:
    """A loopback DNS listener answering each query through handler(query) -> [datagrams]."""

    def __init__(self, transport, handler):
        self.transport, self.handler = transport, handler
        kind = socket.SOCK_DGRAM if transport == 'udp' else socket.SOCK_STREAM
        self.socket = socket.socket(socket.AF_INET, kind)
        self.socket.bind(('127.0.0.1', 0))
        self.port = self.socket.getsockname()[1]
        if transport == 'tcp':
            self.socket.listen(4)
        self.socket.settimeout(0.05)
        self.stopping = False
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        while not self.stopping:
            try:
                if self.transport == 'udp':
                    data, peer = self.socket.recvfrom(4096)
                    for answer in self.handler(data):
                        self.socket.sendto(answer, peer)
                    continue
                connection, _ = self.socket.accept()
            except (socket.timeout, OSError):
                continue
            with connection:
                connection.settimeout(1)
                try:
                    size = struct.unpack('!H', connection.recv(2))[0]
                    data = b''
                    while len(data) < size:
                        data += connection.recv(size - len(data))
                    for answer in self.handler(data):
                        connection.sendall(struct.pack('!H', len(answer)) + answer)
                except (OSError, struct.error):
                    pass

    def close(self):
        self.stopping = True
        self.thread.join()
        self.socket.close()


class QueryTests(unittest.TestCase):
    def serve(self, transport, handler):
        server = Server(transport, handler)
        self.addCleanup(server.close)
        return server.port

    def test_a_query_is_one_recursive_question_with_a_random_identifier(self):
        query = p.build_query('Localhost')
        self.assertEqual(struct.pack('!HHHH', 0x0100, 1, 0, 0), query[2:10])
        self.assertEqual(b'\x09Localhost\x00\x00\x01\x00\x01', query[12:])
        self.assertGreater(len({p.build_query('x.example.com')[:2] for _ in range(64)}), 1)
        for invalid in ('', '.', 'a..b', 'x' * 64 + '.com', ('a' * 63 + '.') * 4 + 'com', 'café.com'):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                p.build_query(invalid)

    def test_only_the_reply_to_this_question_counts(self):
        query = p.build_query('probe.example.com')
        self.assertEqual(p.NXDOMAIN, p.answer_rcode(reply(query, p.NXDOMAIN), query))
        # Case may differ in an echoed question; nothing else may.
        self.assertEqual(0, p.answer_rcode(reply(query, 0, question=query[12:].upper()), query))
        other = (struct.unpack('!H', query[:2])[0] + 1) % 65536
        for name, response in (('another identifier', reply(query, 0, identifier=other)),
                               ('a query, not a reply', reply(query, 0, flags=0x0100)),
                               ('another question', reply(query, 0, question=p.build_query('x.example.com')[12:])),
                               ('truncated header', reply(query, 0)[:11])):
            with self.subTest(name):
                self.assertIsNone(p.answer_rcode(response, query))
        # A server that echoes no question still answers by identifier.
        bare = reply(query, p.SERVFAIL)[:12]
        bare = bare[:4] + b'\x00\x00' + bare[6:]
        self.assertEqual(p.SERVFAIL, p.answer_rcode(bare, query))

    def test_udp_returns_the_response_code_and_ignores_stray_datagrams(self):
        for rcode in (p.NOERROR, p.SERVFAIL, p.NXDOMAIN, 5):
            with self.subTest(rcode=rcode):
                port = self.serve('udp', lambda data, rcode=rcode: [
                    reply(data, 0, identifier=(struct.unpack('!H', data[:2])[0] + 1) % 65536),
                    reply(data, 0, question=b'\x01x\x00\x00\x01\x00\x01'),
                    reply(data, rcode)])
                self.assertEqual(rcode, p.query('127.0.0.1', port, 'localhost', 'udp', 1.0))

    def test_tcp_returns_the_response_code_and_rejects_another_answer(self):
        port = self.serve('tcp', lambda data: [reply(data, p.NXDOMAIN)])
        self.assertEqual(p.NXDOMAIN, p.query('127.0.0.1', port, 'localhost', 'tcp', 1.0))
        port = self.serve('tcp', lambda data: [reply(data, 0, identifier=(struct.unpack('!H', data[:2])[0] + 1) % 65536)])
        with self.assertRaises(p.ProbeError):
            p.query('127.0.0.1', port, 'localhost', 'tcp', 1.0)
        port = self.serve('tcp', lambda data: [])
        with self.assertRaises(p.ProbeError):
            p.query('127.0.0.1', port, 'localhost', 'tcp', 1.0)

    def test_silence_and_a_closed_port_are_no_answer_within_the_deadline(self):
        for transport in ('udp', 'tcp'):
            with self.subTest(transport=transport):
                # A listener that never answers: the whole query is bounded.
                port = self.serve(transport, lambda data: time.sleep(0.5) or [])
                started = time.monotonic()
                with self.assertRaises(p.ProbeError):
                    p.query('127.0.0.1', port, 'localhost', transport, 0.2)
                self.assertLess(time.monotonic() - started, 0.45)
                # A stray answer does not extend a UDP deadline either.
        port = self.serve('udp', lambda data: [reply(data, 0, identifier=(struct.unpack('!H', data[:2])[0] + 1) % 65536)])
        started = time.monotonic()
        with self.assertRaises(p.ProbeError):
            p.query('127.0.0.1', port, 'localhost', 'udp', 0.2)
        self.assertLess(time.monotonic() - started, 0.45)
        closed = socket.socket()
        closed.bind(('127.0.0.1', 0))
        port = closed.getsockname()[1]
        closed.close()
        for transport in ('udp', 'tcp'):
            with self.subTest(closed=transport), self.assertRaises(p.ProbeError):
                p.query('127.0.0.1', port, 'localhost', transport, 0.5)
        with self.assertRaises(ValueError):
            p.query('127.0.0.1', port, 'localhost', 'quic', 0.5)

    def test_a_verdict_counts_nxdomain_as_an_answer_and_only_servfail_or_silence_as_failure(self):
        def ask(result):
            def answer(server, name, timeout):
                if isinstance(result, Exception):
                    raise result
                return result
            return answer
        for result, expected in ((p.NOERROR, 'ok'), (p.NXDOMAIN, 'ok'), (p.SERVFAIL, 'fail'),
                                 (p.ProbeError('timed out'), 'fail'), (5, 'other'), (1, 'other'), (4, 'other')):
            with self.subTest(result=result):
                self.assertEqual(expected, p.verdict(ask(result), p.MIHOMO, 'x.example.com', 1))

    def test_the_module_uses_the_standard_library_only(self):
        # The routing adapter imports it as well as the manager.
        tree = ast.parse(SCRIPT.read_text())
        modules = {alias.name.split('.')[0] for node in ast.walk(tree) if isinstance(node, ast.Import)
                   for alias in node.names}
        modules |= {node.module.split('.')[0] for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
        self.assertTrue(modules)
        self.assertLessEqual(modules, set(sys.stdlib_module_names))


class Clock:
    def __init__(self, now=1000.0):
        self.now = now

    def __call__(self):
        return self.now


class Ask:
    """Scripted listeners: liveness answers from Mihomo, and upstream answers per server."""

    def __init__(self):
        self.liveness = p.NOERROR
        self.mihomo = p.NXDOMAIN
        self.router = p.NOERROR
        self.calls = []

    def __call__(self, server, name, timeout):
        self.calls.append((server, name, timeout))
        if name == p.LIVENESS_NAME:
            self.assert_server(server, p.MIHOMO)
            result = self.liveness
        else:
            result = self.mihomo if server == p.MIHOMO else self.router
        if callable(result):
            result = result(name)
        if isinstance(result, Exception):
            raise result
        return result

    @staticmethod
    def assert_server(server, expected):
        if server != expected:
            raise AssertionError(server)

    def upstream(self):
        return [call for call in self.calls if call[1] != p.LIVENESS_NAME]


class VerdictTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.ask = Ask()
        self.labels = iter('label%d' % number for number in range(1000))
        self.record = None
        self.pauses = []

    def sleep(self, seconds):
        self.pauses.append(seconds)
        self.clock.now += seconds

    def tick(self, seconds=5.0, identity=CORE):
        self.clock.now += seconds
        self.record = p.tick(self.record, identity, self.clock, self.ask, lambda: next(self.labels), self.sleep)
        self.assertTrue(p.valid(self.record))
        return self.record

    def armed(self):
        return p.redirect_allowed(self.record, CORE, self.clock())

    def test_a_new_core_is_untrusted_until_its_first_answer(self):
        self.ask.liveness = p.ProbeError('silent')
        self.tick()
        self.assertEqual((False, 'starting'), (self.record['healthy'], self.record['reason']))
        self.assertFalse(self.armed())
        self.ask.liveness = p.NOERROR
        self.tick()
        self.assertTrue(self.armed())
        # A core that never answered twice needs the full hysteresis instead.
        self.record = None
        self.ask.liveness = p.ProbeError('silent')
        self.tick()
        self.tick()
        self.assertEqual('liveness', self.record['reason'])
        self.ask.liveness = p.NOERROR
        self.tick()
        self.tick()
        self.assertFalse(self.armed())
        self.tick()
        self.assertTrue(self.armed())

    def test_two_liveness_failures_withdraw_and_three_passes_rearm(self):
        self.tick()
        self.assertTrue(self.armed())
        for answer in (p.ProbeError('silent'), p.SERVFAIL, 5):
            with self.subTest(answer=answer):
                self.ask.liveness = answer
                self.ask.calls.clear()
                self.pauses.clear()
                # An armed core's first failure is asked again a second later,
                # within the same tick, and the second failure withdraws.
                self.tick()
                self.assertFalse(self.armed())
                self.assertEqual('liveness', self.record['reason'])
                self.assertEqual([p.CONFIRM_PAUSE], self.pauses)
                self.assertEqual([p.LIVENESS_NAME] * 2, [call[1] for call in self.ask.calls])
                # Withdrawn, it is asked once a tick again.
                self.tick()
                self.assertEqual([p.CONFIRM_PAUSE], self.pauses)
                self.assertEqual(3, len(self.ask.calls))
                self.ask.liveness = p.NXDOMAIN
                self.tick()
                self.tick()
                self.assertFalse(self.armed(), 'Two passes are not enough.')
                self.tick()
                self.assertTrue(self.armed())
        # One unanswered query the second one clears withdraws nothing, and
        # that tick leaves its due upstream round to the next.
        answers = iter([p.ProbeError('silent'), p.NOERROR])
        self.ask.liveness = lambda name: next(answers)
        self.ask.calls.clear()
        self.tick(60)
        self.assertTrue(self.armed())
        self.assertEqual((0, 1), (self.record['failures'], self.record['passes']))
        self.assertEqual([], self.ask.upstream())
        self.ask.liveness = p.NOERROR
        self.tick()
        self.assertEqual(1, len(self.ask.upstream()))
        # A blip between passes starts the count again.
        self.ask.liveness = p.ProbeError('silent')
        self.tick()
        self.tick()
        self.ask.liveness = p.NOERROR
        self.tick()
        self.tick()
        self.ask.liveness = p.ProbeError('silent')
        self.tick()
        self.ask.liveness = p.NOERROR
        self.tick()
        self.tick()
        self.assertFalse(self.armed())
        self.tick()
        self.assertTrue(self.armed())

    def test_upstream_rounds_rotate_zones_with_random_labels_about_once_a_minute(self):
        for _ in range(40):
            self.tick()
        names = [call[1] for call in self.ask.upstream()]
        # The first tick and then every sixty seconds: 5 s ticks for 200 s.
        self.assertEqual(4, len(names))
        self.assertEqual(['label0.example.com', 'label1.cloudflare.com', 'label2.microsoft.com',
                          'label3.example.com'], names)
        self.assertTrue(all(call[0] == p.MIHOMO and call[2] == p.UPSTREAM_TIMEOUT for call in self.ask.upstream()))
        self.assertEqual(3, len(set(p.UPSTREAM_DOMAINS)))
        self.assertRegex(p.random_label(), r'\A[0-9a-f]{16}\Z')
        self.assertNotEqual(p.random_label(), p.random_label())
        for call in self.ask.calls:
            if call[1] == p.LIVENESS_NAME:
                self.assertEqual((p.MIHOMO, p.LIVENESS_TIMEOUT), (call[0], call[2]))

    def test_the_router_dns_is_asked_only_when_mihomo_fails(self):
        self.tick()
        self.assertEqual([p.MIHOMO], [call[0] for call in self.ask.upstream()])
        self.ask.mihomo = p.SERVFAIL
        self.tick(60)
        self.assertEqual([p.MIHOMO, p.MIHOMO, p.ROUTER], [call[0] for call in self.ask.upstream()])
        self.assertEqual(self.ask.upstream()[-2][1], self.ask.upstream()[-1][1])

    def test_mihomo_failing_where_the_router_answers_on_two_zones_withdraws(self):
        self.tick()
        self.ask.mihomo = p.SERVFAIL
        self.tick(60)
        self.assertTrue(self.armed(), 'One zone is not enough.')
        self.ask.mihomo = p.ProbeError('silent')
        self.tick(60)
        self.assertFalse(self.armed())
        self.assertEqual('upstream', self.record['reason'])
        self.assertEqual({'cloudflare.com', 'microsoft.com'}, p.evidence(self.record))
        # Liveness passing is not enough to come back; Mihomo must resolve.
        for _ in range(11):
            self.tick()
        self.assertFalse(self.armed())
        self.tick()
        self.assertFalse(self.armed())
        self.ask.mihomo = p.NXDOMAIN
        self.tick(60)
        self.assertTrue(self.armed())
        self.assertEqual([], self.record['rounds'])

    def test_both_failing_does_nothing(self):
        # The WAN is down: Mihomo and the router DNS fail alike, round after round.
        self.tick()
        self.ask.mihomo = p.SERVFAIL
        self.ask.router = p.ProbeError('silent')
        for _ in range(6):
            self.tick(60)
            self.assertTrue(self.armed())
        # One zone's own servers failing is no evidence against Mihomo, and
        # its rounds push older evidence out rather than joining it.
        self.ask.router = lambda name: p.SERVFAIL if name.endswith('.cloudflare.com') else p.NOERROR
        self.ask.mihomo = p.NOERROR
        self.record = None
        self.tick()     # example.com: Mihomo answers
        self.ask.mihomo = p.SERVFAIL
        self.tick(60)   # cloudflare.com: both fail
        self.tick(60)   # microsoft.com: Mihomo fails, the router answers
        self.assertTrue(self.armed())
        self.tick(60)   # example.com: the second zone
        self.assertFalse(self.armed())
        self.assertEqual({'example.com', 'microsoft.com'}, p.evidence(self.record))

    def test_evidence_expires_with_the_rounds_that_carried_it(self):
        self.tick()
        self.ask.mihomo = p.SERVFAIL
        self.ask.router = p.NOERROR
        self.tick(60)
        self.ask.router = p.ProbeError('silent')
        for _ in range(3):
            self.tick(60)
        self.assertEqual(set(), p.evidence(self.record))
        self.ask.router = p.NOERROR
        self.tick(60)
        self.assertTrue(self.armed(), 'Evidence from four rounds ago no longer counts.')

    def test_nxdomain_or_an_empty_answer_clears_the_evidence(self):
        for answer in (p.NXDOMAIN, p.NOERROR):
            with self.subTest(answer=answer):
                self.record = None
                self.ask.mihomo = p.NOERROR
                self.tick()
                self.ask.mihomo = p.SERVFAIL
                self.tick(60)
                self.ask.mihomo = answer
                self.tick(60)
                self.ask.mihomo = p.SERVFAIL
                self.tick(60)
                self.assertTrue(self.armed())
                self.assertEqual(1, len(p.evidence(self.record)))

    def test_an_answer_that_is_neither_success_nor_failure_proves_nothing(self):
        self.tick()
        self.ask.mihomo = 5
        for _ in range(4):
            self.tick(60)
        self.assertTrue(self.armed())
        self.assertEqual(set(), p.evidence(self.record))
        self.assertNotIn(p.ROUTER, [call[0] for call in self.ask.upstream()])

    def test_a_listener_that_comes_back_is_checked_upstream_at_once(self):
        self.tick()
        self.ask.liveness = p.ProbeError('silent')
        self.tick()
        self.tick()
        before = len(self.ask.upstream())
        self.ask.liveness = p.NOERROR
        self.tick()
        self.assertEqual(before + 1, len(self.ask.upstream()))
        # Mihomo's upstream failing where the router's works keeps it out even
        # after three passes.
        self.record = None
        self.tick()
        self.ask.mihomo = p.SERVFAIL
        self.tick(60)
        self.ask.liveness = p.ProbeError('silent')
        self.tick()
        self.tick()
        self.ask.liveness = p.NOERROR
        self.tick()
        self.tick()
        self.tick()
        self.assertFalse(self.armed())
        self.assertEqual('upstream', self.record['reason'])
        self.ask.liveness = p.ProbeError('silent')
        self.tick()
        self.tick()
        self.assertEqual('liveness', self.record['reason'])

    def test_a_new_core_or_an_unusable_record_starts_afresh(self):
        self.tick()
        self.ask.liveness = p.ProbeError('silent')
        self.tick()
        self.tick()
        self.assertEqual('liveness', self.record['reason'])
        self.ask.liveness = p.NOERROR
        self.tick(identity=OTHER)
        self.assertEqual(OTHER, self.record['core'])
        self.assertTrue(self.record['healthy'])
        self.assertFalse(p.redirect_allowed(self.record, CORE, self.clock()))
        self.assertTrue(p.redirect_allowed(self.record, OTHER, self.clock()))
        for broken in ({}, [], {'version': 2}, dict(self.record, healthy='yes'), dict(self.record, passes=-1),
                       dict(self.record, rounds=[{'domain': 'example.org', 'mihomo': 'fail', 'router': 'ok'}]),
                       dict(self.record, core={'pid': '4242', 'birth': CORE['birth']}),
                       dict(self.record, checked=True), dict(self.record, armed_since=1.0)):
            with self.subTest(broken=broken):
                self.assertFalse(p.valid(broken))
                self.record = broken
                self.tick(identity=CORE)
                self.assertEqual(CORE, self.record['core'])
        self.assertIsNone(p.core_identity({'pid': 1, 'birth': 'now'}))
        self.assertEqual(CORE, p.core_identity(dict(CORE, ppid=1, argv=['/usr/local/bin/mihomo'])))

    def test_only_a_fresh_healthy_verdict_about_the_running_core_arms(self):
        # Three watchdog ticks of five seconds, as the documentation states.
        self.assertEqual(15.0, p.HEALTH_FRESH)
        self.tick()
        now = self.record['checked']
        self.assertTrue(p.redirect_allowed(self.record, CORE, now + p.HEALTH_FRESH))
        self.assertFalse(p.redirect_allowed(self.record, CORE, now + p.HEALTH_FRESH + 0.01))
        self.assertFalse(p.redirect_allowed(self.record, CORE, now - 0.01))
        self.assertFalse(p.redirect_allowed(self.record, None, now))
        self.assertFalse(p.redirect_allowed(dict(self.record, healthy=False), CORE, now))
        self.assertFalse(p.redirect_allowed(dict(self.record, core=None), CORE, now))
        self.assertFalse(p.redirect_allowed(None, CORE, now))

    def test_the_verdict_is_stamped_after_the_probes_it_rests_on(self):
        def slow(server, name, timeout):
            self.clock.now += 4
            return p.NOERROR
        record = p.tick(None, CORE, self.clock, slow, lambda: 'x')
        self.assertEqual(self.clock.now, record['checked'])
        self.assertEqual(1008.0, record['checked'])

    def test_a_starting_core_is_given_three_seconds_at_most(self):
        sleeps = []

        def sleep(seconds):
            sleeps.append(seconds)
            self.clock.now += seconds

        def silent(server, name, timeout):
            self.assertLessEqual(timeout, p.LIVENESS_TIMEOUT)
            self.clock.now += timeout
            raise p.ProbeError('silent')

        record = p.start(CORE, self.clock, silent, sleep)
        self.assertEqual((False, 'starting', 0), (record['healthy'], record['reason'], record['failures']))
        self.assertLessEqual(record['checked'] - 1000.0, p.START_BUDGET + 0.001)

        def refused(server, name, timeout):
            raise p.ProbeError('refused')

        self.clock.now = 1000.0
        sleeps.clear()
        record = p.start(CORE, self.clock, refused, sleep)
        self.assertFalse(record['healthy'])
        self.assertAlmostEqual(p.START_BUDGET, sum(sleeps))
        answers = iter([p.ProbeError('not yet'), p.NOERROR])

        def ready(server, name, timeout):
            answer = next(answers)
            if isinstance(answer, Exception):
                raise answer
            return answer

        record = p.start(CORE, self.clock, ready, sleep)
        self.assertTrue(p.redirect_allowed(record, CORE, self.clock()))
        # The watchdog's first tick checks upstream straight away.
        self.record = record
        self.tick()
        self.assertEqual(1, len(self.ask.upstream()))


class HintTests(unittest.TestCase):
    STATES = ('all udp 127.0.0.1:1053 (10.0.0.1:53) <- 10.0.0.5:45302       SINGLE:MULTIPLE\n'
              'all tcp 127.0.0.1:7894 (203.0.113.9:443) <- 10.0.0.6:40001       ESTABLISHED:ESTABLISHED\n'
              'all tcp 203.0.113.9:443 <- 10.0.0.7:40002       ESTABLISHED:ESTABLISHED\n'
              'all tcp 192.0.2.10:61000 (10.0.0.7:40002) -> 203.0.113.9:443       ESTABLISHED:ESTABLISHED\n'
              'all udp 10.0.0.1:53 <- 10.9.0.5:45300       SINGLE:MULTIPLE\n'
              'all tcp 2001:db8::1[443] <- 2001:db8::2[5555]       ESTABLISHED:ESTABLISHED\n'
              'all icmp 10.0.0.8:1 <- 10.0.0.1:1       0:0\n')
    SOURCES = [ipaddress.ip_network('10.0.0.0/24'), ipaddress.ip_network('2001:db8:1::/64')]

    def test_the_state_table_shows_redirected_dns_and_other_activity_apart(self):
        self.assertEqual((True, True), p.redirect_activity(self.STATES, self.SOURCES, 1053))
        without = '\n'.join(line for line in self.STATES.splitlines() if ':1053' not in line) + '\n'
        self.assertEqual((False, True), p.redirect_activity(without, self.SOURCES, 1053))
        # Only a captured source's inbound states are its activity; the fast
        # path's translated TCP counts, a translated DNS state does not.
        self.assertEqual((True, False), p.redirect_activity(self.STATES.splitlines()[0], self.SOURCES, 1053))
        self.assertEqual((False, True), p.redirect_activity(self.STATES.splitlines()[1], self.SOURCES, 1053))
        self.assertEqual((False, False), p.redirect_activity('\n'.join(self.STATES.splitlines()[3:]),
                                                             self.SOURCES, 1053))
        self.assertEqual((False, False), p.redirect_activity(self.STATES, [], 1054))

    def test_the_hint_needs_five_quiet_minutes_of_active_captured_sources(self):
        record = p.observe_arming(p.fresh(CORE, 0.0), True, 100.0)
        self.assertEqual((100.0, 100.0, 160.0), (record['armed_since'], record['dns_seen'], record['next_activity']))
        self.assertFalse(p.activity_due(record, 159.0))
        self.assertTrue(p.activity_due(record, 160.0))
        record = p.observe_activity(record, (False, True), 399.0)
        self.assertFalse(record['hint'])
        record = p.observe_activity(record, (False, True), 400.0)
        self.assertTrue(record['hint'])
        self.assertEqual(460.0, record['next_activity'])
        # Unknown activity changes nothing but the schedule.
        self.assertTrue(p.observe_activity(record, None, 460.0)['hint'])
        # One redirected query clears it, and quiet sources raise none.
        cleared = p.observe_activity(record, (True, True), 460.0)
        self.assertEqual((False, 460.0), (cleared['hint'], cleared['dns_seen']))
        self.assertFalse(p.observe_activity(record, (False, False), 460.0)['hint'])
        # Staying armed keeps the start; a withdrawal forgets it all.
        self.assertEqual(100.0, p.observe_arming(record, True, 900.0)['armed_since'])
        withdrawn = p.observe_arming(record, False, 900.0)
        self.assertEqual((None, None, None, False), (withdrawn['armed_since'], withdrawn['dns_seen'],
                                                     withdrawn['next_activity'], withdrawn['hint']))
        self.assertFalse(p.activity_due(withdrawn, 10 ** 6))
        self.assertTrue(p.valid(record) and p.valid(withdrawn))


if __name__ == '__main__':
    unittest.main()
