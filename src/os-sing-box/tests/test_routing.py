"""Exercise private-FIB routing, firewall policy, and ownership transitions."""
import copy
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
import sys
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / 'src/usr/local/opnsense/scripts/singbox/routing.py'
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'common'))
spec = importlib.util.spec_from_file_location('singbox_routing', SCRIPT)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
import tun_policy_routing as shared


def route(destination, gateway, interface, flags='US'):
    net = ipaddress.ip_network(destination)
    return {'family': net.version, 'destination': str(net), 'scope': '',
            'gateway': gateway, 'interface': interface, 'flags': flags, 'discard': ''}


def route_mutation(args):
    return args[0] == '/sbin/route' or (args[0] == '/usr/local/bin/python3' and args[1].endswith('/singbox/native_route.py'))


def state(identifier, fib, policy=''):
    return ('all tcp 10.0.0.2:40000 -> 203.0.113.2:443 ESTABLISHED:ESTABLISHED\n'
            '   age 00:00:01, expires in 00:01:00, rule 1\n'
            '   id: %016x creatorid: 11223344%s rtable: %d\n' % (identifier, policy, fib))


class Kernel:
    """Model native command effects, including kernel-cloned connected routes."""
    def __init__(self):
        base = [route('0.0.0.0/0', '192.0.2.1', 'vtnet0', 'UGS'),
                route('10.0.0.0/24', 'interface', 'vtnet1', 'U'),
                route('10.2.0.0/24', '10.0.0.3', 'vtnet1', 'UGS'),
                route('192.0.2.0/24', 'interface', 'vtnet0', 'U'),
                route('127.0.0.1/32', 'interface', 'lo0', 'UH'),
                route('::/0', '2001:db8:ffff::1', 'vtnet0', 'UGS'),
                route('2001:db8:1::/64', 'interface', 'vtnet1', 'U')]
        self.tables = {0: {m.route_key(value): value for value in base}}
        self.alive = True
        self.stopped = False
        self.fibs = 1
        self.anchor = ''
        self.foreign_rules = ''
        self.fail_rule_scan = False
        self.states = ''
        self.killed = []
        self.calls = []
        self.fail_add = False
        self.fail_key = None
        self.fail_kill = False
        self.populate_foreign = False
        self.empty_header_only = False
        self.diagnosis = b''
        self.delays = []

    def delay(self, seconds):
        self.delays.append(seconds)

    def run(self, args, **options):
        self.calls.append(list(args))
        output, code = b'', 0
        if args == ['/sbin/sysctl', '-n', 'net.fibs']:
            output = str(self.fibs).encode()
        elif args[0] == '/sbin/sysctl':
            self.fibs = int(args[1].split('=')[1])
            cloned = {key: copy.deepcopy(value) for key, value in self.tables[0].items()
                      if value['gateway'] == 'interface'}
            if self.populate_foreign:
                foreign = route('203.0.113.0/24', '192.0.2.9', 'vtnet0')
                cloned[m.route_key(foreign)] = foreign
            self.tables[self.fibs - 1] = cloned
        elif args[0] == '/usr/bin/netstat':
            fib, family = int(args[args.index('-F') + 1]), 4 if args[-1] == 'inet' else 6
            lines = ['Routing tables', 'Destination Gateway Flags Netif Expire']
            for value in self.tables[fib].values():
                if value['family'] == family:
                    gateway = 'link#1' if value['gateway'] == 'interface' else value['gateway']
                    destination = 'default' if value['destination'] in ('0.0.0.0/0', '::/0') else value['destination']
                    lines.append('%s %s %s %s' % (destination, gateway, value['flags'], value['interface']))
            if self.empty_header_only and len(lines) == 2:
                lines = ['Routing tables (fib: %d)' % fib]
            output = ('\n'.join(lines) + '\n').encode()
        elif args[0] == '/bin/ps':
            code = 0 if self.alive else 1
            output = (('Mon Sep 14 01:00:00 2026 /usr/local/bin/sing-box run -c ' + str(self.runtime)).encode()) if self.alive else b''
        elif args == ['/sbin/ifconfig', m.TUN]:
            output = b'tun_singbox: flags=8043\n inet 198.18.0.1 netmask 0xfffffffc\n inet6 fdfe:dcba:9876::1 prefixlen 126\n'
        elif args[:4] == ['/sbin/pfctl', '-a', m.ANCHOR, '-sr']:
            # Real pfctl -sr omits table definitions.
            output = ('\n'.join(line for line in self.anchor.splitlines() if line.startswith('match '))).encode()
        elif args == ['/sbin/pfctl', '-a', '*', '-sr']:
            code = 1 if self.fail_rule_scan else 0
            owned = '\n'.join('  ' + line for line in self.anchor.splitlines()
                              if line.startswith('match '))
            output = ('anchor "%s" all {\n%s\n}\n%s' % (
                m.ANCHOR, owned, self.foreign_rules)).encode()
        elif args[:3] == ['/sbin/pfctl', '-a', m.ANCHOR]:
            if '-f' in args:
                self.anchor = Path(args[-1]).read_text()
        elif args == ['/sbin/pfctl', '-ss', '-vv']:
            output = self.states.encode()
        elif args[:3] == ['/sbin/pfctl', '-k', 'id']:
            code = 1 if self.fail_kill else 0
            if not code:
                self.killed.append(args[-1])
        elif args[0] == '/usr/local/bin/python3' and args[1].endswith('/singbox/native_route.py'):
            assert args[2:4] == ['add', '--fib'] and args[5] == '--route', args
            fib, value = int(args[4]), json.loads(args[6])
            key = m.route_key(value)
            source = self.tables[0].get(key)
            if source is None or m.route_semantic(source) != m.route_semantic(value):
                code = 1
            elif self.fail_add or key == self.fail_key or key in self.tables[fib]:
                code = 1
            else:
                installed = copy.deepcopy(value)
                installed['flags'] += '' if 'S' in installed['flags'] else 'S'
                self.tables[fib][key] = installed
        elif args[0] == '/sbin/route':
            # Native modifiers must follow the command keyword.
            assert args[2] in ('add', 'delete') and args[3] == '-fib', args
            fib, destination = int(args[4]), args[7]
            value = route(destination, 'interface' if '-iface' in args else args[8],
                          args[args.index('-iface') + 1] if '-iface' in args else args[args.index('-ifp') + 1])
            key = m.route_key(value)
            if args[2] == 'delete':
                del self.tables[fib][key]
            elif self.fail_add or key == self.fail_key:
                code = 1
            elif key in self.tables[fib]:
                code = 1
            else:
                self.tables[fib][key] = value
        else:
            raise AssertionError('Unexpected command: ' + repr(args))
        return subprocess.CompletedProcess(args, code, output, self.diagnosis if code else b'')

    def process(self, pid):
        return {'pid': pid, 'birth': '1770000000:12345', 'uid': os.geteuid(),
                'executable': os.path.realpath('/usr/local/bin/sing-box'),
                'argv': ['/usr/local/bin/sing-box', 'run', '-c', str(self.runtime)],
                'stopped': self.stopped} if self.alive else None


class RoutingTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='singbox-routing-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.kernel = Kernel()
        mocked = patch.object(m, 'process', side_effect=self.kernel.process)
        mocked.start(); self.addCleanup(mocked.stop)
        self.routing = m.Routing(self.root, self.kernel.run, self.kernel.delay)
        self.routing.state.mkdir(parents=True)
        self.settings = {'ipv6': True, 'transparent': True, 'transparent_consent': True,
                         'device_mode': 'off', 'device_list': []}
        self.config = {'inbounds': [{'type': 'tun', 'auto_route': False, 'interface_name': m.TUN}], 'dns': {'servers': []}}
        self.context = {'interfaces': [
            {'name': 'wan', 'device': 'vtnet0', 'networks': ['192.0.2.0/24'], 'wan': True},
            {'name': 'lan', 'device': 'vtnet1', 'networks': ['10.0.0.0/24', '2001:db8:1::/64'], 'wan': False},
            {'name': 'opt1', 'device': m.TUN, 'networks': ['198.18.0.0/30'], 'wan': False}],
            'local_addresses': ['192.0.2.2', '10.0.0.1', '2001:db8:1::1']}
        self.kernel.runtime = self.routing.state / 'runtime.json'
        self.write_inputs()
        pid = self.routing.path('/var/run/sing-box.pid')
        pid.parent.mkdir(parents=True)
        pid.write_text('12345')

    def write_inputs(self):
        policy = self.routing.path('/usr/local/etc/sing-box/integration.json')
        policy.parent.mkdir(parents=True, exist_ok=True)
        policy.write_text(json.dumps(self.settings))
        policy.chmod(0o600)
        for name, value in [('routing-context.json', self.context), ('runtime.json', self.config),
            ('service-state.json', {'core': {'pid': 12345, 'birth': '1770000000:12345',
                'uid': os.geteuid(), 'executable': os.path.realpath('/usr/local/bin/sing-box'),
                'arguments': ['/usr/local/bin/sing-box', 'run', '-c', str(self.kernel.runtime)]}})]:
            path = self.routing.state / name
            path.write_text(json.dumps(value))
            path.chmod(0o600)

    def test_enable_stop_and_reuse_preserve_main_routes_and_policy_states(self):
        original = copy.deepcopy(self.kernel.tables[0])
        result = self.routing.execute('enable')
        fib = result['fib']
        self.assertTrue(result['active'])
        self.assertEqual(self.kernel.tables[0], original)
        self.assertEqual(self.kernel.tables[fib]['4:0.0.0.0/0%']['interface'], m.TUN)
        self.assertEqual(self.kernel.tables[fib]['6:::/0%']['interface'], m.TUN)
        self.assertNotIn('pass ', self.kernel.anchor)
        self.assertNotIn('quick', self.kernel.anchor)
        self.assertNotIn('on vtnet0', self.kernel.anchor)
        self.assertIn('proto tcp', self.kernel.anchor)
        self.assertIn('flags S/SA', self.kernel.anchor)
        self.assertIn('inet6 proto udp ', self.kernel.anchor)
        self.assertNotIn('icmp', self.kernel.anchor)
        self.assertIn('10.2.0.0/24', self.kernel.anchor)
        self.kernel.states = state(1, fib) + state(2, fib, ' reply-to: 192.0.2.1@vtnet0') + state(3, 0)
        self.routing.execute('disable')
        self.assertEqual(self.kernel.anchor, '')
        self.assertEqual(self.kernel.killed, ['0000000000000001/11223344'])
        self.assertEqual(self.kernel.tables[fib]['4:0.0.0.0/0%']['gateway'], '192.0.2.1')
        self.assertEqual(self.kernel.tables[fib]['6:::/0%']['gateway'], '2001:db8:ffff::1')
        self.assertEqual(self.kernel.tables[0], original)
        self.assertEqual(self.routing.execute('enable')['fib'], fib)
        self.assertEqual(self.kernel.fibs, 2)
        self.assertEqual(os.stat(self.routing.marker).st_mode & 0o777, 0o600)

    def test_kernel_cloned_routes_are_borrowed_and_preserved(self):
        self.routing.execute('enable')
        record = self.routing.load()
        self.assertNotIn('4:10.0.0.0/24%', record['routes'])
        self.assertIn('4:10.0.0.0/24%', self.kernel.tables[record['fib']])
        self.routing.execute('disable')
        self.assertEqual(self.kernel.tables[record['fib']]['4:10.0.0.0/24%']['flags'], 'U')

    def test_cold_gateway_cycle_uses_native_interface_add_and_preserves_main(self):
        cyclic = [route('10.99.0.1/32', '10.255.255.1', 'wg0', 'UGHS'),
                  route('10.255.255.1/32', '10.99.0.1', 'wg0', 'UGHS')]
        for value in cyclic:
            self.kernel.tables[0][m.route_key(value)] = value
        original = copy.deepcopy(self.kernel.tables[0])
        fib = self.routing.execute('enable')['fib']
        for value in cyclic:
            self.assertEqual(m.route_semantic(self.kernel.tables[fib][m.route_key(value)]), m.route_semantic(value))
        numeric_cli = [args for args in self.kernel.calls if args[0] == '/sbin/route' and args[2] == 'add' and '-iface' not in args]
        self.assertEqual(numeric_cli, [])
        self.routing.execute('disable')
        self.assertEqual(self.kernel.tables[0], original)
        self.assertFalse(self.routing.load()['pending'])

    def test_exclusive_add_race_does_not_claim_foreign_route(self):
        original = self.kernel.run
        foreign = route('10.2.0.0/24', '10.0.0.99', 'vtnet1', 'UGS')
        injected = False
        def concurrent(args, **options):
            nonlocal injected
            if args[0] == '/usr/local/bin/python3' and args[1].endswith('/singbox/native_route.py') and json.loads(args[6])['destination'] == foreign['destination'] and not injected:
                injected = True
                self.kernel.tables[int(args[4])][m.route_key(foreign)] = foreign
            return original(args, **options)
        self.routing.runner = concurrent
        with self.assertRaises(m.RoutingError):
            self.routing.execute('enable')
        self.assertTrue(injected)
        record = self.routing.load()
        self.assertNotIn(m.route_key(foreign), record['routes'])
        self.assertEqual(self.kernel.tables[record['fib']][m.route_key(foreign)], foreign)
        self.assertFalse(record['active'])

    def test_repeated_allocation_failure_reuses_the_reserved_table(self):
        self.kernel.populate_foreign = True
        for attempt in range(3):
            with self.subTest(attempt=attempt), self.assertRaises(m.RoutingError):
                self.routing.execute('enable')
            record = self.routing.load()
            self.assertEqual(self.kernel.fibs, 2)
            self.assertEqual(record['reserved'], 1)
            self.assertIsNone(record['fib'])
        self.assertEqual(self.kernel.delays, [m.RESERVE_BACKOFF] * 2 * 3)
        del self.kernel.tables[1]['4:203.0.113.0/24%']
        result = self.routing.execute('enable')
        self.assertEqual((result['active'], result['fib'], self.kernel.fibs), (True, 1, 2))
        self.assertIsNone(self.routing.load()['reserved'])

    def test_route_failures_retain_the_native_helper_diagnosis(self):
        self.kernel.fail_key = '4:10.2.0.0/24%'
        self.kernel.diagnosis = b'Native routing operation failed: [Errno 17] File exists\n'
        with self.assertRaisesRegex(m.RoutingError, r'native_route\.py operation failed with status 1\. .*Errno 17'):
            self.routing.execute('enable')

    def test_unrecorded_equal_numeric_route_is_preserved_as_foreign(self):
        value = route('10.5.0.0/24', '10.0.0.6', 'vtnet1', 'UG')
        self.kernel.tables[0][m.route_key(value)] = value
        key = m.route_key(value)
        fib = self.routing.execute('enable')['fib']
        self.assertEqual('UGS', self.kernel.tables[fib][key]['flags'])
        record = self.routing.load()
        del record['routes'][key]
        self.routing.save(record)
        with self.assertRaises(m.RoutingError):
            self.routing.execute('enable')
        self.assertEqual('UGS', self.kernel.tables[fib][key]['flags'])
        self.assertNotIn(key, self.routing.load()['routes'])

    def test_route_add_is_preceded_by_durable_pending_receipt(self):
        original = self.routing.route_command
        observed = []

        def checked(action, fib, value):
            saved = self.routing.load()
            self.assertFalse(saved['active'])
            self.assertTrue(saved['pending'])
            if action == 'add':
                self.assertEqual(saved['pending_route']['key'], m.route_key(value))
                self.assertEqual(saved['pending_route']['route'], value)
            observed.append(action)
            return original(action, fib, value)

        self.routing.route_command = checked
        self.assertTrue(self.routing.execute('enable')['active'])
        self.assertIn('add', observed)
        self.assertNotIn('pending_route', self.routing.load())

    def test_crash_after_add_never_claims_an_equal_route_without_provenance(self):
        original_save = self.routing.save
        original_route = self.routing.route_command
        target = {'key': None, 'adds': 0}

        class Crash(BaseException):
            pass

        def counted(action, fib, value):
            if action == 'add':
                target['key'] = target['key'] or m.route_key(value)
                if m.route_key(value) == target['key']:
                    target['adds'] += 1
            return original_route(action, fib, value)

        def crash_before_commit(record):
            key = target['key']
            if (key is not None and 'pending_route' not in record
                    and key in record['routes']
                    and key in self.kernel.tables[record['fib']]):
                raise Crash
            return original_save(record)

        self.routing.route_command = counted
        self.routing.save = crash_before_commit
        with self.assertRaises(Crash):
            self.routing.execute('enable')
        self.routing.save = original_save
        saved = self.routing.load()
        self.assertEqual(saved['pending_route']['key'], target['key'])
        self.assertNotIn(target['key'], saved['routes'])
        self.assertEqual(target['adds'], 1)
        with self.assertRaisesRegex(m.RoutingError, 'ambiguous ownership'):
            self.routing.execute('enable')
        self.assertEqual(target['adds'], 1)
        pending = self.routing.load()
        self.assertIn('pending_route', pending)
        self.assertTrue(pending['route_recovery_ambiguous'])
        self.assertIn(target['key'], self.kernel.tables[pending['fib']])
        del self.kernel.tables[pending['fib']][target['key']]
        self.routing.execute('disable')
        self.assertNotIn('pending_route', self.routing.load())

    def test_pending_route_mismatch_is_preserved_during_cleanup(self):
        fib = self.routing.execute('enable')['fib']
        key = '4:0.0.0.0/0%'
        record = self.routing.load()
        intended = record['routes'].pop(key)
        record.update(active=False, pending=True,
                      pending_route={'key': key, 'route': intended})
        self.routing.save(record)
        foreign = route('0.0.0.0/0', '198.51.100.1', 'vtnet9', 'UGS')
        self.kernel.tables[fib][key] = foreign
        result = self.routing.execute('disable')
        self.assertFalse(result['pending'])
        self.assertEqual(self.kernel.tables[fib][key], foreign)
        saved = self.routing.load()
        self.assertNotIn('pending_route', saved)
        self.assertNotIn(key, saved['routes'])

    def test_pending_equal_tun_default_is_preserved_until_ambiguity_is_resolved(self):
        fib = self.routing.execute('enable')['fib']
        key = '4:0.0.0.0/0%'
        record = self.routing.load()
        intended = record['routes'].pop(key)
        record.update(active=False, pending=True,
                      pending_route={'key': key, 'route': intended})
        self.routing.save(record)
        self.assertEqual(self.kernel.tables[fib][key]['interface'], m.TUN)
        with self.assertRaisesRegex(m.RoutingError, 'ambiguous ownership'):
            self.routing.execute('disable')
        saved = self.routing.load()
        self.assertTrue(saved['pending'])
        self.assertTrue(saved['route_recovery_ambiguous'])
        self.assertEqual(self.kernel.tables[fib][key]['interface'], m.TUN)
        del self.kernel.tables[fib][key]
        result = self.routing.execute('disable')
        self.assertFalse(result['pending'])
        self.assertEqual(self.kernel.tables[fib][key]['gateway'],
                         self.kernel.tables[0][key]['gateway'])
        self.assertNotIn('pending_route', self.routing.load())

    def test_crash_after_anchor_load_is_withdrawn_from_pending_state(self):
        original = self.routing.anchor

        class Crash(BaseException):
            pass

        def crash_after_load(content):
            original(content)
            if content:
                raise Crash

        self.routing.anchor = crash_after_load
        with self.assertRaises(Crash):
            self.routing.execute('enable')
        saved = self.routing.load()
        self.assertFalse(saved['active'])
        self.assertTrue(saved['pending'])
        self.assertIn('match in', self.kernel.anchor)
        self.routing.anchor = original
        result = self.routing.execute('refresh')
        self.assertFalse(result['active'])
        self.assertFalse(result['pending'])
        self.assertEqual(self.kernel.anchor, '')
        key = '4:0.0.0.0/0%'
        self.assertEqual(self.kernel.tables[saved['fib']][key]['gateway'],
                         self.kernel.tables[0][key]['gateway'])

    def test_final_state_save_failure_withdraws_live_capture(self):
        original = self.routing.save
        failed = False

        def fail_active_once(record):
            nonlocal failed
            if record.get('active') and not failed:
                failed = True
                raise m.RoutingError('simulated final journal failure')
            return original(record)

        self.routing.save = fail_active_once
        with self.assertRaisesRegex(m.RoutingError, 'simulated final journal failure'):
            self.routing.execute('enable')
        saved = self.routing.load()
        self.assertTrue(failed)
        self.assertFalse(saved['active'])
        self.assertFalse(saved['pending'])
        self.assertEqual(self.kernel.anchor, '')
        self.assertEqual(self.kernel.tables[saved['fib']]['4:0.0.0.0/0%']['gateway'],
                         self.kernel.tables[0]['4:0.0.0.0/0%']['gateway'])

    def test_state_replace_fsyncs_file_and_directory(self):
        observed = []
        native_fsync = os.fsync

        def fsync(fd):
            observed.append(stat.S_ISDIR(os.fstat(fd).st_mode))
            return native_fsync(fd)

        with patch.object(os, 'fsync', side_effect=fsync):
            self.routing.save({'schema': 1, 'fib': None, 'active': False,
                               'routes': {}, 'pending': False})
        self.assertEqual(observed, [False, True])

    def test_combined_ipv4_ipv6_route_limit_is_enforced(self):
        first = {'4:' + str(number): None for number in range(4097)}
        second = {'6:' + str(number): None for number in range(4096)}
        with patch.object(shared, 'parse_routes', side_effect=(first, second)):
            with self.assertRaisesRegex(m.RoutingError, 'route count'):
                self.routing.routes(0)

    def test_empty_native_fib_without_columns_can_be_allocated(self):
        self.kernel.empty_header_only = True
        original = self.kernel.run
        def without_clones(args, **options):
            result = original(args, **options)
            if args[0] == '/sbin/sysctl' and args[1].startswith('net.fibs='):
                self.kernel.tables[self.kernel.fibs - 1] = {}
            return result
        self.routing.runner = without_clones
        self.assertTrue(self.routing.execute('enable')['active'])

    def test_large_valid_config_uses_plugin_limit_but_state_remains_bounded(self):
        config = json.dumps(self.config).encode()[:-1] + b',"padding":"' + b'x' * m.LIMIT + b'"}'
        (self.routing.state / 'runtime.json').write_bytes(config)
        self.assertTrue(self.routing.execute('enable')['active'])
        (self.routing.state / 'routing-context.json').write_bytes(b' ' * (m.LIMIT + 1))
        with self.assertRaises(m.RoutingError):
            self.routing.execute('refresh')

    def test_foreign_new_fib_route_is_never_modified(self):
        self.kernel.populate_foreign = True
        with self.assertRaises(m.RoutingError):
            self.routing.execute('enable')
        self.assertEqual(self.kernel.tables[1]['4:203.0.113.0/24%']['gateway'], '192.0.2.9')
        self.assertEqual(self.kernel.anchor, '')

    def test_external_owned_route_rewrite_preserved_on_stop(self):
        fib = self.routing.execute('enable')['fib']
        key = '4:10.2.0.0/24%'
        self.kernel.tables[fib][key]['gateway'] = '10.0.0.99'
        self.routing.execute('disable')
        self.assertEqual(self.kernel.tables[fib][key]['gateway'], '10.0.0.99')
        self.assertNotIn(key, self.routing.load()['routes'])
        self.assertEqual(self.kernel.tables[fib]['4:0.0.0.0/0%']['interface'], 'vtnet0')
        with self.assertRaises(m.RoutingError):
            self.routing.execute('enable')
        self.assertEqual(self.kernel.anchor, '')

    def test_failed_route_change_is_pending_then_refresh_recovers(self):
        fib = self.routing.execute('enable')['fib']
        self.kernel.fail_add = True
        with self.assertRaises(m.RoutingError):
            self.routing.execute('disable')
        self.assertFalse(self.routing.load()['active'])
        self.assertTrue(self.routing.load()['pending'])
        self.assertEqual(self.kernel.anchor, '')
        self.kernel.fail_add = False
        self.routing.execute('refresh')
        self.assertFalse(self.routing.load()['pending'])
        self.assertEqual(self.kernel.tables[fib]['4:0.0.0.0/0%']['gateway'], '192.0.2.1')

    def test_stop_restores_both_defaults_before_specific_ipv6_failure(self):
        fib = self.routing.execute('enable')['fib']
        value = route('2001:db8:99::/64', '2001:db8:1::2', 'vtnet1', 'UGS')
        self.kernel.tables[0][m.route_key(value)] = value
        self.kernel.fail_key = m.route_key(value)
        with self.assertRaises(m.RoutingError):
            self.routing.execute('disable')
        self.assertEqual(self.kernel.tables[fib]['4:0.0.0.0/0%']['gateway'], '192.0.2.1')
        self.assertEqual(self.kernel.tables[fib]['6:::/0%']['gateway'], '2001:db8:ffff::1')
        self.assertEqual(self.kernel.anchor, '')
        self.assertTrue(self.routing.load()['pending'])

    def test_failed_refresh_resumes_after_transient_route_failure(self):
        self.routing.execute('enable')
        value = route('10.4.0.0/24', '10.0.0.5', 'vtnet1', 'UGS')
        self.kernel.tables[0][m.route_key(value)] = value
        self.kernel.fail_key = m.route_key(value)
        for _ in range(2):
            with self.assertRaises(m.RoutingError):
                self.routing.execute('refresh')
            self.assertFalse(self.routing.load()['active'])
            self.assertTrue(self.routing.load()['resume'])
            self.assertEqual(self.kernel.anchor, '')
        self.kernel.fail_key = None
        self.assertTrue(self.routing.execute('refresh')['active'])
        self.assertFalse(self.routing.load()['resume'])

    def test_refresh_resume_obeys_consent_and_explicit_disable(self):
        self.routing.execute('enable')
        record = self.routing.load()
        record.update(active=False, resume=True)
        self.routing.save(record)
        self.settings['transparent_consent'] = False
        self.write_inputs()
        self.assertFalse(self.routing.execute('refresh')['active'])
        self.assertFalse(self.routing.load()['resume'])
        self.settings['transparent_consent'] = True
        self.write_inputs()
        self.routing.execute('enable')
        self.routing.execute('disable')
        self.assertFalse(self.routing.execute('refresh')['active'])

    def test_failed_state_kill_still_restores_ordinary_routes_and_retries(self):
        fib = self.routing.execute('enable')['fib']
        self.kernel.states, self.kernel.fail_kill = state(1, fib), True
        with self.assertRaises(m.RoutingError):
            self.routing.execute('disable')
        self.assertEqual(self.kernel.tables[fib]['4:0.0.0.0/0%']['gateway'], '192.0.2.1')
        self.assertTrue(self.routing.load()['pending'])
        self.kernel.fail_kill = False
        self.routing.execute('refresh')
        self.assertFalse(self.routing.load()['pending'])

    def test_foreign_recursive_rtable_rule_blocks_initial_enable(self):
        self.kernel.foreign_rules = (
            'anchor "operator" all {\n'
            '  pass in on vtnet1 rtable 1 label "operator"\n'
            '}\n')
        with self.assertRaises(m.RoutingError):
            self.routing.execute('enable')
        saved = self.routing.load()
        self.assertFalse(saved['active'])
        self.assertTrue(saved['pending'])
        self.assertTrue(saved['pf_collision'])
        self.assertEqual(self.kernel.anchor, '')
        self.assertEqual(self.kernel.tables[saved['fib']]['4:0.0.0.0/0%']['gateway'],
                         self.kernel.tables[0]['4:0.0.0.0/0%']['gateway'])

    def test_runtime_pf_collision_withdraws_capture_without_killing_states(self):
        fib = self.routing.execute('enable')['fib']
        self.kernel.states = state(1, fib)
        self.kernel.foreign_rules = (
            'pass in on vtnet1 rtable %d label "operator"\n' % fib)
        with self.assertRaises(m.RoutingError):
            self.routing.execute('disable')
        saved = self.routing.load()
        self.assertEqual(self.kernel.killed, [])
        self.assertEqual(self.kernel.states, state(1, fib))
        self.assertEqual(self.kernel.anchor, '')
        self.assertFalse(saved['active'])
        self.assertTrue(saved['pending'])
        self.assertTrue(saved['pf_collision'])
        self.assertEqual(self.kernel.tables[fib]['4:0.0.0.0/0%']['gateway'],
                         self.kernel.tables[0]['4:0.0.0.0/0%']['gateway'])

    def test_crash_recovery_collision_keeps_pending_ownership(self):
        fib = self.routing.execute('enable')['fib']
        record = self.routing.load()
        record.update(active=False, pending=True, resume=False)
        self.routing.save(record)
        self.kernel.states = state(2, fib)
        self.kernel.foreign_rules = (
            'anchor "late/operator" all {\n'
            '  pass in on vtnet1 rtable %d label "late"\n'
            '}\n' % fib)
        with self.assertRaises(m.RoutingError):
            self.routing.execute('refresh')
        saved = self.routing.load()
        self.assertEqual(self.kernel.killed, [])
        self.assertEqual(self.kernel.anchor, '')
        self.assertFalse(saved['active'])
        self.assertTrue(saved['pending'])
        self.assertTrue(saved['pf_collision'])
        self.assertEqual(saved['fib'], fib)

    def test_collision_retry_waits_for_ambiguous_states_to_drain(self):
        fib = self.routing.execute('enable')['fib']
        self.kernel.states = state(3, fib)
        self.kernel.foreign_rules = (
            'pass in on vtnet1 rtable %d label "operator"\n' % fib)
        with self.assertRaises(m.RoutingError):
            self.routing.execute('disable')
        self.kernel.foreign_rules = ''
        with self.assertRaises(m.RoutingError):
            self.routing.execute('disable')
        self.assertEqual(self.kernel.killed, [])
        self.assertTrue(self.routing.load()['pf_collision'])
        self.kernel.states = ''
        result = self.routing.execute('disable')
        self.assertFalse(result['pending'])
        saved = self.routing.load()
        self.assertNotIn('pf_collision', saved)
        self.assertEqual(saved['fib'], fib)

    def test_recursive_pf_scan_failure_is_fail_closed(self):
        fib = self.routing.execute('enable')['fib']
        self.kernel.states = state(4, fib)
        self.kernel.fail_rule_scan = True
        with self.assertRaises(m.RoutingError):
            self.routing.execute('disable')
        saved = self.routing.load()
        self.assertEqual(self.kernel.killed, [])
        self.assertEqual(self.kernel.anchor, '')
        self.assertFalse(saved['active'])
        self.assertTrue(saved['pending'])
        self.assertTrue(saved['pf_collision'])
        self.assertEqual(self.kernel.tables[fib]['4:0.0.0.0/0%']['gateway'],
                         self.kernel.tables[0]['4:0.0.0.0/0%']['gateway'])

    def test_large_ordinary_pf_table_does_not_block_targeted_stop_cleanup(self):
        fib = self.routing.execute('enable')['fib']
        ordinary = state(9, 0)
        self.kernel.states = ordinary * (m.LIMIT // len(ordinary) + 1) + state(1, fib)
        self.assertGreater(len(self.kernel.states.encode()), m.LIMIT)
        self.assertFalse(self.routing.execute('disable')['pending'])
        self.assertEqual(self.kernel.killed, ['0000000000000001/11223344'])
        self.assertEqual(self.kernel.tables[fib]['4:0.0.0.0/0%']['gateway'], '192.0.2.1')

    def test_malformed_owned_state_still_restores_defaults_then_idempotent_retry(self):
        fib = self.routing.execute('enable')['fib']
        self.kernel.states = state(1, fib).replace('0000000000000001', 'invalid')
        with self.assertRaises(m.RoutingError):
            self.routing.execute('disable')
        self.assertEqual(self.kernel.anchor, '')
        self.assertEqual(self.kernel.tables[fib]['4:0.0.0.0/0%']['gateway'], '192.0.2.1')
        self.assertEqual(self.kernel.tables[fib]['6:::/0%']['gateway'], '2001:db8:ffff::1')
        self.assertTrue(self.routing.load()['pending'])
        self.kernel.states = ''
        self.routing.execute('disable')
        self.kernel.calls.clear()
        self.assertFalse(self.routing.execute('disable')['pending'])
        self.assertFalse(any(route_mutation(args) for args in self.kernel.calls))

    def test_dead_core_refresh_disables_capture(self):
        self.routing.execute('enable')
        self.kernel.alive = False
        self.assertFalse(self.routing.execute('refresh')['active'])
        self.assertEqual(self.kernel.anchor, '')

    def test_paused_core_withdraws_capture_and_sigcont_waits_for_explicit_restart(self):
        native = copy.deepcopy(self.kernel.tables[0])
        fib = self.routing.execute('enable')['fib']
        self.kernel.stopped = True
        self.assertFalse(self.routing.core_alive())
        result = self.routing.execute('refresh')
        self.assertFalse(result['active'])
        self.assertFalse(result['pending'])
        self.assertEqual(self.kernel.anchor, '')
        self.assertEqual(self.kernel.tables[fib]['4:0.0.0.0/0%']['gateway'], '192.0.2.1')
        self.assertEqual(self.kernel.tables[0], native)
        self.kernel.stopped = False
        self.assertTrue(self.routing.core_alive())
        self.assertFalse(self.routing.execute('refresh')['active'])
        self.assertTrue(self.routing.execute('enable')['active'])

    def test_corrupt_owner_uid_or_executable_cannot_authorize_capture(self):
        for changed in ({'uid': os.geteuid() + 1}, {'executable': '/tmp/foreign-core'}):
            with self.subTest(changed=changed):
                self.write_inputs()
                path = self.routing.state / 'service-state.json'
                record = json.loads(path.read_text())
                record['core'].update(changed)
                path.write_text(json.dumps(record))
                self.assertFalse(self.routing.core_alive())
                self.assertFalse(self.routing.execute('enable')['active'])
                self.assertEqual(self.kernel.fibs, 1)

    def test_refresh_avoids_route_mutation_until_changed_and_rebuilds_empty_anchor(self):
        self.routing.execute('enable')
        self.kernel.calls.clear()
        self.routing.execute('refresh')
        self.assertFalse(any(route_mutation(args) for args in self.kernel.calls))
        self.assertFalse(any(args[0] == '/sbin/pfctl' and '-f' in args for args in self.kernel.calls))
        self.kernel.anchor = ''
        self.routing.execute('refresh')
        self.assertIn('match in', self.kernel.anchor)
        new = route('10.3.0.0/24', '10.0.0.4', 'vtnet1', 'UGS')
        self.kernel.tables[0][m.route_key(new)] = new
        self.routing.execute('refresh')
        self.assertIn('10.3.0.0/24', self.kernel.anchor)
        self.assertIn(m.route_key(new), self.kernel.tables[1])

    def test_automatic_routes_or_fake_dns_fail_before_capture(self):
        for field in ('automatic', 'fake-ip'):
            with self.subTest(field=field):
                self.config['inbounds'][0]['auto_route'] = field == 'automatic'
                self.config['dns']['servers'] = [{'type': 'fakeip'}] if field == 'fake-ip' else []
                self.write_inputs()
                with self.assertRaises(m.RoutingError):
                    self.routing.execute('enable')
                self.assertEqual(self.kernel.fibs, 1)
                self.assertEqual(self.kernel.anchor, '')

    def test_external_anchor_rule_is_never_flushed(self):
        self.kernel.anchor = 'match in on vtnet1 label "operator"'
        with self.assertRaises(m.RoutingError):
            self.routing.execute('disable')
        self.assertIn('operator', self.kernel.anchor)

    def test_foreign_anchor_noop_refresh_fails_closed_without_flushing_foreign_rules(self):
        fib = self.routing.execute('enable')['fib']
        self.kernel.anchor += '\nmatch in on vtnet1 label "operator"\n'
        with self.assertRaises(m.RoutingError):
            self.routing.execute('refresh')
        self.assertIn('operator', self.kernel.anchor)
        self.assertFalse(self.routing.load()['active'])
        self.assertTrue(self.routing.load()['pending'])
        self.assertEqual(self.kernel.tables[fib]['4:0.0.0.0/0%']['gateway'], '192.0.2.1')

    def test_noop_five_hundred_route_sync_uses_one_snapshot(self):
        for number in range(500):
            value = route('10.128.%d.%d/32' % (number // 256, number % 256), '10.0.0.3', 'vtnet1')
            self.kernel.tables[0][m.route_key(value)] = value
        self.routing.execute('enable')
        self.kernel.calls.clear()
        record = self.routing.load()
        desired = copy.deepcopy(self.kernel.tables[record['fib']])
        self.routing.sync(record, desired, native=self.kernel.tables[0])
        self.assertEqual(sum(args[0] == '/usr/bin/netstat' for args in self.kernel.calls), 2)
        self.assertFalse(any(route_mutation(args) for args in self.kernel.calls))

    def single_fib_commands(self, count=1, current=0):
        original = self.kernel.run

        def run(args, **options):
            if args[:3] == ['/usr/bin/netstat', '-rn', '-F']:
                self.kernel.calls.append(list(args))
                return subprocess.CompletedProcess(args, 1, b'', b'invalid fib')
            if args == ['/sbin/sysctl', '-n', 'net.fibs']:
                self.kernel.calls.append(list(args))
                return subprocess.CompletedProcess(args, 0, str(count).encode(), b'')
            if args == ['/sbin/sysctl', '-n', 'net.my_fibnum']:
                self.kernel.calls.append(list(args))
                return subprocess.CompletedProcess(args, 0, str(current).encode(), b'')
            if args[:3] == ['/usr/bin/netstat', '-rn', '-f']:
                value = original(args[:2] + ['-F', '0'] + args[2:], **options)
                self.kernel.calls[-1] = list(args)
                return value
            return original(args, **options)

        self.routing.runner = run

    def test_single_fib_zero_snapshot_uses_verified_unqualified_netstat(self):
        self.single_fib_commands()
        self.assertEqual(self.routing.routes(0), self.kernel.tables[0])
        fallback = [args for args in self.kernel.calls if args[:3] == ['/usr/bin/netstat', '-rn', '-f']]
        self.assertEqual(fallback, [['/usr/bin/netstat', '-rn', '-f', 'inet'],
                                    ['/usr/bin/netstat', '-rn', '-f', 'inet6']])
        self.assertEqual(self.kernel.fibs, 1)
        self.assertFalse(any(route_mutation(args) for args in self.kernel.calls))

    def test_failed_fib_snapshot_cannot_fall_back_to_another_table(self):
        for count, current, fib in ((1, 1, 0), (1, 0, 1), (2, 0, 0), (2, 0, 1)):
            with self.subTest(count=count, current=current, fib=fib):
                self.kernel.calls.clear()
                self.single_fib_commands(count, current)
                with self.assertRaises(m.RoutingError):
                    self.routing.routes(fib)
                self.assertFalse(any(args[:3] == ['/usr/bin/netstat', '-rn', '-f'] for args in self.kernel.calls))

    def test_whitelist_and_blacklist_cover_routed_subnet_and_both_families(self):
        for mode in ('whitelist', 'blacklist'):
            self.settings.update(device_mode=mode, device_list=['10.2.0.7', '2001:db8:1::7'])
            content, _, _ = self.routing.policy(self.settings, self.context, self.kernel.tables[0], {4, 6}, 1)
            source = [line for line in content.splitlines() if line.startswith('table <singbox_sources')][0]
            selected = [ipaddress.ip_network(value.strip()) for value in source.partition('{')[2].partition('}')[0].split(',')]
            for address in ('10.2.0.7', '2001:db8:1::7'):
                ip = ipaddress.ip_address(address)
                contained = any(ip.version == net.version and ip in net for net in selected)
                self.assertEqual(contained, mode == 'whitelist')
            ip = ipaddress.ip_address('10.2.0.8')
            self.assertEqual(any(ip.version == net.version and ip in net for net in selected), mode == 'blacklist')

    def test_marker_requires_private_regular_file(self):
        self.routing.execute('enable')
        self.routing.marker.chmod(0o644)
        with self.assertRaises(m.RoutingError):
            self.routing.execute('status')
        self.routing.marker.unlink()
        self.routing.marker.symlink_to(self.routing.path('/usr/local/etc/sing-box/integration.json'))
        with self.assertRaises(m.RoutingError):
            self.routing.execute('status')


class ParsingTests(unittest.TestCase):
    def test_recursive_rtable_scan_excludes_only_exact_owned_anchor_rules(self):
        owned = ('anchor "singbox" all {\n'
                 '  match in on vtnet1 label "singbox-routing" rtable 7\n'
                 '}\n')
        self.assertFalse(shared.foreign_rtable_rules(
            owned, 7, 'singbox', 'singbox-routing'))
        for rules in (
                'match in label "singbox-routing" rtable 7\n',
                'anchor "other" all {\n  match in label "singbox-routing" rtable 7\n}\n',
                'anchor "singbox" all {\n  match in label "singbox-routing-extra" rtable 7\n}\n',
                'anchor "singbox/child" all {\n  match in label "singbox-routing" rtable 7\n}\n'):
            with self.subTest(rules=rules):
                self.assertTrue(shared.foreign_rtable_rules(
                    rules, 7, 'singbox', 'singbox-routing'))

    def test_anchor_ownership_requires_generated_structure_not_only_label(self):
        routing = object.__new__(m.Routing)
        for line in (
                'pass in quick on vtnet1 rtable 1 label "singbox-routing"',
                'match in on vtnet1 inet proto udp from <operator> to any '
                'label "singbox-routing" rtable 1'):
            with self.subTest(line=line):
                self.assertFalse(routing.owned_anchor_line(line))

    def test_tun_counterparts_require_exact_tuple_origin_protocol_and_creator(self):
        def flow(identifier, headline, metadata=''):
            return headline + '\n   id: %016x creatorid: 11223344%s\n' % (identifier, metadata)
        text = flow(1, 'all udp 198.51.100.10:18083 <- 192.0.2.11:42100 SINGLE:MULTIPLE', ' rtable: 2\n   origif: epair2a')
        text += flow(2, 'all udp 192.0.2.11:42100 -> 198.51.100.10:18083 MULTIPLE:SINGLE', '\n   origif: tun_singbox')
        text += flow(3, 'all udp 192.0.2.11:42101 -> 198.51.100.10:18083 MULTIPLE:SINGLE', '\n   origif: tun_singbox')
        text += flow(4, 'all tcp 192.0.2.11:42100 -> 198.51.100.10:18083 ESTABLISHED:ESTABLISHED', '\n   origif: tun_singbox')
        text += flow(5, 'all udp 192.0.2.11:42100 -> 198.51.100.10:18083 MULTIPLE:SINGLE', '\n   origif: epair1a')
        text += flow(6, 'all udp 192.0.2.129:42100 (192.0.2.11:42100) -> 198.51.100.10:18083 MULTIPLE:SINGLE', '\n   origif: tun_singbox')
        text += flow(7, 'all udp 192.0.2.11:42100 -> 198.51.100.10:18083 MULTIPLE:SINGLE', ' reply-to: 192.0.2.1@epair1a\n   origif: tun_singbox')
        text += flow(8, 'all udp 192.0.2.11:42100 -> 198.51.100.10:18083 MULTIPLE:SINGLE', '\n   origif: tun_singbox').replace('creatorid: 11223344', 'creatorid: 55667788')
        self.assertEqual(m.capture_states(text, 2), ['0000000000000001/11223344', '0000000000000002/11223344'])

    def test_ifbound_ipv6_tun_counterpart_uses_bracket_port_and_reverse_tuple(self):
        text = ('epair2a tcp 2001:db8:100::10[18080] <- 2001:db8:3::11[41700] FIN_WAIT_2:FIN_WAIT_2\n'
                '   id: 0000000000000001 creatorid: 11223344 rtable: 2\n'
                'tun_singbox tcp 2001:db8:3::11[41700] -> 2001:db8:100::10[18080] FIN_WAIT_2:FIN_WAIT_2\n'
                '   id: 0000000000000002 creatorid: 11223344\n')
        self.assertEqual(m.capture_states(text, 2), ['0000000000000001/11223344', '0000000000000002/11223344'])

    def test_empty_fib_requires_native_title_and_matching_optional_family(self):
        for text in ('Routing tables (fib: 2024)\n', 'Routing tables (fib: 1)\n\nInternet:\n'):
            self.assertEqual(m.parse_routes(text, 4), {})
        self.assertEqual(m.parse_routes('Routing tables (fib: 1)\nInternet6:\n', 6), {})
        for text in ('', 'unknown\n', 'Routing tables\nInternet6:\n', 'Routing tables\nforeign data\n'):
            with self.assertRaises(m.RoutingError):
                m.parse_routes(text, 4)

    def test_netstat_short_networks_scopes_and_neighbor_entries(self):
        ipv4 = m.parse_routes('Destination Gateway Flags Netif Expire\n10.2 link#2 U vtnet1\n10.2.0.2 00:11:22:33:44:55 UHLW vtnet1 100\n', 4)
        self.assertEqual(list(ipv4), ['4:10.2.0.0/16%'])
        ipv6 = m.parse_routes('Destination Gateway Flags Netif Expire\nfe80::%vtnet1/64 link#2 U vtnet1\n', 6)
        self.assertEqual(list(ipv6), ['6:fe80::/64%vtnet1'])
        with self.assertRaises(m.RoutingError):
            m.parse_routes('Destination Gateway Flags Netif\n10.0.0.0/24 invalid U vtnet1\n', 4)

    def test_strict_state_ids_keep_non_tun_gateway_and_foreign_fib(self):
        text = state(1, 2) + state(2, 2, ' route-to: 192.0.2.1@vtnet0') + state(3, 2, ' reply-to: 0.0.0.0@tun_singbox') + state(4, 12)
        self.assertEqual(m.capture_states(text, 2), ['0000000000000001/11223344', '0000000000000003/11223344'])
        with self.assertRaises(m.RoutingError):
            m.capture_states(state(1, 2).replace('0000000000000001', 'bad'), 2)

    def test_empty_list_compatibility_and_prefix_clipping(self):
        lan = [ipaddress.ip_network('10.0.0.0/24')]
        self.assertEqual(m.source_networks(lan, {'device_mode': 'whitelist', 'device_list': []}), lan)
        self.assertEqual(m.source_networks(lan, {'device_mode': 'whitelist', 'device_list': ['10.0.0.0/8']}), lan)
        self.assertEqual(m.source_networks(lan, {'device_mode': 'whitelist', 'device_list': ['192.0.2.1']}), [])


if __name__ == '__main__':
    unittest.main()
