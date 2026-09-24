"""Exercise private-FIB routing, firewall policy, and ownership transitions."""
import copy
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import yaml

SCRIPT = Path(__file__).resolve().parents[1] / 'src/usr/local/opnsense/scripts/mihomo/routing.py'
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'common'))
sys.path.insert(0, str(SCRIPT.parent))
spec = importlib.util.spec_from_file_location('mihomo_routing', SCRIPT)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def route(destination, gateway, interface, flags='US'):
    net = ipaddress.ip_network(destination)
    return {'family': net.version, 'destination': str(net), 'scope': '',
            'gateway': gateway, 'interface': interface, 'flags': flags, 'discard': ''}


def route_mutation(args):
    return args[0] == '/sbin/route' or (args[0] == '/usr/local/bin/python3' and args[1].endswith('/mihomo/native_route.py'))


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
        self.fibs = 1
        self.anchor = ''
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
        # TCP redirection: the root rdr-anchor hook, the core's listener as
        # sockstat reports it, and translation rules the plugin does not own.
        self.hooked = False
        self.listener_rows = []
        self.foreign_translation = ''
        self.translation_flushed = False
        self.flushed_tables = []

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
            if fib not in self.tables:
                return subprocess.CompletedProcess(args, 64, b'', b'netstat: %d: invalid fib\n' % fib)
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
            output = b'/usr/local/bin/mihomo -d /var/db/os-mihomo' if self.alive else b''
        elif args == ['/sbin/ifconfig', m.TUN]:
            output = b'tun_mihomo: flags=8043\n inet 198.18.0.1 netmask 0xfffffffc\n inet6 fdfe:dcba:9876::1 prefixlen 126\n'
        elif args == ['/sbin/pfctl', '-a', '*', '-sr']:
            rules = [line for line in self.anchor.splitlines() if line.startswith('match ')]
            output = (('anchor "mihomo" all {\n' + '\n'.join(rules) + '\n}\n')
                      if rules else '').encode()
        elif args[:4] == ['/sbin/pfctl', '-a', m.ANCHOR, '-sr']:
            # Real pfctl -sr omits table definitions.
            output = ('\n'.join(line for line in self.anchor.splitlines() if line.startswith('match '))).encode()
        elif args == ['/sbin/pfctl', '-sn']:
            output = b'nat-anchor "acme-client/*" all\nrdr-anchor "acme-client/*" all\n'
            if self.hooked:
                output += b'rdr-anchor "mihomo" all\n'
        elif args == ['/sbin/pfctl', '-a', m.ANCHOR, '-sn']:
            # The printed forms pfctl 15.1 uses for the generated rules.
            printed = [] if self.translation_flushed else [
                line.replace(' to !<', ' to ! <').replace(' to any port 53', ' to any port = domain')
                for line in self.anchor.splitlines() if line.startswith(('rdr ', 'no rdr '))]
            output = '\n'.join(printed + [line for line in [self.foreign_translation] if line]).encode()
        elif args == ['/sbin/pfctl', '-a', m.ANCHOR, '-sT']:
            output = '\n'.join(line.split('<')[1].split('>')[0] for line in self.anchor.splitlines()
                               if line.startswith('table ')).encode()
        elif args[:4] == ['/sbin/pfctl', '-a', m.ANCHOR, '-t'] and args[5:] == ['-T', 'flush']:
            self.flushed_tables.append(args[4])
        elif args[0] == '/usr/bin/sockstat':
            assert args == ['/usr/bin/sockstat', '-4', '-l', '-q', '-P', 'tcp', '-p', str(m.REDIRECT_PORT)], args
            output = ''.join('root mihomo %s 5 tcp4 %s *:*\n' % row for row in self.listener_rows).encode()
        elif args[:3] == ['/sbin/pfctl', '-a', m.ANCHOR]:
            if '-f' in args:
                self.anchor = Path(args[-1]).read_text()
                # A load replaces every rule of the anchor, foreign ones included.
                self.foreign_translation = ''
                self.translation_flushed = False
        elif args == ['/sbin/pfctl', '-ss', '-vv']:
            output = self.states.encode()
        elif args[:3] == ['/sbin/pfctl', '-k', 'id']:
            code = 1 if self.fail_kill else 0
            if not code:
                self.killed.append(args[-1])
        elif args[0] == '/usr/local/bin/python3' and args[1].endswith('/mihomo/native_route.py'):
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
                # Both route(8) and the netlink helper ask for RTF_STATIC, so
                # an installed copy prints 'S' even when its source does not.
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


class RoutingTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='mihomo-routing-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.kernel = Kernel()
        self.routing = m.Routing(self.root, self.kernel.run, self.kernel.delay)
        # Route mechanics are isolated here; exact process ownership has its
        # own journal and PID-reuse suite in test_process_owner.py.
        self.routing.core_alive = lambda: self.kernel.alive
        self.routing.state.mkdir(parents=True)
        self.settings = {'service_enabled': True, 'transparent': True, 'transparent_consent': True,
                         'device_mode': 'off', 'device_list': []}
        self.config = {'tun': {'enable': True, 'auto-route': False}, 'ipv6': True,
                       'dns': {'enable': True, 'enhanced-mode': 'redir-host'}}
        self.context = {'interfaces': [
            {'name': 'wan', 'device': 'vtnet0', 'networks': ['192.0.2.0/24'], 'wan': True},
            {'name': 'lan', 'device': 'vtnet1', 'networks': ['10.0.0.0/24', '2001:db8:1::/64'], 'wan': False},
            {'name': 'opt1', 'device': m.TUN, 'networks': ['198.18.0.0/30'], 'wan': False}],
            'local_addresses': ['192.0.2.2', '10.0.0.1', '2001:db8:1::1']}
        self.write_inputs()
        pid = self.routing.path('/var/run/mihomo-child.pid')
        pid.parent.mkdir(parents=True)
        pid.write_text('12345')

    def write_inputs(self):
        for name, value in [('settings.json', self.settings), ('routing-context.json', self.context)]:
            (self.routing.state / name).write_text(json.dumps(value))
        (self.routing.state / 'config.yaml').write_text(yaml.safe_dump(self.config))

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
            if args[0] == '/usr/local/bin/python3' and args[1].endswith('/mihomo/native_route.py') and json.loads(args[6])['destination'] == foreign['destination'] and not injected:
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
            # One bump was paid for; every later attempt re-examines that table.
            self.assertEqual(self.kernel.fibs, 2)
            self.assertEqual(record['reserved'], 1)
            self.assertIsNone(record['fib'])
        self.assertEqual(self.kernel.delays, [m.RESERVE_BACKOFF] * 2 * 3)
        del self.kernel.tables[1]['4:203.0.113.0/24%']
        result = self.routing.execute('enable')
        self.assertEqual((result['active'], result['fib'], self.kernel.fibs), (True, 1, 2))
        self.assertIsNone(self.routing.load()['reserved'])

    def test_route_failures_name_the_program_and_quote_its_diagnosis(self):
        self.kernel.fail_key = '4:10.2.0.0/24%'
        self.kernel.diagnosis = b'Native routing operation failed: [Errno 17] File exists\n'
        with self.assertRaisesRegex(m.RoutingError, r'native_route\.py operation failed with status 1\. .*Errno 17'):
            self.routing.execute('enable')
        self.kernel.fail_key, self.kernel.diagnosis = None, b''
        self.kernel.fail_add = True
        with self.assertRaisesRegex(m.RoutingError, r'The route operation failed with status 1\.$'):
            self.routing.execute('enable')

    def test_unrecorded_copy_of_a_system_route_is_preserved_as_foreign(self):
        value = route('10.5.0.0/24', '10.0.0.6', 'vtnet1', 'UG')
        self.kernel.tables[0][m.route_key(value)] = value
        key = m.route_key(value)
        fib = self.routing.execute('enable')['fib']
        self.assertEqual(self.kernel.tables[fib][key]['flags'], 'UGS')
        record = self.routing.load()
        # An add whose ownership write never landed leaves exactly this state.
        del record['routes'][key]
        self.routing.save(record)
        with self.assertRaises(m.RoutingError):
            self.routing.execute('enable')
        self.assertEqual(self.kernel.tables[fib][key]['gateway'], '10.0.0.6')
        self.assertEqual(self.kernel.tables[fib][key]['flags'], 'UGS')
        self.assertNotIn(key, self.routing.load()['routes'])

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
        config = yaml.safe_dump(self.config).encode() + b'#' + b'x' * m.LIMIT + b'\n'
        (self.routing.state / 'config.yaml').write_bytes(config)
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

    def test_reboot_reset_net_fibs_releases_stale_journal_table(self):
        # net.fibs is not persistent, so a reboot can leave the journal naming
        # a table the kernel no longer creates. The watcher's refresh must
        # withdraw capture without querying or rewriting that table.
        stale = route('10.99.0.0/24', '10.0.0.9', 'vtnet1')
        self.routing.save({'schema': 1, 'fib': 2023, 'active': False, 'pending': True,
                           'routes': {m.route_key(stale): stale}, 'reserved': None})
        result = self.routing.execute('refresh')
        self.assertFalse(result['active'])
        self.assertFalse(result['pending'])
        self.assertIsNone(result['fib'])
        record = self.routing.load()
        self.assertEqual(record['routes'], {})
        self.assertFalse(any(args[0] == '/usr/bin/netstat' and '2023' in args
                             for args in self.kernel.calls))
        self.assertEqual(self.kernel.anchor, '')
        # The next start reserves a table inside the current kernel range.
        result = self.routing.execute('enable')
        self.assertTrue(result['active'])
        self.assertEqual(result['fib'], 1)
        self.assertEqual(self.kernel.fibs, 2)
        self.assertEqual(self.kernel.tables[1]['4:0.0.0.0/0%']['interface'], m.TUN)

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
                self.config['tun']['auto-route'] = field == 'automatic'
                self.config['dns']['enhanced-mode'] = field
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

    def test_whitelist_and_blacklist_cover_routed_subnet_and_both_families(self):
        for mode in ('whitelist', 'blacklist'):
            self.settings.update(device_mode=mode, device_list=['10.2.0.7', '2001:db8:1::7'])
            content, _, _ = self.routing.policy(self.settings, self.context, self.kernel.tables[0], {4, 6}, 1)
            source = [line for line in content.splitlines() if line.startswith('table <mihomo_sources')][0]
            selected = [ipaddress.ip_network(value.strip()) for value in source.partition('{')[2].partition('}')[0].split(',')]
            for address in ('10.2.0.7', '2001:db8:1::7'):
                ip = ipaddress.ip_address(address)
                contained = any(ip.version == net.version and ip in net for net in selected)
                self.assertEqual(contained, mode == 'whitelist')
            ip = ipaddress.ip_address('10.2.0.8')
            self.assertEqual(any(ip.version == net.version and ip in net for net in selected), mode == 'blacklist')

    def test_capture_interfaces_narrow_candidates_across_multi_wan_and_multi_lan(self):
        self.context = {'interfaces': [
            {'name': 'wan', 'device': 'vtnet0', 'networks': ['192.0.2.0/24'], 'wan': True},
            {'name': 'opt1', 'device': 'pppoe0', 'networks': ['198.51.100.7/32'], 'wan': True},
            {'name': 'lan', 'device': 'bridge0', 'networks': ['10.0.0.0/24'], 'wan': False},
            {'name': 'opt2', 'device': 'igc2', 'networks': [], 'wan': False},
            {'name': 'opt5', 'device': 'vlan0.20', 'networks': ['10.20.0.0/24'], 'wan': False},
            {'name': 'opt6', 'device': 'igc4', 'networks': ['10.30.0.0/16'], 'wan': False},
            {'name': 'openvpn', 'device': 'openvpn', 'networks': [], 'wan': False, 'virtual': True},
            {'name': 'opt8', 'device': m.TUN, 'networks': ['198.18.0.0/30'], 'wan': False}],
            'local_addresses': ['192.0.2.2', '198.51.100.7', '10.0.0.1', '10.20.0.1', '10.30.0.1']}

        def captured(selection):
            self.settings['capture_interfaces'] = selection
            self.write_inputs()
            settings, context, _ = self.routing.routing_inputs()
            content, interfaces, _ = self.routing.policy(settings, context, self.kernel.tables[0], {4}, 1)
            devices = {line.split()[3] for line in content.splitlines() if line.startswith('match in on ')}
            local = [line for line in content.splitlines() if line.startswith('table <mihomo_local>')][0]
            return devices, interfaces, local

        # Automatic: every internal interface with an address, never an uplink or the TUN.
        devices, count, local = captured([])
        self.assertEqual({'bridge0', 'vlan0.20', 'igc4'}, devices)
        self.assertEqual(3, count)
        # A selection narrows the candidates without narrowing what bypasses:
        # the router's addresses on every network still stay off the TUN.
        devices, count, narrowed = captured(['opt5'])
        self.assertEqual({'vlan0.20'}, devices)
        self.assertEqual(local, narrowed)
        self.assertEqual({'bridge0', 'igc4'}, captured(['lan', 'opt6', 'opt5'])[0] - {'vlan0.20'})
        # An uplink of a multi-WAN router, the TUN, an interface group, a
        # bridge member without an address or a missing interface captures nothing.
        for selection in (['wan'], ['opt1'], ['opt8'], ['openvpn'], ['opt2'], ['opt99']):
            self.assertEqual((set(), 0), captured(selection)[:2], selection)
        self.assertEqual({'bridge0'}, captured(['opt1', 'lan', 'opt99'])[0])
        # Anything that is not a list of identifiers is refused before capture.
        for invalid in ('lan', ['lan;pfctl'], [7], ['x' * 40], ['opt%d' % n for n in range(m.DEVICE_LIMIT + 1)]):
            self.settings['capture_interfaces'] = invalid
            self.write_inputs()
            with self.assertRaises(m.RoutingError, msg=invalid):
                self.routing.routing_inputs()

    def test_capture_waits_for_a_selected_interface_to_gain_its_address(self):
        # A VPN server assigned as an interface starts after the core at boot
        # and raises no WAN event, so the refresh itself has to notice it.
        self.settings['capture_interfaces'] = ['opt5']
        down = {'name': 'opt5', 'device': 'vlan0.20', 'networks': [], 'wan': False}
        self.context['interfaces'].append(down)
        self.write_inputs()
        self.assertFalse(self.routing.execute('enable')['active'])
        self.assertTrue(self.routing.load()['awaiting_sources'])
        mutations = lambda: [call for call in self.kernel.calls
                             if route_mutation(call) or call[:3] == ['/sbin/pfctl', '-a', m.ANCHOR] and '-f' in call]
        before = len(mutations())
        for _ in range(2):
            status = self.routing.execute('refresh')
            self.assertFalse(status['active'])
            self.assertEqual(0, status['interface_count'])
        self.assertEqual(before, len(mutations()), 'waiting must not repeat the withdrawal on every tick')
        self.assertTrue(self.routing.load()['awaiting_sources'])
        down['networks'] = ['10.20.0.0/24']
        self.context['local_addresses'].append('10.20.0.1')
        self.write_inputs()
        status = self.routing.execute('refresh')
        self.assertTrue(status['active'])
        self.assertEqual(1, status['interface_count'])
        self.assertNotIn('awaiting_sources', self.routing.load())
        # Transparent routing switched off while waiting stops the wait.
        down['networks'] = []
        self.write_inputs()
        self.routing.execute('enable')
        self.assertTrue(self.routing.load()['awaiting_sources'])
        self.settings['transparent'] = False
        self.write_inputs()
        self.assertFalse(self.routing.execute('refresh')['active'])
        self.assertNotIn('awaiting_sources', self.routing.load())

    REDIRECTED = ('all tcp 127.0.0.1:%d (203.0.113.9:443) <- 10.0.0.5:5000       ESTABLISHED:ESTABLISHED\n'
                  '   age 00:00:01, expires in 00:01:00, rule 1\n'
                  '   id: %016x creatorid: 11223344\n')

    def ready_redirect(self, pid=4242):
        """Everything the fast TCP path needs: setting, listener, hook, owning core."""
        self.settings['tcp_redirect'] = True
        self.config['listeners'] = [{'name': m.REDIRECT_LISTENER, 'type': 'redir',
                                     'port': m.REDIRECT_PORT, 'listen': '127.0.0.1'}]
        self.write_inputs()
        self.kernel.hooked = True
        self.kernel.listener_rows = [(str(pid), '127.0.0.1:%d' % m.REDIRECT_PORT)]
        group = MagicMock()
        group.discover.return_value = {'child': {'pid': pid}}
        group.same.return_value = True
        patcher = patch.object(m, 'core_group', return_value=group)
        patcher.start()
        self.addCleanup(patcher.stop)
        return group

    def translation(self):
        return [line for line in self.kernel.anchor.splitlines() if line.startswith(('rdr ', 'no rdr '))]

    def test_tcp_redirect_loads_only_for_an_owned_listener_behind_a_hooked_anchor(self):
        self.ready_redirect()
        result = self.routing.execute('enable')
        self.assertTrue(result['active'])
        self.assertEqual(m.REDIRECT_PORT, result['tcp_redirect_port'])
        self.assertEqual([
            'no rdr on vtnet1 inet proto tcp from <mihomo_sources_0> to any port 53',
            'rdr on vtnet1 inet proto tcp from <mihomo_sources_0> to !<mihomo_local> -> 127.0.0.1 port %d'
            % m.REDIRECT_PORT], self.translation())
        lines = self.kernel.anchor.splitlines()
        self.assertLess(max(index for index, line in enumerate(lines) if line.startswith(('rdr ', 'no rdr '))),
                        min(index for index, line in enumerate(lines) if line.startswith('match ')))
        self.assertIn('match in on vtnet1 inet proto tcp from <mihomo_sources_0>', self.kernel.anchor)
        cases = [
            ('setting off', lambda group: self.settings.update(tcp_redirect=False)),
            ('listener not rendered', lambda group: self.config.pop('listeners')),
            ('listener on another address', lambda group: self.config.update(listeners=[dict(
                self.config['listeners'][0], listen='0.0.0.0')])),
            ('listener duplicated', lambda group: self.config['listeners'].append(dict(self.config['listeners'][0]))),
            ('filter never reloaded', lambda group: setattr(self.kernel, 'hooked', False)),
            ('port held by another process', lambda group: setattr(
                self.kernel, 'listener_rows', [('999', '127.0.0.1:%d' % m.REDIRECT_PORT)])),
            ('wildcard listener beside the core', lambda group: self.kernel.listener_rows.append(
                ('999', '*:%d' % m.REDIRECT_PORT))),
            ('listener not bound yet', lambda group: setattr(self.kernel, 'listener_rows', [])),
            ('core not recorded', lambda group: setattr(group.discover, 'return_value', None)),
            ('core replaced', lambda group: setattr(group.same, 'return_value', False)),
        ]
        for name, change in cases:
            with self.subTest(name):
                group = self.ready_redirect()
                self.routing.execute('refresh')
                self.assertEqual(2, len(self.translation()))
                change(group)
                self.write_inputs()
                result = self.routing.execute('refresh')
                self.assertTrue(result['active'])
                self.assertNotIn('tcp_redirect_port', result)
                self.assertEqual([], self.translation())
                self.assertIn('match in on vtnet1 inet proto tcp from <mihomo_sources_0>', self.kernel.anchor)

    def test_redirect_refresh_stays_quiet_and_restores_a_flushed_translation(self):
        self.ready_redirect()
        self.routing.execute('enable')
        self.kernel.calls.clear()
        self.routing.execute('refresh')
        self.assertFalse(any(args[0] == '/sbin/pfctl' and '-f' in args for args in self.kernel.calls))
        self.assertFalse(any(route_mutation(args) for args in self.kernel.calls))
        self.kernel.translation_flushed = True
        self.routing.execute('refresh')
        self.assertTrue(any(args[0] == '/sbin/pfctl' and '-f' in args for args in self.kernel.calls))
        self.assertEqual(2, len(self.translation()))
        self.assertFalse(self.kernel.translation_flushed)

    def test_losing_the_listener_returns_tcp_to_the_tun_and_drops_redirected_states(self):
        self.ready_redirect()
        fib = self.routing.execute('enable')['fib']
        self.kernel.states = self.REDIRECTED % (m.REDIRECT_PORT, 0xaa) + state(1, fib)
        self.kernel.listener_rows = []
        result = self.routing.execute('refresh')
        self.assertTrue(result['active'])
        self.assertNotIn('tcp_redirect_port', self.routing.load())
        # Only connections bound to the withdrawn listener are dropped.
        self.assertEqual(['00000000000000aa/11223344'], self.kernel.killed)
        self.assertEqual([], self.translation())

    def test_disable_withdraws_the_redirect_and_every_owned_state(self):
        self.ready_redirect()
        fib = self.routing.execute('enable')['fib']
        self.kernel.states = (self.REDIRECTED % (m.REDIRECT_PORT, 0xaa) + state(1, fib)
                              + self.REDIRECTED % (7999, 0xbb) + state(2, 0))
        result = self.routing.execute('disable')
        self.assertFalse(result['active'])
        self.assertNotIn('tcp_redirect_port', result)
        self.assertEqual('', self.kernel.anchor)
        self.assertEqual(['0000000000000001/11223344', '00000000000000aa/11223344'], sorted(self.kernel.killed))
        self.assertNotIn('tcp_redirect_port', self.routing.load())

    def test_foreign_translation_rule_fails_closed_unflushed_and_empties_owned_sources(self):
        self.ready_redirect()
        fib = self.routing.execute('enable')['fib']
        foreign = 'rdr on vtnet1 inet proto tcp from any to any port = http -> 10.0.0.9 port 3128'
        self.kernel.foreign_translation = foreign
        with self.assertRaises(m.RoutingError):
            self.routing.execute('refresh')
        self.assertEqual(foreign, self.kernel.foreign_translation)
        self.assertEqual(['mihomo_sources_0'], self.kernel.flushed_tables)
        record = self.routing.load()
        self.assertFalse(record['active'])
        self.assertTrue(record['pending'])
        self.assertEqual(self.kernel.tables[fib]['4:0.0.0.0/0%']['gateway'], '192.0.2.1')

    def test_first_redirect_enable_journals_the_port_before_loading_the_anchor(self):
        # A failure right after the load must still find the translated states;
        # the port therefore has to be durable before the rules exist.
        self.ready_redirect()
        self.kernel.states = self.REDIRECTED % (m.REDIRECT_PORT, 0xaa)
        saved = []
        original_save, original_anchor = self.routing.save, self.routing.anchor

        def save(record):
            saved.append(dict(record))
            return original_save(record)

        def anchor(content):
            if content:
                self.assertEqual(m.REDIRECT_PORT, saved[-1].get('tcp_redirect_port'))
                self.assertTrue(saved[-1]['pending'])
            original_anchor(content)
            if content:
                raise m.RoutingError('injected failure after the load')

        with patch.object(self.routing, 'save', side_effect=save), \
                patch.object(self.routing, 'anchor', side_effect=anchor), \
                self.assertRaises(m.RoutingError):
            self.routing.execute('enable')
        self.assertIn('00000000000000aa/11223344', self.kernel.killed)
        self.assertEqual('', self.kernel.anchor)
        self.assertNotIn('tcp_redirect_port', self.routing.load())

    def test_journaled_port_lets_recovery_drop_redirected_states_after_a_crash(self):
        self.ready_redirect()
        self.routing.execute('enable')
        record = self.routing.load()
        record.update(active=False, pending=True)
        self.routing.save(record)
        self.kernel.alive = False
        self.kernel.states = self.REDIRECTED % (m.REDIRECT_PORT, 0xaa)
        result = self.routing.execute('refresh')
        self.assertFalse(result['active'])
        self.assertIn('00000000000000aa/11223344', self.kernel.killed)
        self.assertNotIn('tcp_redirect_port', self.routing.load())
        self.assertEqual('', self.kernel.anchor)

    def test_marker_requires_private_regular_file(self):
        self.routing.execute('enable')
        self.routing.marker.chmod(0o644)
        with self.assertRaises(m.RoutingError):
            self.routing.execute('status')
        self.routing.marker.unlink()
        self.routing.marker.symlink_to(self.routing.state / 'settings.json')
        with self.assertRaises(m.RoutingError):
            self.routing.execute('status')

    def test_a_record_without_the_owned_table_is_refused_but_a_reserved_one_loads(self):
        # Every caller indexes record['fib']; an absent key has to be rejected
        # here or it surfaces as a KeyError past the module's own handler.
        self.routing.save({'schema': 1, 'active': False, 'pending': False, 'routes': {}})
        for action in ('status', 'disable', 'enable'):
            with self.subTest(action=action), self.assertRaises(m.RoutingError):
                self.routing.execute(action)
        self.routing.save({'schema': 1, 'fib': None, 'reserved': 1, 'active': False,
                           'pending': False, 'routes': {}})
        self.assertEqual(self.routing.load()['reserved'], 1)
        self.assertIsNone(self.routing.load()['fib'])


class ParsingTests(unittest.TestCase):
    def test_tun_counterparts_require_exact_tuple_origin_protocol_and_creator(self):
        def flow(identifier, headline, metadata=''):
            return headline + '\n   id: %016x creatorid: 11223344%s\n' % (identifier, metadata)
        text = flow(1, 'all udp 198.51.100.10:18083 <- 192.0.2.11:42100 SINGLE:MULTIPLE', ' rtable: 2\n   origif: epair2a')
        text += flow(2, 'all udp 192.0.2.11:42100 -> 198.51.100.10:18083 MULTIPLE:SINGLE', '\n   origif: tun_mihomo')
        text += flow(3, 'all udp 192.0.2.11:42101 -> 198.51.100.10:18083 MULTIPLE:SINGLE', '\n   origif: tun_mihomo')
        text += flow(4, 'all tcp 192.0.2.11:42100 -> 198.51.100.10:18083 ESTABLISHED:ESTABLISHED', '\n   origif: tun_mihomo')
        text += flow(5, 'all udp 192.0.2.11:42100 -> 198.51.100.10:18083 MULTIPLE:SINGLE', '\n   origif: epair1a')
        text += flow(6, 'all udp 192.0.2.129:42100 (192.0.2.11:42100) -> 198.51.100.10:18083 MULTIPLE:SINGLE', '\n   origif: tun_mihomo')
        text += flow(7, 'all udp 192.0.2.11:42100 -> 198.51.100.10:18083 MULTIPLE:SINGLE', ' reply-to: 192.0.2.1@epair1a\n   origif: tun_mihomo')
        text += flow(8, 'all udp 192.0.2.11:42100 -> 198.51.100.10:18083 MULTIPLE:SINGLE', '\n   origif: tun_mihomo').replace('creatorid: 11223344', 'creatorid: 55667788')
        self.assertEqual(m.capture_states(text, 2), ['0000000000000001/11223344', '0000000000000002/11223344'])

    def test_ifbound_ipv6_tun_counterpart_uses_bracket_port_and_reverse_tuple(self):
        text = ('epair2a tcp 2001:db8:100::10[18080] <- 2001:db8:3::11[41700] FIN_WAIT_2:FIN_WAIT_2\n'
                '   id: 0000000000000001 creatorid: 11223344 rtable: 2\n'
                'tun_mihomo tcp 2001:db8:3::11[41700] -> 2001:db8:100::10[18080] FIN_WAIT_2:FIN_WAIT_2\n'
                '   id: 0000000000000002 creatorid: 11223344\n')
        self.assertEqual(m.capture_states(text, 2), ['0000000000000001/11223344', '0000000000000002/11223344'])

    def test_empty_fib_requires_native_title_and_matching_optional_family(self):
        for text in ('Routing tables (fib: 2024)\n', 'Routing tables (fib: 1)\n\nInternet:\n'):
            self.assertEqual(m.parse_routes(text, 4), {})
        self.assertEqual(m.parse_routes('Routing tables (fib: 1)\nInternet6:\n', 6), {})
        for text in ('', 'unknown\n', 'Routing tables\nInternet6:\n', 'Routing tables\nforeign data\n'):
            with self.assertRaises(m.RoutingError):
                m.parse_routes(text, 4)

    def test_multipath_destination_is_refused_before_a_copy_is_requested(self):
        # A unicast netlink reply names only the selected path, so the helper
        # cannot recognize a multipath source. This is where that is caught.
        text = ('Destination Gateway Flags Netif Expire\n'
                '10.81.0.0/24 10.0.0.9 UGS vtnet0\n'
                '10.81.0.0/24 10.0.0.10 UGS vtnet0\n')
        with self.assertRaisesRegex(m.RoutingError, 'Multiple routes to one destination'):
            m.parse_routes(text, 4)

    def test_netstat_short_networks_scopes_and_neighbor_entries(self):
        ipv4 = m.parse_routes('Destination Gateway Flags Netif Expire\n10.2 link#2 U vtnet1\n10.2.0.2 00:11:22:33:44:55 UHLW vtnet1 100\n', 4)
        self.assertEqual(list(ipv4), ['4:10.2.0.0/16%'])
        ipv6 = m.parse_routes('Destination Gateway Flags Netif Expire\nfe80::%vtnet1/64 link#2 U vtnet1\n', 6)
        self.assertEqual(list(ipv6), ['6:fe80::/64%vtnet1'])
        with self.assertRaises(m.RoutingError):
            m.parse_routes('Destination Gateway Flags Netif\n10.0.0.0/24 invalid U vtnet1\n', 4)

    def test_strict_state_ids_keep_non_tun_gateway_and_foreign_fib(self):
        text = state(1, 2) + state(2, 2, ' route-to: 192.0.2.1@vtnet0') + state(3, 2, ' reply-to: 0.0.0.0@tun_mihomo') + state(4, 12)
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
