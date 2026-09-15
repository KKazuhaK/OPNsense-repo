"""Keep all network plugins bound to one route ownership implementation."""

import ast
import errno
import importlib.util
import ipaddress
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
from unittest.mock import MagicMock, patch
import unittest


REPO = Path(__file__).resolve().parents[3]
SCRIPT = REPO / 'src/common/route_control.py'
POLICY_SCRIPT = REPO / 'src/common/tun_policy_routing.py'
sys.path.insert(0, str(SCRIPT.parent))
spec = importlib.util.spec_from_file_location('shared_route_control', SCRIPT)
route = importlib.util.module_from_spec(spec)
spec.loader.exec_module(route)
policy_spec = importlib.util.spec_from_file_location(
    'shared_tun_policy_routing', POLICY_SCRIPT)
policy = importlib.util.module_from_spec(policy_spec)
policy_spec.loader.exec_module(policy)


def forwarding(destination='10.0.0.0/24', flags='UG'):
    return {'family': 4, 'destination': destination, 'scope': '',
            'gateway': '10.255.255.1', 'interface': 'vtnet0',
            'flags': flags, 'discard': ''}


class SharedSourceTests(unittest.TestCase):
    def test_three_adapters_contain_no_netlink_implementation(self):
        adapters = [
            REPO / 'src/os-mihomo/src/usr/local/opnsense/scripts/mihomo/native_route.py',
            REPO / 'src/os-sing-box/src/usr/local/opnsense/scripts/singbox/native_route.py',
            REPO / 'src/os-easytier/src/usr/local/opnsense/scripts/easytier/native_route.py',
        ]
        for adapter in adapters:
            with self.subTest(adapter=adapter):
                tree = ast.parse(adapter.read_text())
                self.assertFalse(any(isinstance(node, (ast.FunctionDef, ast.ClassDef)) for node in ast.walk(tree)))
                imported = {alias.name for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
                            for alias in node.names}
                self.assertTrue({'*'} == imported or {'RouteError', 'mutate'} <= imported)
                self.assertEqual({'route_control'}, {node.module for node in ast.walk(tree)
                                                     if isinstance(node, ast.ImportFrom)})
        shared_methods = {
            'allocate', 'anchor', 'check_anchor', 'command', 'disable', 'enable',
            'execute', 'load', 'occupied', 'path', 'policy', 'read',
            'route_command', 'routes', 'save', 'status', 'sync',
        }
        for routing in [
                REPO / 'src/os-mihomo/src/usr/local/opnsense/scripts/mihomo/routing.py',
                REPO / 'src/os-sing-box/src/usr/local/opnsense/scripts/singbox/routing.py']:
            with self.subTest(routing=routing):
                tree = ast.parse(routing.read_text())
                classes = [node for node in tree.body if isinstance(node, ast.ClassDef)]
                self.assertEqual(['Routing'], [node.name for node in classes])
                self.assertEqual(['TunPolicyRouting'],
                                 [base.id for base in classes[0].bases
                                  if isinstance(base, ast.Name)])
                methods = {node.name for node in classes[0].body
                           if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
                self.assertFalse(methods & shared_methods)

        policy = ast.parse(POLICY_SCRIPT.read_text())
        policy_class = next(node for node in policy.body
                            if isinstance(node, ast.ClassDef)
                            and node.name == 'TunPolicyRouting')
        implemented = {node.name for node in policy_class.body
                       if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
        self.assertTrue(shared_methods <= implemented)

    def test_every_package_stages_the_exact_shared_bytes(self):
        registry = json.loads((REPO / 'packaging/plugins.json').read_text())['plugins']
        for plugin, directory in (('os-sing-box', 'singbox'), ('os-easytier', 'easytier')):
            destination = '/usr/local/opnsense/scripts/' + directory + '/route_control.py'
            with self.subTest(plugin=plugin):
                self.assertEqual(destination, registry[plugin]['shared']['src/common/route_control.py'])
                build = (REPO / 'src' / plugin / 'build.sh').read_text()
                self.assertIn('route_control.py', build)
                self.assertIn('../common/', build)

        policy_destination = '/usr/local/opnsense/scripts/singbox/tun_policy_routing.py'
        self.assertEqual(policy_destination,
                         registry['os-sing-box']['shared'][
                             'src/common/tun_policy_routing.py'])
        sing_build = (REPO / 'src/os-sing-box/build.sh').read_text()
        self.assertIn('tun_policy_routing.py', sing_build)

        helper_path = REPO / 'src/os-mihomo/packaging/target.py'
        helper_spec = importlib.util.spec_from_file_location('mihomo_shared_target', helper_path)
        helper = importlib.util.module_from_spec(helper_spec)
        helper_spec.loader.exec_module(helper)
        target = helper.resolve_target(REPO / 'src/os-mihomo')
        staged = helper.staged_files(REPO / 'src/os-mihomo', target, '1.2.5')
        for source, destination in (
                (SCRIPT, '/usr/local/opnsense/scripts/mihomo/route_control.py'),
                (POLICY_SCRIPT,
                 '/usr/local/opnsense/scripts/mihomo/tun_policy_routing.py')):
            with self.subTest(source=source):
                self.assertEqual(source.read_bytes(), staged[destination])


class SharedPolicyTests(unittest.TestCase):
    class SyncHarness(policy.TunPolicyRouting):
        def __init__(self, live):
            self.live = live
            self.saved = []

        def routes(self, _fib):
            return self.live

        def save(self, record):
            self.saved.append(json.loads(json.dumps(record)))

        def route_command(self, _action, _fib, _route):
            raise AssertionError('An adoption test must not mutate a route.')

    def test_unrecorded_equal_numeric_copy_remains_foreign(self):
        wanted = forwarding(flags='UG')
        existing = forwarding(flags='UGS')
        key = route.route_key(wanted)
        record = {'fib': 1, 'routes': {}}
        harness = self.SyncHarness({key: existing})
        with self.assertRaises(policy.RoutingError):
            harness.sync(record, {key: wanted})
        self.assertEqual({}, record['routes'])
        self.assertEqual([], harness.saved)

        variants = [
            forwarding('0.0.0.0/0', flags='UGS'),
            {**existing, 'gateway': '10.255.255.2'},
            {**existing, 'gateway': 'interface'},
            {**existing, 'discard': 'blackhole'},
        ]
        desired = [
            forwarding('0.0.0.0/0', flags='UG'),
            wanted,
            wanted,
            wanted,
        ]
        for current, expected in zip(variants, desired):
            record = {'fib': 1, 'routes': {}}
            key = route.route_key(expected)
            with self.subTest(current=current), self.assertRaises(policy.RoutingError):
                self.SyncHarness({key: current}).sync(record, {key: expected})
            self.assertEqual({}, record['routes'])

    def test_cloned_direct_route_remains_borrowed(self):
        wanted = {**forwarding(flags='U'), 'gateway': 'interface'}
        key = route.route_key(wanted)
        record = {'fib': 1, 'routes': {}}
        harness = self.SyncHarness({key: dict(wanted)})
        harness.sync(record, {key: wanted}, native={key: wanted})
        self.assertEqual({}, record['routes'])
        self.assertEqual([], harness.saved)

    def test_ambiguous_direct_default_add_is_preserved_without_adoption(self):
        wanted = {**forwarding('0.0.0.0/0', flags=''), 'gateway': 'interface',
                  'interface': 'tun_test'}
        key = route.route_key(wanted)

        class Harness(self.SyncHarness):
            def route_command(inner, action, _fib, value):
                self.assertEqual('add', action)
                installed = {**value, 'flags': 'US'}
                inner.live[key] = installed
                raise policy.RoutingMutationAmbiguous('injected timeout after effect')

        record = {'fib': 1, 'routes': {}}
        harness = Harness({})
        with self.assertRaisesRegex(policy.RoutingMutationAmbiguous, 'ambiguous add'):
            harness.sync(record, {key: wanted})
        self.assertEqual({}, record['routes'])
        self.assertEqual(key, record['pending_route']['key'])
        self.assertTrue(record['route_recovery_ambiguous'])

    def test_explicit_direct_add_rejection_never_adopts_an_identical_route(self):
        wanted = {**forwarding('0.0.0.0/0', flags=''), 'gateway': 'interface',
                  'interface': 'tun_test'}
        key = route.route_key(wanted)

        class Harness(self.SyncHarness):
            def route_command(inner, action, _fib, value):
                self.assertEqual('add', action)
                inner.live[key] = {**value, 'flags': 'US'}
                raise policy.RoutingError('explicit EEXIST')

        record = {'fib': 1, 'routes': {}}
        with self.assertRaisesRegex(policy.RoutingError, 'ambiguous ownership'):
            Harness({}).sync(record, {key: wanted})
        self.assertEqual({}, record['routes'])
        self.assertEqual(key, record['pending_route']['key'])

    def test_state_rejects_boolean_fib_and_unsafe_plugin_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            class Harness(policy.TunPolicyRouting):
                STATE = '/state'
                TUN = 'tun_test'
                ANCHOR = 'test'
                LABEL = 'test-routing'
                PF_PREFIX = 'test'
                NATIVE_PYTHON = '/usr/local/bin/python3'
                NATIVE_HELPER = '/helper.py'
                ROUTING_LOCK = '/run/test.lock'

            harness = Harness(root, lambda args, **_options: subprocess.CompletedProcess(
                args, 0, b'1\n', b''), lambda _seconds: None)
            harness.state.mkdir(parents=True)
            harness.marker.write_text(json.dumps({
                'schema': 1, 'fib': True, 'active': False,
                'pending': False, 'routes': {},
            }))
            harness.marker.chmod(0o600)
            with self.assertRaises(policy.RoutingError):
                harness.load()

            lock = harness.path(Harness.ROUTING_LOCK)
            lock.parent.mkdir(parents=True)
            lock.write_text('')
            lock.chmod(0o644)
            with self.assertRaises(policy.RoutingError):
                harness.execute('status')

    def test_invalid_net_fib_count_is_a_routing_error(self):
        record = {'schema': 1, 'fib': None, 'active': False,
                  'pending': False, 'routes': {}}

        class Harness(policy.TunPolicyRouting):
            STATE = '/state'
            TUN = 'tun_test'
            ANCHOR = 'test'
            LABEL = 'test-routing'
            PF_PREFIX = 'test'
            NATIVE_PYTHON = '/usr/local/bin/python3'
            NATIVE_HELPER = '/helper.py'
            ROUTING_LOCK = '/run/test.lock'

        def run(args, **_options):
            self.assertEqual(['/sbin/sysctl', '-n', 'net.fibs'], args)
            return subprocess.CompletedProcess(args, 0, b'not-a-number\n', b'')

        with tempfile.TemporaryDirectory() as directory:
            harness = Harness(Path(directory), run, lambda _seconds: None)
            harness.path('/var/run').mkdir(parents=True)
            with self.assertRaisesRegex(policy.RoutingError, 'No supported private'):
                harness.allocate(record)

    def test_reboot_reduced_fib_count_releases_stale_journal_without_netstat(self):
        # net.fibs is not persistent. After a reboot the kernel can expose one
        # table while the journal still names a higher one; withdrawal must
        # neither query nor rewrite a table the kernel did not create.
        class Harness(policy.TunPolicyRouting):
            STATE = '/state'
            TUN = 'tun_test'
            ANCHOR = 'test'
            LABEL = 'test-routing'
            PF_PREFIX = 'test'
            NATIVE_PYTHON = '/usr/local/bin/python3'
            NATIVE_HELPER = '/helper.py'
            ROUTING_LOCK = '/run/test.lock'

            def command(self, args, **_options):
                if args == ['/sbin/sysctl', '-n', 'net.fibs']:
                    return subprocess.CompletedProcess(args, 0, b'1\n', b'')
                if args[0] == '/usr/bin/netstat':
                    raise AssertionError('A stale table must never be read: ' + repr(args))
                return subprocess.CompletedProcess(args, 0, b'', b'')

        with tempfile.TemporaryDirectory() as directory:
            harness = Harness(Path(directory), lambda *_args, **_options: None,
                              lambda _seconds: None)
            stale = forwarding()
            record = {'schema': 1, 'fib': 2023, 'active': False, 'pending': True,
                      'routes': {route.route_key(stale): stale}, 'reserved': None}
            result = harness.disable(record)
            self.assertFalse(result['pending'])
            self.assertIsNone(result['fib'])
            self.assertEqual({}, record['routes'])
            self.assertFalse(harness.load()['pending'])
            self.assertIsNone(harness.load()['fib'])

    def test_reservation_is_journalled_before_inspection_and_reused(self):
        record = {'fib': None, 'routes': {}, 'active': False}
        count = [1]
        saves = []
        blocked = [True]

        def resize(value):
            self.assertEqual(1, saves[-1]['reserved'])
            count[0] = value

        def save(value):
            saves.append(json.loads(json.dumps(value)))

        with self.assertRaisesRegex(route.RouteError, 'table 1 is occupied'):
            route.reserve_private_fib(record, lambda: count[0], resize,
                                      lambda _fib: blocked[0], save, lambda _seconds: None)
        self.assertEqual(2, count[0])
        self.assertEqual(1, record['reserved'])
        first_save_count = len(saves)
        with self.assertRaises(route.RouteError):
            route.reserve_private_fib(record, lambda: count[0], resize,
                                      lambda _fib: blocked[0], save, lambda _seconds: None)
        self.assertEqual(2, count[0])
        self.assertEqual(first_save_count, len(saves))
        blocked[0] = False
        self.assertEqual(1, route.reserve_private_fib(record, lambda: count[0], resize,
                                                     lambda _fib: blocked[0], save))
        self.assertEqual(1, record['fib'])
        self.assertIsNone(record['reserved'])

    def test_irreversible_fib_growth_reuses_write_ahead_receipt_after_failure(self):
        for takes_effect in (False, True):
            with self.subTest(takes_effect=takes_effect):
                record = {'fib': None, 'routes': {}, 'active': False}
                count = [1]
                saves = []
                attempts = [0]

                def resize(value):
                    attempts[0] += 1
                    self.assertEqual(1, saves[-1]['reserved'])
                    if takes_effect or attempts[0] > 1:
                        count[0] = value
                    if attempts[0] == 1:
                        raise RuntimeError('injected lost acknowledgement')

                with self.assertRaisesRegex(RuntimeError, 'lost acknowledgement'):
                    route.reserve_private_fib(
                        record, lambda: count[0], resize, lambda _fib: False,
                        lambda value: saves.append(json.loads(json.dumps(value))))
                self.assertEqual(1, record['reserved'])
                self.assertEqual(1, route.reserve_private_fib(
                    record, lambda: count[0], resize, lambda _fib: False,
                    lambda value: saves.append(json.loads(json.dumps(value)))))
                self.assertEqual(2, count[0])
                self.assertEqual(1 if takes_effect else 2, attempts[0])

    def test_global_lock_gives_concurrent_plugins_distinct_fibs(self):
        records = [{'fib': None, 'routes': {}, 'active': False} for _ in range(2)]
        count = [1]
        start = threading.Barrier(2)
        failures = []

        def worker(record, lock):
            try:
                start.wait()
                route.reserve_private_fib(record, lambda: count[0],
                                          lambda value: count.__setitem__(0, value),
                                          lambda _fib: False, lambda _record: None,
                                          lock_path=lock)
            except BaseException as error:
                failures.append(error)

        with tempfile.TemporaryDirectory() as directory:
            lock = Path(directory) / 'fib.lock'
            threads = [threading.Thread(target=worker, args=(record, lock)) for record in records]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(5)
        self.assertFalse(failures)
        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual({1, 2}, {record['fib'] for record in records})
        self.assertEqual(3, count[0])

    def test_adoption_semantics_ignore_only_kernel_generated_flags(self):
        wanted = forwarding(flags='UG')
        installed = forwarding(flags='UGS')
        self.assertEqual(route.route_semantic(wanted), route.route_semantic(installed))
        self.assertNotEqual(route.route_identity(wanted), route.route_identity(installed))
        self.assertNotEqual(route.route_semantic(wanted),
                            route.route_semantic({**installed, 'gateway': '10.255.255.2'}))

    def test_private_fib_allows_only_cloned_nondefault_routes(self):
        cloned = {**forwarding(flags='U'), 'gateway': 'interface'}
        native = {'route': cloned}
        self.assertFalse(route.private_fib_occupied(native, {'route': dict(cloned)}))
        numeric = forwarding(flags='UGS')
        self.assertTrue(route.private_fib_occupied({'route': numeric}, {'route': dict(numeric)}))
        self.assertTrue(route.private_fib_occupied(native, {'route': {**cloned, 'flags': 'UG'}}))
        discarded = {**cloned, 'discard': 'blackhole'}
        self.assertTrue(route.private_fib_occupied({'route': discarded}, {'route': dict(discarded)}))
        default = forwarding('0.0.0.0/0')
        self.assertTrue(route.private_fib_occupied({'default': default}, {'default': default}))

    def test_direct_route_ambiguous_ack_uses_readback_without_adoption(self):
        net = ipaddress.ip_network('192.168.101.0/24')
        exact = route.direct_payload(net, 17, add=True)
        connector = MagicMock()
        connector.__enter__.return_value = connector
        connector.__exit__.return_value = False
        with patch.object(route, 'exchange', side_effect=[route.RouteError('timeout'), exact]) as exchange, \
             self.assertRaisesRegex(route.RouteAmbiguous, 'ownership was not established'):
            route.mutate('add', str(net), 'vpn0', lambda: (connector, 700), lambda _name: 17)
        self.assertEqual(2, exchange.call_count)
        self.assertEqual(route.GETROUTE, exchange.call_args_list[-1].args[3])

        changed = route.direct_payload(net, 18, add=True)
        with patch.object(route, 'exchange', side_effect=[route.RouteError('timeout'), changed]):
            with self.assertRaises(route.RouteError):
                route.mutate('add', str(net), 'vpn0', lambda: (connector, 700), lambda _name: 17)

        missing = route.RouteRejected(errno.ESRCH, 'No such process')
        with patch.object(route, 'exchange', side_effect=[route.RouteError('timeout'), missing]):
            route.mutate('delete', str(net), 'vpn0', lambda: (connector, 700), lambda _name: 17)

    def test_explicit_kernel_errno_is_preserved_without_readback(self):
        connector = MagicMock()
        connector.__enter__.return_value = connector
        connector.__exit__.return_value = False
        rejected = route.RouteRejected(errno.EEXIST, 'File exists')
        with patch.object(route, 'exchange', side_effect=rejected) as exchange:
            with self.assertRaises(route.RouteRejected) as raised:
                route.mutate('add', '192.168.101.0/24', 'vpn0',
                             lambda: (connector, 700), lambda _name: 17)
        self.assertEqual(errno.EEXIST, raised.exception.errno)
        self.assertIn('File exists', str(raised.exception))
        self.assertEqual(1, exchange.call_count)


if __name__ == '__main__':
    unittest.main()
