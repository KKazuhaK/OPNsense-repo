"""Verify bounded imports, administrator precedence, and runtime ownership."""
from contextlib import redirect_stderr
import importlib.util
import ipaddress
import io
import json
from pathlib import Path
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

PACKAGE = Path(__file__).resolve().parents[2]
SCRIPTS = PACKAGE / 'src/usr/local/opnsense/scripts/easytier'
sys.path.insert(0, str(PACKAGE.parent / 'common'))
spec = importlib.util.spec_from_file_location('easytier_network_test', SCRIPTS / 'network.py')
n = importlib.util.module_from_spec(spec)
spec.loader.exec_module(n)
spec = importlib.util.spec_from_file_location('easytier_native_route_test', PACKAGE.parent / 'common/route_control.py')
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)


def route(destination, interface='vtnet0', gateway='link#1', flags='U'):
    return {'destination': destination, 'interface': interface, 'gateway': gateway, 'flags': flags}


def process_receipt(pid, arguments, birth=None):
    return {'pid': pid, 'birth': birth or '1780000000:' + str(pid), 'uid': n.os.geteuid(),
            'executable': n.os.path.realpath(arguments[0]), 'argv': list(arguments)}


def kernel_process(receipt, **changes):
    return {**receipt, 'ppid': 1, 'stopped': False, **changes}


class NetworkTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.addCleanup(patch.stopall)
        root = Path(self.directory.name)
        for name, path in (('ROOT', root), ('JOURNAL', root / 'owner.json'), ('RUNTIME', root / 'runtime.toml'),
                           ('CORE_PID', root / 'pid'), ('CONFIG', root / 'config.toml')):
            patch.object(n, name, path).start()
        core_arguments = [n.CORE, '--config-file', str(n.RUNTIME), '--rpc-portal', '127.0.0.1:30120']
        self.record = {'schema': 1, 'mode': 'supervised', 'token': 'private-token', 'routes': {},
                       'core': process_receipt(42, core_arguments), 'interface': {'name': 'vpn_custom', 'index': 17,
                       'description': 'EasyTier owner private-token', 'opened_by': 42, 'original': 'tun3'}}

    def test_exact_process_receipts_include_uid_executable_nul_argv_and_birth(self):
        arguments = n.supervisor_arguments()
        expected = process_receipt(42, arguments)
        with patch.object(n, 'process', return_value=kernel_process(expected)):
            self.assertEqual(n.identity(42), expected)
            self.assertTrue(n.same_process(expected))
        with patch.object(n, 'process', return_value=kernel_process(expected, ppid=99)), \
             self.assertRaisesRegex(n.PolicyError, 'unexpected parent'):
            n.identity(42, parent=41)
        for change in ({'birth': '1780000001:42'}, {'uid': n.os.geteuid() + 1},
                       {'executable': '/usr/sbin/sshd'}, {'argv': ['sshd']}):
            with self.subTest(change=change), patch.object(
                    n, 'process', return_value=kernel_process(expected, **change)):
                self.assertFalse(n.same_process(expected))

    def test_signal_rechecks_exact_identity_and_preserves_reused_pid(self):
        arguments = n.supervisor_arguments()
        expected = process_receipt(42, arguments)
        replacement = kernel_process(expected, birth='1780000001:42',
                                     executable='/usr/sbin/sshd', argv=['sshd'])
        with patch.object(n, 'process', side_effect=[kernel_process(expected), replacement]), \
             patch.object(n.os, 'kill') as kill:
            self.assertTrue(n.same_process(expected))
            self.assertFalse(n.signal_process(expected, n.signal.SIGTERM, arguments))
        kill.assert_not_called()

    def test_core_pid_reuse_between_stop_check_and_signal_is_preserved(self):
        arguments = [n.CORE, '--config-file', str(n.RUNTIME), '--rpc-portal', '127.0.0.1:30120']
        owned = process_receipt(42, arguments)
        record = {'schema': 1, 'mode': 'supervised', 'core': owned}
        replacement = kernel_process(owned, birth='1780000001:42',
                                     executable='/usr/sbin/sshd', argv=['sshd'])
        with patch.object(n, 'process', side_effect=[kernel_process(owned), replacement, replacement]), \
             patch.object(n.os, 'kill') as kill:
            self.assertEqual(n.terminate_core(record), 0)
        kill.assert_not_called()

    def test_stop_launcher_adopts_core_when_exec_crosses_exact_signal(self):
        portal = '127.0.0.1:30120'
        launch_arguments = n.launcher_arguments(descriptor=8, portal=portal)
        launcher = process_receipt(42, launch_arguments)
        core = process_receipt(42, [n.CORE, '--config-file', str(n.RUNTIME),
                                    '--rpc-portal', portal], birth=launcher['birth'])
        record = {'schema': 1, 'launcher': launcher}
        with patch.object(n, 'identity', side_effect=[launcher, core]), \
             patch.object(n, 'signal_process', return_value=False), \
             patch.object(n, 'write_journal') as write:
            n.stop_launcher(record)
        self.assertNotIn('launcher', record)
        self.assertEqual(record['core'], core)
        write.assert_called_once_with(record)

    def test_stop_launcher_preserves_unexpected_same_execution(self):
        portal = '127.0.0.1:30120'
        launcher = process_receipt(
            42, n.launcher_arguments(descriptor=8, portal=portal))
        foreign = process_receipt(
            42, ['/usr/sbin/sshd'], birth=launcher['birth'])
        record = {'schema': 1, 'launcher': launcher}
        with patch.object(n, 'identity', return_value=foreign), \
             patch.object(n, 'write_journal') as write, \
             self.assertRaisesRegex(n.PolicyError, 'unexpected process'):
            n.stop_launcher(record)
        self.assertEqual(record['launcher'], launcher)
        write.assert_not_called()

    def test_launcher_requires_release_byte_before_exec(self):
        with patch.object(n.sys, 'platform', 'freebsd15'), \
             patch.object(n.os, 'geteuid', return_value=0), \
             patch.object(n.os, 'read', return_value=b''), \
             patch.object(n.os, 'close'), patch.object(n.os, 'execv') as execute:
            self.assertEqual(n.launcher('8', '127.0.0.1:30120'), 0)
        execute.assert_not_called()

        with patch.object(n.sys, 'platform', 'freebsd15'), \
             patch.object(n.os, 'geteuid', return_value=0), \
             patch.object(n.os, 'read', return_value=b'1'), \
             patch.object(n.os, 'close'), patch.object(
                 n.os, 'execv', side_effect=RuntimeError('exec boundary')) as execute, \
             self.assertRaisesRegex(RuntimeError, 'exec boundary'):
            n.launcher('8', '127.0.0.1:30120')
        execute.assert_called_once_with(
            n.CORE, [n.CORE, '--config-file', str(n.RUNTIME),
                     '--rpc-portal', '127.0.0.1:30120'])

    def test_pidfile_creation_is_exclusive_and_foreign_file_is_preserved(self):
        n.CORE_PID.write_text('99\n')
        with self.assertRaises(FileExistsError):
            n.create_pidfile(42)
        self.assertEqual(n.CORE_PID.read_text(), '99\n')
        n.CORE_PID.unlink()
        n.create_pidfile(42)
        self.assertEqual(n.CORE_PID.read_text(), '42\n')
        self.assertEqual(n.CORE_PID.stat().st_mode & 0o777, 0o600)

    def test_cleanup_preserves_pidfile_after_pid_is_reused_by_foreign_process(self):
        n.CORE_PID.write_text('42\n')
        record = {**self.record, 'interface': None}
        foreign = process_receipt(42, ['/usr/sbin/sshd'])
        with patch.object(n, 'routing_table', return_value={}), \
             patch.object(n, 'identity', return_value=foreign):
            n.cleanup(record)
        self.assertEqual(n.CORE_PID.read_text(), '42\n')

    def test_native_add_rechecks_the_exact_interface_inside_index_resolution(self):
        calls = []
        class NativeError(Exception):
            pass
        def native_mutate(action, destination, interface, index=None):
            calls.append((action, destination, interface))
            index(interface)
            self.fail('The native request must not be constructed after ownership changes.')
        adapter = SimpleNamespace(mutate=native_mutate, RouteError=NativeError)
        with patch.dict(sys.modules, {'native_route': adapter}), \
             patch.object(n, 'owns_running_interface', return_value=False), \
             self.assertRaisesRegex(n.RouteMutationError, 'ownership changed'):
            n.mutate_route('add', '192.168.101.0/24', 'vpn_custom', self.record)
        self.assertEqual(calls, [('add', '192.168.101.0/24', 'vpn_custom')])

    def test_private_remote_subnets_allowed_and_public_default_routes_rejected(self):
        for cidr in ('10.125.0.0/24', '172.31.2.0/24', '192.168.101.0/24'):
            self.assertEqual(n.validate_configuration({'routes': [cidr]}), 'easytier0')
        for cidr in ('64.0.0.0/2', '0.0.0.0/0', '192.167.0.0/16', 'fc00::/7', 'not-a-network'):
            with self.subTest(cidr=cidr), self.assertRaises(n.PolicyError):
                n.validate_configuration({'routes': [cidr]})

    def test_overlay_names_and_ipv6_modes_validated_without_changing_document(self):
        document = {'flags': {'dev_name': 'vpn_custom'}, 'ipv4': '10.125.0.1/24', 'ipv6': 'fd01::1/64',
                    'future': {'nested': ['value']}}
        before = json.dumps(document)
        self.assertEqual(n.validate_configuration(document), 'vpn_custom')
        self.assertEqual(json.dumps(document), before)
        for edit in ({'dhcp': True}, {'ipv4': '64.1.1.1/24'}, {'ipv6': '2001:db8::1/64'},
                     {'ipv6_public_addr_auto': True}, {'ipv6_public_addr_provider': True},
                     {'flags': {'dev_name': 'foreign; destroy'}}):
            with self.subTest(edit=edit), self.assertRaises(n.PolicyError):
                n.validate_configuration(edit)

    def test_native_prefix_protection_distinguishes_remote_private_and_default(self):
        table = {'0.0.0.0/0': route('0.0.0.0/0', 'vtnet1', '198.51.100.1'),
                 '192.168.8.0/22': route('192.168.8.0/22'),
                 '10.0.0.1/32': route('10.0.0.1/32', 'wg0', '10.255.255.1')}
        for value in ('192.168.8.1/32', '192.168.0.0/16', '10.0.0.0/24'):
            self.assertTrue(n.protected(ipaddress.ip_network(value), table))
        self.assertFalse(n.protected(ipaddress.ip_network('192.168.101.0/24'), table))
        with patch.object(n, 'load_record', return_value={}):
            with self.assertRaisesRegex(n.PolicyError, 'explicit VPN route overlaps'):
                n.validate_live_configuration({'routes': ['10.0.0.0/24']}, table)
            self.assertEqual(n.validate_live_configuration({'routes': ['192.168.101.0/24']}, table), 'easytier0')

    def test_numeric_ipv4_parser_and_scoped_ipv6_do_not_collapse_native_routes(self):
        text = 'Destination Gateway Flags Netif Expire\ndefault 198.51.100.1 UGS vtnet1\n10/8 link#1 U vtnet0\n192.168.8.1 aa:bb:cc:dd:ee:ff UHL vtnet0\n'
        self.assertEqual(set(n.parse_routes(text, 4)), {'0.0.0.0/0', '10.0.0.0/8'})
        text = 'Destination Gateway Flags Netif\ndefault fe80::1%vtnet1 UGS vtnet1\nfe80::%vtnet0/64 link#1 U vtnet0\nfe80::%vtnet1/64 link#2 U vtnet1\nfd10::/64 link#3 U wg0\n'
        self.assertEqual(set(n.parse_routes(text, 6)), {'::/0', 'fd10::/64'})
        for text in ('missing heading', 'Destination Gateway Flags Netif\n10.0.0.0/24 only-two',
                     'Destination Gateway Flags Netif\ninvalid link#1 U vtnet0'):
            with self.assertRaises(n.PolicyError):
                n.parse_routes(text, 4)

    def test_learned_routes_skip_local_row_but_keep_peer_named_local(self):
        rows = [{'proxy_cidrs': '192.168.8.0/22', 'next_hop_hostname': 'Local', 'next_hop_ipv4': '-'},
                {'proxy_cidrs': '192.168.101.0/24,64.0.0.0/2', 'next_hop_hostname': 'Local', 'next_hop_ipv4': '10.125.0.2'}]
        self.assertEqual(n.learned_routes(json.dumps(rows)), ['192.168.101.0/24', '64.0.0.0/2'])
        for data in ({'wrapped': rows}, [None], [{'proxy_cidrs': ['unexpected']}], [{'proxy_cidrs': 'x'}] * 1025):
            with self.assertRaises(n.PolicyError):
                n.learned_routes(json.dumps(data))

    def test_safe_learned_import_preserves_native_routes_and_counts_rejections(self):
        table = {'0.0.0.0/0': route('0.0.0.0/0', 'vtnet1', '198.51.100.1'),
                 '192.168.8.0/22': route('192.168.8.0/22')}
        native = dict(table)
        def mutate(action, destination, interface, owner=None):
            self.assertEqual(action, 'add')
            self.assertIs(owner, self.record)
            table[destination] = route(destination, interface, 'link#17', 'US')
            return True
        with patch.object(n, 'routing_table', side_effect=lambda: dict(table)), \
             patch.object(n, 'owns_running_interface', return_value=True), \
             patch.object(n, 'mutate_route', side_effect=mutate) as mutation:
            n.sync_routes(self.record, ['192.168.101.0/24', '192.168.8.1/32', '64.0.0.0/2', '0.0.0.0/0'])
        self.assertEqual(mutation.call_count, 1)
        self.assertEqual(self.record['rejected_routes'], {'public_or_invalid': 2, 'native_conflict': 1})
        self.assertEqual(self.record['imported_route_count'], 1)
        self.assertTrue(all(table[key] == value for key, value in native.items()))

    def test_route_add_persists_exact_intent_before_kernel_mutation(self):
        destination = '192.168.101.0/24'
        table = {}
        def mutate(action, value, interface, owner=None):
            self.assertEqual((action, value, interface), ('add', destination, 'vpn_custom'))
            self.assertIs(owner, self.record)
            persisted = json.loads(n.JOURNAL.read_text())
            self.assertEqual(persisted['pending_route'], n.route_receipt(self.record, destination))
            self.assertNotIn(destination, persisted['routes'])
            table[destination] = route(destination, interface, 'link#17', 'US')
            return True
        with patch.object(n, 'routing_table', side_effect=lambda: dict(table)), \
             patch.object(n, 'owns_running_interface', return_value=True), \
             patch.object(n, 'mutate_route', side_effect=mutate):
            n.sync_routes(self.record, [destination])
        persisted = n.load_record()
        self.assertNotIn('pending_route', persisted)
        self.assertEqual(persisted['routes'][destination], table[destination])

    def test_crash_after_route_add_preserves_equal_route_as_ambiguous(self):
        destination = '192.168.101.0/24'
        table = {}
        original_write = n.write_journal
        def crash_before_commit(record):
            if destination in record.get('routes', {}) and 'pending_route' not in record:
                raise OSError('fixture power loss')
            original_write(record)
        def mutate(action, value, interface, owner=None):
            if action == 'add':
                self.assertIs(owner, self.record)
                table[value] = route(value, interface, 'link#17', 'US')
            else:
                table.pop(value, None)
            return True
        with patch.object(n, 'routing_table', side_effect=lambda: dict(table)), \
             patch.object(n, 'owns_running_interface', return_value=True), \
             patch.object(n, 'mutate_route', side_effect=mutate), \
             patch.object(n, 'write_journal', side_effect=crash_before_commit):
            with self.assertRaisesRegex(OSError, 'power loss'):
                n.sync_routes(self.record, [destination])
        recovered = n.load_record()
        self.assertIn('pending_route', recovered)
        self.assertEqual(recovered['routes'], {})
        with patch.object(n, 'routing_table', side_effect=lambda: dict(table)), \
             patch.object(n, 'mutate_route', side_effect=mutate):
            with self.assertRaisesRegex(n.PolicyError, 'ambiguous ownership'):
                n.remove_routes(recovered)
        self.assertIn(destination, table)
        self.assertTrue(n.load_record()['route_recovery_ambiguous'])
        table.pop(destination)
        with patch.object(n, 'routing_table', side_effect=lambda: dict(table)), \
             patch.object(n, 'mutate_route', side_effect=mutate):
            n.remove_routes(recovered)
        self.assertNotIn('pending_route', n.load_record())

    def test_pending_equal_route_is_ambiguous_and_foreign_mismatch_survives(self):
        destination = '192.168.101.0/24'
        receipt = n.route_receipt(self.record, destination)
        exact = route(destination, 'vpn_custom', 'link#17', 'US')
        self.record['pending_route'] = receipt
        with patch.object(n, 'routing_table', return_value={destination: exact}), \
             patch.object(n, 'owns_running_interface', return_value=True), \
             patch.object(n, 'mutate_route') as mutation:
            with self.assertRaisesRegex(n.PolicyError, 'ambiguous ownership'):
                n.sync_routes(self.record, [destination])
        mutation.assert_not_called()
        self.assertEqual(self.record['routes'], {})
        self.assertIn('pending_route', self.record)
        self.assertTrue(self.record['route_recovery_ambiguous'])

        foreign = route(destination, 'wg1', '10.2.2.2', 'UGS')
        record = {**self.record, 'routes': {}, 'pending_route': receipt}
        record.pop('route_recovery_ambiguous', None)
        table = {destination: foreign}
        with patch.object(n, 'routing_table', side_effect=lambda: dict(table)), \
             patch.object(n, 'mutate_route') as mutation:
            n.remove_routes(record)
        mutation.assert_not_called()
        self.assertEqual(table, {destination: foreign})
        self.assertNotIn('pending_route', record)

    def test_invalid_pending_route_receipt_fails_closed_without_mutation(self):
        destination = '192.168.101.0/24'
        self.record['pending_route'] = {'schema': 1, 'action': 'add',
                                        'destination': destination, 'interface': 'foreign'}
        with patch.object(n, 'routing_table', return_value={destination: route(destination)}), \
             patch.object(n, 'mutate_route') as mutation, \
             self.assertRaisesRegex(n.PolicyError, 'pending VPN route receipt is invalid'):
            n.remove_routes(self.record)
        mutation.assert_not_called()
        self.assertIn('pending_route', self.record)

    def test_single_fib_default_dump_fallback_requires_proven_current_fib_zero(self):
        heading = 'Destination Gateway Flags Netif\n'
        def command(args, timeout=5):
            if args[0].endswith('netstat'):
                return SimpleNamespace(returncode=1 if '-F' in args else 0, stdout=heading)
            return SimpleNamespace(returncode=0, stdout='1' if args[-1] == 'net.fibs' else '0')
        with patch.object(n, 'run', side_effect=command):
            self.assertEqual(n.routing_table(), {})
        for count, current in (('2', '0'), ('1', '1')):
            def unsafe(args, timeout=5):
                if args[0].endswith('netstat'):
                    return SimpleNamespace(returncode=1, stdout='')
                return SimpleNamespace(returncode=0, stdout=count if args[-1] == 'net.fibs' else current)
            with patch.object(n, 'run', side_effect=unsafe), self.assertRaises(n.PolicyError):
                n.routing_table()

    def test_failed_safe_route_import_reports_failure_and_does_not_claim_ownership(self):
        with patch.object(n, 'routing_table', return_value={}), \
             patch.object(n, 'owns_running_interface', return_value=True), \
             patch.object(n, 'mutate_route', return_value=False):
            n.sync_routes(self.record, ['192.168.101.0/24'])
        self.assertEqual(self.record['routes'], {})
        self.assertEqual(self.record['rejected_routes']['installation_failure'], 1)
        self.assertIn('could not be installed', self.record['error'])

    def test_native_route_diagnostic_reaches_private_log_and_public_status_bounded(self):
        diagnostic = 'Native route add failed:\n\x00\x1b[31m' + '\N{SNOWMAN}' * 600
        output = io.StringIO()
        with patch.object(n, 'routing_table', return_value={}), \
             patch.object(n, 'owns_running_interface', return_value=True), \
             patch.object(n, 'mutate_route', side_effect=n.RouteMutationError(diagnostic)), \
             redirect_stderr(output):
            n.sync_routes(self.record, ['192.168.101.0/24'])
        self.assertEqual(self.record['routes'], {})
        self.assertNotIn('\n', self.record['error'])
        self.assertNotIn('\x00', self.record['error'])
        self.assertNotIn('\x1b', self.record['error'])
        self.assertLessEqual(len(self.record['error'].encode()), n.ROUTING_DIAGNOSTIC_LIMIT)
        self.assertIn('Native route add failed', self.record['error'])
        self.assertEqual(output.getvalue().strip(), self.record['error'])
        self.assertEqual(n.public_status()['network_error'], self.record['error'])

    def test_native_route_delete_diagnostic_is_retained_for_recovery(self):
        destination = '192.168.101.0/24'
        expected = route(destination, 'vpn_custom', 'link#17', 'US')
        self.record['routes'][destination] = expected
        with patch.object(n, 'routing_table', return_value={destination: expected}), \
             patch.object(n, 'mutate_route', side_effect=n.RouteMutationError('[Errno 16] Device busy')):
            with self.assertRaisesRegex(n.PolicyError, r'Device busy') as caught:
                n.remove_routes(self.record)
        self.assertLessEqual(len(str(caught.exception).encode()), n.ROUTING_DIAGNOSTIC_LIMIT)
        self.assertIn(destination, self.record['routes'])

    def test_new_native_route_takes_precedence_and_changed_exact_route_is_not_deleted(self):
        destination = '192.168.101.0/24'
        owned = route(destination, 'vpn_custom', 'link#17', 'US')
        self.record['routes'][destination] = owned
        native = route('192.168.101.10/32', 'wg0', '10.1.1.1', 'UGHS')
        table = {destination: owned, native['destination']: native}
        def withdraw(action, value, interface):
            self.assertEqual((action, value, interface), ('delete', destination, 'vpn_custom'))
            table.pop(destination)
            return True
        with patch.object(n, 'routing_table', side_effect=lambda: dict(table)), \
             patch.object(n, 'mutate_route', side_effect=withdraw) as mutation:
            n.sync_routes(self.record, [destination])
        mutation.assert_called_once_with('delete', destination, 'vpn_custom')
        self.assertEqual(self.record['routes'], {})
        self.record['routes'][destination] = owned
        foreign = route(destination, 'wg1', '10.2.2.2', 'UGS')
        with patch.object(n, 'routing_table', return_value={destination: foreign}), patch.object(n, 'mutate_route') as mutation:
            n.remove_routes(self.record)
        mutation.assert_not_called()
        self.assertEqual(self.record['routes'], {})

    def test_failed_route_removal_retains_ownership_for_recovery(self):
        destination = '192.168.101.0/24'
        self.record['routes'][destination] = route(destination, 'vpn_custom', 'link#17', 'US')
        with patch.object(n, 'routing_table', return_value=dict(self.record['routes'])), patch.object(n, 'mutate_route', return_value=False):
            with self.assertRaises(n.PolicyError):
                n.remove_routes(self.record)
        self.assertIn(destination, self.record['routes'])

    def test_interface_cleanup_requires_index_kernel_driver_and_description_token(self):
        expected = dict(self.record['interface'])
        closed = {**expected, 'opened_by': None}
        with patch.object(n, 'routing_table', return_value={}), \
             patch.object(n, 'run', return_value=SimpleNamespace(returncode=0, stdout='', stderr='')) as command:
            for change in ({'index': 18}, {'description': 'foreign'}, {'original': 'bridge3'}):
                self.record['interface'] = dict(expected)
                current = {**closed, **change}
                with patch.object(n, 'interface_identity', return_value=current):
                    n.cleanup(self.record)
            command.assert_not_called()
            self.record['interface'] = dict(expected)
            with patch.object(n, 'interface_identity', side_effect=[closed, None]):
                n.cleanup(self.record)
            command.assert_called_once_with(['/sbin/ifconfig', 'vpn_custom', 'destroy'])
            self.assertNotIn('interface', self.record)
        forbidden = ('filter', 'reload', 'pfctl', 'killall')
        self.assertFalse(any(value in str(command.call_args_list) for value in forbidden))

    def test_failed_interface_destruction_is_reported_and_receipt_is_retryable(self):
        expected = dict(self.record['interface'])
        closed = {**expected, 'opened_by': None}
        failed = SimpleNamespace(returncode=1, stdout='', stderr='ifconfig: Device busy')
        with patch.object(n, 'routing_table', return_value={}), \
             patch.object(n, 'interface_identity', return_value=closed), \
             patch.object(n, 'run', return_value=failed):
            with self.assertRaisesRegex(n.PolicyError, 'cleanup is incomplete'):
                n.cleanup(self.record)
        retained = n.load_record()
        self.assertEqual(expected, retained['interface'])
        self.assertTrue(retained['cleanup_pending'])
        self.assertIn('could not be destroyed', retained['cleanup_error'])

        success = SimpleNamespace(returncode=0, stdout='', stderr='')
        with patch.object(n, 'routing_table', return_value={}), \
             patch.object(n, 'interface_identity', side_effect=[closed, None]), \
             patch.object(n, 'run', return_value=success):
            n.cleanup(retained)
        recovered = n.load_record()
        self.assertNotIn('interface', recovered)
        self.assertNotIn('cleanup_pending', recovered)

    def test_cleanup_preserves_same_interface_opened_by_a_foreign_process(self):
        expected = dict(self.record['interface'])
        foreign = {**expected, 'opened_by': 99}
        with patch.object(n, 'routing_table', return_value={}), \
             patch.object(n, 'interface_identity', return_value=foreign), \
             patch.object(n, 'run') as command:
            n.cleanup(self.record)
        command.assert_not_called()
        self.assertNotIn('interface', self.record)

    def test_claiming_receipt_cleans_either_side_after_core_closes_tun(self):
        original = {**self.record['interface'], 'description': ''}
        receipt = {**original, 'phase': 'claiming', 'preclaim': dict(original)}
        self.record['interface'] = receipt
        for description in ('', 'EasyTier owner private-token'):
            with self.subTest(description=description):
                current = {**original, 'description': description, 'opened_by': None}
                record = {**self.record, 'interface': dict(receipt)}
                success = SimpleNamespace(returncode=0, stdout='', stderr='')
                with patch.object(n, 'routing_table', return_value={}), \
                     patch.object(n, 'interface_identity', side_effect=[current, None]), \
                     patch.object(n, 'run', return_value=success) as command:
                    n.cleanup(record)
                command.assert_called_once_with(['/sbin/ifconfig', 'vpn_custom', 'destroy'])
                self.assertNotIn('interface', record)

    def test_active_supervisor_stop_reloads_and_propagates_route_cleanup_failure(self):
        arguments = n.supervisor_arguments()
        owner = {'pid': 41, 'birth': '1780000000:41', 'uid': n.os.geteuid(),
                 'executable': n.os.path.realpath(arguments[0]), 'argv': arguments}
        destination = '192.168.101.0/24'
        record = {'token': 'private-token', 'supervisor': owner, 'active': True,
                  'routes': {destination: route(destination, 'vpn_custom', 'link#17', 'US')}}
        alive = {'owner': True}

        def same_process(value):
            return value == owner and alive['owner']

        def terminate(_pid, _signal):
            alive['owner'] = False

        with patch.object(n, 'load_record', side_effect=[record, record]), \
             patch.object(n, 'same_process', side_effect=same_process), \
             patch.object(n.os, 'kill', side_effect=terminate), \
             patch.object(n, 'routing_table', return_value=dict(record['routes'])), \
             patch.object(n, 'mutate_route', return_value=False):
            with self.assertRaisesRegex(n.PolicyError, 'route could not be removed'):
                n.stop()
        self.assertIn(destination, record['routes'])

    def test_reused_supervisor_pid_and_foreign_pidfile_never_authorize_kill(self):
        n.CORE_PID.write_text('42\n')
        helpers = SimpleNamespace(rpc_portal=lambda for_connection=False: '127.0.0.1:15888')
        with patch.dict(sys.modules, {'manage': helpers}), \
             patch.object(n, 'load_record', return_value={'supervisor': {'pid': 42, 'birth': 'old'}}), \
             patch.object(n, 'identity', return_value={'pid': 42, 'birth': 'new', 'uid': 0,
                                                       'executable': '/usr/sbin/sshd', 'argv': ['sshd']}), \
             patch.object(n, 'cleanup'), patch.object(n.os, 'kill') as kill:
            self.assertEqual(n.stop(), 1)
        kill.assert_not_called()

    def test_legacy_adoption_requires_exact_core_argv_and_signals_only_after_recheck(self):
        n.CORE_PID.write_text('42\n')
        portal = '127.0.0.1:15888'
        arguments = [n.CORE, '--config-file', str(n.CONFIG), '--rpc-portal', portal]
        owned = process_receipt(42, arguments)
        helpers = SimpleNamespace(rpc_portal=lambda for_connection=False: portal)
        alive = {'value': True}
        def current(pid):
            return owned if pid == 42 and alive['value'] else None
        def terminate(pid, number):
            self.assertEqual((pid, number), (42, n.signal.SIGTERM))
            alive['value'] = False
        with patch.dict(sys.modules, {'manage': helpers}), \
             patch.object(n, 'identity', side_effect=current), \
             patch.object(n, 'routing_table', return_value={}), \
             patch.object(n, 'interface_identity', return_value=None), \
             patch.object(n.os, 'kill', side_effect=terminate) as kill:
            self.assertEqual(n.stop_legacy(), 0)
        kill.assert_called_once_with(42, n.signal.SIGTERM)
        self.assertFalse(n.CORE_PID.exists())

        # Saving a new portal before restart must not make the already-running
        # legacy process impossible to stop.  Its recorded argv remains exact.
        n.CORE_PID.write_text('42\n')
        alive['value'] = True
        with patch.object(n, 'identity', side_effect=current), \
             patch.object(n, 'routing_table', return_value={}), \
             patch.object(n, 'interface_identity', return_value=None), \
             patch.object(n.os, 'kill', side_effect=terminate) as kill:
            self.assertEqual(n.stop_legacy(), 0)
        kill.assert_called_once_with(42, n.signal.SIGTERM)
        self.assertFalse(n.CORE_PID.exists())

        n.CORE_PID.write_text('42\n')
        foreign = process_receipt(42, [n.CORE, '--config-file', '/tmp/foreign.toml',
                                       '--rpc-portal', portal])
        with patch.dict(sys.modules, {'manage': helpers}), \
             patch.object(n, 'identity', return_value=foreign), \
             patch.object(n.os, 'kill') as kill:
            self.assertEqual(n.stop_legacy(), 1)
        kill.assert_not_called()
        self.assertEqual(n.CORE_PID.read_text(), '42\n')

    def test_dead_legacy_pidfile_is_retired_without_signalling(self):
        n.CORE_PID.write_text('42\n')
        with patch.object(n, 'identity', return_value=None), \
             patch.object(n.os, 'kill') as kill:
            self.assertEqual(n.stop_legacy(), 0)
        kill.assert_not_called()
        self.assertFalse(n.CORE_PID.exists())

    def supervisor_fixture(self, hang=False):
        from unittest.mock import MagicMock
        manager_spec = importlib.util.spec_from_file_location('easytier_supervisor_renderer', SCRIPTS / 'manage.py')
        manager = importlib.util.module_from_spec(manager_spec)
        manager_spec.loader.exec_module(manager)
        data = {'hostname': 'fixture', 'ipv4': '10.125.0.1/24', 'rpc_portal': '127.0.0.1:30120',
                'network_identity': {'network_secret': 'SENTINEL_SECRET'},
                'flags': {'dev_name': 'vpn_custom'}, 'future_fields': {'array': [1, 2, 3]}}
        original = manager.render(data)
        n.CONFIG.write_text(original)
        table = {'192.168.8.0/22': route('192.168.8.0/22'),
                 '0.0.0.0/0': route('0.0.0.0/0', 'vtnet1', '198.51.100.1', 'UGS')}
        native = dict(table)
        interface = None
        events = []
        child = MagicMock(pid=42)
        dead = False
        released = False
        launched_arguments = None
        def launch(arguments, **options):
            nonlocal launched_arguments
            runtime = __import__('tomllib').loads(n.RUNTIME.read_text())
            self.assertEqual(runtime, {**data, 'routes': []})
            self.assertEqual(n.RUNTIME.stat().st_mode & 0o777, 0o600)
            self.assertEqual(n.CONFIG.read_text(), original)
            self.assertEqual(arguments[2], 'launch')
            self.assertEqual(arguments[-1], '127.0.0.1:30120')
            self.assertEqual(options['pass_fds'], (100,))
            self.assertTrue(options['close_fds'])
            launched_arguments = arguments
            return child
        child.poll.side_effect = lambda: 1 if dead else None
        rpc_calls = 0
        def command(arguments, timeout=5):
            nonlocal interface, rpc_calls
            events.append(tuple(arguments))
            if arguments[0] == '/sbin/ifconfig' and arguments[2] == 'description':
                interface['description'] = arguments[3]
            if arguments[0] == '/sbin/ifconfig' and arguments[2] == 'destroy':
                interface = None
                table.pop('10.125.0.0/24', None)
            if arguments[0] == n.CLI:
                rpc_calls += 1
                if hang and rpc_calls > 1:
                    return SimpleNamespace(returncode=1, stdout='')
                return SimpleNamespace(returncode=0, stdout=json.dumps([
                    {'proxy_cidrs': '192.168.101.0/24,64.0.0.0/2,192.168.8.1/32',
                     'next_hop_hostname': 'peer', 'next_hop_ipv4': 'DIRECT'}]))
            return SimpleNamespace(returncode=0, stdout='YES')
        def mutation(action, destination, name, owner=None):
            events.append((action, destination, name))
            if action == 'add':
                self.assertIsNotNone(owner)
                table[destination] = route(destination, name, 'link#17', 'US')
            else:
                table.pop(destination)
            return True
        def sleep(value):
            nonlocal dead, interface
            if not hang:
                dead = True
                if interface:
                    interface['opened_by'] = None
        def terminate(_pid=None, _signal=None):
            nonlocal dead, interface
            events.append(('terminate-owned-core',))
            dead = True
            if interface:
                interface['opened_by'] = None
        child.terminate.side_effect = terminate
        helpers = SimpleNamespace(render=manager.render, rpc_portal=lambda for_connection=True: '127.0.0.1:30120')
        def process_identity(pid, parent=None):
            if pid == child.pid and dead:
                return None
            arguments = (n.supervisor_arguments() if pid == n.os.getpid() else
                         ([n.CORE, '--config-file', str(n.RUNTIME), '--rpc-portal', '127.0.0.1:30120']
                          if released else launched_arguments))
            return {'pid': pid, 'birth': '1780000000:' + str(pid), 'uid': n.os.geteuid(),
                    'executable': n.os.path.realpath(arguments[0]), 'argv': arguments}
        def release(descriptor, content):
            nonlocal released, interface
            self.assertEqual((descriptor, content), (101, b'1'))
            released = True
            interface = dict(self.record['interface'])
            interface['description'] = ''
            table['10.125.0.0/24'] = route('10.125.0.0/24', 'vpn_custom', 'link#17')
            return 1
        with patch.dict(sys.modules, {'manage': helpers}), patch.object(n, 'identity', side_effect=process_identity), \
             patch.object(n, 'routing_table', side_effect=lambda: dict(table)), patch.object(n, 'interface_identity', side_effect=lambda name: dict(interface) if interface else None), \
             patch.object(n, 'run', side_effect=command), patch.object(n.subprocess, 'Popen', side_effect=launch), \
             patch.object(n, 'mutate_route', side_effect=mutation), patch.object(n.time, 'sleep', side_effect=sleep), \
             patch.object(n.os, 'kill', side_effect=terminate), patch.object(n.signal, 'signal'), \
             patch.object(n.os, 'pipe', return_value=(100, 101)), patch.object(n.os, 'write', side_effect=release), \
             patch.object(n.os, 'close'):
            if hang:
                with self.assertRaisesRegex(n.PolicyError, 'Core RPC stopped responding'):
                    n.supervise()
            else:
                self.assertEqual(n.supervise(), 0)
        record = n.load_record()
        self.assertFalse(record['active'])
        self.assertEqual(record['routes'], {})
        self.assertEqual(record['rejected_routes'], {'public_or_invalid': 1, 'native_conflict': 1})
        self.assertEqual(table, native)
        self.assertFalse(n.RUNTIME.exists())
        self.assertFalse(n.CORE_PID.exists())
        self.assertEqual(n.CONFIG.read_text(), original)
        deletion = next(i for i, event in enumerate(events) if event[0] == 'delete')
        destruction = next(i for i, event in enumerate(events) if event[:3] == ('/sbin/ifconfig', 'vpn_custom', 'destroy'))
        self.assertLess(deletion, destruction)
        if hang:
            termination = next(i for i, event in enumerate(events) if event[0] == 'terminate-owned-core')
            self.assertLess(deletion, termination)
            self.assertIn('Core RPC stopped responding', record['error'])
        self.assertFalse(any('pfctl' in str(event) or 'configctl' in str(event) or 'unbound' in str(event) for event in events))

    def test_supervisor_runtime_copy_crash_cleanup_and_no_native_service_mutation(self):
        self.supervisor_fixture()

    def test_rpc_hang_withdraws_owned_routes_before_stopping_only_its_core(self):
        self.supervisor_fixture(hang=True)


class NativeRequestTests(unittest.TestCase):
    def test_exclusive_add_and_oif_bound_delete_requests(self):
        for action, kind, flags in (('add', a.NEWROUTE, a.CREATE | a.EXCL), ('delete', 25, 0)):
            connector = SimpleNamespace()
            from unittest.mock import MagicMock
            sock = MagicMock()
            connector = lambda: (sock, 700)
            with patch.object(a, 'exchange') as exchange:
                a.mutate(action, '192.168.101.0/24', 'vpn_custom', connector=connector, index=lambda value: 17)
            args = exchange.call_args.args
            self.assertEqual(args[3:5], (kind, flags))
            header = a.ROUTE.unpack_from(args[5])
            self.assertEqual(header[:2], (2, 24))
            attrs = a.attributes(args[5][a.ROUTE.size:])
            self.assertEqual(a.U32.unpack(attrs[a.OIF]), (17,))
            self.assertEqual(a.U32.unpack(attrs[a.TABLE]), (0,))
            self.assertNotIn(a.GATEWAY, attrs)


if __name__ == '__main__':
    unittest.main()
