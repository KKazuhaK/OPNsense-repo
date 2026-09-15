"""Exercise runtime isolation, consent, PID ownership and failed-start recovery."""
import copy
import fcntl
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HELPERS = Path(__file__).resolve().parents[1] / 'src/usr/local/opnsense/scripts/singbox'
sys.path.insert(0, str(HELPERS))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'common'))
spec = importlib.util.spec_from_file_location('singbox_integration', HELPERS / 'integration.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def config():
    return {'future': {'retain': 'SENTINEL_SECRET'}, 'inbounds': [
        {'type': 'socks', 'tag': 'socks', 'listen': '127.0.0.1', 'listen_port': 7892},
        {'type': 'tun', 'tag': 'tun', 'address': ['172.19.0.1/30'], 'stack': 'gvisor',
         'auto_route': True, 'strict_route': True, 'route_address': ['64.0.0.0/2'],
         'inet6_route_address': ['::/0'], 'route_address_set': ['world'],
         'auto_redirect': True, 'future_tun_option': 'retain'}],
        'outbounds': [{'type': 'direct', 'password': 'SENTINEL_PASSWORD'}],
        'dns': {'servers': [{'type': 'udp', 'server': '1.1.1.1'}]}}


class ExactIdentityTests(unittest.TestCase):
    def snapshot(self, **changes):
        return {'pid': 12345, 'ppid': 1, 'uid': os.geteuid(), 'birth': '1770000000:12345',
                'executable': os.path.realpath(m.CORE), 'stopped': False,
                'argv': [m.CORE, 'run', '-c', str(m.STATE / 'runtime.json')]} | changes

    def test_kernel_arguments_and_microsecond_birth_define_ownership(self):
        value = self.snapshot()
        with patch.object(m, 'process', return_value=value):
            record = {'core': m.identity(value['pid'])}
            self.assertTrue(m.owned(record))
            self.assertEqual(record['core']['birth'], '1770000000:12345')
            # Displayed ps decorations and shell quoting never enter argv.
            self.assertEqual(record['core']['arguments'], value['argv'])
        for change in ({'birth': '1770000000:12346'}, {'uid': os.geteuid() + 1},
                       {'executable': '/tmp/foreign-core'}, {'argv': value['argv'] + ['(sing-box)']}):
            with self.subTest(change=change), patch.object(m, 'process', return_value=self.snapshot(**change)):
                self.assertFalse(m.owned(record))

    def test_paused_core_retains_signal_ownership(self):
        with patch.object(m, 'process', return_value=self.snapshot()):
            record = {'core': m.identity(12345)}
        with patch.object(m, 'process', return_value=self.snapshot(stopped=True, ppid=2)), patch.object(m.os, 'kill') as kill:
            self.assertTrue(m.owned(record))
            self.assertTrue(m.signal_owned(record, 'core', signal.SIGTERM))
            kill.assert_called_once_with(12345, signal.SIGTERM)

    def test_real_watcher_arguments_reparent_and_pause_without_transferring_owner(self):
        args = [sys.executable, str(Path(m.__file__).resolve()), 'watch']
        value = self.snapshot(argv=args, executable=os.path.realpath(sys.executable))
        with patch.object(m, 'process', return_value=value):
            record = {'watcher': m.identity(12345)}
            self.assertTrue(m.owned(record, 'watcher'))
        with patch.object(m, 'process', return_value=value | {'ppid': 2, 'stopped': True}), patch.object(m.os, 'kill') as kill:
            self.assertTrue(m.signal_owned(record, 'watcher', signal.SIGTERM))
            kill.assert_called_once_with(12345, signal.SIGTERM)

    def test_status_separates_paused_identity_from_actual_routing_and_pending_recovery(self):
        with tempfile.TemporaryDirectory() as root:
            manager = m.Manager(Path(root) / 'state', FakeRouting())
            value = self.snapshot()
            with patch.object(m, 'process', return_value=value):
                record = {'core': m.identity(12345), 'transparent': True}
            m.write_json(manager.record_path, record)
            with patch.object(m, 'process', return_value=value | {'stopped': True}):
                with patch.object(manager.routing, 'execute', return_value={'active': True, 'pending': False}):
                    status = manager.status()
                    self.assertTrue(status['process_alive'])
                    self.assertTrue(status['paused'])
                    self.assertFalse(status['running'])
                    self.assertTrue(status['routing_active'])
                    self.assertFalse(status['routing_fallback'])
                with patch.object(manager.routing, 'execute', return_value={'active': False, 'pending': True}):
                    self.assertFalse(manager.status()['routing_fallback'])
                with patch.object(manager.routing, 'execute', return_value={'active': False, 'pending': False}):
                    self.assertTrue(manager.status()['routing_fallback'])
            with patch.object(m, 'process', return_value=value), patch.object(manager.routing, 'execute', return_value={'active': False, 'pending': False}):
                status = manager.status()
                self.assertTrue(status['running'])
                self.assertTrue(status['restart_required'])
                self.assertFalse(status['transparent'])

    def test_routing_status_diagnostic_is_private_single_line_and_bounded(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            manager = m.Manager(root / 'state', FakeRouting(), log=root / 'service.log')
            detail = 'Native routing operation failed:\n\x00\x1b[31m' + '\N{SNOWMAN}' * 600
            manager.remember_routing_error(m.RoutingError(detail))
            self.assertEqual(manager.routing_error_path.stat().st_mode & 0o777, 0o600)
            status = manager.status()
            self.assertTrue(status['recovery_pending'])
            self.assertNotIn('\n', status['routing_error'])
            self.assertNotIn('\x00', status['routing_error'])
            self.assertNotIn('\x1b', status['routing_error'])
            self.assertLessEqual(len(status['routing_error'].encode()), m.ROUTING_DIAGNOSTIC_LIMIT)
            self.assertIn('Native routing operation failed', status['routing_error'])

            manager.routing_error_path.chmod(0o644)
            self.assertEqual(manager.routing_error(), 'The private routing diagnostic is invalid.')
            manager.routing_error_path.unlink()
            foreign = root / 'foreign'
            foreign.write_text('{"error":"foreign"}')
            manager.routing_error_path.symlink_to(foreign)
            self.assertEqual(manager.routing_error(), 'The private routing diagnostic could not be read.')

    def test_guardian_persists_diagnostic_to_status_and_clears_it_after_recovery(self):
        class GuardianRouting(FakeRouting):
            def __init__(self):
                super().__init__()
                self.failed = True

            def execute(self, action):
                self.calls.append(action)
                if action == 'refresh' and self.failed:
                    raise m.RoutingError('native route add failed:\n[Errno 17] File exists')
                return {'active': action in ('refresh', 'status'), 'pending': False, 'busy': False}

        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            routing = GuardianRouting()
            manager = m.Manager(root / 'state', routing, log=root / 'service.log')
            record = {'schema': 1, 'watcher': {'pid': os.getpid()}}
            m.write_json(manager.record_path, record)
            output = io.StringIO()
            with patch.object(m.sys, 'stderr', output), patch.object(m.time, 'sleep', side_effect=StopIteration):
                with self.assertRaises(StopIteration):
                    manager.watch()
            self.assertIn('[Errno 17] File exists', output.getvalue())
            self.assertIn('[Errno 17] File exists', manager.status()['routing_error'])

            routing.failed = False
            with patch.object(m.time, 'sleep', side_effect=StopIteration):
                with self.assertRaises(StopIteration):
                    manager.watch()
            self.assertFalse(manager.routing_error_path.exists())
            self.assertEqual(manager.status()['routing_error'], '')

    def test_invalid_pid_never_reaches_kernel_and_lookup_errors_are_not_disappearance(self):
        with patch.object(m, 'process') as process:
            for pid in (0, -1, 1, True, '12345', 2147483648):
                self.assertIsNone(m.identity(pid))
            process.assert_not_called()
        with patch.object(m, 'process', side_effect=RuntimeError('Unknown kernel layout')):
            with self.assertRaises(m.IntegrationError):
                m.identity(12345)


class RenderTests(unittest.TestCase):
    def test_proxy_only_retains_every_non_tun_field_and_user_document(self):
        original = config()
        before = copy.deepcopy(original)
        rendered = m.render(original, {})
        self.assertEqual(original, before)
        self.assertEqual(rendered['inbounds'], [original['inbounds'][0]])
        self.assertEqual({k: v for k, v in rendered.items() if k != 'inbounds'},
                         {k: v for k, v in original.items() if k != 'inbounds'})

    def test_explicit_capture_disables_all_fork_global_route_ranges_without_rewriting(self):
        original = config()
        rendered = m.render(original, {'transparent': True, 'transparent_consent': True})
        tun = rendered['inbounds'][1]
        self.assertFalse(tun['auto_route'])
        self.assertFalse(tun['strict_route'])
        self.assertNotIn('route_address', tun)
        self.assertNotIn('route_address_set', tun)
        self.assertNotIn('inet6_route_address', tun)
        self.assertNotIn('auto_redirect', tun)
        self.assertEqual(tun['interface_name'], m.TUN)
        self.assertEqual(tun['future_tun_option'], 'retain')
        self.assertEqual(original['inbounds'][1]['route_address'], ['64.0.0.0/2'])

    def test_legacy_global_auto_route_does_not_grant_consent(self):
        original = config()
        self.assertFalse(m.policy({})['transparent'])
        self.assertFalse(any(item['type'] == 'tun' for item in m.render(original, {})['inbounds']))
        with self.assertRaises(m.IntegrationError):
            m.render(original, {'transparent': True})

    def test_invalid_capture_and_fake_dns_are_rejected_before_core_launch(self):
        for mutation in ('no-tun', 'two-tuns', 'system-stack', 'fake-ip', 'external-fd', 'public-prefix'):
            with self.subTest(mutation=mutation):
                data = config()
                if mutation == 'no-tun': data['inbounds'].pop()
                if mutation == 'two-tuns': data['inbounds'].append(copy.deepcopy(data['inbounds'][1]))
                if mutation == 'system-stack': data['inbounds'][1]['stack'] = 'system'
                if mutation == 'fake-ip': data['dns']['servers'].append({'type': 'fakeip'})
                if mutation == 'external-fd': data['inbounds'][1]['file_descriptor'] = 3
                if mutation == 'public-prefix': data['inbounds'][1]['address'] = ['8.8.8.8/24']
                with self.assertRaises(m.IntegrationError):
                    m.render(data, {'transparent': True, 'transparent_consent': True})

    def test_ipv6_capture_requires_a_tun_address_and_preserves_legacy_addressing(self):
        data = config()
        given = {'transparent': True, 'transparent_consent': True, 'ipv6': True}
        with self.assertRaises(m.IntegrationError): m.render(data, given)
        tun = data['inbounds'][1]
        tun['inet4_address'] = tun.pop('address')
        tun['inet6_address'] = ['fd00:19::1/126']
        rendered = m.render(data, given)
        self.assertEqual(rendered['inbounds'][1]['inet6_address'], ['fd00:19::1/126'])

    def test_policy_retains_future_fields_and_normalizes_devices(self):
        result = m.policy({'device_mode': 'blacklist', 'device_list': ['192.168.8.7', '192.168.9.5/24'],
                           'future_policy': {'keep': 'unchanged'}})
        self.assertEqual(result['device_list'], ['192.168.8.7/32', '192.168.9.0/24'])
        self.assertEqual(result['future_policy'], {'keep': 'unchanged'})
        for given in ({'transparent': 1}, {'device_mode': 'invalid'}, {'device_list': ['hostname']},
                      {'device_list': ['10.0.0.1'] * 129}):
            with self.assertRaises(m.IntegrationError): m.policy(given)


class FakeRouting:
    def __init__(self):
        self.calls = []
        self.fail_cleanup = False
        self.fail_enable = False
    def execute(self, action):
        self.calls.append(action)
        if action == 'disable' and self.fail_cleanup: raise m.RoutingError('retry')
        if action == 'enable' and self.fail_enable: raise m.RoutingError('startup')
        return {'active': action in ('enable', 'status'), 'pending': False}
    def routes(self, fib):
        assert fib == 0
        return {}


class OwnedTunTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.manager = m.Manager(self.root / 'state', FakeRouting(), self.root / 'core.pid',
                                 log=self.root / 'service.log')
        self.receipt = {'name': m.TUN, 'index': 12, 'driver': 'tun0', 'metric': 0, 'mtu': 65535,
                        'description': 'Singbox owner ' + 'a' * 32}
        self.current = self.receipt | {'opened_by': None, 'address': None, 'flags': '8002'}
        self.calls = []
        self.fail_description = False
        mocked = patch.object(m, 'command', side_effect=self.command)
        mocked.start(); self.addCleanup(mocked.stop)
        mocked = patch.object(m.socket, 'if_nametoindex', side_effect=lambda name: self.current['index'])
        mocked.start(); self.addCleanup(mocked.stop)

    def command(self, argv, check=True):
        self.calls.append(argv)
        if argv == ['/sbin/ifconfig', '-v', m.TUN]:
            if self.current is None:
                return subprocess.CompletedProcess(argv, 1, b'', b'No such interface')
            item = self.current
            body = '%s: flags=%s<BROADCAST,MULTICAST> metric %d mtu %d\n' % (m.TUN, item['flags'], item['metric'], item['mtu'])
            body += '\tdescription: %s\n\tdrivername: %s\n' % (item['description'], item['driver'])
            if item['opened_by'] is not None: body += '\tOpened by PID %d\n' % item['opened_by']
            if item['address']: body += '\tinet %s netmask 0xfffffffc\n' % item['address']
            return subprocess.CompletedProcess(argv, 0, body.encode(), b'')
        if argv == ['/sbin/ifconfig', m.TUN, 'destroy']:
            self.current = None
        elif argv[:3] == ['/sbin/ifconfig', m.TUN, 'description']:
            if self.fail_description:
                raise m.IntegrationError('Injected description failure')
            self.current['description'] = argv[3]
        else:
            raise AssertionError('Unexpected TUN operation: ' + repr(argv))
        return subprocess.CompletedProcess(argv, 0, b'', b'')

    def fail_destroy(self, replacement=None):
        original = self.command
        def command(argv, check=True):
            if argv == ['/sbin/ifconfig', m.TUN, 'destroy']:
                self.calls.append(argv)
                if replacement is not None:
                    self.current = replacement
                return subprocess.CompletedProcess(argv, 1, b'', b'busy')
            return original(argv, check)
        return command

    def test_real_parser_cleans_only_closed_owned_tun_and_is_idempotent(self):
        self.manager.cleanup_tun({'tun': self.receipt})
        self.assertIsNone(self.current)
        self.assertIn(['/sbin/ifconfig', m.TUN, 'destroy'], self.calls)
        self.manager.cleanup_tun({'tun': self.receipt})
        self.assertEqual(sum('destroy' in call for call in self.calls), 1)

    def test_failed_destroy_retries_only_while_the_exact_owned_tun_remains(self):
        with patch.object(m, 'command', side_effect=self.fail_destroy()):
            with self.assertRaisesRegex(m.IntegrationError, 'destruction failed'):
                self.manager.cleanup_tun({'tun': self.receipt})
        foreign = self.current | {'index': 99, 'driver': 'tun9', 'description': 'Administrator'}
        with patch.object(m, 'command', side_effect=self.fail_destroy(foreign)):
            self.manager.cleanup_tun({'tun': self.receipt})
        self.assertEqual(self.current, foreign)

    def test_foreign_index_driver_description_config_or_open_tun_are_preserved(self):
        for mutation in ({'index': 13}, {'driver': 'tun1'}, {'description': 'Administrator'},
                         {'metric': 1}, {'mtu': 1400}, {'opened_by': 12345},
                         {'flags': '1008043'}, {'address': '192.0.2.2'}):
            with self.subTest(mutation=mutation):
                self.current = self.receipt | {'opened_by': None, 'address': None, 'flags': '8002'} | mutation
                self.calls.clear()
                with self.assertRaises(m.IntegrationError):
                    self.manager.cleanup_tun({'tun': self.receipt})
                self.assertFalse(any('destroy' in call for call in self.calls))

    def test_claim_verifies_actual_opener_and_journals_before_marking(self):
        core = {'pid': 12345, 'birth': '1770000000:12345', 'uid': os.geteuid(),
                'executable': os.path.realpath(m.CORE), 'arguments': [m.CORE, 'run', '-c', str(m.STATE / 'runtime.json')]}
        self.current.update(description='', opened_by=12345, flags='1008043', address='198.18.0.1')
        record = {'core': core}
        with patch.object(m, 'identity', return_value=core):
            self.manager.claim_tun(record)
        journal = json.loads(self.manager.record_path.read_text())
        self.assertEqual(journal['tun'], record['tun'])
        self.assertEqual(self.current['description'], record['tun']['description'])
        self.current.update(description='', opened_by=12345)
        self.calls.clear()
        with patch.object(m, 'identity', return_value=core), patch.object(m, 'write_json', side_effect=OSError('Journal failed')):
            with self.assertRaises(OSError): self.manager.claim_tun({'core': core})
        self.assertFalse(any('description' in call for call in self.calls))
        self.current['opened_by'] = 12346
        with patch.object(m, 'identity', return_value=core):
            with self.assertRaises(m.IntegrationError): self.manager.claim_tun({'core': core})

    def test_failed_description_mutation_keeps_a_recoverable_preclaim_receipt(self):
        core = {'pid': 12345, 'birth': '1770000000:12345', 'uid': os.geteuid(),
                'executable': os.path.realpath(m.CORE),
                'arguments': [m.CORE, 'run', '-c', str(m.STATE / 'runtime.json')]}
        self.current.update(description='', opened_by=core['pid'], flags='1008043', address='198.18.0.1')
        self.fail_description = True
        with patch.object(m, 'identity', return_value=core):
            with self.assertRaisesRegex(m.IntegrationError, 'Injected description failure'):
                self.manager.claim_tun({'core': core})
        journal = json.loads(self.manager.record_path.read_text())
        self.assertEqual('claiming', journal['tun']['phase'])
        self.assertEqual(core['pid'], journal['tun']['preclaim']['opened_by'])
        self.assertEqual('', journal['tun']['preclaim']['description'])

        self.fail_description = False
        self.current.update(opened_by=None, flags='8002', address=None)
        with patch.object(m, 'identity', return_value=None):
            self.manager.stop()
        self.assertIsNone(self.current)
        self.assertFalse(self.manager.record_path.exists())

    def test_dead_core_stop_cleans_tun_while_retaining_a_reused_foreign_pidfile(self):
        core = {'pid': 12345, 'birth': '1770000000:12345', 'uid': os.geteuid(),
                'executable': os.path.realpath(m.CORE), 'arguments': [m.CORE, 'run', '-c', str(m.STATE / 'runtime.json')]}
        record = {'core': core, 'tun': self.receipt}
        m.write_json(self.manager.record_path, record)
        self.manager.pidfile.write_text('12345\n')
        foreign = core | {'birth': '1770000000:12346', 'arguments': ['/usr/sbin/sshd']}
        with patch.object(m, 'identity', return_value=foreign), patch.object(m.os, 'kill') as kill:
            self.manager.stop()
            kill.assert_not_called()
        self.assertIsNone(self.current)
        self.assertEqual(self.manager.pidfile.read_text(), '12345\n')

    def test_busy_cleanup_lock_is_bounded_preserves_tun_and_can_retry(self):
        self.manager.state.mkdir(mode=0o700)
        fd = os.open(self.manager.state / 'tun-cleanup.lock', os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            with patch.object(m.time, 'monotonic', side_effect=[0, 3]):
                with self.assertRaises(m.IntegrationError):
                    self.manager.cleanup_tun({'tun': self.receipt})
            self.assertFalse(any('destroy' in call for call in self.calls))
        finally:
            os.close(fd)
        self.manager.cleanup_tun({'tun': self.receipt})
        self.assertIsNone(self.current)

    def test_foreign_tun_cleanup_retains_receipt_and_recovery_watcher(self):
        watcher = {'pid': 12346, 'birth': '1770000000:12345', 'uid': os.geteuid(),
                   'executable': os.path.realpath(sys.executable),
                   'arguments': [sys.executable, str(Path(m.__file__).resolve()), 'watch']}
        m.write_json(self.manager.record_path, {'watcher': watcher, 'tun': self.receipt})
        self.manager.remember_routing_error(m.RoutingError('stale route failure'))
        self.current['description'] = 'Administrator changed this interface'
        with patch.object(m, 'identity', side_effect=lambda pid: watcher if pid == watcher['pid'] else None), patch.object(m.os, 'kill') as kill:
            with self.assertRaises(m.IntegrationError): self.manager.stop()
            kill.assert_not_called()
        self.assertTrue(self.manager.record_path.exists())
        self.assertEqual(json.loads(self.manager.record_path.read_text())['tun'], self.receipt)
        self.assertFalse(self.manager.routing_error_path.exists())


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.state = self.root / 'state'
        self.configuration = self.root / 'config.json'
        self.policy = self.root / 'integration.json'
        self.pid = self.root / 'core.pid'
        self.routing = FakeRouting()
        self.manager = m.Manager(self.state, self.routing, self.pid, self.configuration,
                                 log=self.root / 'log')
        self.configuration.write_text(json.dumps(config()))
        self.configuration.chmod(0o600)
        self.processes = {}
        self.paused_processes = set()
        self.signals = []
        self.clock = 0
        self.tun_ready = True
        self.core_fail = False
        self.setup_result = b'changed\n'
        self.command_calls = []
        self.tun_description = ''
        for name, value in [('STATE', self.state), ('POLICY', self.policy), ('PIDFILE', self.pid)]:
            p = patch.object(m, name, value); p.start(); self.addCleanup(p.stop)
        p = patch.object(m, 'identity', side_effect=lambda pid: copy.deepcopy(self.processes.get(pid))); p.start(); self.addCleanup(p.stop)
        def kill(pid, sig):
            self.signals.append((pid, sig))
            if sig == signal.SIGCONT:
                self.paused_processes.discard(pid)
            elif pid not in self.paused_processes:
                self.processes.pop(pid, None)
        p = patch.object(m.os, 'kill', side_effect=kill); p.start(); self.addCleanup(p.stop)
        p = patch.object(m, 'command', side_effect=self.command); p.start(); self.addCleanup(p.stop)
        p = patch.object(self.manager, 'tun_snapshot', side_effect=self.tun_snapshot); p.start(); self.addCleanup(p.stop)
        p = patch.object(m.subprocess, 'Popen', side_effect=self.popen); p.start(); self.addCleanup(p.stop)
        def release(descriptor, content):
            current = self.processes.get(100)
            if content == b'1' and current is not None:
                if self.core_fail:
                    self.processes.pop(100, None)
                else:
                    self.processes[100] = current | {
                        'arguments': m.core_arguments(),
                        'executable': os.path.realpath(m.CORE),
                    }
            return len(content)
        p = patch.object(m.os, 'write', side_effect=release); p.start(); self.addCleanup(p.stop)
        p = patch.object(m.time, 'sleep', return_value=None); p.start(); self.addCleanup(p.stop)
        def clock(): self.clock += .25; return self.clock
        p = patch.object(m.time, 'monotonic', side_effect=clock); p.start(); self.addCleanup(p.stop)
        real_open = open
        p = patch('builtins.open', side_effect=lambda path, *a, **kw: real_open(self.root / 'log', *a, **kw) if path == '/var/log/sing-box.log' else real_open(path, *a, **kw)); p.start(); self.addCleanup(p.stop)

    def command(self, args, check=True):
        self.command_calls.append(args)
        if args[:3] == ['/sbin/ifconfig', m.TUN, 'description']:
            self.tun_description = args[3]
        if args[:2] == ['/sbin/ifconfig', m.TUN]:
            # The pre-start ownership check must see the interface as absent.
            code = 0 if self.processes and self.tun_ready else 1
        elif args[:2] == ['/usr/sbin/service', 'mihomo']: code = 1
        else: code = 0
        output = self.setup_result if args[-1:] == ['enable'] and 'config_setup.php' in args[-2] else b''
        return subprocess.CompletedProcess(args, code, output, b'')

    def tun_snapshot(self):
        if 100 not in self.processes or not self.tun_ready:
            return None
        return {'name': m.TUN, 'index': 12, 'driver': 'tun0', 'metric': 0, 'mtu': 65535,
                'description': self.tun_description, 'opened_by': 100, 'closed': False}

    def popen(self, args, **kwargs):
        outer = self
        pid = 100 if args[2:3] == ['launch'] else 101
        arguments = args
        self.processes[pid] = {'pid': pid, 'birth': '1770000000:12345', 'arguments': arguments,
                               'uid': os.geteuid(), 'executable': os.path.realpath(arguments[0])}
        class Process:
            def __init__(self): self.pid = pid
            def poll(self): return None if pid in outer.processes else 1
            def terminate(self): outer.processes.pop(pid, None)
            def kill(self): outer.processes.pop(pid, None)
            def wait(self, timeout): return 0
        return Process()

    def test_core_exec_is_released_only_after_durable_launcher_receipt(self):
        writes = []
        actual_write = m.write_json
        def record(path, value):
            actual_write(path, value)
            if Path(path) == self.manager.record_path:
                writes.append(copy.deepcopy(value))
        with patch.object(m, 'write_json', side_effect=record):
            self.manager.start(self.configuration)
        self.assertGreaterEqual(len(writes), 2)
        self.assertIsNotNone(writes[0]['launcher'])
        self.assertIsNone(writes[0]['core'])
        self.assertIsNone(writes[1]['launcher'])
        self.assertEqual(writes[1]['core']['arguments'], m.core_arguments())

    def test_failed_launcher_journal_aborts_the_known_child_before_release(self):
        actual_write = m.write_json
        def fail_launcher(path, value):
            if Path(path) == self.manager.record_path and value.get('launcher') is not None:
                raise OSError('Injected launcher journal failure')
            return actual_write(path, value)
        with patch.object(m, 'write_json', side_effect=fail_launcher):
            with self.assertRaisesRegex(OSError, 'launcher journal'):
                self.manager.start(self.configuration)
        self.assertFalse(self.processes)
        self.assertFalse(self.pid.exists())

    def test_durable_launcher_recovery_promotes_expected_exec_and_rejects_foreign_exec(self):
        launch = m.launcher_arguments(descriptor=9)
        launcher = {'pid': 100, 'birth': '1770000000:12345', 'uid': os.geteuid(),
                    'executable': os.path.realpath(launch[0]), 'arguments': launch}
        m.write_json(self.manager.record_path, {'schema': 1, 'launcher': launcher})
        self.processes[100] = launcher | {
            'executable': os.path.realpath(m.CORE), 'arguments': m.core_arguments()}
        self.manager.stop()
        self.assertIn((100, signal.SIGTERM), self.signals)
        self.assertFalse(self.manager.record_path.exists())

        m.write_json(self.manager.record_path, {'schema': 1, 'launcher': launcher})
        self.processes[100] = launcher | {
            'executable': '/usr/sbin/sshd', 'arguments': ['/usr/sbin/sshd']}
        with self.assertRaises(m.IntegrationError):
            self.manager.stop()
        self.assertIn(100, self.processes)
        self.assertEqual(self.signals.count((100, signal.SIGTERM)), 1)

    def test_launcher_eof_exits_without_exec_and_release_enters_fib_zero(self):
        with patch.object(m.os, 'read', return_value=b''), patch.object(m.os, 'close') as close, \
                patch.object(m.os, 'execv') as execute:
            self.assertIsNone(m.launch_core('9'))
            close.assert_called_once_with(9)
            execute.assert_not_called()
        with patch.object(m.os, 'read', return_value=b'1'), patch.object(m.os, 'close'), \
                patch.object(m.os, 'execv') as execute:
            m.launch_core('9')
            execute.assert_called_once_with(m.SETFIB, m.setfib_arguments())
        for descriptor in ('2', '-1', 'not-a-fd', '2147483648'):
            with self.subTest(descriptor=descriptor), self.assertRaises(m.IntegrationError):
                m.launch_core(descriptor)

    def capture_settings(self):
        m.write_json(self.policy, {'transparent': True, 'transparent_consent': True})

    def test_proxy_only_starts_without_tun_and_preserves_authoritative_configuration(self):
        before = self.configuration.read_bytes()
        result = self.manager.start(self.configuration)
        self.assertTrue(result['running'])
        self.assertFalse(result['transparent'])
        self.assertEqual(before, self.configuration.read_bytes())
        self.assertFalse(any(args[0] == '/sbin/ifconfig' for args in self.command_calls))
        self.assertNotIn('enable', self.routing.calls)
        self.manager.stop()
        self.assertFalse(self.processes)
        self.assertFalse(self.pid.exists())

    def test_capture_starts_with_native_egress_and_owned_watcher_before_activation(self):
        self.capture_settings()
        self.manager.start(self.configuration)
        self.assertEqual(self.processes[100]['arguments'], [m.CORE, 'run', '-c', str(self.state / 'runtime.json')])
        self.assertIn(101, self.processes)
        self.assertIn('enable', self.routing.calls)
        self.assertEqual(self.state.stat().st_mode & 0o777, 0o700)
        self.manager.stop()
        self.assertCountEqual(self.signals, [(100, signal.SIGTERM), (101, signal.SIGTERM)])

    def test_capture_reloads_filter_only_after_native_xml_changes(self):
        self.capture_settings()
        m.write_json(self.state / 'routing-context.json', {})
        self.setup_result = b'unchanged\n'
        self.manager.start(self.configuration)
        self.assertNotIn(['/usr/local/sbin/configctl', 'filter', 'reload'], self.command_calls)
        self.manager.stop()

    def test_capture_reloads_filter_when_runtime_context_is_missing(self):
        self.capture_settings()
        self.setup_result = b'unchanged\n'
        self.manager.start(self.configuration)
        self.assertIn(['/usr/local/sbin/configctl', 'filter', 'reload'], self.command_calls)
        self.assertFalse(self.manager.filter_reload_path.exists())
        self.manager.stop()

    def test_invalid_native_xml_change_result_aborts_before_core_launch(self):
        self.capture_settings()
        m.write_json(self.manager.filter_reload_path, {'schema': 1, 'pending': True})
        self.setup_result = b''
        with self.assertRaisesRegex(m.IntegrationError, 'invalid result'):
            self.manager.start(self.configuration)
        self.assertFalse(self.processes)
        self.assertFalse(self.pid.exists())
        self.assertTrue(self.manager.filter_reload_path.exists())

        self.setup_result = b'unchanged\n'
        self.manager.start(self.configuration)
        self.assertIn(['/usr/local/sbin/configctl', 'filter', 'reload'], self.command_calls)
        self.assertFalse(self.manager.filter_reload_path.exists())

    def test_tun_timeout_and_capture_failure_terminate_only_spawned_owned_core(self):
        for failure in ('tun-timeout', 'routing'):
            with self.subTest(failure=failure):
                self.capture_settings()
                self.tun_ready = failure != 'tun-timeout'
                self.routing.fail_enable = failure == 'routing'
                with self.assertRaises((m.IntegrationError, m.RoutingError)):
                    self.manager.start(self.configuration)
                self.assertFalse(self.processes)
                self.assertFalse(self.pid.exists())
                self.assertEqual(self.routing.calls[-1], 'disable')
                if failure == 'routing':
                    self.assertIn('startup', self.manager.routing_error())
                    self.assertIn('startup', (self.root / 'log').read_text())
                self.tun_ready = True

    def test_stale_reused_pid_and_wrong_argv_are_never_signaled(self):
        for birth, arguments in [('1770000000:12346', [m.CORE, 'run', '-c', str(self.state / 'runtime.json')]),
                                 ('1770000000:12345', ['/usr/sbin/sshd'])]:
            with self.subTest(arguments=arguments):
                wanted = {'pid': 100, 'birth': '1770000000:12345', 'uid': os.geteuid(),
                          'executable': os.path.realpath(m.CORE), 'arguments': [m.CORE, 'run', '-c', str(self.state / 'runtime.json')]}
                m.write_json(self.manager.record_path, {'core': wanted})
                self.processes[100] = dict(wanted, birth=birth, arguments=arguments)
                self.pid.write_text('100\n')
                self.manager.stop()
                self.assertFalse(self.signals)
                self.assertIn(100, self.processes)
                self.assertEqual(self.pid.read_text(), '100\n')

    def test_legacy_stop_validates_saved_config_argument_and_uses_graceful_close(self):
        self.pid.write_text('100\n')
        self.processes[100] = {'pid': 100, 'birth': '1770000000:12345', 'uid': os.geteuid(),
                               'executable': os.path.realpath(m.CORE),
                               'arguments': [m.CORE, 'run', '-c', str(self.configuration)]}
        self.manager.stop()
        self.assertEqual(self.signals, [(100, signal.SIGCONT), (100, signal.SIGTERM)])
        self.assertFalse(self.pid.exists())

    def test_legacy_paused_core_is_resumed_before_graceful_upgrade_stop(self):
        self.pid.write_text('100\n')
        self.processes[100] = {'pid': 100, 'birth': '1770000000:12345', 'uid': os.geteuid(),
                               'executable': os.path.realpath(m.CORE),
                               'arguments': [m.CORE, 'run', '-c', str(self.configuration)]}
        self.paused_processes.add(100)
        self.manager.stop()
        self.assertEqual(self.signals, [(100, signal.SIGCONT), (100, signal.SIGTERM)])
        self.assertNotIn(100, self.processes)
        self.assertFalse(self.pid.exists())

    def test_legacy_foreign_uid_or_executable_with_matching_argv_is_preserved(self):
        for change in ({'uid': os.geteuid() + 1}, {'executable': '/tmp/foreign-core'}):
            with self.subTest(change=change):
                self.pid.write_text('100\n')
                self.processes[100] = {'pid': 100, 'birth': '1770000000:12345', 'uid': os.geteuid(),
                                       'executable': os.path.realpath(m.CORE),
                                       'arguments': [m.CORE, 'run', '-c', str(self.configuration)]} | change
                self.manager.stop()
                self.assertFalse(self.signals)
                self.assertEqual(self.pid.read_text(), '100\n')

    def test_pending_cleanup_keeps_watcher_for_retry_and_never_restores_foreign_dns(self):
        self.capture_settings()
        self.manager.start(self.configuration)
        resolver = self.root / 'resolv.conf'
        resolver.write_bytes(b'nameserver 192.168.8.1\n# administrator change\n')
        self.routing.fail_cleanup = True
        with self.assertRaises(m.IntegrationError): self.manager.stop()
        self.assertIn(101, self.processes)
        self.assertNotIn(100, self.processes)
        self.assertTrue(self.manager.record_path.exists())
        self.assertEqual(resolver.read_bytes(), b'nameserver 192.168.8.1\n# administrator change\n')

    def test_pidfile_symlink_is_preserved_and_never_overwrites_its_target(self):
        foreign = self.root / 'foreign-pid'
        foreign.write_text('98765\n')
        self.pid.symlink_to(foreign)
        with self.assertRaises(m.IntegrationError): self.manager.start(self.configuration)
        self.assertTrue(self.pid.is_symlink())
        self.assertEqual(foreign.read_text(), '98765\n')
        self.assertFalse(self.processes)

    def test_dead_pidfile_is_replaced_but_concurrent_regular_file_is_preserved(self):
        self.pid.write_text('999\n')
        self.manager.start(self.configuration)
        self.assertEqual(self.pid.read_text(), '100\n')
        self.manager.stop()
        self.assertFalse(self.pid.exists())

        actual_open = m.os.open
        injected = []
        def concurrent(path, flags, *args):
            if Path(path) == self.pid and flags & os.O_EXCL and not injected:
                injected.append(True)
                self.pid.write_text('999\n')
            return actual_open(path, flags, *args)
        with patch.object(m.os, 'open', side_effect=concurrent):
            with self.assertRaises(FileExistsError):
                self.manager.start(self.configuration)
        self.assertEqual(self.pid.read_text(), '999\n')
        self.assertFalse(self.processes)

    def test_private_policy_and_journal_reject_symlink_and_public_permissions(self):
        m.write_json(self.policy, {})
        self.policy.chmod(0o644)
        with self.assertRaises(m.IntegrationError): m.private_json(self.policy)
        self.policy.unlink()
        self.policy.symlink_to(self.configuration)
        with self.assertRaises(OSError): m.private_json(self.policy)

    def test_service_lock_rejects_public_mode(self):
        self.state.mkdir(mode=0o700, exist_ok=True)
        lock = self.state / 'service.lock'
        lock.write_text('')
        lock.chmod(0o644)
        with self.assertRaisesRegex(m.IntegrationError, 'service lock'):
            self.manager.lock()

    def test_state_directory_and_private_json_reject_public_or_nonregular_objects(self):
        self.state.mkdir(mode=0o700, exist_ok=True)
        self.state.chmod(0o755)
        with self.assertRaisesRegex(m.IntegrationError, 'state directory'):
            self.manager.lock()
        self.state.chmod(0o700)
        fifo = self.state / 'record-fifo'
        os.mkfifo(fifo, 0o600)
        with self.assertRaisesRegex(m.IntegrationError, 'not private'):
            m.private_json(fifo)


if __name__ == '__main__':
    unittest.main()
