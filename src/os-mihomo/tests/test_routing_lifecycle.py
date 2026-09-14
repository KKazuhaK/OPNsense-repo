"""Exercise routing failures through the real manager without native services."""
import json
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import unittest
from unittest import mock

import yaml

from test_mihomo import FakeSystem, SCRIPT, SUBSCRIPTION, m


class RoutingSystem(FakeSystem):
    def __init__(self):
        super().__init__()
        self.routing_active = False
        self.fail_stop_after_dead = 0
        self.fail_spawn_after_alive = 0
        self.fail_destroy = False

    def routing(self, action):
        self.events.append('routing-' + action)
        if action != 'refresh':
            self.routing_active = action == 'enable'
            m.atomic_write(self.state / 'routing-state.json',
                           json.dumps({'active': self.routing_active}).encode())

    def start(self, config, transparent):
        super().start(config, transparent)
        if self.fail_spawn_after_alive:
            self.fail_spawn_after_alive -= 1
            raise OSError('Injected readiness failure after spawning the core.')

    def tun(self):
        super().tun()
        self.routing('enable')

    def stop(self):
        self.routing('disable')
        super().stop()
        if self.fail_stop_after_dead:
            self.fail_stop_after_dead -= 1
            self.events.append('stop-error-after-core-dead')
            raise m.Error('Injected routing cleanup failure after stopping the core.')

    def destroy_tun(self):
        self.routing('disable')
        super().destroy_tun()
        if self.fail_destroy:
            raise m.Error('Injected state cleanup failure after removing capture.')

    def rescue(self, settings):
        self.events.append('rescue-dns')
        self.dns(False, settings)

    def watch(self):
        self.events.append('watch')


class RoutingLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.system = RoutingSystem()
        self.manager = m.Manager(Path(self.temp.name), self.system)
        self.system.state = self.manager.state
        self.manager.initialize()
        self.manager.dispatch('start')

    def activate(self):
        self.manager.apply(SUBSCRIPTION)
        self.manager.dispatch('enable-transparent')
        self.assertTrue(self.system.routing_active)
        self.assertTrue(self.system.forwarded)
        self.system.events.clear()

    def configuration(self):
        return {path: path.read_bytes() for path in
                (self.manager.settings_file, self.manager.config_file,
                 self.manager.source_file, self.manager.merge_file)}

    def test_initial_stop_failure_after_core_exit_restores_previous_service(self):
        self.activate()
        before = self.configuration()
        settings = dict(self.manager.settings(), secret='rejected-replacement-secret')
        self.system.fail_stop_after_dead = 1

        with self.assertRaisesRegex(m.Error, 'previous configuration'):
            self.manager.apply(SUBSCRIPTION, settings)

        self.assertEqual(before, self.configuration())
        self.assertTrue(self.system.alive)
        self.assertTrue(self.system.routing_active)
        self.assertTrue(self.system.forwarded)
        self.assertLess(self.system.events.index('stop-error-after-core-dead'),
                        self.system.events.index('start-transparent'))

    def test_direct_start_replay_write_failure_removes_capture_and_stops_core(self):
        self.activate()
        self.manager.dispatch('suspend')
        self.manager.selections_file.write_text('{"Proxy":"ON"}')
        self.system.events.clear()
        original = m.atomic_write

        def fail_replay(path, *args, **kwargs):
            if path == self.manager.replay_file:
                raise OSError('Injected replay journal write failure.')
            return original(path, *args, **kwargs)

        with mock.patch.object(m, 'atomic_write', side_effect=fail_replay):
            with self.assertRaisesRegex(OSError, 'replay journal'):
                self.manager.dispatch('start')

        self.assertFalse(self.system.alive)
        self.assertFalse(self.system.routing_active)
        self.assertFalse(self.system.forwarded)
        self.assertLess(self.system.events.index('routing-enable'),
                        self.system.events.index('routing-disable'))
        self.assertLess(self.system.events.index('routing-disable'),
                        self.system.events.index('stop'))
        self.assertNotIn('watch', self.system.events)
        self.assertFalse(json.loads(self.manager.status_file.read_bytes())['routing_active'])

    def test_direct_start_readiness_error_after_spawn_stops_the_new_core(self):
        self.activate()
        self.manager.dispatch('suspend')
        self.system.events.clear()
        self.system.fail_spawn_after_alive = 1

        with self.assertRaisesRegex(OSError, 'readiness failure'):
            self.manager.dispatch('start')

        self.assertFalse(self.system.alive)
        self.assertFalse(self.system.routing_active)
        self.assertFalse(self.system.forwarded)
        self.assertIn('stop', self.system.events)
        self.assertNotIn('routing-enable', self.system.events)

    def test_system_stop_removes_capture_before_terminating_core_and_destroying_tun(self):
        system = m.System()
        live = {'core': True, 'capture': True}
        events = []
        pid = self.manager.state / 'isolated-core.pid'
        daemon_pid = self.manager.state / 'isolated-daemon.pid'

        def routing(action):
            self.assertEqual('disable', action)
            live['capture'] = False
            events.append('remove-capture')

        def valid_pid(path, expected):
            return 123 if path == str(pid) and live['core'] else None

        def kill(process, sig):
            self.assertEqual(123, process)
            if sig == 0:
                raise ProcessLookupError()
            self.assertEqual(signal.SIGTERM, sig)
            self.assertFalse(live['capture'])
            live['core'] = False
            events.append('terminate-core')

        def command(args, **kwargs):
            self.assertIn(args, [['/sbin/ifconfig', 'tun_mihomo'],
                                 ['/sbin/ifconfig', 'tun_mihomo', 'destroy']])
            if args[-1] == 'destroy':
                self.assertFalse(live['capture'])
                self.assertFalse(live['core'])
                events.append('destroy-tun')
            return subprocess.CompletedProcess(args, 0, b'', b'')

        with mock.patch.object(m, 'PID', str(pid)), mock.patch.object(m, 'DAEMON_PID', str(daemon_pid)), \
                mock.patch.object(system, 'routing', side_effect=routing), \
                mock.patch.object(system, 'valid_pid', side_effect=valid_pid), \
                mock.patch.object(system, 'run', side_effect=command), \
                mock.patch.object(system, '_host_dns_prepare', return_value=None), \
                mock.patch.object(m.os, 'kill', side_effect=kill), mock.patch.object(m.time, 'sleep'):
            system.stop()

        self.assertLess(events.index('remove-capture'), events.index('terminate-core'))
        self.assertLess(events.index('terminate-core'), events.index('destroy-tun'))

    def test_crash_state_cleanup_failure_does_not_block_direct_dns_recovery(self):
        self.activate()
        self.system.alive = False
        self.system.fail_destroy = True

        status = self.manager.watchdog_tick()

        self.assertFalse(self.system.routing_active)
        self.assertFalse(self.system.forwarded)
        self.assertFalse(status['dns_active'])
        self.assertFalse(status['routing_active'])
        self.assertIn('Routing cleanup failed', status['error'])
        self.assertLess(self.system.events.index('destroy-tun'),
                        self.system.events.index('dns-off'))

    def test_backup_guard_failure_still_recovers_dns_after_routing_cleanup_error(self):
        self.activate()
        self.system.alive = False
        self.system.fail_destroy = True

        with mock.patch.object(self.manager, '_guard_backup',
                               side_effect=m.BackupIntegrityError('Edited backup fixture.')):
            status = self.manager.watchdog_tick()

        self.assertFalse(self.system.forwarded)
        self.assertFalse(status['dns_active'])
        self.assertFalse(status['routing_active'])
        self.assertIn('rescue-dns', self.system.events)
        self.assertIn('Routing cleanup failed', status['error'])
        self.assertIn('Edited backup fixture', status['error'])
        self.assertTrue(self.manager.backup_warning_file.exists())

    def test_disabled_dns_fallback_keeps_dns_policy_while_removing_capture(self):
        self.activate()
        self.manager.write_settings(dict(self.manager.settings(), dns_fallback=False))
        self.system.alive = False
        self.system.fail_destroy = True

        status = self.manager.watchdog_tick()

        self.assertFalse(self.system.routing_active)
        self.assertTrue(self.system.forwarded)
        self.assertTrue(status['dns_active'])
        self.assertFalse(status['routing_active'])
        self.assertNotIn('dns-off', self.system.events)

    def test_runtime_status_requires_boolean_routing_marker_and_live_core(self):
        self.activate()
        marker = self.manager.state / 'routing-state.json'
        cases = [(None, True, False), ('invalid JSON', True, False),
                 ('[]', True, False), ('{}', True, False),
                 ('{"active":1}', True, False), ('{"active":"true"}', True, False),
                 ('{"active":false}', True, False), ('{"active":true}', True, True),
                 ('{"active":true}', False, False)]
        for content, alive, expected in cases:
            with self.subTest(marker=content, core_alive=alive):
                marker.unlink(missing_ok=True)
                if content is not None:
                    marker.write_text(content)
                self.system.alive = alive
                status = self.manager.publish_status()
                self.assertIs(status['routing_active'], expected)
                self.assertTrue(status['transparent'], 'Configured consent must survive a crash.')

    def test_gui_active_badge_uses_runtime_routing_instead_of_saved_consent(self):
        view = SCRIPT.parents[2] / 'mvc/app/views/OPNsense/Mihomo/index.volt'
        text = view.read_text()
        self.assertIn('const routed = state.routing_active === true;', text)
        badge = text[text.index("$('#mihomo-transparent')"):text.index("$('#mihomo-dns')")]
        self.assertIn('routed ?', badge)
        self.assertNotIn('state.transparent', badge)

    def test_direct_start_persists_real_dns_and_clears_stored_fake_ip_override(self):
        self.activate()
        self.manager.dispatch('suspend')
        self.manager.write_settings(dict(self.manager.settings(), dns_mode='normal'))
        overlay = m.parse_yaml(self.manager.merge_file.read_bytes())
        overlay.setdefault('dns', {}).update({'enhanced-mode': 'fake-ip',
                                             'nameserver': ['192.0.2.53']})
        self.manager.merge_file.write_text(yaml.safe_dump(overlay, sort_keys=False))

        self.manager.dispatch('start')

        self.assertEqual('redir-host', self.manager.settings()['dns_mode'])
        stored = m.parse_yaml(self.manager.merge_file.read_bytes())
        self.assertNotIn('enhanced-mode', stored['dns'])
        self.assertEqual(['192.0.2.53'], stored['dns']['nameserver'])
        self.assertEqual('redir-host', m.parse_yaml(self.manager.config_file.read_bytes())['dns']['enhanced-mode'])

    def test_upgrade_persists_real_dns_from_legacy_settings_and_merge(self):
        self.activate()
        self.manager.dispatch('suspend')
        self.manager.write_settings(dict(self.manager.settings(), dns_mode='fake-ip'))
        overlay = m.parse_yaml(self.manager.merge_file.read_bytes())
        overlay.setdefault('dns', {})['enhanced-mode'] = 'fake-ip'
        self.manager.merge_file.write_text(yaml.safe_dump(overlay, sort_keys=False))

        self.manager.initialize(upgrade=True)

        self.assertEqual('redir-host', self.manager.settings()['dns_mode'])
        self.assertNotIn('enhanced-mode', m.parse_yaml(self.manager.merge_file.read_bytes()).get('dns', {}))
        self.assertEqual('redir-host', m.parse_yaml(self.manager.config_file.read_bytes())['dns']['enhanced-mode'])
        self.assertTrue(self.manager.settings()['transparent_consent'])


class TunOwnershipHelperTests(unittest.TestCase):
    def test_unmodified_php_helper_preserves_operator_tun_configuration(self):
        php = shutil.which('php')
        if not php:
            self.skipTest('PHP integration fixtures require the existing PHP runtime.')
        fixture = Path(__file__).with_name('native') / 'test-tun-rule-ownership.php'
        result = subprocess.run([php, str(fixture)], capture_output=True, text=True, timeout=20)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn('TUN ownership checks passed', result.stdout)


if __name__ == '__main__':
    unittest.main()
