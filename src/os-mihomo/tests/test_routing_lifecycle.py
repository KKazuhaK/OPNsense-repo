"""Exercise routing failures through the real manager without native services."""
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

import yaml

from test_mihomo import FakeSystem, GLOBAL_LAN, SCRIPT, SUBSCRIPTION, interfaces, m
import dns_probe


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
        # A fresh install answers only captured devices; these tests exercise
        # the resolver-wide integration every upgraded router keeps.
        self.manager.write_settings(dict(self.manager.settings(), dns_scope='all'))
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

        def routing(action):
            self.assertEqual('disable', action)
            live['capture'] = False
            events.append('remove-capture')

        def terminate():
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

        def destroy_owned(prepare=None):
            prepared = prepare() if prepare is not None else None
            command(['/sbin/ifconfig', 'tun_mihomo', 'destroy'])
            return True, prepared

        owned = mock.Mock()
        owned.stop.side_effect = terminate
        with mock.patch.object(system, 'routing', side_effect=routing), \
                mock.patch.object(system, '_core_group', return_value=owned), \
                mock.patch.object(system, 'running', side_effect=lambda: live['core']), \
                mock.patch.object(system, 'run', side_effect=command), \
                mock.patch.object(system, 'destroy_owned_tun', side_effect=destroy_owned), \
                mock.patch.object(system, '_host_dns_prepare', return_value=None), \
                mock.patch.object(m.time, 'sleep'):
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
        self.assertIn('Injected state cleanup failure', status['error'])
        self.assertLess(self.system.events.index('destroy-tun'),
                        self.system.events.index('dns-off'))

    def test_native_routing_stderr_is_single_line_bounded_and_reaches_status(self):
        system = m.System()
        native = ('Mihomo routing could not be applied safely.\n\x00\x1b[31mNative routing operation failed: '
                  + '\N{SNOWMAN}' * 600).encode()
        failure = subprocess.CompletedProcess([], 1, b'', native)
        with mock.patch.object(system, 'run', return_value=failure) as command:
            with self.assertRaises(m.Error) as caught:
                system.routing('enable')
        command.assert_called_once_with(
            ['/usr/local/bin/python3', m.ROUTING_HELPER, 'enable'], timeout=90, check=False)
        detail = str(caught.exception)
        self.assertNotIn('\n', detail)
        self.assertNotIn('\x00', detail)
        self.assertNotIn('\x1b', detail)
        self.assertLessEqual(len(detail.encode()), m.ROUTING_DIAGNOSTIC_LIMIT)
        self.assertIn('Native routing operation failed', detail)

        status = self.manager.publish_status(error=caught.exception)
        self.assertEqual(status['error'], detail)

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

    def test_a_captured_scope_never_forwards_unbound_and_a_crash_withdraws_it_whatever_the_fallback(self):
        # Captured devices must never lose DNS to a failed core: the redirect
        # lives in the routing anchor, which the crash rescue always clears.
        config = self.manager.path('/conf/config.xml')
        config.parent.mkdir(parents=True, exist_ok=True)
        config.write_text('<opnsense><OPNsense><unboundplus/></OPNsense></opnsense>')
        self.manager.write_settings(dict(self.manager.settings(), dns_scope='captured', dns_fallback=False))
        self.manager.apply(SUBSCRIPTION)
        self.manager.dispatch('enable-transparent')
        self.assertTrue(self.system.routing_active)
        self.assertFalse(self.system.forwarded)
        self.system.alive = False

        status = self.manager.watchdog_tick()

        self.assertFalse(self.system.routing_active)
        self.assertIn('routing-disable', self.system.events)
        self.assertNotIn('dns-on', self.system.events)
        self.assertFalse(status['dns_active'])
        self.assertEqual('off', status['dns_scope'])

    def validate_dnssec(self):
        config = self.manager.path('/conf/config.xml')
        config.parent.mkdir(parents=True, exist_ok=True)
        config.write_text('<opnsense><OPNsense><unboundplus><general><dnssec>1</dnssec></general>'
                          '</unboundplus></OPNsense></opnsense>')
        self.system.dnssec = True

    def test_crash_with_a_validating_resolver_removes_capture_without_a_dns_restore(self):
        # A validating resolver was never handed to Mihomo, so the crash rescue
        # removes capture and has no DNS change to undo.
        self.validate_dnssec()
        self.manager.apply(SUBSCRIPTION)
        self.manager.dispatch('enable-transparent')
        self.assertTrue(self.system.routing_active)
        self.assertFalse(self.system.forwarded)
        self.assertEqual(m.DNSSEC_NOTE, json.loads(self.manager.status_file.read_bytes())['dns_note'])
        self.system.events.clear()
        self.system.alive = False

        status = self.manager.watchdog_tick()

        self.assertFalse(self.system.routing_active)
        self.assertFalse(status['routing_active'])
        self.assertFalse(status['dns_active'])
        self.assertEqual('', status['dns_note'])
        self.assertIn('destroy-tun', self.system.events)
        self.assertNotIn('dns-off', self.system.events)

    def test_a_runtime_dnssec_hand_back_keeps_transparent_routing_armed(self):
        self.activate()
        self.validate_dnssec()

        status = self.manager.watchdog_tick()

        self.assertFalse(self.system.forwarded)
        self.assertFalse(status['dns_active'])
        self.assertTrue(self.system.alive)
        self.assertTrue(self.system.routing_active)
        self.assertTrue(status['routing_active'])
        self.assertLess(self.system.events.index('dns-off'), self.system.events.index('assign-tun'))
        self.assertLess(self.system.events.index('assign-tun'), self.system.events.index('routing-enable'))

    def test_a_backup_guard_failure_still_hands_a_validating_resolver_back(self):
        # Restoring an OPNsense backup can both switch DNSSEC on and leave the
        # Mihomo backup pending, which fails the guard on every tick.
        self.activate()
        self.validate_dnssec()

        with mock.patch.object(self.manager, '_guard_backup',
                               side_effect=m.Error('A restored Mihomo configuration is pending.')):
            status = self.manager.watchdog_tick()
            again = self.manager.watchdog_tick()

        self.assertFalse(self.system.forwarded)
        self.assertFalse(status['dns_active'])
        self.assertFalse(again['dns_active'])
        self.assertEqual(m.DNSSEC_NOTE, status['dns_note'])
        self.assertIn('A restored Mihomo configuration is pending.', status['error'])
        # Pending XML is not paired with the journals: the rescue removes only
        # the forward zone, once, and leaves the TUN assignment and routing be.
        self.assertEqual(['rescue-dns', 'dns-off'], self.system.events)
        self.assertTrue(self.system.alive)
        self.assertTrue(status['routing_active'])

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


class Clock:
    def __init__(self, now=10000.0):
        self.now = now

    def __call__(self):
        return self.now


class ProbingSystem(RoutingSystem):
    """A core whose DNS answers as scripted, behind routing that arms the redirect as the adapter does.

    The routing side arms only for a captured scope with a fresh, healthy
    verdict about the running core, which is exactly the adapter's condition
    beyond the listener and hook checks exercised in test_routing.py.
    """

    def __init__(self, clock):
        super().__init__()
        self.clock = clock
        self.lives = 0
        self.identity = None
        self.liveness = dns_probe.NOERROR
        self.mihomo = dns_probe.NXDOMAIN
        self.router = dns_probe.NOERROR
        self.activity = (True, True)
        self.queries = []
        self.query_seconds = 0.0

    def start(self, config, transparent):
        super().start(config, transparent)
        self.lives += 1
        self.identity = {'pid': 4000 + self.lives, 'birth': '1700000000:%d' % self.lives}

    def core_identity(self):
        return self.identity if self.alive else None

    def dns_query(self, server, name, timeout):
        self.events.append('dns-probe')
        self.queries.append((server, name, timeout))
        result = (self.router if server == dns_probe.ROUTER
                  else self.liveness if name == dns_probe.LIVENESS_NAME else self.mihomo)
        if isinstance(result, Exception):
            # A silent listener costs the full timeout.
            self.clock.now += timeout
            raise result
        return result

    def dns_redirect_activity(self):
        self.events.append('dns-activity')
        return self.activity

    def routing(self, action):
        self.events.append('routing-' + action)
        if action != 'refresh':
            self.routing_active = action == 'enable'
        record = {'active': self.routing_active}
        settings = json.loads((self.state / 'settings.json').read_bytes())
        try:
            verdict = json.loads(self.health.read_bytes())
        except (OSError, ValueError):
            verdict = None
        # As the adapter reads it: IPv6 reaching captured devices, or not
        # knowing, makes the scope every device.
        try:
            reaching = json.loads((self.state / 'dns-scope.json').read_bytes()).get('ipv6_reaching') is not False
        except (OSError, ValueError):
            reaching = True
        if (self.routing_active and settings.get('dns_scope') == 'captured' and not reaching
                and dns_probe.redirect_allowed(verdict, self.core_identity(), self.clock())):
            record['dns_redirect_port'] = 1053
        m.atomic_write(self.state / 'routing-state.json', json.dumps(record).encode())


class CapturedDnsHealthTests(unittest.TestCase):
    """The watchdog withdraws and re-arms captured devices' DNS without touching the core or Unbound."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.clock = Clock()
        self.system = ProbingSystem(self.clock)
        self.manager = m.Manager(Path(self.temp.name), self.system)
        self.manager.clock = self.clock
        self.sleeps = []
        self.manager.sleep = self.sleep
        self.system.state = self.manager.state
        self.system.health = self.manager.dns_health_file
        config = self.manager.path('/conf/config.xml')
        config.parent.mkdir(parents=True, exist_ok=True)
        config.write_text('<opnsense><OPNsense><unboundplus/></OPNsense></opnsense>')
        # A fresh installation answers only captured devices.
        self.manager.initialize()
        self.assertEqual('captured', self.manager.settings()['dns_scope'])
        self.manager.dispatch('start')
        self.manager.apply(SUBSCRIPTION)
        self.manager.dispatch('enable-transparent')

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.clock.now += seconds

    def tick(self, seconds=5.0):
        self.clock.now += seconds
        return self.manager.watchdog_tick()

    def verdict(self):
        return json.loads(self.manager.dns_health_file.read_bytes())

    def log(self):
        path = self.manager.path('/var/log/mihomo.log')
        return path.read_text().splitlines() if path.exists() else []

    def armed(self, status):
        return status['dns_redirect'] and self.manager.dns_redirect_armed()

    def test_a_new_core_is_probed_before_the_first_enable_and_armed_by_it(self):
        events = self.system.events
        start = max(index for index, event in enumerate(events) if event == 'start-transparent')
        probe = events.index('dns-probe', start)
        self.assertLess(probe, events.index('assign-tun', start))
        self.assertLess(events.index('assign-tun', start), events.index('routing-enable', start))
        status = json.loads(self.manager.status_file.read_bytes())
        self.assertTrue(self.armed(status))
        self.assertEqual(('captured', ''), (status['dns_scope'], status['dns_note']))
        self.assertEqual(0o600, self.manager.dns_health_file.stat().st_mode & 0o777)
        self.assertEqual(self.system.identity, self.verdict()['core'])
        self.assertEqual(1, sum(line.endswith(m.DNS_ARMED_LOG) for line in self.log()))
        # Captured devices are reached by redirect alone: Unbound never forwards.
        self.assertNotIn('dns-on', events)
        self.assertFalse(self.system.forwarded)

    def test_the_verdict_is_replaced_atomically_without_forcing_it_to_disk(self):
        # Rewritten every tick; a torn one after a power loss reads as unhealthy.
        record = self.verdict()
        with mock.patch.object(m.os, 'fsync') as fsync:
            self.manager.write_dns_health(record)
            fsync.assert_not_called()
            m.atomic_write(self.manager.state / 'durable-fixture', b'x')
            self.assertEqual(2, fsync.call_count)
        self.assertEqual(record, self.verdict())
        self.assertEqual(0o600, self.manager.dns_health_file.stat().st_mode & 0o777)
        self.manager.dns_health_file.write_text('{')
        self.assertIsNone(self.manager.read_dns_health())
        # The next probe starts that core's verdict afresh.
        self.assertTrue(self.armed(self.tick()))
        self.assertEqual(self.system.identity, self.verdict()['core'])

    def test_a_silent_core_still_starts_and_the_watchdog_arms_it_when_it_answers(self):
        self.system.liveness = dns_probe.ProbeError('silent')
        started = self.clock()
        self.manager.dispatch('restart')
        # The probe gave up within its budget and the start went on.
        self.assertLessEqual(self.clock() - started, dns_probe.START_BUDGET + 0.001)
        self.assertTrue(self.system.alive)
        self.assertTrue(self.system.routing_active)
        status = self.manager.dispatch('status')
        self.assertFalse(status['dns_redirect'])
        self.assertEqual(m.CAPTURED_WAIT_NOTE, status['dns_note'])
        self.system.liveness = dns_probe.NOERROR
        self.assertTrue(self.armed(self.tick()))

    def test_a_stalled_core_is_withdrawn_within_one_tick_and_rearmed_after_three(self):
        lives = self.system.lives
        self.system.events.clear()
        self.sleeps.clear()
        self.system.liveness = dns_probe.ProbeError('stalled')
        status = self.tick()
        # The first unanswered probe is asked again a second later, and the
        # tick probes both before the refresh that acts on the verdict.
        self.assertFalse(self.armed(status))
        self.assertEqual(['dns-probe', 'dns-probe', 'routing-refresh'], self.system.events)
        self.assertEqual([dns_probe.CONFIRM_PAUSE], self.sleeps)
        self.assertEqual(('captured', m.PAUSED_NOTES['liveness']), (status['dns_scope'], status['dns_note']))
        self.assertTrue(status['routing_active'])
        self.assertTrue(self.log()[-1].endswith(m.DNS_WITHDRAWN_LOG % 'Mihomo DNS stopped answering'))
        # One query the second one clears withdraws nothing.
        self.system.liveness = dns_probe.NOERROR
        for _ in range(3):
            status = self.tick()
        self.assertTrue(self.armed(status))
        answers = iter([dns_probe.ProbeError('blip'), dns_probe.NOERROR])

        def blip(server, name, timeout):
            if name != dns_probe.LIVENESS_NAME:
                return dns_probe.NXDOMAIN
            answer = next(answers)
            if isinstance(answer, Exception):
                raise answer
            return answer

        with mock.patch.object(self.system, 'dns_query', side_effect=blip):
            self.assertTrue(self.armed(self.tick()))
        self.system.liveness = dns_probe.ProbeError('stalled')
        self.assertFalse(self.armed(self.tick()))
        self.system.liveness = dns_probe.NOERROR
        self.tick()
        self.assertFalse(self.armed(self.tick()))
        status = self.tick()
        self.assertTrue(self.armed(status))
        self.assertEqual('', status['dns_note'])
        self.assertTrue(self.log()[-1].endswith(m.DNS_ARMED_LOG))
        # Neither the core nor Unbound was touched.
        self.assertEqual(lives, self.system.lives)
        self.assertFalse({'stop', 'start-transparent', 'dns-on', 'dns-off', 'destroy-tun'} & set(self.system.events))

    def test_upstream_failure_the_router_dns_does_not_share_withdraws_until_mihomo_resolves(self):
        self.system.mihomo = dns_probe.SERVFAIL
        status = self.tick(60)
        self.assertTrue(self.armed(status), 'One zone is not enough.')
        status = self.tick(60)
        self.assertFalse(self.armed(status))
        self.assertEqual(m.PAUSED_NOTES['upstream'], status['dns_note'])
        self.assertTrue(self.log()[-1].endswith(m.DNS_WITHDRAWN_LOG % m.DNS_WITHDRAW_REASONS['upstream']))
        for _ in range(11):
            self.assertFalse(self.armed(self.tick()))
        self.system.mihomo = dns_probe.NXDOMAIN
        self.assertTrue(self.armed(self.tick()))

    def test_both_failing_withdraws_nothing(self):
        self.system.mihomo = dns_probe.SERVFAIL
        self.system.router = dns_probe.ProbeError('WAN down')
        for _ in range(5):
            self.assertTrue(self.armed(self.tick(60)))
        self.assertFalse(any('withdrawn' in line for line in self.log()))

    def test_a_tick_holds_the_lock_for_seven_seconds_of_probing_at_most(self):
        # Every upstream answer is silent, and the start found the router DNS
        # silent too, so a tick asks it again whenever it may.
        self.system.mihomo = dns_probe.ProbeError('silent')
        self.system.router = dns_probe.ProbeError('silent')
        observed = json.loads(self.manager.dns_scope_file.read_bytes())
        self.manager.dns_scope_file.write_text(json.dumps(dict(observed, router_dns_answered=False)))
        bound = dns_probe.LIVENESS_TIMEOUT + 2 * dns_probe.UPSTREAM_TIMEOUT
        self.assertEqual(7.0, bound)
        for seconds, liveness, spent in (
                # An upstream round, and the router DNS is not asked again.
                (60.0, dns_probe.NOERROR, bound),
                # No round: the router DNS is asked again.
                (5.0, dns_probe.NOERROR, 2 * dns_probe.LIVENESS_TIMEOUT),
                # A stall: asked again after the pause, and no round.
                (5.0, dns_probe.ProbeError('stalled'), 3 * dns_probe.LIVENESS_TIMEOUT + dns_probe.CONFIRM_PAUSE)):
            with self.subTest(seconds=seconds, liveness=liveness):
                self.system.liveness = liveness
                self.system.queries.clear()
                self.sleeps.clear()
                self.tick(seconds)
                self.assertEqual(spent, sum(query[2] for query in self.system.queries) + sum(self.sleeps))
                self.assertLessEqual(spent, bound)

    def test_a_probe_that_cannot_run_or_be_recorded_never_stops_the_watchdog(self):
        # The watchdog loop survives only Error and OSError, and without it no
        # later failure is withdrawn at all. The verdict it could not renew
        # ages out instead, which withdraws the redirect.
        for name, patcher in (
                ('probe', lambda: mock.patch.object(self.system, 'dns_query', side_effect=TypeError('broken'))),
                ('record', lambda: mock.patch.object(self.manager, 'write_dns_health',
                                                     side_effect=OSError('read-only')))):
            with self.subTest(name):
                self.manager.dispatch('restart')
                self.assertTrue(self.armed(self.tick()))
                checked = self.verdict()['checked']
                with patcher():
                    while self.clock() + 5 - checked <= dns_probe.HEALTH_FRESH:
                        self.system.events.clear()
                        status = self.tick()
                        self.assertIn('routing-refresh', self.system.events)
                        self.assertTrue(self.armed(status))
                    status = self.tick()
                self.assertFalse(self.armed(status))
                self.assertEqual(checked, self.verdict()['checked'])

    def test_a_crash_withdraws_whatever_the_fallback_and_the_next_core_starts_untrusted(self):
        for fallback in (True, False):
            with self.subTest(dns_fallback=fallback):
                self.manager.write_settings(dict(self.manager.settings(), dns_fallback=fallback))
                self.manager.dispatch('start')
                if not self.system.alive:
                    self.manager.dispatch('restart')
                self.assertTrue(self.armed(self.tick()))
                self.system.alive = False
                self.system.events.clear()
                status = self.tick()
                self.assertEqual(['routing-disable', 'destroy-tun'], self.system.events)
                self.assertFalse(status['dns_redirect'])
                self.assertFalse(self.manager.dns_redirect_armed())
                self.assertFalse(self.manager.dns_health_file.exists())
                self.assertTrue(self.log()[-1].endswith(m.DNS_WITHDRAWN_LOG % 'Mihomo exited'))
                self.assertNotIn('dns-on', self.system.events)
                # A later tick finds nothing more to withdraw or log.
                lines = len(self.log())
                self.tick()
                self.assertEqual(lines, len(self.log()))
        previous = self.system.identity
        self.manager.dispatch('start')
        self.assertNotEqual(previous, self.verdict()['core'])
        self.assertEqual(self.system.identity, self.verdict()['core'])

    def test_a_restarted_core_is_never_trusted_on_the_old_ones_verdict(self):
        self.system.liveness = dns_probe.ProbeError('stalled')
        self.tick()
        self.tick()
        self.assertEqual('liveness', self.verdict()['reason'])
        old = self.verdict()
        # Another core under the same verdict: nothing it says counts.
        self.system.identity = {'pid': 5000, 'birth': '1700000000:99'}
        self.system.liveness = dns_probe.NOERROR
        self.tick()
        self.assertEqual(self.system.identity, self.verdict()['core'])
        self.assertTrue(self.verdict()['healthy'])
        self.assertNotEqual(old['core'], self.verdict()['core'])

    def test_stop_withdraws_synchronously_and_forgets_the_verdict(self):
        self.assertTrue(self.manager.dns_health_file.exists())
        self.manager.dispatch('stop')
        self.assertFalse(self.manager.dns_health_file.exists())
        self.assertFalse(self.manager.dns_redirect_armed())
        self.assertTrue(self.log()[-1].endswith(m.DNS_WITHDRAWN_LOG % 'the service stopped'))
        status = json.loads(self.manager.status_file.read_bytes())
        self.assertEqual(('off', False), (status['dns_scope'], status['dns_redirect']))

    def test_a_failing_backup_guard_still_withdraws_a_stalled_core(self):
        self.system.liveness = dns_probe.ProbeError('stalled')
        with mock.patch.object(self.manager, '_guard_backup',
                               side_effect=m.Error('A restored Mihomo configuration is pending.')):
            self.tick()
            status = self.tick()
        self.assertFalse(self.armed(status))
        self.assertIn(m.PAUSED_NOTES['liveness'], status['dns_note'])
        self.assertIn('A restored Mihomo configuration is pending.', status['error'])
        self.assertNotIn('dns-on', self.system.events)

    def test_other_scopes_keep_no_verdict_and_never_probe(self):
        for scope in ('all', 'off'):
            with self.subTest(scope=scope):
                payload = self.manager.state / 'request.json'
                payload.write_text(json.dumps({'dns_scope': scope}))
                self.manager.dispatch('set-settings', str(payload))
                self.system.queries.clear()
                self.tick(60)
                self.assertEqual([], self.system.queries)
                self.assertFalse(self.manager.dns_health_file.exists())
                self.assertFalse(self.manager.dns_redirect_armed())

    def test_active_sources_without_redirected_dns_raise_the_rule_hint(self):
        self.system.activity = (False, True)
        for _ in range(4):
            status = self.tick(60)
            self.assertNotIn(m.RULE_HINT_NOTE, status['dns_note'])
        status = self.tick(60)
        self.assertEqual(m.RULE_HINT_NOTE, status['dns_note'])
        self.assertTrue(self.armed(status), 'A hint withdraws nothing.')
        self.system.activity = (True, True)
        self.assertEqual('', self.tick(60)['dns_note'])
        # The state table is read once a minute, not every tick.
        self.system.events.clear()
        for _ in range(11):
            self.tick()
        self.assertEqual(0, self.system.events.count('dns-activity'))
        self.tick()
        self.assertEqual(1, self.system.events.count('dns-activity'))

    def test_a_silent_router_dns_is_reported_for_local_names_until_it_answers(self):
        changed = self.clock()
        self.assertEqual({'ipv6_reaching': False, 'changed': changed, 'router_dns_answered': True},
                         json.loads(self.manager.dns_scope_file.read_bytes()))
        self.system.router = dns_probe.ProbeError('silent')
        self.manager.dispatch('restart')
        # The scope did not change, so neither did when it last changed.
        self.assertEqual({'ipv6_reaching': False, 'changed': changed, 'router_dns_answered': False},
                         json.loads(self.manager.dns_scope_file.read_bytes()))
        # It costs local names only: the start went on and armed the redirect.
        status = self.manager.dispatch('status')
        self.assertTrue(self.armed(status))
        self.assertEqual(m.LOCAL_NAMES_NOTE, status['dns_note'])
        self.assertEqual(m.LOCAL_NAMES_NOTE, self.tick()['dns_note'])
        self.system.router = dns_probe.NOERROR
        self.assertEqual('', self.tick()['dns_note'])
        self.assertTrue(json.loads(self.manager.dns_scope_file.read_bytes())['router_dns_answered'])
        # Once it answered, the watchdog asks it nothing more.
        self.system.queries.clear()
        self.tick()
        self.assertNotIn(dns_probe.ROUTER, [query[0] for query in self.system.queries])

    def test_the_notes_combine_with_dnssec_and_the_scope_fallbacks(self):
        config = self.manager.path('/conf/config.xml')
        config.write_text('<opnsense><OPNsense><unboundplus><general><dnssec>1</dnssec></general>'
                          '</unboundplus></OPNsense></opnsense>')
        self.system.liveness = dns_probe.ProbeError('stalled')
        self.tick()
        status = self.tick()
        self.assertEqual(' '.join((m.PAUSED_NOTES['liveness'], m.CAPTURED_DNSSEC_NOTE)), status['dns_note'])
        self.system.liveness = dns_probe.NOERROR
        for _ in range(3):
            status = self.tick()
        self.assertEqual(m.CAPTURED_DNSSEC_NOTE, status['dns_note'])
        # Router DNS with every device reads as off and says why; no verdict is kept.
        dot = self.manager.path('/var/unbound/etc/dot.conf')
        dot.parent.mkdir(parents=True, exist_ok=True)
        dot.write_text('forward-addr: 1.1.1.1@853\n')
        payload = self.manager.state / 'request.json'
        payload.write_text(json.dumps({'dns_scope': 'all', 'router_dns': True}))
        self.manager.dispatch('set-settings', str(payload))
        status = self.tick()
        self.assertEqual(('off', m.ROUTER_DNS_NOTE), (status['dns_scope'], status['dns_note']))
        self.assertFalse(self.manager.dns_health_file.exists())


class Ipv6ScopeChangeTests(unittest.TestCase):
    """A captured scope follows IPv6 reaching its devices by restarting, keeping DNS answered throughout."""

    OFFER = ('<opnsense><dhcpdv6><lan><enable>1</enable></lan></dhcpdv6>'
             '<OPNsense><unboundplus/></OPNsense></opnsense>')

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.clock = Clock()
        self.system = ProbingSystem(self.clock)
        self.manager = m.Manager(Path(self.temp.name), self.system)
        self.manager.clock = self.clock
        self.manager.sleep = lambda seconds: setattr(self.clock, 'now', self.clock.now + seconds)
        self.system.state = self.manager.state
        self.system.health = self.manager.dns_health_file
        config = self.manager.path('/conf/config.xml')
        config.parent.mkdir(parents=True, exist_ok=True)
        # The router offers clients IPv6 all along; whether it reaches them is
        # whether the LAN holds a global prefix.
        config.write_text(self.OFFER)
        interfaces(self.manager, self.system, lan=['fe80::1%vtnet1'])
        self.manager.initialize()
        self.manager.dispatch('start')
        self.manager.apply(SUBSCRIPTION)
        self.manager.dispatch('enable-transparent')
        # What the running core's journal said when each start began it.
        self.journals = []
        original = self.system.start

        def start(config, transparent):
            self.journals.append(json.loads(self.manager.dns_scope_file.read_bytes()))
            original(config, transparent)

        self.system.start = start

    def prefix(self, present):
        interfaces(self.manager, self.system, lan=['fe80::1%vtnet1'] + ([GLOBAL_LAN] if present else []))

    def tick(self, seconds=5.0):
        self.clock.now += seconds
        return self.manager.watchdog_tick()

    def log(self):
        return self.manager.path('/var/log/mihomo.log').read_text().splitlines()

    def test_a_prefix_arriving_and_leaving_moves_the_scope_with_the_redirect_zone_and_status(self):
        status = self.tick()
        self.assertEqual(('captured', True, False), (status['dns_scope'], status['dns_redirect'], status['dns_active']))
        lives = self.system.lives
        # A delegated prefix arrives after the start.
        self.prefix(True)
        self.system.events.clear()
        status = self.tick()
        self.assertEqual(('captured', True), (status['dns_scope'], status['dns_redirect']))
        status = self.tick()
        events = self.system.events
        # The redirect goes with capture before the core stops, the zone comes
        # only once the new core answers: captured devices always have DNS.
        self.assertLess(events.index('routing-disable'), events.index('stop'))
        self.assertLess(events.index('start-transparent'), events.index('dns-on'))
        self.assertEqual(lives + 1, self.system.lives)
        self.assertEqual((True, 'all', False, m.IPV6_NOTE),
                         (status['dns_active'], status['dns_scope'], status['dns_redirect'], status['dns_note']))
        self.assertTrue(self.system.forwarded)
        self.assertFalse(self.manager.dns_redirect_armed())
        self.assertFalse(self.manager.dns_health_file.exists())
        # Journaled before the core started, so the adapter never armed it.
        self.assertTrue(self.journals[-1]['ipv6_reaching'])
        self.assertNotIn('dns-probe', events[events.index('stop'):])
        log = self.log()
        self.assertTrue(log[-3].endswith(m.IPV6_MOVE_LOGS[True]))
        self.assertTrue(log[-2].endswith(m.DNS_WITHDRAWN_LOG % 'the DNS scope changed'))
        self.assertTrue(log[-1].endswith(m.IPV6_MOVED_LOG % 'every device'))
        # Every device stays put: no probe, no restart.
        self.system.events.clear()
        for _ in range(12):
            self.assertEqual('all', self.tick()['dns_scope'])
        self.assertEqual({'routing-refresh'}, set(self.system.events))
        # The prefix leaves: held until ten minutes after the change.
        changed = json.loads(self.manager.dns_scope_file.read_bytes())['changed']
        self.assertLess(changed, self.clock())
        self.prefix(False)
        while self.clock() + 5 < changed + m.SCOPE_CHANGE_INTERVAL:
            status = self.tick()
            self.assertEqual(('all', True), (status['dns_scope'], status['dns_active']))
        self.assertIn(m.IPV6_WAIT_NOTE, status['dns_note'])
        self.system.events.clear()
        status = self.tick()
        events = self.system.events
        # The zone goes before the core stops; the redirect comes back only
        # once the new core answered its probe.
        self.assertLess(events.index('dns-off'), events.index('stop'))
        probe = events.index('dns-probe', events.index('start-transparent'))
        self.assertLess(probe, events.index('routing-enable'))
        self.assertNotIn('dns-on', events)
        self.assertFalse(self.system.forwarded)
        self.assertFalse(self.journals[-1]['ipv6_reaching'])
        self.assertEqual((False, 'captured', True, ''),
                         (status['dns_active'], status['dns_scope'], status['dns_redirect'], status['dns_note']))
        log = self.log()
        self.assertTrue(log[-1].endswith(m.IPV6_MOVED_LOG % 'captured devices'))
        self.assertTrue(any(line.endswith(m.DNS_ARMED_LOG) for line in log[-3:]))
        # A restart now keeps what the watchdog decided.
        self.manager.dispatch('restart')
        self.assertEqual(('captured', True), (self.tick()['dns_scope'], self.manager.dns_redirect_armed()))

    def test_a_new_core_that_fails_during_the_change_is_rolled_back_and_answered_by_the_router_meanwhile(self):
        self.tick()
        self.prefix(True)
        self.tick()
        self.system.fail_spawn_after_alive = 1
        self.system.events.clear()
        status = self.tick()
        events = self.system.events
        # The failed start stopped its own core and restored direct DNS; the
        # previous scope came back and re-armed once its core answered.
        self.assertEqual(2, events.count('stop'))
        self.assertNotIn('dns-on', events)
        self.assertFalse(self.system.forwarded)
        self.assertTrue(self.system.alive)
        self.assertEqual(('captured', True), (status['dns_scope'], status['dns_redirect']))
        self.assertIn(m.IPV6_FAILED_NOTE % 'Injected readiness failure after spawning the core.', status['dns_note'])
        self.assertEqual([True, False], [journal['ipv6_reaching'] for journal in self.journals])
        # Tried again after a minute, and then it holds.
        self.system.events.clear()
        while 'stop' not in self.system.events:
            status = self.tick()
        self.assertEqual(('all', True, m.IPV6_NOTE), (status['dns_scope'], status['dns_active'], status['dns_note']))

    def killed(self, *args):
        # SIGKILL: nothing after this point of the change runs.
        raise KeyboardInterrupt()

    def successor(self):
        """The next watchdog, a new process that knows nothing the dead one kept in memory."""
        manager = m.Manager(Path(self.temp.name), self.system)
        manager.clock = self.clock
        manager.sleep = self.manager.sleep
        return manager

    def test_a_watchdog_killed_between_the_stop_and_the_new_core_leaves_direct_dns(self):
        self.tick()
        self.prefix(True)
        self.tick()
        self.system.start = self.killed
        with self.assertRaises(KeyboardInterrupt):
            self.tick()
        self.assertTrue(self.manager.scope_move_file.exists())
        self.assertFalse(self.system.alive)
        self.assertFalse(self.system.forwarded)
        self.assertFalse(self.manager.dns_redirect_armed())
        # The next watchdog restores direct DNS in case the new start had got
        # as far as the zone, and settles the journal.
        self.system.events.clear()
        status = self.successor().watchdog_tick()
        self.assertIn('dns-off', self.system.events)
        self.assertFalse(self.system.forwarded)
        self.assertFalse(self.manager.scope_move_file.exists())
        self.assertEqual((False, False, False, 'off'),
                         (status['running'], status['dns_active'], status['dns_redirect'], status['dns_scope']))
        # A start decides afresh.
        self.system.start = ProbingSystem.start.__get__(self.system)
        self.manager.dispatch('start')
        status = self.manager.dispatch('status')
        self.assertEqual((True, 'all', m.IPV6_NOTE), (status['dns_active'], status['dns_scope'], status['dns_note']))

    def test_a_pending_backup_restore_does_not_keep_an_unfinished_change_from_restoring_direct_dns(self):
        self.tick()
        self.prefix(True)
        self.tick()
        self.system.watch = self.killed
        with self.assertRaises(KeyboardInterrupt):
            self.tick()
        del self.system.watch
        self.assertTrue(self.system.forwarded)
        # The new core dies before any watchdog finished the change, while a
        # restored backup blocks the ordinary tick.
        self.system.alive = False
        successor = self.successor()
        self.system.events.clear()
        with mock.patch.object(successor, '_guard_backup',
                               side_effect=m.Error('A restored Mihomo configuration is pending.')):
            status = successor.watchdog_tick()
        self.assertIn('rescue-dns', self.system.events)
        self.assertFalse(self.system.forwarded)
        self.assertFalse(status['dns_active'])
        self.assertFalse(successor.scope_move_file.exists())

    def test_a_watchdog_killed_after_the_new_core_wrote_the_zone_is_finished_by_the_next_one(self):
        self.tick()
        self.prefix(True)
        self.tick()
        self.system.watch = self.killed
        with self.assertRaises(KeyboardInterrupt):
            self.tick()
        # The new core runs and Unbound forwards to it, but the last status
        # is the stop's.
        self.assertTrue(self.system.alive)
        self.assertTrue(self.system.forwarded)
        self.assertTrue(self.manager.scope_move_file.exists())
        self.assertFalse(json.loads(self.manager.status_file.read_bytes())['dns_active'])
        del self.system.watch
        successor = self.successor()
        self.system.events.clear()
        status = successor.watchdog_tick()
        self.assertIn('stop', self.system.events)
        self.assertEqual((True, 'all', False, m.IPV6_NOTE),
                         (status['dns_active'], status['dns_scope'], status['dns_redirect'], status['dns_note']))
        self.assertTrue(self.system.forwarded)
        self.assertFalse(successor.scope_move_file.exists())
        self.assertTrue(self.log()[-2].endswith(m.IPV6_FINISH_LOG))
        self.assertTrue(self.log()[-1].endswith(m.IPV6_MOVED_LOG % 'every device'))
        # So a crash now restores direct DNS.
        self.system.alive = False
        self.clock.now += 5
        self.assertFalse(successor.watchdog_tick()['dns_active'])
        self.assertFalse(self.system.forwarded)

    def test_a_crash_after_the_change_follows_the_captured_scopes_fail_open_rescue(self):
        self.manager.write_settings(dict(self.manager.settings(), dns_fallback=False))
        self.tick()
        self.prefix(True)
        self.tick()
        self.assertTrue(self.tick()['dns_active'])
        self.system.alive = False
        self.system.events.clear()
        status = self.tick()
        self.assertEqual(['routing-disable', 'destroy-tun', 'dns-off'], self.system.events)
        self.assertFalse(self.system.forwarded)
        self.assertEqual((False, 'off'), (status['dns_active'], status['dns_scope']))
        # The next start finds no prefix but keeps every device, as a start
        # moves only that way; the watchdog confirms the way back and waits
        # out the interval since the change, then re-arms the redirect.
        changed = json.loads(self.manager.dns_scope_file.read_bytes())['changed']
        self.prefix(False)
        self.manager.dispatch('start')
        status = self.manager.dispatch('status')
        self.assertEqual(('all', True, False), (status['dns_scope'], status['dns_active'], status['dns_redirect']))
        while self.clock() < changed + m.SCOPE_CHANGE_INTERVAL + 10:
            status = self.tick()
        self.assertEqual(('captured', False, True),
                         (status['dns_scope'], status['dns_active'], status['dns_redirect']))


class RouterDnsCheckTests(unittest.TestCase):
    def test_the_router_dns_check_asks_over_tcp_and_needs_noerror(self):
        system = m.System()
        for answer, accepted in ((dns_probe.NOERROR, True), (dns_probe.NXDOMAIN, False),
                                 (dns_probe.SERVFAIL, False), (dns_probe.ProbeError('silent'), False)):
            with self.subTest(answer=answer), mock.patch.object(
                    m.dns_probe, 'query', side_effect=[answer]) as query:
                if accepted:
                    system.check_router_dns()
                else:
                    with self.assertRaisesRegex(m.Error, 'router DNS resolver did not answer'):
                        system.check_router_dns()
                query.assert_called_once_with('127.0.0.1', 53, 'localhost', 'tcp', 3.0)

    def test_probes_ask_mihomo_over_udp_about_the_recorded_core(self):
        system = m.System()
        with mock.patch.object(m.dns_probe, 'query', return_value=3) as query:
            self.assertEqual(3, system.dns_query(dns_probe.MIHOMO, 'localhost', 1.0))
        query.assert_called_once_with('127.0.0.1', 1053, 'localhost', 'udp', 1.0)
        group = mock.MagicMock()
        child = {'pid': 77, 'ppid': 1, 'birth': '1700000000:5', 'uid': 0}
        group.discover.return_value = {'child': child}
        group.same.return_value = True
        with mock.patch.object(system, '_core_group', return_value=group):
            self.assertEqual({'pid': 77, 'birth': '1700000000:5'}, system.core_identity())
            group.discover.assert_called_once_with(adopt=False)
            group.same.return_value = False
            self.assertIsNone(system.core_identity())
            group.discover.return_value = None
            self.assertIsNone(system.core_identity())
            group.discover.side_effect = m.OwnershipError('journal')
            self.assertIsNone(system.core_identity())

    def test_activity_is_read_from_the_anchor_sources_and_the_state_table(self):
        system = m.System()
        outputs = {
            ('/sbin/pfctl', '-a', 'mihomo', '-sT'): b'mihomo_local\nmihomo_self\nmihomo_sources_0\n',
            ('/sbin/pfctl', '-a', 'mihomo', '-t', 'mihomo_sources_0', '-T', 'show'): b'   10.0.0.0/24\n   10.9.0.7\n',
            ('/sbin/pfctl', '-ss'): (b'all udp 127.0.0.1:1053 (10.0.0.1:53) <- 10.0.0.5:45302       SINGLE:MULTIPLE\n'
                                     b'all tcp 203.0.113.9:443 <- 10.9.0.7:40002       ESTABLISHED:ESTABLISHED\n'),
        }

        def run(args, **kwargs):
            return subprocess.CompletedProcess(args, 0, outputs[tuple(args)], b'')

        with mock.patch.object(system, 'run', side_effect=run):
            self.assertEqual((True, True), system.dns_redirect_activity())
        with mock.patch.object(system, 'run', side_effect=m.Error('pfctl failed')):
            self.assertIsNone(system.dns_redirect_activity())


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
