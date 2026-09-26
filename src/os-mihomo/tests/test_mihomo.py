"""Exercise subscription failures and routing transitions without changing the host."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import yaml

SCRIPT = Path(__file__).resolve().parents[1] / 'src/usr/local/opnsense/scripts/mihomo/mihomo.py'
sys.path.insert(0, str(SCRIPT.parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'common'))
spec = importlib.util.spec_from_file_location('mihomo', SCRIPT)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

SUBSCRIPTION = b'''proxy-groups:
- name: Proxy
  type: select
  proxies: ["\\U0001F1F9\\U0001F1FC Taiwan", ON]
proxies:
- {name: "\\U0001F1F9\\U0001F1FC Taiwan", type: socks5, server: example.invalid, port: 1080}
- {type: socks5, password: "x, name: INJECTED", name: ON, server: example.invalid, port: 1080}
rules: ["MATCH,Proxy"]
dns: {enable: true, listen: ':53', enhanced-mode: fake-ip, fake-ip-range: 198.18.0.1/16}
'''


class FakeSystem:
    def __init__(self):
        self.alive = False
        self.forwarded = False
        self.events = []
        self.fail_start = 0
        self.reject = False
        self.dnssec = False

    def running(self): return self.alive
    def validate(self, candidate):
        self.events.append('validate')
        if self.reject:
            raise m.Error('Rejected test config.')
    def start(self, config, transparent):
        self.events.append('start-transparent' if transparent else 'start-proxy')
        if self.fail_start:
            self.fail_start -= 1
            raise m.Error('Injected startup failure.')
        self.alive = True
    def stop(self):
        self.events.append('stop')
        self.alive = False
    def dns(self, enabled, settings):
        self.events.append('dns-on' if enabled else 'dns-off')
        # The helper leaves a validating resolver alone and says so.
        self.forwarded = enabled and not self.dnssec
        return self.forwarded
    def watch(self): pass
    def stop_watch(self): pass
    def destroy_tun(self): self.events.append('destroy-tun')
    def remove(self): self.events.append('remove-owned-integration')
    def tun(self): self.events.append('assign-tun')
    def check_router_dns(self): self.events.append('check-router-dns')


class StateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.system = FakeSystem()
        self.manager = m.Manager(Path(self.temp.name), self.system)
        self.manager.initialize()
        self.manager.dispatch('start')

    def snapshot(self):
        return {p.name: p.read_bytes() for p in self.manager.state.iterdir() if p.is_file()}

    def test_fresh_install_is_proxy_only_and_cannot_enable_without_subscription(self):
        self.assertTrue(self.system.alive)
        self.assertFalse(self.system.forwarded)
        config = m.parse_yaml(self.manager.config_file.read_bytes())
        self.assertFalse(config['tun']['enable'])
        self.assertFalse(config['dns']['enable'])
        self.assertEqual([], config['tun']['dns-hijack'])
        self.assertNotIn('dns-on', self.system.events)
        with self.assertRaises(m.Error): self.manager.dispatch('enable-transparent')

    def test_provider_semantics_and_secret_survive_refresh_and_upgrade(self):
        secret = self.manager.settings()['secret']
        self.manager.apply(SUBSCRIPTION)
        self.manager.dispatch('enable-transparent')
        original = m.parse_yaml(SUBSCRIPTION)
        config = m.parse_yaml(self.manager.config_file.read_bytes())
        for key in ['proxies', 'proxy-groups', 'rules']:
            self.assertEqual(original[key], config[key])
        self.assertEqual('ON', config['proxies'][1]['name'])
        self.assertEqual(config['proxies'][0]['name'], config['proxy-groups'][0]['proxies'][0])
        self.assertTrue(self.system.forwarded)
        self.manager.apply(SUBSCRIPTION)
        self.manager.dispatch('suspend')
        self.manager.initialize(upgrade=True)
        self.manager.dispatch('boot')
        self.assertTrue(self.system.forwarded)
        self.assertTrue(self.manager.settings()['transparent'])
        self.assertEqual(secret, self.manager.settings()['secret'])
        self.assertEqual(secret, m.parse_yaml(self.manager.config_file.read_bytes())['secret'])

    def test_rejected_subscription_never_changes_live_files_or_restarts(self):
        self.manager.apply(SUBSCRIPTION)
        before = self.snapshot()
        events = list(self.system.events)
        for bad in [b'<html>SECRET</html>', b'proxy-groups: [{proxies: [x]}]\nrules: [MATCH,DIRECT]',
                    SUBSCRIPTION + b'dns: {listen: 53}\n']:
            with self.assertRaises(m.Error): self.manager.apply(bad)
            self.assertEqual(before, self.snapshot())
            self.assertEqual(events, self.system.events)
        self.system.reject = True
        with self.assertRaises(m.Error): self.manager.apply(SUBSCRIPTION)
        self.assertEqual(before, self.snapshot())
        self.assertTrue(self.system.alive)

    def test_restart_failure_restores_active_config_source_and_secret(self):
        self.manager.apply(SUBSCRIPTION)
        self.manager.dispatch('enable-transparent')
        before = self.snapshot()
        settings = self.manager.settings()
        settings['secret'] = 'replacement-secret'
        self.system.fail_start = 1
        with self.assertRaises(m.Error): self.manager.apply(SUBSCRIPTION, settings)
        self.assertEqual(before, self.snapshot())
        self.assertTrue(self.system.alive)
        self.assertTrue(self.system.forwarded)

    def test_failed_rollback_keeps_direct_dns_and_original_files(self):
        self.manager.apply(SUBSCRIPTION)
        self.manager.dispatch('enable-transparent')
        before = self.snapshot()
        self.system.fail_start = 2
        with self.assertRaises(m.Error): self.manager.apply(SUBSCRIPTION)
        self.assertEqual(before, self.snapshot())
        self.assertFalse(self.system.alive)
        self.assertFalse(self.system.forwarded)
        self.assertIn('Direct DNS', json.loads(self.manager.status_file.read_bytes())['error'])

    def test_dns_is_restored_before_core_stop_and_wan_does_not_revive_stop(self):
        self.manager.apply(SUBSCRIPTION)
        self.manager.dispatch('enable-transparent')
        self.system.events.clear()
        self.manager.dispatch('stop')
        self.assertLess(self.system.events.index('dns-off'), self.system.events.index('stop'))
        self.manager.dispatch('wan-restart')
        self.manager.dispatch('boot')
        self.assertFalse(self.system.alive)

    def test_wan_restart_ignores_inet6_while_mihomo_ipv6_is_off(self):
        self.manager.apply(SUBSCRIPTION)
        self.manager.dispatch('enable-transparent')
        self.assertFalse(self.manager.settings()['ipv6'])
        self.system.events.clear()
        self.assertEqual({'running': True}, self.manager.dispatch('wan-restart', 'inet6'))
        self.assertEqual([], self.system.events)
        self.assertTrue(self.system.alive)
        # IPv4 changes and events that name no family still restart the core.
        for family in ('inet', '', None):
            self.system.events.clear()
            self.manager.dispatch('wan-restart', family)
            self.assertIn('stop', self.system.events, family)
            self.assertIn('start-transparent', self.system.events, family)
            self.assertTrue(self.system.alive)

    def test_wan_restart_follows_inet6_when_mihomo_ipv6_is_on(self):
        self.manager.apply(SUBSCRIPTION)
        settings = self.manager.settings()
        settings['ipv6'] = True
        self.manager.write_settings(settings)
        self.manager.dispatch('enable-transparent')
        self.system.events.clear()
        self.manager.dispatch('wan-restart', 'inet6')
        self.assertIn('stop', self.system.events)
        self.assertTrue(self.system.alive)

    def test_inet6_wan_event_does_not_revive_a_stopped_core(self):
        self.manager.apply(SUBSCRIPTION)
        self.manager.dispatch('enable-transparent')
        self.manager.dispatch('stop')
        self.system.events.clear()
        self.assertEqual({'running': False}, self.manager.dispatch('wan-restart', 'inet6'))
        self.assertEqual([], self.system.events)
        self.assertFalse(self.system.alive)

    def test_crash_fallback_is_per_router_and_keeps_opt_in(self):
        self.manager.apply(SUBSCRIPTION)
        self.manager.dispatch('enable-transparent')
        self.system.alive = False
        status = self.manager.watchdog_tick()
        self.assertFalse(status['dns_active'])
        self.assertFalse(self.system.forwarded)
        self.assertTrue(self.manager.settings()['transparent'])
        self.manager.dispatch('start')
        settings = self.manager.settings()
        settings['dns_fallback'] = False
        self.manager.write_settings(settings)
        self.system.alive = False
        self.assertTrue(self.manager.watchdog_tick()['dns_active'])
        self.assertTrue(self.system.forwarded)

    def test_settings_on_fresh_proxy_restart_with_same_transaction(self):
        payload = self.manager.state / 'request.json'
        payload.write_text(json.dumps({'secret': 'new-secret'}))
        self.manager.dispatch('set-settings', str(payload))
        self.assertEqual('new-secret', m.parse_yaml(self.manager.config_file.read_bytes())['secret'])
        self.assertIn('stop', self.system.events)
        self.assertFalse(self.manager.source_file.exists())

    def test_fast_tcp_path_renders_its_listener_and_guards_the_port(self):
        self.manager.apply(SUBSCRIPTION)
        self.manager.dispatch('enable-transparent')
        owned = {'name': m.REDIRECT_LISTENER, 'type': 'redir', 'port': m.REDIRECT_PORT, 'listen': '127.0.0.1'}
        payload = self.manager.state / 'request.json'
        payload.write_text(json.dumps({'tcp_redirect': True}))
        self.manager.dispatch('set-settings', str(payload))
        self.assertIs(True, self.manager.settings()['tcp_redirect'])
        self.assertIn(owned, m.parse_yaml(self.manager.config_file.read_bytes())['listeners'])
        for key in ('mixed_port', 'socks_port'):
            payload.write_text(json.dumps({key: m.REDIRECT_PORT}))
            with self.subTest(key=key), self.assertRaisesRegex(m.Error, 'transparent TCP listener'):
                self.manager.dispatch('set-settings', str(payload))
        payload.write_text(json.dumps({'tcp_redirect': 'yes'}))
        with self.assertRaises(m.Error):
            self.manager.dispatch('set-settings', str(payload))
        self.assertIs(True, self.manager.settings()['tcp_redirect'])
        payload.write_text(json.dumps({'tcp_redirect': False}))
        self.manager.dispatch('set-settings', str(payload))
        self.assertNotIn(owned, m.parse_yaml(self.manager.config_file.read_bytes()).get('listeners') or [])
        # With the path off the port is an ordinary choice again.
        payload.write_text(json.dumps({'mixed_port': m.REDIRECT_PORT}))
        self.manager.dispatch('set-settings', str(payload))

    def test_status_reports_the_fast_tcp_path_and_why_it_waits(self):
        self.manager.apply(SUBSCRIPTION)
        self.manager.dispatch('enable-transparent')
        routing = self.manager.state / 'routing-state.json'
        routing.write_text(json.dumps({'active': True, 'tcp_redirect_port': m.REDIRECT_PORT}))
        status = self.manager.publish_status()
        self.assertTrue(status['tcp_redirect'])
        self.assertEqual('', status['tcp_redirect_note'])
        routing.write_text(json.dumps({'active': True}))
        self.assertFalse(self.manager.publish_status()['tcp_redirect'])
        self.assertEqual('', self.manager.publish_status()['tcp_redirect_note'])
        settings = self.manager.settings()
        settings['tcp_redirect'] = True
        self.manager.write_settings(settings)
        self.assertIn('port %d is taken' % m.REDIRECT_PORT, self.manager.publish_status()['tcp_redirect_note'])
        self.manager.apply(SUBSCRIPTION)
        self.assertIn('until the core listener', self.manager.publish_status()['tcp_redirect_note'])
        routing.write_text(json.dumps({'active': False, 'tcp_redirect_port': m.REDIRECT_PORT}))
        status = self.manager.publish_status()
        self.assertFalse(status['tcp_redirect'])
        self.assertEqual('', status['tcp_redirect_note'])

    def test_capture_interfaces_are_saved_normalised_and_reported(self):
        payload = self.manager.state / 'request.json'
        payload.write_text(json.dumps({'capture_interfaces': ['opt5', 'lan', 'opt5']}))
        self.manager.dispatch('set-settings', str(payload))
        self.assertEqual(['opt5', 'lan'], self.manager.settings()['capture_interfaces'])
        # Settings that do not mention the field leave the selection alone.
        payload.write_text(json.dumps({'secret': 'another-secret'}))
        self.manager.dispatch('set-settings', str(payload))
        self.assertEqual(['opt5', 'lan'], self.manager.settings()['capture_interfaces'])
        payload.write_text(json.dumps({'capture_interfaces': []}))
        self.manager.dispatch('set-settings', str(payload))
        self.assertEqual([], self.manager.settings()['capture_interfaces'])
        for invalid in (['lan;x'], 'lan', [1]):
            payload.write_text(json.dumps({'capture_interfaces': invalid}))
            with self.assertRaises(m.Error):
                self.manager.dispatch('set-settings', str(payload))
        self.assertEqual([], self.manager.settings()['capture_interfaces'])

    def test_devices_action_offers_capture_candidates_from_the_routing_context(self):
        (self.manager.state / 'routing-context.json').write_text(json.dumps({'interfaces': [
            {'name': 'wan', 'device': 'igc1', 'networks': ['192.0.2.2/24'], 'wan': True},
            {'name': 'lan', 'device': 'bridge0', 'networks': ['192.168.0.1/22'], 'wan': False, 'descr': 'LAN'},
            {'name': 'opt5', 'device': 'vlan0.20', 'networks': ['192.168.20.1/24'], 'wan': False, 'descr': 'Guest'}],
            'local_addresses': []}))
        settings = self.manager.settings()
        settings.update(transparent=True, capture_interfaces=['opt5', 'opt1'])
        self.manager.write_settings(settings)
        self.system.run = lambda *args, **kwargs: subprocess.CompletedProcess(args, 0, b'', b'')
        found = self.manager.dispatch('devices')
        self.assertEqual(['lan', 'opt5'], [item['name'] for item in found['interfaces']])
        self.assertEqual('Capture only from: Guest (opt5), opt1.', found['routing'][0])
        self.assertIn('opt1', found['routing'][1])

    def test_settings_action_applies_listener_and_tun_fields_before_and_after_subscription(self):
        payload = self.manager.state / 'request.json'
        for has_subscription, mixed_port in ((False, 17890), (True, 17892)):
            with self.subTest(has_subscription=has_subscription):
                if has_subscription:
                    self.manager.apply(SUBSCRIPTION)
                given = {'mixed_port': mixed_port, 'socks_port': mixed_port + 1,
                         'allow_lan': True, 'bind_address': '10.0.0.1',
                         'tun_stack': 'system', 'tun_mtu': 1400}
                payload.write_text(json.dumps(given))
                self.manager.dispatch('set-settings', str(payload))
                settings = self.manager.settings()
                for key, value in given.items():
                    self.assertEqual(value, settings[key], key)
                generated = m.parse_yaml(self.manager.config_file.read_bytes())
                for key in ('mixed_port', 'socks_port', 'allow_lan', 'bind_address'):
                    self.assertEqual(given[key], generated[key.replace('_', '-')], key)
                self.assertEqual('system', generated['tun']['stack'])
                self.assertEqual(1400, generated['tun']['mtu'])
                self.assertFalse(generated['tun']['enable'])
                self.assertTrue(self.system.alive)

    def test_settings_action_persists_normalized_dot_without_rewriting_subscription(self):
        self.manager.apply(SUBSCRIPTION)
        source = self.manager.source_file.read_bytes()
        payload = self.manager.state / 'request.json'
        payload.write_text(json.dumps({
            'dns_override': True,
            'dns_default': ['tls://162.159.36.5#v5brh3pn84.cloudflare-gateway.com'],
            'dns_nameserver': ['tls://162.159.36.5#v5brh3pn84.cloudflare-gateway.com'],
            'dns_proxy_nameserver': ['tls://162.159.36.5#v5brh3pn84.cloudflare-gateway.com']}))
        self.manager.dispatch('set-settings', str(payload))
        expected = ['tls://v5brh3pn84.cloudflare-gateway.com']
        settings = self.manager.settings()
        self.assertTrue(settings['dns_override'])
        self.assertEqual(['162.159.36.5'], settings['dns_default'])
        self.assertEqual(expected, settings['dns_nameserver'])
        self.assertEqual(expected, settings['dns_proxy_nameserver'])
        generated = m.parse_yaml(self.manager.config_file.read_bytes())['dns']
        self.assertEqual(expected, generated['nameserver'])
        self.assertEqual(expected, generated['proxy-server-nameserver'])
        self.assertEqual(source, self.manager.source_file.read_bytes())

    def test_dns_override_can_be_disabled_without_erasing_manual_or_subscription_data(self):
        data = m.parse_yaml(SUBSCRIPTION)
        data['dns']['nameserver'] = ['https://provider.invalid/dns-query']
        subscription = yaml.safe_dump(data, sort_keys=False).encode()
        self.manager.apply(subscription)
        source = self.manager.source_file.read_bytes()
        payload = self.manager.state / 'request.json'
        manual = ['tls://dot.example.net']
        payload.write_text(json.dumps({'dns_override': True, 'dns_nameserver': manual}))
        self.manager.dispatch('set-settings', str(payload))
        self.assertEqual(manual, m.parse_yaml(self.manager.config_file.read_bytes())['dns']['nameserver'])
        payload.write_text(json.dumps({'dns_override': False}))
        self.manager.dispatch('set-settings', str(payload))
        settings = self.manager.settings()
        self.assertFalse(settings['dns_override'])
        self.assertEqual(manual, settings['dns_nameserver'])
        self.assertEqual(['https://provider.invalid/dns-query'],
                         m.parse_yaml(self.manager.config_file.read_bytes())['dns']['nameserver'])
        self.assertEqual(source, self.manager.source_file.read_bytes())

    def test_settings_action_rejects_invalid_listener_and_tun_fields_without_changes(self):
        payload = self.manager.state / 'request.json'
        for invalid in ({'mixed_port': 53}, {'socks_port': 7890},
                        {'mixed_port': True}, {'allow_lan': 'yes'},
                        {'bind_address': 'invalid'}, {'tun_stack': 'invalid'},
                        {'tun_mtu': 1}):
            with self.subTest(invalid=invalid):
                payload.write_text(json.dumps(invalid))
                before = self.snapshot()
                events = list(self.system.events)
                with self.assertRaises(m.Error):
                    self.manager.dispatch('set-settings', str(payload))
                self.assertEqual(before, self.snapshot())
                self.assertEqual(events, self.system.events)
                self.assertTrue(self.system.alive)

    def unbound(self, dnssec):
        """Give the router a resolver that does or does not validate DNSSEC."""
        config = self.manager.path('/conf/config.xml')
        config.parent.mkdir(parents=True, exist_ok=True)
        general = '<general><dnssec>1</dnssec></general>' if dnssec else ''
        config.write_text('<opnsense><OPNsense><unboundplus>' + general
                          + '<dots/></unboundplus></OPNsense></opnsense>')
        self.system.dnssec = dnssec

    def status_file(self):
        return json.loads(self.manager.status_file.read_bytes())

    def test_repeated_start_preserves_generated_dns_mode(self):
        dot = self.manager.path('/var/unbound/etc/dot.conf')
        dot.parent.mkdir(parents=True, exist_ok=True)
        dot.write_text('forward-addr: 1.1.1.1@853\n')
        self.unbound(False)
        self.manager.apply(SUBSCRIPTION)
        for dnssec in (False, True):
            for router_dns, dns_enabled in ((True, True), (False, False), (False, True)):
                with self.subTest(router_dns=router_dns, dns_enabled=dns_enabled, dnssec=dnssec):
                    self.unbound(dnssec)
                    settings = self.manager.settings()
                    settings['router_dns'] = router_dns
                    overlay = {'tun': {'enable': True, 'auto-route': True},
                               'dns': {'enable': dns_enabled, 'listen': '127.0.0.1:1053'}}
                    self.manager.apply(SUBSCRIPTION, settings, overlay=overlay)
                    self.manager.dispatch('enable-transparent')
                    # A validating resolver declines the forward zone, and
                    # every path that reports it has to say so, not only start.
                    expected = dns_enabled and not router_dns and not dnssec
                    note = m.DNSSEC_NOTE if dns_enabled and not router_dns and dnssec else ''
                    status = self.manager.dispatch('status')
                    self.assertEqual(expected, status['dns_active'])
                    self.assertEqual(note, status['dns_note'])
                    self.assertEqual(expected, self.system.forwarded)
                    # boot and start find the core running and only republish.
                    for action in ('boot', 'start'):
                        result = self.manager.dispatch(action)
                        self.assertEqual(expected, result['dns_active'], action)
                        self.assertEqual(note, result['dns_note'], action)
                        self.assertEqual(note, self.status_file()['dns_note'], action)

    def test_the_dnssec_note_survives_the_backup_mirror_and_the_watchdog(self):
        self.unbound(True)
        self.manager.apply(SUBSCRIPTION)
        self.manager.dispatch('enable-transparent')
        self.assertIn('dns-on', self.system.events)
        self.assertFalse(self.system.forwarded)
        # dispatch('start') republishes through _mirrored_result, which passes
        # on only dns_active and error; the note must be derived again there.
        self.manager.dispatch('start')
        self.assertFalse(self.status_file()['dns_active'])
        self.assertEqual(m.DNSSEC_NOTE, self.status_file()['dns_note'])
        status = self.manager.watchdog_tick()
        self.assertFalse(status['dns_active'])
        self.assertEqual(m.DNSSEC_NOTE, status['dns_note'])
        self.assertEqual(m.DNSSEC_NOTE, self.status_file()['dns_note'])
        # Once validation is off again, the next restart applies the zone.
        self.unbound(False)
        self.assertEqual(m.DNS_RESTART_NOTE, self.manager.watchdog_tick()['dns_note'])
        self.assertFalse(self.manager.dispatch('start')['dns_active'])
        result = self.manager.dispatch('restart')
        self.assertTrue(result['dns_active'])
        self.assertEqual('', result['dns_note'])
        self.assertTrue(self.system.forwarded)
        # A stopped service has nothing to explain.
        self.unbound(True)
        self.manager.dispatch('stop')
        self.assertEqual('', self.status_file()['dns_note'])

    def test_the_watchdog_hands_a_resolver_that_starts_validating_back_once(self):
        self.unbound(False)
        self.manager.apply(SUBSCRIPTION)
        self.manager.dispatch('enable-transparent')
        self.assertTrue(self.status_file()['dns_active'])
        self.assertTrue(self.system.forwarded)
        # DNSSEC switched on while Unbound forwards to Mihomo: every signed
        # zone would fail validation until the next start.
        self.unbound(True)
        self.system.events.clear()
        status = self.manager.watchdog_tick()
        self.assertFalse(status['dns_active'])
        self.assertEqual(m.DNSSEC_NOTE, status['dns_note'])
        self.assertFalse(self.system.forwarded)
        self.assertTrue(self.system.alive)
        # Removing the integration releases the TUN assignment the running
        # core still needs, so it is put back in the same tick.
        self.assertEqual(['dns-off', 'assign-tun'], self.system.events)
        for _ in range(2):
            self.assertFalse(self.manager.watchdog_tick()['dns_active'])
        self.assertEqual(1, self.system.events.count('dns-off'))

    def test_a_failed_dns_hand_back_stays_reported_active_and_is_retried(self):
        self.unbound(False)
        self.manager.apply(SUBSCRIPTION)
        self.manager.dispatch('enable-transparent')
        self.unbound(True)
        original = self.system.dns
        self.system.dns = lambda enabled, settings: (_ for _ in ()).throw(m.Error('Injected Unbound restart failure.'))
        status = self.manager.watchdog_tick()
        self.assertTrue(status['dns_active'], 'the crash rescue must still see the integration')
        self.assertIn('Returning DNS to the validating resolver failed and will be retried', status['error'])
        self.system.dns = original
        self.system.events.clear()
        status = self.manager.watchdog_tick()
        self.assertFalse(status['dns_active'])
        self.assertEqual(['dns-off', 'assign-tun'], self.system.events)
        self.assertFalse(self.manager.tun_reassign_file.exists())

    def test_a_failed_tun_reassignment_is_retried_alone_once_dns_is_handed_back(self):
        self.unbound(False)
        self.manager.apply(SUBSCRIPTION)
        self.manager.dispatch('enable-transparent')
        self.unbound(True)
        original = self.system.tun
        self.system.tun = lambda: (_ for _ in ()).throw(m.Error('Injected TUN assignment failure.'))
        self.system.events.clear()
        status = self.manager.watchdog_tick()
        # Unbound is back on its own upstreams, so the status says so and names
        # the step that is still owed.
        self.assertEqual(['dns-off'], self.system.events)
        self.assertFalse(self.system.forwarded)
        self.assertFalse(status['dns_active'])
        self.assertEqual(m.DNSSEC_NOTE, status['dns_note'])
        self.assertIn('restoring the TUN assignment failed and will be retried', status['error'])
        self.assertIn('Injected TUN assignment failure', status['error'])
        self.assertFalse(self.manager.watchdog_tick()['dns_active'])
        self.system.tun = original
        self.system.events.clear()
        status = self.manager.watchdog_tick()
        self.assertEqual(['assign-tun'], self.system.events)
        self.assertEqual('', status['error'])
        self.assertFalse(self.manager.tun_reassign_file.exists())
        self.manager.watchdog_tick()
        self.assertEqual(['assign-tun'], self.system.events)

    def test_a_restart_takes_over_a_tun_reassignment_the_watchdog_still_owes(self):
        self.unbound(False)
        self.manager.apply(SUBSCRIPTION)
        self.manager.dispatch('enable-transparent')
        self.unbound(True)
        original = self.system.tun
        self.system.tun = lambda: (_ for _ in ()).throw(m.Error('Injected TUN assignment failure.'))
        self.manager.watchdog_tick()
        self.assertTrue(self.manager.tun_reassign_file.exists())
        self.system.tun = original
        self.manager.dispatch('restart')
        self.assertFalse(self.manager.tun_reassign_file.exists())
        self.system.events.clear()
        self.manager.watchdog_tick()
        self.assertNotIn('assign-tun', self.system.events)

    def test_a_start_rejected_after_restoring_direct_dns_stops_reporting_it(self):
        # With DNS recovery off a crash leaves Unbound forwarding, and the
        # status keeps saying so. A start that restores direct DNS and then
        # fails must not leave that claim behind for the watchdog to repeat.
        self.unbound(False)
        self.manager.apply(SUBSCRIPTION)
        self.manager.write_settings(dict(self.manager.settings(), dns_fallback=False))
        self.manager.dispatch('enable-transparent')
        self.system.alive = False
        self.assertTrue(self.manager.watchdog_tick()['dns_active'])
        self.assertTrue(self.system.forwarded)
        self.system.reject = True
        with self.assertRaises(m.Error):
            self.manager.dispatch('start')
        self.assertFalse(self.system.forwarded)
        self.assertFalse(self.status_file()['dns_active'])
        self.assertIn('Rejected test config.', self.status_file()['error'])
        self.assertFalse(self.manager.watchdog_tick()['dns_active'])

    def test_an_unreadable_resolver_configuration_never_counts_as_validating(self):
        # The watchdog loop survives only Error and OSError.
        config = self.manager.path('/conf/config.xml')
        config.parent.mkdir(parents=True, exist_ok=True)
        for content in (b"<?xml version='1.0' encoding='x-unknown'?><opnsense/>",
                        b"<?xml version='1.0' encoding='shift_jis'?><opnsense/>", b'<opnsense>', b''):
            with self.subTest(content=content):
                config.write_bytes(content)
                self.assertFalse(self.manager.unbound_validating())

    def test_an_already_running_boot_reports_the_request_without_a_published_answer(self):
        # A false positive costs the crash rescue one harmless restoration; a
        # false negative would skip it.
        self.unbound(False)
        self.manager.apply(SUBSCRIPTION)
        self.manager.dispatch('enable-transparent')
        self.manager.status_file.unlink()
        self.assertTrue(self.manager.dispatch('boot')['dns_active'])

    def test_an_already_running_boot_keeps_a_published_answer_only_while_requested(self):
        self.unbound(False)
        self.manager.apply(SUBSCRIPTION)
        self.manager.dispatch('enable-transparent')
        self.assertTrue(self.status_file()['dns_active'])
        settings = json.loads(self.manager.settings_file.read_bytes())
        settings['router_dns'] = True
        self.manager.settings_file.write_text(json.dumps(settings))
        self.assertFalse(self.manager.dispatch('boot')['dns_active'])

    def test_boot_restores_direct_dns_before_a_rejected_configuration(self):
        self.unbound(False)
        self.manager.apply(SUBSCRIPTION)
        self.manager.dispatch('enable-transparent')
        self.assertTrue(self.system.forwarded)
        # An unclean shutdown leaves Unbound forwarding to a core that is gone,
        # and the configuration no longer validates when the router comes up.
        self.system.alive = False
        self.system.reject = True
        self.system.events.clear()
        with self.assertRaises(m.Error):
            self.manager.dispatch('boot')
        self.assertIn('dns-off', self.system.events)
        self.assertIn('validate', self.system.events)
        self.assertLess(self.system.events.index('dns-off'), self.system.events.index('validate'))
        self.assertFalse(self.system.forwarded)
        self.assertNotIn('dns-on', self.system.events)

    def test_the_request_ignores_capture_selection_and_follows_router_dns(self):
        generated = {'tun': {'enable': True}, 'dns': {'enable': True, 'listen': '127.0.0.1:1053'}}
        self.assertTrue(m.dns_requested({'router_dns': False}, generated))
        self.assertTrue(m.dns_requested({'router_dns': False, 'device_mode': 'whitelist',
                                         'device_list': ['192.0.2.10'], 'capture_interfaces': ['opt5']},
                                        generated))
        self.assertFalse(m.dns_requested({'router_dns': True}, generated))
        for changed in ({'tun': {'enable': False}}, {'dns': {'enable': False}},
                        {'dns': {'enable': True, 'listen': '127.0.0.1:1054'}}, {'dns': None}, {'tun': 'on'}):
            with self.subTest(changed=changed):
                self.assertFalse(m.dns_requested({}, dict(generated, **changed)))

    def test_transparent_migration_saves_real_dns_instead_of_using_legacy_fake_pool(self):
        self.manager.apply(SUBSCRIPTION.replace(b'198.18.0.1/16', b'28.0.0.1/8'))
        settings = self.manager.settings()
        settings['dns_mode'] = 'fake-ip'
        self.manager.write_settings(settings)
        self.manager.dispatch('enable-transparent')
        self.assertEqual('redir-host', self.manager.settings()['dns_mode'])
        self.assertEqual('redir-host', m.parse_yaml(self.manager.config_file.read_bytes())['dns']['enhanced-mode'])
        self.assertTrue(self.system.forwarded)

    def test_log_failure_does_not_block_an_operation(self):
        path = self.manager.path('/var/log/mihomo_sub.log')
        path.mkdir(parents=True)
        self.manager.log('Safe diagnostic.')
        self.manager.apply(SUBSCRIPTION)
        self.assertTrue(self.system.alive)


class BundledCoreStackTests(unittest.TestCase):
    def test_unsupported_tun_stacks_are_rejected_before_running_the_core(self):
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / 'config.yaml'
            system = m.System()
            with mock.patch.object(system, 'run') as run:
                for stack in ('system', 'mixed'):
                    candidate.write_text(yaml.safe_dump({'tun': {'enable': True, 'stack': stack}}))
                    with self.subTest(stack=stack), self.assertRaisesRegex(m.Error, 'gVisor'):
                        system.validate(candidate)
                run.assert_not_called()

    def test_gvisor_and_disabled_tun_use_normal_core_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / 'config.yaml'
            system = m.System()
            for enabled, stack in ((True, 'gvisor'), (False, 'system'), (False, 'mixed')):
                candidate.write_text(yaml.safe_dump({'tun': {'enable': enabled, 'stack': stack}}))
                with self.subTest(enabled=enabled, stack=stack), mock.patch.object(system, 'run', return_value=subprocess.CompletedProcess([], 0)) as run:
                    system.validate(candidate)
                    run.assert_called_once()


class RecoveryTests(unittest.TestCase):
    setUp = StateTests.setUp
    snapshot = StateTests.snapshot

    def test_cleanup_failure_cannot_prevent_file_and_secret_rollback(self):
        self.manager.apply(SUBSCRIPTION)
        self.manager.dispatch('enable-transparent')
        before = self.snapshot()
        original_start = self.system.start
        original_dns = self.system.dns
        fail = {'cleanup': False}
        def start(config, transparent):
            if self.system.fail_start:
                fail['cleanup'] = True
            return original_start(config, transparent)
        def dns(enabled, settings):
            if not enabled and fail['cleanup']:
                fail['cleanup'] = False
                raise m.Error('Injected cleanup failure.')
            return original_dns(enabled, settings)
        self.system.start = start
        self.system.dns = dns
        self.system.fail_start = 1
        settings = self.manager.settings()
        settings['secret'] = 'should-not-survive-rollback'
        with self.assertRaises(m.Error): self.manager.apply(SUBSCRIPTION, settings)
        self.assertEqual(before, self.snapshot())
        self.assertTrue(self.system.alive)
        self.assertTrue(self.system.forwarded)


class UpgradeTests(unittest.TestCase):
    setUp = StateTests.setUp

    def test_upgrade_keeps_pre_switch_manual_dns_enabled(self):
        data = m.parse_yaml(SUBSCRIPTION)
        data['dns']['nameserver'] = ['https://provider.invalid/dns-query']
        subscription = yaml.safe_dump(data, sort_keys=False).encode()
        manual = ['tls://dot.example.net']
        settings = dict(self.manager.settings(), dns_override=True, dns_nameserver=manual)
        self.manager.apply(subscription, settings)
        legacy = self.manager.settings()
        legacy.pop('dns_override')
        legacy['switch_schema'] = m.SWITCH_SCHEMA - 1
        self.manager.write_settings(legacy)
        self.manager.initialize(upgrade=True)
        migrated = self.manager.settings()
        self.assertTrue(migrated['dns_override'])
        self.assertEqual(manual, migrated['dns_nameserver'])
        self.assertEqual(manual, m.parse_yaml(self.manager.config_file.read_bytes())['dns']['nameserver'])

    def test_explicit_consent_survives_upgrade_and_same_version_reinstall(self):
        self.manager.apply(SUBSCRIPTION)
        self.manager.dispatch('enable-transparent')
        before = self.manager.settings()
        self.assertEqual(m.STATE_SCHEMA, before['state_schema'])
        self.assertTrue(before['transparent_consent'])
        for upgrade in (True, False):
            self.manager.dispatch('suspend')
            self.manager.initialize(upgrade=upgrade)
            self.manager.dispatch('boot')
            self.assertEqual(before, self.manager.settings())
            self.assertTrue(self.system.alive)
            self.assertTrue(self.system.forwarded)

    def test_administrative_stop_is_preserved_by_upgrade_and_reinstall(self):
        self.manager.apply(SUBSCRIPTION)
        self.manager.dispatch('enable-transparent')
        self.manager.dispatch('stop')
        before = self.manager.settings()
        for upgrade in (True, False):
            self.manager.dispatch('suspend')
            self.manager.initialize(upgrade=upgrade)
            self.manager.dispatch('boot')
            self.manager.dispatch('wan-restart')
            self.assertEqual(before, self.manager.settings())
            self.assertFalse(self.system.alive)
            self.assertFalse(self.system.forwarded)

    def test_unmarked_legacy_flags_are_reset_once_without_losing_credentials(self):
        self.manager.apply(SUBSCRIPTION)
        self.manager.dispatch('enable-transparent')
        self.manager.dispatch('suspend')
        settings = self.manager.settings()
        for key in ('state_schema', 'transparent_consent'):
            settings.pop(key)
        settings['service_enabled'] = False
        self.manager.write_settings(settings)
        self.manager.initialize(upgrade=True)
        migrated = self.manager.settings()
        self.assertFalse(migrated['transparent'])
        self.assertFalse(migrated['transparent_consent'])
        self.assertTrue(migrated['service_enabled'])
        self.assertEqual(settings['secret'], migrated['secret'])
        self.assertEqual(SUBSCRIPTION, self.manager.source_file.read_bytes())
        self.manager.dispatch('boot')
        self.manager.dispatch('enable-transparent')
        self.manager.dispatch('suspend')
        self.manager.initialize(upgrade=True)
        self.manager.dispatch('boot')
        self.assertTrue(self.system.forwarded)

    def test_unknown_or_incomplete_schema_cannot_bless_legacy_tun_flags(self):
        self.manager.apply(SUBSCRIPTION)
        self.manager.dispatch('enable-transparent')
        self.manager.dispatch('suspend')
        for schema, consent in ((0, True), (999, True), (True, True), (m.STATE_SCHEMA, 'yes')):
            settings = self.manager.settings()
            settings.update(transparent=True, state_schema=schema, transparent_consent=consent)
            self.manager.write_settings(settings)
            self.manager.initialize(upgrade=True)
            self.assertFalse(self.manager.settings()['transparent'])
            self.assertFalse(self.manager.settings()['transparent_consent'])
        settings = self.manager.settings()
        settings.update(transparent=True, transparent_consent=False)
        self.manager.write_settings(settings)
        self.manager.initialize(upgrade=True)
        self.assertFalse(self.manager.settings()['transparent'])

    def test_activation_failure_does_not_persist_consent(self):
        self.manager.apply(SUBSCRIPTION)
        self.system.fail_start = 1
        with self.assertRaises(m.Error):
            self.manager.dispatch('enable-transparent')
        self.assertFalse(self.manager.settings()['transparent'])
        self.assertFalse(self.manager.settings()['transparent_consent'])
        self.assertTrue(self.system.alive)

    def test_disable_and_genuine_removal_revoke_transparent_consent(self):
        self.manager.apply(SUBSCRIPTION)
        self.manager.dispatch('enable-transparent')
        self.manager.dispatch('disable-transparent')
        self.assertFalse(self.manager.settings()['transparent_consent'])
        self.manager.dispatch('enable-transparent')
        self.manager.dispatch('remove')
        self.manager.initialize(upgrade=False)
        self.manager.dispatch('boot')
        self.assertFalse(self.manager.settings()['transparent'])
        self.assertFalse(self.manager.settings()['transparent_consent'])
        self.assertFalse(self.system.alive)


class ConcurrentUpdateTests(unittest.TestCase):
    setUp = StateTests.setUp
    def test_watchdog_can_recover_while_download_waits_and_latest_secret_is_used(self):
        from unittest.mock import patch
        self.manager.apply(SUBSCRIPTION)
        self.manager.dispatch('enable-transparent')
        def fetch(*args):
            with self.manager.lock(blocking=False):
                self.system.alive = False
                self.manager.watchdog_tick()
                settings = self.manager.settings()
                settings['secret'] = 'secret-changed-during-download'
                self.manager.write_settings(settings)
            return SUBSCRIPTION
        with patch.object(m, 'fetch_subscription', fetch):
            self.manager.update()
        self.assertFalse(self.system.forwarded)
        self.assertEqual('secret-changed-during-download', self.manager.settings()['secret'])
        self.assertEqual('secret-changed-during-download', m.parse_yaml(self.manager.config_file.read_bytes())['secret'])

    def test_changed_url_discards_old_download(self):
        from unittest.mock import patch
        before = self.manager.config_file.read_bytes()
        def fetch(*args):
            with self.manager.lock(blocking=False):
                settings = self.manager.settings()
                settings['subscription_url'] = 'https://example.invalid/new-subscription'
                self.manager.write_settings(settings)
            return SUBSCRIPTION
        with patch.object(m, 'fetch_subscription', fetch):
            with self.assertRaises(m.Error): self.manager.update()
        self.assertEqual(before, self.manager.config_file.read_bytes())


class FetchTests(unittest.TestCase):
    def request(self, results, proxy='127.0.0.1:7891'):
        calls = []
        def run(args, **kwargs):
            calls.append(args)
            self.assertNotIn('PRIVATE_TOKEN', ' '.join(args))
            config = Path(args[args.index('--config') + 1])
            self.assertEqual(0o600, config.stat().st_mode & 0o777)
            self.assertIn('PRIVATE_TOKEN', config.read_text())
            self.assertEqual('url = "https://example.invalid/sub/PRIVATE_TOKEN"\n', config.read_text())
            result = results.pop(0)
            if result == (0, '200'):
                Path(args[args.index('--output') + 1]).write_bytes(SUBSCRIPTION)
            return subprocess.CompletedProcess(args, result[0], result[1].encode(), b'PRIVATE_TOKEN')
        return calls, lambda: m.fetch_subscription('https://example.invalid/sub/PRIVATE_TOKEN', 'OPNsense-Mihomo/1 (test)',
                                                    proxy, run=run, sleep=lambda _: None)

    def test_all_4xx_stop_after_one_request_without_fallback(self):
        for code in ['400', '401', '403', '404', '408', '429']:
            calls, fetch = self.request([(0, code)])
            with self.assertRaises(m.Error) as raised: fetch()
            self.assertEqual(1, len(calls))
            self.assertNotIn('PRIVATE_TOKEN', str(raised.exception))

    def test_timeout_and_5xx_allow_bounded_retries_then_proxy(self):
        calls, fetch = self.request([(28, '000'), (0, '503'), (0, '200')])
        self.assertEqual(SUBSCRIPTION, fetch())
        self.assertEqual(3, len(calls))
        self.assertNotIn('--socks5-hostname', calls[0])
        self.assertIn('--socks5-hostname', calls[2])

    def test_nonretryable_tls_or_dns_failures_are_not_repeated(self):
        for error in [6, 7, 35, 60]:
            calls, fetch = self.request([(error, '000')])
            with self.assertRaises(m.Error): fetch()
            self.assertEqual(1, len(calls))

    def test_four_requests_are_the_upper_bound(self):
        calls, fetch = self.request([(0, '503')] * 4)
        with self.assertRaises(m.Error): fetch()
        self.assertEqual(4, len(calls))


class YamlTests(unittest.TestCase):
    def test_alias_merge_is_valid_and_duplicate_explicit_keys_are_rejected(self):
        data = m.parse_yaml(b'default: &d {enabled: true, label: ON}\ncopy: {<<: *d, enabled: false}')
        self.assertEqual({'enabled': False, 'label': 'ON'}, data['copy'])
        with self.assertRaises(m.Error): m.parse_yaml(b'dns: {}\ndns: {}')
        with self.assertRaises(m.Error): m.parse_yaml(b'loop: &x {nested: *x}')



class IntegrationHelperTests(unittest.TestCase):
    def setUp(self):
        import shutil
        self.php = shutil.which('php')
        if not self.php:
            self.skipTest('PHP is verified separately on FreeBSD.')
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = self.root / 'conf/config.xml'
        self.config.parent.mkdir()
        self.config.write_text('''<opnsense><interfaces><lan><if>em1</if></lan></interfaces><filter/>
<OPNsense><unboundplus><forwarding><enabled>1</enabled></forwarding>
<advanced><privateaddress>10.0.0.0/8,198.18.0.0/15</privateaddress></advanced>
<dots><dot uuid="owner-dot"><enabled>1</enabled><type>dot</type><domain/><server>1.1.1.1</server><port>853</port></dot>
<dot uuid="private-dot"><enabled>1</enabled><type>forward</type><domain>home.test</domain><server>192.0.2.1</server><port>53</port></dot></dots>
</unboundplus></OPNsense></opnsense>''')
        self.original = self.xml()
        self.dot = self.root / 'var/unbound/etc/dot.conf'
        self.dot.parent.mkdir(parents=True)
        self.dot.write_text('OWNER DNS OVER TLS CONFIGURATION')

    def xml(self):
        import xml.etree.ElementTree as ET
        return ET.canonicalize(self.config.read_text(), strip_text=True)

    def helper(self, action, fallback='1'):
        return subprocess.run([self.php, str(SCRIPT.with_name('setup_unbound.php')), action, fallback],
                              env=dict(os.environ, OS_MIHOMO_ROOT=str(self.root)), capture_output=True, text=True)

    def zone(self):
        return self.root / 'usr/local/etc/unbound.opnsense.d/zz-mihomo.conf'

    def helper_state(self, result):
        lines = [line for line in result.stdout.splitlines() if line.startswith('Mihomo integration state: ')]
        self.assertEqual(1, len(lines))
        return json.loads(lines[0].split(': ', 1)[1])

    def real_dns_mode(self, mode, dnssec=False):
        """A resolver in the given Mihomo DNS mode.

        The non-validating group starts with forwarding already off, so the
        journal and private-address semantics are what changes. The DNSSEC
        control group keeps forwarding on, so that any change to it shows.
        """
        if dnssec:
            self.config.write_text(self.original.replace(
                '<forwarding>', '<general><dnssec>1</dnssec></general><forwarding>'))
        else:
            self.config.write_text(self.original.replace(
                '<forwarding><enabled>1</enabled>', '<forwarding><enabled>0</enabled>'))
        state = self.root / 'var/db/os-mihomo'
        state.mkdir(parents=True, exist_ok=True)
        settings = state / 'settings.json'
        settings.write_text(json.dumps({'dns_mode': mode}))
        settings.chmod(0o600)
        return state

    def unbound_subtree(self):
        import xml.etree.ElementTree as ET
        return ET.tostring(ET.parse(self.config).getroot().find('./OPNsense/unboundplus'))

    def test_disable_removes_the_forward_zone_even_when_the_rest_fails(self):
        # Everything after this point can throw -- a restored configuration
        # whose Unbound model no longer matches, a truncated state file -- and
        # the caller stops the core regardless. A zone left behind points the
        # router's root at a port with nothing behind it.
        self.assertEqual(0, self.helper('enable').returncode)
        self.assertTrue(self.zone().exists())
        self.config.write_text('<opnsense><interfaces/><filter/><OPNsense/></opnsense>')
        self.assertNotEqual(0, self.helper('disable').returncode)
        self.assertFalse(self.zone().exists())

    def test_a_validating_resolver_gets_no_forward_zone(self):
        # Mihomo answers fake-ip records, which carry no signature, so every
        # signed zone would fail validation. The only configuration that makes
        # Unbound accept them is the one that stops it starting.
        self.config.write_text(self.config.read_text().replace(
            '<forwarding>', '<general><dnssec>1</dnssec></general><forwarding>'))
        before = self.unbound_subtree()
        result = self.helper('enable')
        self.assertEqual(0, result.returncode)
        self.assertFalse(self.zone().exists())
        self.assertFalse(self.helper_state(result)['effective_forwarding'])
        self.assertFalse(self.helper_state(result)['dns_changed'])
        # Nothing else changes either: turning forwarding off with no zone in
        # its place would leave Unbound recursing from the root instead of
        # using the operator's upstreams. Only the TUN assignment is added.
        self.assertEqual(before, self.unbound_subtree())
        self.assertFalse((self.root / 'var/db/os-mihomo/dns-state.json').exists())
        repeated = self.helper('enable')
        self.assertEqual(0, repeated.returncode)
        self.assertIn('unchanged', repeated.stdout)
        self.assertEqual({'effective_forwarding': False, 'dns_changed': False,
                          'integration_changed': False, 'filter_changed': False,
                          'cron_changed': False}, self.helper_state(repeated))
        self.assertEqual(before, self.unbound_subtree())
        self.assertFalse(self.zone().exists())

    def test_a_validating_resolver_keeps_journal_private_address_and_forwarding(self):
        import xml.etree.ElementTree as ET
        for mode in ('redir-host', 'normal', 'fake-ip', 'unknown'):
            with self.subTest(mode=mode):
                state = self.real_dns_mode(mode, dnssec=True)
                expected = self.xml()
                before = self.unbound_subtree()
                enabled = self.helper('enable')
                self.assertEqual(0, enabled.returncode)
                self.assertFalse(self.helper_state(enabled)['effective_forwarding'])
                self.assertFalse(self.helper_state(enabled)['dns_changed'])
                self.assertFalse((state / 'dns-state.json').exists())
                self.assertEqual(before, self.unbound_subtree())
                root = ET.parse(self.config).getroot()
                self.assertEqual('1', root.findtext('./OPNsense/unboundplus/forwarding/enabled'))
                self.assertIn('198.18.0.0/15', root.findtext(
                    './OPNsense/unboundplus/advanced/privateaddress').split(','))
                self.assertFalse(self.zone().exists())
                self.assertEqual(0, self.helper('disable').returncode)
                self.assertEqual(expected, self.xml())

    def test_a_journal_left_before_validation_is_kept_for_disable_to_restore(self):
        # The state an earlier release left on a validating resolver: forwarding
        # off and the fake-ip range removed, with no forward zone behind them.
        # enable must not touch it, and the disable every start runs first puts
        # the operator's configuration back.
        import xml.etree.ElementTree as ET
        state = self.real_dns_mode('fake-ip', dnssec=True)
        self.config.write_text(self.config.read_text().replace(
            '<forwarding><enabled>1</enabled>', '<forwarding><enabled>0</enabled>'
        ).replace('10.0.0.0/8,198.18.0.0/15', '10.0.0.0/8'))
        journal = state / 'dns-state.json'
        journal.write_text(json.dumps({'forwarding': '1', 'roots': {'owner-dot': '1'},
                                      'had_fake_ip_private_address': True,
                                      'removed_fake_ip_private_address': True}))
        saved = journal.read_bytes()
        before = self.unbound_subtree()
        enabled = self.helper('enable')
        self.assertEqual(0, enabled.returncode)
        self.assertFalse(self.helper_state(enabled)['effective_forwarding'])
        self.assertEqual(saved, journal.read_bytes())
        self.assertEqual(before, self.unbound_subtree())
        self.assertFalse(self.zone().exists())
        disabled = self.helper('disable')
        self.assertEqual(0, disabled.returncode)
        self.assertTrue(self.helper_state(disabled)['dns_changed'])
        root = ET.parse(self.config).getroot()
        self.assertEqual('1', root.findtext('./OPNsense/unboundplus/forwarding/enabled'))
        self.assertIn('198.18.0.0/15', root.findtext(
            './OPNsense/unboundplus/advanced/privateaddress').split(','))
        self.assertFalse(journal.exists())

    def test_forwarding_metadata_follows_enable_and_disable(self):
        enabled = self.helper('enable')
        self.assertEqual(0, enabled.returncode)
        self.assertTrue(self.zone().exists())
        self.assertTrue(self.helper_state(enabled)['effective_forwarding'])
        self.assertTrue(self.helper_state(enabled)['dns_changed'])
        disabled = self.helper('disable')
        self.assertEqual(0, disabled.returncode)
        self.assertFalse(self.zone().exists())
        self.assertFalse(self.helper_state(disabled)['effective_forwarding'])
        self.assertTrue(self.helper_state(disabled)['dns_changed'])

    def test_tun_only_cleanup_reports_integration_change_without_dns_change(self):
        self.config.write_text(self.config.read_text().replace(
            '<forwarding><enabled>1</enabled>', '<general><dnssec>1</dnssec></general><forwarding><enabled>0</enabled>'
        ).replace('10.0.0.0/8,198.18.0.0/15', '10.0.0.0/8'))
        enabled = self.helper('enable')
        self.assertEqual(0, enabled.returncode)
        disabled = self.helper('disable')
        self.assertEqual(0, disabled.returncode)
        self.assertEqual({'effective_forwarding': False, 'dns_changed': False,
                          'integration_changed': True, 'filter_changed': True,
                          'cron_changed': False}, self.helper_state(disabled))

    def test_real_dns_modes_preserve_operator_private_address_and_journal(self):
        for mode in ('redir-host', 'normal'):
            with self.subTest(mode=mode):
                state = self.real_dns_mode(mode)
                expected = self.xml()
                before = self.unbound_subtree()
                enabled = self.helper('enable')
                self.assertEqual(0, enabled.returncode)
                # Forwarding was already off and the private address stays, so
                # the forward zone is the only DNS change.
                self.assertTrue(self.helper_state(enabled)['dns_changed'])
                self.assertTrue(self.helper_state(enabled)['effective_forwarding'])
                self.assertEqual(before, self.unbound_subtree())
                self.assertTrue(self.zone().exists())
                journal = state / 'dns-state.json'
                saved = journal.read_bytes()
                self.assertTrue(json.loads(saved)['had_fake_ip_private_address'])
                self.assertFalse(json.loads(saved)['removed_fake_ip_private_address'])
                repeated = self.helper('enable')
                self.assertEqual(0, repeated.returncode)
                self.assertEqual(saved, journal.read_bytes())
                self.assertEqual({'effective_forwarding': True, 'dns_changed': False,
                                  'integration_changed': False, 'filter_changed': False,
                                  'cron_changed': False}, self.helper_state(repeated))
                disabled = self.helper('disable')
                self.assertEqual(0, disabled.returncode)
                self.assertTrue(self.helper_state(disabled)['dns_changed'])
                self.assertFalse(self.zone().exists())
                self.assertEqual(before, self.unbound_subtree())
                self.assertEqual(expected, self.xml())
                self.assertFalse(journal.exists())

    def test_real_dns_does_not_restore_private_address_removed_later_by_operator(self):
        import xml.etree.ElementTree as ET
        self.real_dns_mode('redir-host')
        self.assertEqual(0, self.helper('enable').returncode)
        xml = ET.parse(self.config)
        private = xml.find('./OPNsense/unboundplus/advanced/privateaddress')
        private.text = '10.0.0.0/8,172.16.0.0/12'
        xml.write(self.config)
        before = self.unbound_subtree()
        disabled = self.helper('disable')
        self.assertEqual(0, disabled.returncode)
        # Removing the forward zone is the whole DNS change; the resolver's
        # configuration is left as the operator last saved it.
        self.assertTrue(self.helper_state(disabled)['dns_changed'])
        self.assertFalse(self.zone().exists())
        self.assertEqual(before, self.unbound_subtree())
        self.assertEqual('10.0.0.0/8,172.16.0.0/12', ET.parse(self.config).findtext(
            './OPNsense/unboundplus/advanced/privateaddress'))

    def test_legacy_journal_remains_until_its_removed_private_address_is_restored(self):
        import xml.etree.ElementTree as ET
        state = self.real_dns_mode('redir-host')
        self.config.write_text(self.config.read_text().replace(',198.18.0.0/15', ''))
        journal = state / 'dns-state.json'
        journal.write_text(json.dumps({'forwarding': '0', 'roots': {},
                                      'had_fake_ip_private_address': True}))
        saved = journal.read_bytes()
        before = self.unbound_subtree()
        enabled = self.helper('enable')
        self.assertEqual(0, enabled.returncode)
        # Only the forward zone changes; the legacy journal waits for disable.
        self.assertTrue(self.helper_state(enabled)['dns_changed'])
        self.assertEqual(before, self.unbound_subtree())
        self.assertEqual(saved, journal.read_bytes())
        disabled = self.helper('disable')
        self.assertEqual(0, disabled.returncode)
        self.assertTrue(self.helper_state(disabled)['dns_changed'])
        self.assertIn('198.18.0.0/15', ET.parse(self.config).findtext(
            './OPNsense/unboundplus/advanced/privateaddress').split(','))
        self.assertFalse(journal.exists())

    def test_unknown_and_fake_dns_keep_legacy_private_address_removal(self):
        import xml.etree.ElementTree as ET
        for mode in ('fake-ip', 'unknown'):
            with self.subTest(mode=mode):
                state = self.real_dns_mode(mode)
                expected = self.xml()
                enabled = self.helper('enable')
                self.assertEqual(0, enabled.returncode)
                self.assertTrue(self.helper_state(enabled)['dns_changed'])
                self.assertNotIn('198.18.0.0/15', ET.parse(self.config).findtext(
                    './OPNsense/unboundplus/advanced/privateaddress').split(','))
                self.assertTrue(json.loads((state / 'dns-state.json').read_text())['removed_fake_ip_private_address'])
                self.assertEqual(0, self.helper('disable').returncode)
                self.assertEqual(expected, self.xml())

    def test_the_legacy_forward_zone_name_is_cleared(self):
        # It sorted ahead of the generated dot.conf and never won the root
        # zone, so a copy left behind is dead weight.
        legacy = self.root / 'usr/local/etc/unbound.opnsense.d/00-mihomo.conf'
        legacy.parent.mkdir(parents=True, exist_ok=True)
        legacy.write_text('forward-zone:\n  name: "."\n  forward-addr: 127.0.0.1@1053\n')
        self.assertEqual(0, self.helper('enable').returncode)
        self.assertFalse(legacy.exists())
        self.assertTrue(self.zone().exists())

    def test_enable_disable_remove_leaves_owner_dots_alone_and_only_removes_owned_interface(self):
        import xml.etree.ElementTree as ET
        self.assertEqual(0, self.helper('enable').returncode)
        root = ET.parse(self.config).getroot()
        # The operator's own upstreams are not ours to switch off, and the
        # plugin no longer owns an entry here at all: an entry naming the root
        # as its domain makes OPNsense generate domain-insecure: "." beside it,
        # which stops the resolver starting. The forward zone is a drop-in file.
        self.assertEqual('1', root.findtext('./OPNsense/unboundplus/dots/dot[@uuid="owner-dot"]/enabled'))
        self.assertEqual('1', root.findtext('./OPNsense/unboundplus/dots/dot[@uuid="private-dot"]/enabled'))
        self.assertIsNone(root.find('./OPNsense/unboundplus/dots/dot[@uuid="b126bf65-a985-49ca-a9d2-16f156aac198"]'))
        zone = self.root / 'usr/local/etc/unbound.opnsense.d/zz-mihomo.conf'
        self.assertTrue(zone.exists(), 'the forward zone must be written under the test root')
        self.assertIn('127.0.0.1@1053', zone.read_text())
        self.assertEqual(0, self.helper('enable').returncode)
        root = ET.parse(self.config).getroot()
        self.assertEqual(1, len(root.findall('./filter/rule')))
        self.assertEqual(0, self.helper('disable').returncode)
        self.assertEqual('1', ET.parse(self.config).getroot().findtext('./OPNsense/unboundplus/dots/dot[@uuid="owner-dot"]/enabled'))
        self.assertFalse(zone.exists(), 'a forward zone left behind points at a core that is gone')
        self.assertEqual(0, self.helper('remove').returncode)
        self.assertEqual(self.original, self.xml())
        self.assertEqual('OWNER DNS OVER TLS CONFIGURATION', self.dot.read_text())
        self.assertEqual(0, self.helper('remove').returncode)
        self.assertEqual(self.original, self.xml())

    def test_disable_preserves_dns_entries_added_by_owner_while_enabled(self):
        import xml.etree.ElementTree as ET
        self.assertEqual(0, self.helper('enable', '0').returncode)
        root = ET.parse(self.config).getroot()
        dots = root.find('./OPNsense/unboundplus/dots')
        extra = ET.SubElement(dots, 'dot', uuid='new-owner-dot')
        ET.SubElement(extra, 'enabled').text = '1'
        ET.SubElement(extra, 'domain').text = 'example.test'
        ET.SubElement(extra, 'server').text = '192.0.2.2'
        ET.ElementTree(root).write(self.config)
        self.assertEqual(0, self.helper('disable').returncode)
        root = ET.parse(self.config).getroot()
        self.assertIsNotNone(root.find('./OPNsense/unboundplus/dots/dot[@uuid="new-owner-dot"]'))

    def test_state_saved_before_failed_xml_commit_is_reconciled_next_enable(self):
        import xml.etree.ElementTree as ET
        state = self.root / 'var/db/os-mihomo'
        state.mkdir(parents=True)
        (state / 'tun-state.json').write_text(json.dumps({'interface': 'opt0', 'created_interface': True, 'created_rule': True}))
        self.assertEqual(0, self.helper('enable').returncode)
        root = ET.parse(self.config).getroot()
        self.assertEqual('tun_mihomo', root.findtext('./interfaces/opt0/if'))
        self.assertEqual(1, len(root.findall('./filter/rule')))


class CronMigrationTests(unittest.TestCase):
    setUp = IntegrationHelperTests.setUp
    xml = IntegrationHelperTests.xml
    helper = IntegrationHelperTests.helper
    def test_restore_cron_is_idempotent_and_does_not_touch_dns(self):
        state = self.root / 'var/db/os-mihomo/migrate'
        state.mkdir(parents=True)
        (state / 'cron.json').write_text(json.dumps([{'command': 'mihomolocal repair', 'minutes': '30', 'hours': '*/12'}]))
        self.assertEqual(0, self.helper('restore-cron').returncode)
        first = self.xml()
        self.assertEqual(0, self.helper('restore-cron').returncode)
        self.assertEqual(first, self.xml())
        import xml.etree.ElementTree as ET
        root = ET.parse(self.config).getroot()
        self.assertEqual('mihomo sub-update', root.findtext('./cron/item/command'))
        self.assertEqual('1', root.findtext('./OPNsense/unboundplus/dots/dot[@uuid="owner-dot"]/enabled'))

    def test_uninstall_removes_only_mihomo_cron(self):
        self.config.write_text(self.config.read_text().replace('</opnsense>', '<cron><item><command>mihomo sub-update</command></item><item><command>cert renew</command></item></cron></opnsense>'))
        self.assertEqual(0, self.helper('remove').returncode)
        import xml.etree.ElementTree as ET
        root = ET.parse(self.config).getroot()
        self.assertEqual(['cert renew'], [node.text for node in root.findall('./cron/item/command')])


if __name__ == '__main__': unittest.main()


class WatchdogTests(unittest.TestCase):
    """A watchdog must never outlive the code it was started from."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.system = FakeSystem()
        self.manager = m.Manager(Path(self.temp.name), self.system)

    def test_initialize_retires_the_watchdog_so_the_next_start_reloads_the_file(self):
        calls = []
        self.system.stop_watch = lambda: calls.append('stop-watch')
        self.manager.initialize(upgrade=True)
        self.assertEqual(['stop-watch'], calls)

    def test_a_core_that_survived_the_upgrade_still_regains_a_watchdog(self):
        self.manager.initialize()
        calls = []
        self.system.watch = lambda: calls.append('watch')
        self.system.alive = True
        started = []
        self.manager.start = lambda *a, **k: started.append(a)
        self.manager.dispatch('boot')
        # start() is skipped for a running core, so boot has to spawn it itself.
        self.assertEqual(['watch'], calls)
        self.assertEqual([], started)


class ControllerMigrationTests(unittest.TestCase):
    """A stale merge YAML must not move a controller the running config already set."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.manager = m.Manager(Path(self.temp.name), FakeSystem())
        self.manager.initialize()
        self.manager.dispatch('start')

    def test_the_running_address_wins_over_the_one_left_in_the_overlay(self):
        settings = self.manager.settings()
        settings['controller'] = m.ANY_CONTROLLER
        settings.pop('switch_schema')
        self.manager.write_settings(settings)
        # The overlay still carries the loopback address the install shipped with.
        overlay = m.parse_yaml(self.manager.merge_file.read_bytes())
        overlay['external-controller'] = m.LOOPBACK_CONTROLLER
        self.manager.merge_file.write_bytes(yaml.safe_dump(overlay).encode())
        config = m.parse_yaml(self.manager.config_file.read_bytes())
        config['external-controller'] = m.ANY_CONTROLLER
        self.manager.config_file.write_bytes(yaml.safe_dump(config).encode())

        self.manager.initialize(upgrade=True)
        self.assertEqual(m.ANY_CONTROLLER, self.manager.settings()['controller'])
        self.assertNotIn('external-controller',
                         m.parse_yaml(self.manager.merge_file.read_bytes()))


class FreshDashboardTests(unittest.TestCase):
    """A fresh install comes up reachable; the presets state no settings-owned key."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.manager = m.Manager(Path(self.temp.name), FakeSystem())

    def test_a_fresh_install_binds_every_interface(self):
        self.manager.initialize()
        self.assertEqual(m.ANY_CONTROLLER, self.manager.settings()['controller'])

    def test_no_preset_states_the_controller(self):
        # A preset that named it would be absorbed and defeat the default above.
        directory = Path(m.__file__).resolve().parents[3] / 'share/mihomo/presets'
        for preset in sorted(directory.glob('*.yaml')):
            self.assertNotIn('external-controller', m.parse_yaml(preset.read_bytes()), preset.name)

    def test_an_upgrade_keeps_the_address_it_had(self):
        self.manager.initialize()
        settings = self.manager.settings()
        settings['controller'] = m.LOOPBACK_CONTROLLER
        settings.pop('switch_schema')
        self.manager.write_settings(settings)
        self.manager.dispatch('start')
        self.manager.initialize(upgrade=True)
        self.assertEqual(m.LOOPBACK_CONTROLLER, self.manager.settings()['controller'])
