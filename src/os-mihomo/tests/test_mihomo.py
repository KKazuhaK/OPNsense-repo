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
        # What ifconfig lists, by device; None when it cannot be read.
        self.addresses = {}
        self.address_reads = 0

    def running(self): return self.alive
    def ipv6_addresses(self):
        self.address_reads += 1
        return copy.deepcopy(self.addresses)
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


GLOBAL_LAN = '2001:470:1f05::1'


class Clock:
    def __init__(self, now=10000.0):
        self.now = now

    def __call__(self):
        return self.now


def interfaces(manager, system, lan=(), wan=('2a01:4f8:ffff::2',), opt1=()):
    """A routing context of a WAN, a LAN and a second LAN, and the IPv6 addresses ifconfig lists on them."""
    context = {'interfaces': [
        {'name': 'wan', 'device': 'vtnet0', 'networks': ['203.0.113.2/24'], 'wan': True},
        {'name': 'lan', 'device': 'vtnet1', 'networks': ['10.0.0.1/24'], 'wan': False},
        {'name': 'opt1', 'device': 'vtnet2', 'networks': ['10.0.1.1/24'], 'wan': False},
        {'name': 'tun', 'device': 'tun_mihomo', 'networks': ['198.18.0.1/30'], 'wan': False},
        {'name': 'lo0', 'device': 'lo0', 'networks': ['127.0.0.1/8'], 'wan': False}],
        'local_addresses': ['203.0.113.2', '10.0.0.1', '10.0.1.1']}
    manager.state.mkdir(parents=True, exist_ok=True)
    m.atomic_write(manager.state / 'routing-context.json', json.dumps(context).encode())
    system.addresses = {'vtnet0': list(wan), 'vtnet1': list(lan), 'vtnet2': list(opt1),
                        'tun_mihomo': [], 'lo0': ['::1', 'fe80::1%lo0']}


class StateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.system = FakeSystem()
        self.manager = m.Manager(Path(self.temp.name), self.system)
        self.manager.initialize()
        # A fresh install answers only captured devices; these tests exercise
        # the resolver-wide integration every upgraded router keeps.
        self.manager.write_settings(dict(self.manager.settings(), dns_scope='all'))
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
        for scope in m.DNS_SCOPES:
            for dnssec in (False, True):
                for router_dns, dns_enabled in ((True, True), (False, False), (False, True)):
                    with self.subTest(scope=scope, router_dns=router_dns, dns_enabled=dns_enabled, dnssec=dnssec):
                        self.unbound(dnssec)
                        settings = self.manager.settings()
                        settings.update(router_dns=router_dns, dns_scope=scope)
                        overlay = {'tun': {'enable': True, 'auto-route': True},
                                   'dns': {'enable': dns_enabled, 'listen': '127.0.0.1:1053'}}
                        self.manager.apply(SUBSCRIPTION, settings, overlay=overlay)
                        self.system.events.clear()
                        self.manager.dispatch('enable-transparent')
                        # Only 'all' with router DNS off asks Unbound to forward:
                        # router DNS turns it off rather than into a loop, and a
                        # captured scope is reached by redirect. A validating
                        # resolver declines the forward zone, and every path
                        # that reports it has to say so, not only start.
                        requested = dns_enabled and scope == 'all' and not router_dns
                        expected = requested and not dnssec
                        self.assertEqual(requested, 'dns-on' in self.system.events)
                        effective = ('all' if expected else 'captured' if dns_enabled and scope == 'captured'
                                     else 'off')
                        note = (m.DNSSEC_NOTE if requested and dnssec
                                else m.ROUTER_DNS_NOTE if dns_enabled and scope == 'all' and router_dns
                                else m.PRESET_NOTE if not dns_enabled and scope != 'off'
                                else m.CAPTURED_WAIT_NOTE + (' ' + m.CAPTURED_DNSSEC_NOTE if dnssec else '')
                                if effective == 'captured' else '')
                        status = self.manager.dispatch('status')
                        self.assertEqual(expected, status['dns_active'])
                        self.assertEqual(effective, status['dns_scope'])
                        self.assertFalse(status['dns_redirect'])
                        self.assertEqual(note, status['dns_note'])
                        self.assertEqual(expected, self.system.forwarded)
                        # boot and start find the core running and only republish.
                        for action in ('boot', 'start'):
                            result = self.manager.dispatch(action)
                            self.assertEqual(expected, result['dns_active'], action)
                            self.assertEqual(effective, result['dns_scope'], action)
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


class DnsScopeTests(unittest.TestCase):
    """Who Mihomo answers through the router DNS: stored, defaulted, decided and reported."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.system = FakeSystem()
        self.manager = m.Manager(Path(self.temp.name), self.system)
        self.clock = Clock()
        self.manager.clock = self.clock
        self.router(ipv6=False)
        self.manager.initialize()
        self.manager.dispatch('start')

    def tick(self, seconds=5.0):
        self.clock.now += seconds
        return self.manager.watchdog_tick()

    def observation(self):
        return json.loads(self.manager.dns_scope_file.read_bytes())

    def router(self, ipv6=False, dnssec=False, prefix=None):
        """A router that does or does not offer clients IPv6, and whether its LAN holds a global prefix.

        By default the LAN holds one exactly when IPv6 is offered, so IPv6
        reaches captured devices whenever it is offered.
        """
        config = self.manager.path('/conf/config.xml')
        config.parent.mkdir(parents=True, exist_ok=True)
        config.write_text('<opnsense>' + ('<dhcpdv6><lan><enable>1</enable></lan></dhcpdv6>' if ipv6 else '')
                          + '<OPNsense><unboundplus>' + ('<general><dnssec>1</dnssec></general>' if dnssec else '')
                          + '<dots/></unboundplus></OPNsense></opnsense>')
        self.system.dnssec = dnssec
        interfaces(self.manager, self.system, lan=['fe80::1%vtnet1'] + (
            [GLOBAL_LAN] if (ipv6 if prefix is None else prefix) else []))

    def request(self, **values):
        payload = self.manager.state / 'request.json'
        payload.write_text(json.dumps(values))
        return self.manager.dispatch('set-settings', str(payload))

    def stored(self):
        return json.loads(self.manager.settings_file.read_bytes())

    def activate(self, scope):
        self.manager.apply(SUBSCRIPTION)
        self.request(dns_scope=scope)
        self.manager.dispatch('enable-transparent')

    def test_a_fresh_install_answers_captured_devices_only(self):
        self.assertEqual('captured', self.stored()['dns_scope'])
        self.assertEqual(4, m.SWITCH_SCHEMA)
        for upgrade in (False, True):
            # A later init is an upgrade or a reinstall: the stored scope stands.
            self.manager.initialize(upgrade=upgrade)
            self.assertEqual('captured', self.stored()['dns_scope'])

    def test_an_upgrade_keeps_answering_every_device_and_renders_the_same_bytes(self):
        manual = ['tls://dot.example.net']
        # Rendered as 1.4.x rendered it: for every device.
        self.manager.apply(SUBSCRIPTION, dict(self.manager.settings(), dns_nameserver=manual, dns_scope='all'))
        self.manager.dispatch('enable-transparent')
        # Settings exactly as 1.4.x stored them: no scope, and a manual DNS
        # field the operator had switched off.
        legacy = self.stored()
        legacy.pop('dns_scope')
        self.assertFalse(legacy['dns_override'])
        self.manager.settings_file.write_text(json.dumps(legacy, indent=2) + '\n')
        self.manager.dispatch('suspend')
        before = self.manager.config_file.read_bytes()
        self.assertEqual('all', self.manager.settings()['dns_scope'])
        self.manager.initialize(upgrade=True)
        upgraded = self.stored()
        self.assertEqual('all', upgraded['dns_scope'])
        self.assertEqual(dict(legacy, dns_scope='all'), upgraded)
        # No switch re-seeding: that would turn the manual DNS back on.
        self.assertFalse(upgraded['dns_override'])
        self.assertEqual(before, self.manager.config_file.read_bytes())
        self.system.events.clear()
        self.manager.dispatch('boot')
        self.assertIn('dns-on', self.system.events)
        self.assertTrue(self.system.forwarded)

    def test_legacy_and_settingless_upgrades_keep_answering_every_device(self):
        for name, upgrade, legacy in (('legacy scripts', False, True), ('no settings', True, False)):
            with self.subTest(name), tempfile.TemporaryDirectory() as root:
                manager = m.Manager(Path(root), FakeSystem())
                if legacy:
                    migrate = manager.state / 'migrate'
                    migrate.mkdir(parents=True)
                    (migrate / 'config.yaml').write_bytes(SUBSCRIPTION)
                manager.initialize(upgrade=upgrade)
                self.assertEqual('all', json.loads(manager.settings_file.read_bytes())['dns_scope'])

    def test_the_scope_is_one_of_three_names_and_nothing_else(self):
        before = self.stored()
        events = list(self.system.events)
        for invalid in ('everything', 'All', '', True, 1, None, ['all'], {'scope': 'all'}):
            with self.subTest(invalid=invalid), self.assertRaisesRegex(m.Error, 'DNS scope'):
                self.request(dns_scope=invalid)
            self.assertEqual(before, self.stored())
            self.assertEqual(events, self.system.events)
        with self.assertRaisesRegex(m.Error, 'DNS scope'):
            self.manager.check_settings(dict(self.manager.settings(), dns_scope=False))

    def test_a_submission_without_the_scope_keeps_the_stored_one(self):
        for scope in ('off', 'all', 'captured'):
            with self.subTest(scope=scope):
                self.request(dns_scope=scope)
                self.assertEqual(scope, self.stored()['dns_scope'])
                self.request(secret='another-secret', router_dns=False, dns_fallback=True)
                self.assertEqual(scope, self.stored()['dns_scope'])
        # Router DNS with every device is never refused; it counts as off.
        dot = self.manager.path('/var/unbound/etc/dot.conf')
        dot.parent.mkdir(parents=True, exist_ok=True)
        dot.write_text('forward-addr: 1.1.1.1@853\n')
        self.request(dns_scope='all', router_dns=True)
        self.assertEqual(('all', True), (self.stored()['dns_scope'], self.stored()['router_dns']))

    def test_a_captured_scope_leaves_unbound_alone_and_arms_by_redirect(self):
        self.activate('captured')
        self.assertNotIn('dns-on', self.system.events)
        self.assertFalse(self.system.forwarded)
        self.assertEqual({'ipv6_reaching': False, 'changed': self.clock()}, self.observation())
        status = self.manager.dispatch('status')
        self.assertEqual((False, 'captured', False), (status['dns_active'], status['dns_scope'], status['dns_redirect']))
        self.assertEqual(m.CAPTURED_WAIT_NOTE, status['dns_note'])
        routing = self.manager.state / 'routing-state.json'
        routing.write_text(json.dumps({'active': True, 'dns_redirect_port': 1053}))
        status = self.manager.publish_status()
        self.assertTrue(status['dns_redirect'])
        self.assertEqual('', status['dns_note'])
        # A validating resolver is allowed; the note says what is not validated.
        self.router(dnssec=True)
        self.assertEqual(m.CAPTURED_DNSSEC_NOTE, self.manager.publish_status()['dns_note'])
        # A redirect journaled while routing is inactive is not reported armed.
        routing.write_text(json.dumps({'active': False, 'dns_redirect_port': 1053}))
        self.assertFalse(self.manager.publish_status()['dns_redirect'])
        # Nor is one left from another scope.
        self.router()
        routing.write_text(json.dumps({'active': True, 'dns_redirect_port': 1053}))
        self.request(dns_scope='off')
        status = self.manager.publish_status()
        self.assertEqual(('off', False, ''), (status['dns_scope'], status['dns_redirect'], status['dns_note']))

    def test_off_never_asks_unbound_to_forward(self):
        self.activate('off')
        for action in ('restart', 'boot', 'start'):
            self.manager.dispatch(action)
        self.assertNotIn('dns-on', self.system.events)
        self.assertFalse(self.system.forwarded)
        status = self.manager.dispatch('status')
        self.assertEqual((False, 'off', ''), (status['dns_active'], status['dns_scope'], status['dns_note']))

    def test_switching_scope_moves_the_forward_zone_with_it(self):
        self.activate('all')
        self.assertTrue(self.system.forwarded)
        self.assertEqual('all', self.manager.dispatch('status')['dns_scope'])
        self.system.events.clear()
        self.request(dns_scope='captured')
        # The stop before the restart removes the zone; nothing puts it back.
        self.assertIn('dns-off', self.system.events)
        self.assertNotIn('dns-on', self.system.events)
        self.assertFalse(self.system.forwarded)
        self.assertTrue(self.manager.settings()['transparent'])
        self.request(dns_scope='all')
        self.assertTrue(self.system.forwarded)

    def test_captured_falls_back_to_all_while_captured_devices_get_ipv6_mihomo_does_not_carry(self):
        # Refusing would make transparent routing fail on a fresh install;
        # answering every client keeps AAAA from the captured ones as before.
        self.router(ipv6=True)
        self.activate('captured')
        self.assertTrue(self.manager.settings()['transparent'])
        self.assertIn('dns-on', self.system.events)
        self.assertEqual({'ipv6_reaching': True, 'changed': self.clock()}, self.observation())
        status = self.manager.dispatch('status')
        self.assertEqual((True, 'all', m.IPV6_NOTE), (status['dns_active'], status['dns_scope'], status['dns_note']))
        # The stored choice is unchanged, and Mihomo IPv6 lifts the fallback.
        self.assertEqual('captured', self.stored()['dns_scope'])
        self.system.events.clear()
        self.request(ipv6=True)
        self.assertNotIn('dns-on', self.system.events)
        self.assertEqual('captured', self.manager.dispatch('status')['dns_scope'])
        # A configuration that cannot be read counts as offering IPv6.
        self.request(ipv6=False)
        self.manager.path('/conf/config.xml').write_text('<opnsense>')
        self.manager.dispatch('restart')
        self.assertEqual('all', self.manager.dispatch('status')['dns_scope'])

    def test_an_unknown_ipv6_observation_counts_as_offered_as_the_routing_adapter_counts_it(self):
        # Otherwise the status would call captured devices paused while the
        # adapter answers them as every device.
        self.activate('captured')
        routing = self.manager.state / 'routing-state.json'
        routing.write_text(json.dumps({'active': True, 'dns_redirect_port': 1053}))
        for name, damage in (('missing', lambda path: path.unlink()),
                             ('unreadable', lambda path: path.write_text('{'))):
            with self.subTest(name):
                self.manager.dns_scope_file.write_text(json.dumps({'ipv6_reaching': False}))
                self.assertEqual(('captured', True), (self.manager.publish_status()['dns_scope'],
                                                      self.manager.publish_status()['dns_redirect']))
                damage(self.manager.dns_scope_file)
                status = self.manager.publish_status()
                # Unbound was never asked to forward, so nobody is answered until a restart.
                self.assertEqual(('off', False), (status['dns_scope'], status['dns_redirect']))
                self.assertIn(m.IPV6_NOTE, status['dns_note'])
                self.assertIn(m.DNS_RESTART_NOTE, status['dns_note'])

    def test_every_scope_router_dns_dnssec_and_ipv6_combination_has_one_meaning(self):
        dot = self.manager.path('/var/unbound/etc/dot.conf')
        dot.parent.mkdir(parents=True, exist_ok=True)
        dot.write_text('forward-addr: 1.1.1.1@853\n')
        self.activate('captured')
        for scope in m.DNS_SCOPES:
            for router_dns in (False, True):
                for dnssec in (False, True):
                    for ipv6 in (False, True):
                        with self.subTest(scope=scope, router_dns=router_dns, dnssec=dnssec, ipv6=ipv6):
                            self.router(ipv6=ipv6, dnssec=dnssec)
                            self.system.events.clear()
                            if router_dns and ipv6:
                                # Router DNS refuses an IPv6 offer Mihomo does not
                                # carry, as it always has; the scope adds nothing.
                                with self.assertRaisesRegex(m.Error, 'offered IPv6'):
                                    self.request(dns_scope=scope, router_dns=True)
                                continue
                            self.request(dns_scope=scope, router_dns=router_dns)
                            # A validating resolver would decline every device,
                            # so a captured scope then stays as it is.
                            effective = 'all' if scope == 'captured' and ipv6 and not dnssec else scope
                            if effective == 'all' and router_dns:
                                effective = 'off'
                            status = self.manager.dispatch('status')
                            # Only an effective 'all' asks Unbound, and a
                            # validating one declines.
                            self.assertEqual(effective == 'all', 'dns-on' in self.system.events)
                            self.assertEqual(effective == 'all' and not dnssec, status['dns_active'])
                            self.assertEqual('off' if effective == 'all' and dnssec else effective, status['dns_scope'])
                            notes = status['dns_note']
                            self.assertEqual(effective == 'all' and dnssec, m.DNSSEC_NOTE in notes)
                            self.assertEqual(scope == 'all' and router_dns, m.ROUTER_DNS_NOTE in notes)
                            self.assertEqual(scope == 'captured' and ipv6 and not dnssec, m.IPV6_NOTE in notes)
                            self.assertEqual(scope == 'captured' and ipv6 and dnssec, m.IPV6_DNSSEC_NOTE in notes)
                            self.assertEqual(effective == 'captured' and dnssec, m.CAPTURED_DNSSEC_NOTE in notes)
                            # The local-name policy follows the effective scope,
                            # and router DNS asks the router for everything anyway.
                            policy = m.parse_yaml(self.manager.config_file.read_bytes())['dns'].get('nameserver-policy') or {}
                            self.assertEqual(effective == 'captured' and not router_dns,
                                             '+.10.in-addr.arpa' in policy)
                            self.assertEqual(scope, self.stored()['dns_scope'])

    # A stock OPNsense 26.7 configuration: Dnsmasq with its IPv6 range and a
    # LAN that tracks the WAN, which offers clients IPv6 whether or not a
    # prefix ever arrives.
    STOCK = ('<opnsense><interfaces><wan><enable>1</enable><if>vtnet0</if><ipaddrv6>dhcp6</ipaddrv6></wan>'
             '<lan><enable>1</enable><if>vtnet1</if><ipaddrv6>track6</ipaddrv6></lan></interfaces>'
             '<dnsmasq><enable>1</enable><dhcp_ranges uuid="a"><interface>lan</interface>'
             '<start_addr>::1000</start_addr><end_addr>::2000</end_addr><ra_mode>slaac</ra_mode>'
             '</dhcp_ranges></dnsmasq><OPNsense><unboundplus><dots/></unboundplus></OPNsense></opnsense>')

    def test_ipv6_reaches_captured_devices_only_through_a_global_address_on_a_captured_interface(self):
        config = self.manager.path('/conf/config.xml')
        config.write_text(self.STOCK)
        self.assertTrue(m.advertises_ipv6(config.read_bytes()))
        captured = {'dns_scope': 'captured'}
        cases = (
            # Without a prefix the stock offer hands captured devices nothing.
            ('stock, no prefix', {}, {}, False),
            ('global address on the LAN', {'lan': [GLOBAL_LAN]}, {}, True),
            ('global address on a second captured LAN', {'opt1': ['2a01:4f8::1']}, {}, True),
            ('WAN only', {'wan': ['2a01:4f8::2']}, {}, False),
            ('interface left out of capture', {'opt1': ['2a01:4f8::1']}, {'capture_interfaces': ['lan']}, False),
            ('selected interface', {'opt1': ['2a01:4f8::1']}, {'capture_interfaces': ['opt1']}, True),
            ('unique local, link-local and documentation only',
             {'lan': ['fd00:1::1', 'fe80::2%vtnet1', '2001:db8:1::1'], 'opt1': ['fc00::1', '2002:c000:204::1']},
             {}, False),
            ('TUN and loopback', {}, {}, False),
        )
        for name, extra, settings, expected in cases:
            with self.subTest(name):
                interfaces(self.manager, self.system, lan=['fe80::1%vtnet1'] + extra.get('lan', []),
                           wan=['fe80::9%vtnet0'] + extra.get('wan', []), opt1=extra.get('opt1', []))
                self.system.addresses['tun_mihomo'] = ['2a01:4f8::3']
                self.system.addresses['lo0'] = ['2a01:4f8::4']
                self.assertEqual(expected, self.manager.ipv6_reaching(dict(captured, **settings)))
                self.assertEqual(('', expected), self.manager.router_context(dict(captured, **settings)))
                # Only a captured scope asks.
                for scope in ('all', 'off'):
                    self.assertEqual(('', False), self.manager.router_context({'dns_scope': scope}))
        # No offer, no reach, whatever the addresses.
        interfaces(self.manager, self.system, lan=[GLOBAL_LAN])
        config.write_text('<opnsense/>')
        self.assertFalse(self.manager.ipv6_reaching(captured))
        # A fresh installation on the stock configuration answers captured devices.
        config.write_text(self.STOCK)
        interfaces(self.manager, self.system, lan=['fe80::1%vtnet1', 'fd12:3456::1'])
        self.activate('captured')
        self.assertNotIn('dns-on', self.system.events)
        status = self.manager.dispatch('status')
        self.assertEqual(('captured', False), (status['dns_scope'], status['dns_active']))
        self.assertNotIn(m.IPV6_NOTE, status['dns_note'])

    def test_what_cannot_be_read_counts_as_reaching(self):
        config = self.manager.path('/conf/config.xml')
        captured = {'dns_scope': 'captured'}
        for content in (b"<?xml version='1.0' encoding='x-unknown'?><opnsense/>",
                        b"<?xml version='1.0' encoding='shift_jis'?><opnsense/>", b'<opnsense>', b'', None):
            with self.subTest(content=content):
                # Even without any global address anywhere.
                interfaces(self.manager, self.system)
                self.system.addresses['vtnet0'] = []
                if content is None:
                    config.unlink(missing_ok=True)
                else:
                    config.write_bytes(content)
                self.assertTrue(self.manager.ipv6_reaching(captured))
        self.router(ipv6=True, prefix=False)
        self.assertFalse(self.manager.ipv6_reaching(captured))
        # An interface list ifconfig could not give.
        self.system.addresses = None
        self.assertTrue(self.manager.ipv6_reaching(captured))
        with mock.patch.object(self.system, 'ipv6_addresses', side_effect=m.Error('ifconfig failed')):
            self.assertTrue(self.manager.ipv6_reaching(captured))
        # Without a routing context every interface but loopback and the TUN
        # counts: the WAN's address now does, and nothing at all does not.
        self.router(ipv6=True, prefix=False)
        for damage in (lambda path: path.unlink(), lambda path: path.write_text('{'),
                       lambda path: path.write_text(json.dumps({'interfaces': [{'device': 'vtnet1'}]}))):
            with self.subTest(damage=damage):
                self.router(ipv6=True, prefix=False)
                damage(self.manager.state / 'routing-context.json')
                self.assertTrue(self.manager.ipv6_reaching(captured))
                self.system.addresses['vtnet0'] = ['fe80::9%vtnet0']
                self.system.addresses['tun_mihomo'] = ['2a01:4f8::3']
                self.system.addresses['lo0'] = ['2a01:4f8::4']
                self.assertFalse(self.manager.ipv6_reaching(captured))
        # And a start counts what it cannot read as reaching instead of failing.
        self.router(ipv6=False, prefix=True)
        self.activate('captured')
        self.assertEqual('captured', self.manager.dispatch('status')['dns_scope'])
        config.write_bytes(b'<opnsense>')
        self.manager.dispatch('restart')
        self.assertTrue(self.manager.settings()['transparent'])
        status = self.manager.dispatch('status')
        self.assertEqual(('all', m.IPV6_NOTE), (status['dns_scope'], status['dns_note']))

    def test_the_watchdog_follows_ipv6_reaching_captured_devices_both_ways(self):
        self.activate('captured')
        log = self.manager.path('/var/log/mihomo.log')
        self.system.events.clear()
        # One look disagreeing is not enough.
        self.router(ipv6=True)
        status = self.tick()
        self.assertEqual(('captured', False), (status['dns_scope'], status['dns_active']))
        self.assertEqual([], self.system.events)
        # The second look in a row moves towards every device at once, and a
        # start that decided otherwise less than ten minutes ago holds nothing
        # back. What the new scope runs is validated before anything stops.
        status = self.tick()
        self.assertEqual(['validate', 'dns-off', 'stop', 'dns-off', 'validate', 'start-transparent',
                          'assign-tun', 'dns-on'], self.system.events)
        self.assertEqual((True, 'all', m.IPV6_NOTE), (status['dns_active'], status['dns_scope'], status['dns_note']))
        self.assertTrue(self.observation()['ipv6_reaching'])
        self.assertEqual(self.clock(), self.observation()['changed'])
        self.assertEqual('captured', self.stored()['dns_scope'])
        # Every device, so the local-name policy is gone from the core.
        policy = m.parse_yaml(self.manager.config_file.read_bytes())['dns'].get('nameserver-policy') or {}
        self.assertNotIn('+.10.in-addr.arpa', policy)
        lines = log.read_text().splitlines()
        self.assertTrue(lines[-2].endswith(m.IPV6_MOVE_LOGS[True]))
        self.assertTrue(lines[-1].endswith(m.IPV6_MOVED_LOG % 'every device'))
        self.assertEqual(status, self.manager.dispatch('status') | {'updated': status['updated']})
        # IPv6 gone: confirmed, but held for ten minutes after that change.
        self.router(ipv6=False)
        self.system.events.clear()
        changed = self.clock()
        while self.clock() + 5 < changed + m.SCOPE_CHANGE_INTERVAL:
            status = self.tick()
            self.assertEqual('all', status['dns_scope'])
        self.assertEqual([], self.system.events)
        self.assertTrue(self.observation()['waiting'])
        # One note, in place of the one that said captured devices get IPv6.
        self.assertEqual(m.IPV6_WAIT_NOTE, status['dns_note'])
        status = self.tick()
        self.assertEqual(['validate', 'dns-off', 'stop', 'dns-off', 'validate', 'start-transparent', 'assign-tun'],
                         self.system.events)
        self.assertEqual((False, 'captured', m.CAPTURED_WAIT_NOTE),
                         (status['dns_active'], status['dns_scope'], status['dns_note']))
        self.assertFalse(self.system.forwarded)
        self.assertNotIn('waiting', self.observation())
        policy = m.parse_yaml(self.manager.config_file.read_bytes())['dns'].get('nameserver-policy') or {}
        self.assertIn('+.10.in-addr.arpa', policy)
        self.assertTrue(log.read_text().splitlines()[-1].endswith(m.IPV6_MOVED_LOG % 'captured devices'))
        # Back again within ten minutes: towards every device is never held.
        self.router(ipv6=True)
        self.tick(m.IPV6_POLL)
        self.assertEqual('all', self.tick()['dns_scope'])

    def test_a_one_look_blip_changes_nothing_and_an_answer_that_reverts_clears_the_wait(self):
        self.activate('captured')
        self.system.events.clear()
        for _ in range(3):
            self.router(ipv6=True)
            self.assertEqual('captured', self.tick(m.IPV6_POLL)['dns_scope'])
            self.router(ipv6=False)
            self.assertEqual('captured', self.tick()['dns_scope'])
        self.assertEqual([], self.system.events)
        # Held on the way back, then IPv6 returns before the wait is over.
        self.router(ipv6=True)
        self.tick(m.IPV6_POLL)
        self.assertEqual('all', self.tick()['dns_scope'])
        self.router(ipv6=False)
        self.tick(m.IPV6_POLL)
        self.tick()
        self.assertTrue(self.observation()['waiting'])
        self.router(ipv6=True)
        self.system.events.clear()
        status = self.tick(m.IPV6_POLL)
        self.assertEqual(('all', m.IPV6_NOTE), (status['dns_scope'], status['dns_note']))
        self.assertNotIn('waiting', self.observation())
        self.assertEqual([], self.system.events)

    def test_the_watchdog_looks_every_thirty_seconds_and_reads_config_only_when_it_changes(self):
        self.activate('captured')
        self.router(ipv6=True, prefix=False)
        parsed = []
        original = m.advertises_ipv6

        def counted(content):
            parsed.append(content)
            return original(content)

        with mock.patch.object(m, 'advertises_ipv6', side_effect=counted):
            self.tick()
            reads, parses = self.system.address_reads, len(parsed)
            self.assertEqual(1, parses)
            for _ in range(int(m.IPV6_POLL // 5) - 1):
                self.tick()
            self.assertEqual((reads, parses), (self.system.address_reads, len(parsed)))
            self.tick()
            self.assertEqual((reads + 1, parses), (self.system.address_reads, len(parsed)))
            # A change of either input is looked at on the next tick.
            self.router(ipv6=True, prefix=False)
            self.manager.path('/conf/config.xml').write_text(self.STOCK)
            self.tick()
            self.assertEqual((reads + 2, parses + 1), (self.system.address_reads, len(parsed)))
            interfaces(self.manager, self.system, lan=['fe80::1%vtnet1'], opt1=['fd00::1'])
            os.utime(self.manager.state / 'routing-context.json', ns=(1, 1))
            self.tick()
            self.assertEqual((reads + 3, parses + 1), (self.system.address_reads, len(parsed)))
        # Nothing is looked at while the answer cannot change the scope.
        for change in ({'ipv6': True}, {'dns_scope': 'all'}, {'dns_scope': 'off'}):
            with self.subTest(change=change):
                self.request(**dict({'ipv6': False, 'dns_scope': 'captured'}, **change))
                reads = self.system.address_reads
                for _ in range(8):
                    self.tick(m.IPV6_POLL)
                self.assertEqual(reads, self.system.address_reads)

    def test_a_change_that_fails_is_rolled_back_and_retried_later(self):
        self.activate('captured')
        log = self.manager.path('/var/log/mihomo.log')
        self.router(ipv6=True)
        self.tick()
        self.system.fail_start = 1
        self.system.events.clear()
        status = self.tick()
        # The new scope's start failed; the old one is running again.
        self.assertEqual(2, self.system.events.count('start-transparent'))
        self.assertTrue(self.system.alive)
        self.assertEqual(('captured', False), (status['dns_scope'], status['dns_active']))
        self.assertIn(m.IPV6_FAILED_NOTE % 'Injected startup failure.', status['dns_note'])
        self.assertFalse(self.observation()['ipv6_reaching'])
        self.assertIn(m.IPV6_MOVE_FAILED_LOG % ('Injected startup failure.', ''), log.read_text())
        # Every later status says so too, until a start replaces the record.
        self.assertIn(m.IPV6_FAILED_NOTE % 'Injected startup failure.', self.manager.dispatch('status')['dns_note'])
        # Tried again a minute later, not every tick.
        self.system.events.clear()
        started = self.clock()
        while self.clock() + 5 < started + m.retry_delay(1, True):
            self.assertEqual('captured', self.tick()['dns_scope'])
        self.assertEqual([], self.system.events)
        status = self.tick()
        self.assertEqual(('all', True, m.IPV6_NOTE), (status['dns_scope'], status['dns_active'], status['dns_note']))
        self.assertNotIn('failed', self.observation())

    def test_a_change_whose_rollback_fails_leaves_the_service_stopped_with_direct_dns(self):
        self.activate('captured')
        self.router(ipv6=True)
        self.tick()
        self.system.fail_start = 2
        status = self.tick()
        reason = m.IPV6_STOPPED_ERROR % 'Injected startup failure.'
        self.assertFalse(self.system.alive)
        self.assertFalse(self.system.forwarded)
        self.assertEqual((False, False, reason), (status['running'], status['dns_active'], status['error']))
        self.assertFalse(self.manager.scope_move_file.exists())
        self.assertIn('the service is stopped', self.manager.path('/var/log/mihomo.log').read_text())
        # Nothing restarts it behind the administrator's back, and the status
        # keeps saying why.
        self.system.events.clear()
        for _ in range(3):
            self.assertEqual(reason, self.tick(m.SCOPE_CHANGE_INTERVAL)['error'])
        self.assertEqual(reason, self.manager.dispatch('status')['error'])
        self.assertNotIn('start-transparent', self.system.events)
        # A stop replaces the reason, and a start decides afresh.
        self.manager.dispatch('stop')
        self.assertEqual('', self.manager.dispatch('status')['error'])
        self.manager.dispatch('start')
        self.assertEqual(('all', ''), (self.manager.dispatch('status')['dns_scope'],
                                       self.manager.dispatch('status')['error']))

    def test_a_forward_zone_neither_start_could_remove_is_retried_until_it_goes(self):
        self.router(ipv6=True)
        self.activate('captured')
        self.assertTrue(self.system.forwarded)
        self.router(ipv6=False)
        self.clock.now += m.SCOPE_CHANGE_INTERVAL
        original = self.system.dns
        failing = {'on': True}

        def dns(enabled, settings):
            if not enabled and failing['on']:
                self.system.events.append('dns-off-failed')
                raise m.Error('Injected DNS restoration failure.')
            return original(enabled, settings)

        self.system.dns = dns
        self.tick()
        self.system.events.clear()
        status = self.tick()
        # The stop and the rollback both failed to remove the zone, and so did
        # one more try: the change stays journaled and the status errs towards
        # the integration still being there.
        self.assertEqual(['validate', 'dns-off-failed', 'stop', 'dns-off-failed', 'dns-off-failed'],
                         self.system.events)
        self.assertFalse(self.system.alive)
        self.assertTrue(self.system.forwarded)
        self.assertTrue(self.manager.scope_move_file.exists())
        reason = self.manager.stopped_reason()
        self.assertTrue(reason.startswith(m.IPV6_STOPPED_ERROR % ''))
        self.assertEqual((True, reason + ' Direct DNS recovery failed and will be retried.'),
                         (status['dns_active'], status['error']))
        # Every tick tries again until it works.
        for _ in range(2):
            status = self.tick()
            self.assertTrue(status['dns_active'])
            self.assertTrue(self.system.forwarded)
        failing['on'] = False
        status = self.tick()
        self.assertFalse(self.system.forwarded)
        self.assertFalse(self.manager.scope_move_file.exists())
        self.assertEqual((False, reason + ' Direct DNS was restored.'), (status['dns_active'], status['error']))
        self.system.events.clear()
        status = self.tick()
        self.assertEqual((False, reason), (status['dns_active'], status['error']))
        self.assertNotIn('dns-off', self.system.events)

    def attempts(self):
        """When the watchdog validated a new scope's configuration, by the fake clock."""
        times = []
        original = self.system.validate

        def validate(candidate):
            times.append(self.clock())
            original(candidate)

        self.system.validate = validate
        return times

    def test_a_configuration_the_new_scope_cannot_run_leaves_the_service_alone_and_backs_off(self):
        self.activate('captured')
        self.router(ipv6=True)
        self.tick()
        self.system.reject = True
        times = self.attempts()
        self.system.events.clear()
        status = self.tick()
        self.assertEqual(['validate'], self.system.events)
        self.assertTrue(self.system.alive)
        self.assertEqual(('captured', False), (status['dns_scope'], status['dns_active']))
        self.assertIn(m.IPV6_FAILED_NOTE % 'Rejected test config.', status['dns_note'])
        self.assertIn(m.IPV6_RETRY_LOG % ('Rejected test config.); the current scope stays', 60),
                      self.manager.path('/var/log/mihomo.log').read_text())
        # Each failure in a row doubles the wait, and nothing ever stops.
        while self.clock() < times[0] + 60 + 120 + 240 + 20:
            self.tick()
        gaps = [later - earlier for earlier, later in zip(times, times[1:])]
        self.assertEqual(3, len(gaps))
        for gap, delay in zip(gaps, (60, 120, 240)):
            self.assertTrue(delay <= gap < delay + 10, (gap, delay))
        self.assertNotIn('stop', self.system.events)
        # Once it validates, the change goes through and the count starts over.
        self.system.reject = False
        while not self.system.forwarded:
            self.tick()
        self.assertNotIn('failed', self.observation())
        self.tick()
        self.assertEqual((None, 0), (self.manager._reach['retry_at'], self.manager._reach['failures']))

    def test_a_change_back_to_captured_devices_that_fails_waits_the_full_interval(self):
        self.router(ipv6=True)
        self.activate('captured')
        self.router(ipv6=False)
        self.clock.now += m.SCOPE_CHANGE_INTERVAL
        self.system.reject = True
        times = self.attempts()
        self.system.events.clear()
        while len(times) < 2:
            self.tick()
        self.assertTrue(m.SCOPE_CHANGE_INTERVAL <= times[1] - times[0] < m.SCOPE_CHANGE_INTERVAL + 10)
        self.assertNotIn('stop', self.system.events)
        self.assertTrue(self.system.forwarded)

    def test_a_failure_the_answer_then_reverts_on_is_forgotten(self):
        self.activate('captured')
        self.router(ipv6=True)
        self.tick()
        self.system.fail_start = 1
        self.assertIn(m.IPV6_FAILED_NOTE % 'Injected startup failure.', self.tick()['dns_note'])
        self.router(ipv6=False)
        status = self.tick(m.IPV6_POLL)
        self.assertNotIn('failed', self.observation())
        self.assertNotIn(m.IPV6_FAILED_NOTE % 'Injected startup failure.', status['dns_note'])
        self.assertEqual((None, 0), (self.manager._reach['retry_at'], self.manager._reach['failures']))

    def test_nothing_is_listed_while_the_router_offers_no_ipv6(self):
        self.activate('captured')
        self.router(ipv6=False, prefix=True)
        reads = self.system.address_reads
        for _ in range(8):
            self.assertEqual('captured', self.tick(m.IPV6_POLL)['dns_scope'])
        self.assertEqual(reads, self.system.address_reads)

    def test_a_start_with_an_unfinished_change_settles_it(self):
        self.activate('captured')
        self.manager.dispatch('stop')
        self.manager.scope_move_file.write_text('{"ipv6_reaching": true}\n')
        self.manager.dispatch('start')
        self.assertFalse(self.manager.scope_move_file.exists())
        self.system.events.clear()
        self.tick()
        self.assertNotIn('stop', self.system.events)

    def test_a_start_keeps_every_device_until_the_watchdog_confirms_the_way_back(self):
        self.router(ipv6=True)
        self.activate('captured')
        # A WAN reconnect restarts before the delegated prefix is back.
        self.router(ipv6=True, prefix=False)
        for action in ('wan-restart', 'restart'):
            with self.subTest(action=action):
                self.clock.now += 60
                self.manager.dispatch(action)
                status = self.manager.dispatch('status')
                self.assertEqual((True, 'all'), (status['dns_active'], status['dns_scope']))
                # Kept, and the wait back counts from this start.
                self.assertEqual({'ipv6_reaching': True, 'changed': self.clock()}, self.observation())
        changed = self.clock()
        # The prefix is back: nothing to change.
        self.router(ipv6=True)
        self.system.events.clear()
        for _ in range(8):
            self.assertEqual('all', self.tick()['dns_scope'])
        self.assertNotIn('stop', self.system.events)
        # Gone for good: the watchdog confirms it and waits out the interval.
        self.router(ipv6=True, prefix=False)
        while self.clock() + 5 < changed + m.SCOPE_CHANGE_INTERVAL:
            self.assertEqual('all', self.tick()['dns_scope'])
        self.assertEqual('captured', self.tick()['dns_scope'])
        # A start that finds no reach and none recorded decides as it looks.
        self.manager.dispatch('restart')
        self.assertEqual('captured', self.manager.dispatch('status')['dns_scope'])

    def test_an_answer_this_configuration_does_not_depend_on_is_recorded_as_no(self):
        self.router(ipv6=True)
        self.activate('captured')
        self.assertTrue(self.observation()['ipv6_reaching'])
        # Mihomo carries IPv6: the answer changes nothing, so no later start keeps it.
        self.request(ipv6=True)
        self.assertFalse(self.observation()['ipv6_reaching'])
        self.router(ipv6=True, prefix=False)
        self.request(ipv6=False)
        self.assertEqual('captured', self.manager.dispatch('status')['dns_scope'])

    def test_the_first_transparent_start_has_the_filter_write_a_missing_routing_context(self):
        # The WAN holds a global address and the LAN none, and no filter
        # reload has written the routing context since installation.
        self.router(ipv6=True, prefix=False)
        context = self.manager.state / 'routing-context.json'
        saved = context.read_bytes()
        context.unlink()

        def ensure():
            self.system.events.append('filter-reload')
            if not context.exists():
                context.write_bytes(saved)

        self.system.ensure_routing_context = ensure
        self.system.events.clear()
        self.activate('captured')
        self.assertEqual(1, self.system.events.count('filter-reload'))
        self.assertLess(self.system.events.index('filter-reload'), self.system.events.index('start-transparent'))
        self.assertEqual('captured', self.manager.dispatch('status')['dns_scope'])
        self.assertFalse(self.observation()['ipv6_reaching'])
        # Without it the look would count the WAN.
        context.unlink()
        self.assertTrue(self.manager.ipv6_reaching(self.manager.settings()))

    def test_a_validating_resolver_keeps_a_captured_scope_whatever_reaches_its_devices(self):
        self.router(ipv6=False, dnssec=True)
        self.activate('captured')
        self.router(ipv6=True, dnssec=True)
        self.system.events.clear()
        for _ in range(8):
            status = self.tick()
        # Every device would decline and answer nobody: no restart, and one
        # note says what reaches captured devices.
        self.assertNotIn('stop', self.system.events)
        self.assertEqual(('captured', False), (status['dns_scope'], status['dns_active']))
        self.assertIn(m.IPV6_DNSSEC_NOTE, status['dns_note'])
        self.assertIn(m.CAPTURED_DNSSEC_NOTE, status['dns_note'])
        self.assertNotIn(m.IPV6_NOTE, status['dns_note'])
        # A start decides the same.
        self.manager.dispatch('restart')
        status = self.manager.dispatch('status')
        self.assertEqual('captured', status['dns_scope'])
        self.assertIn(m.IPV6_DNSSEC_NOTE, status['dns_note'])
        self.assertEqual({'ipv6_reaching': False, 'ipv6_dnssec': True},
                         {key: self.observation().get(key) for key in ('ipv6_reaching', 'ipv6_dnssec')})
        # DNSSEC off: the fallback is possible again and follows.
        self.router(ipv6=True, dnssec=False)
        for _ in range(8):
            status = self.tick()
        self.assertEqual(('all', True, m.IPV6_NOTE), (status['dns_scope'], status['dns_active'], status['dns_note']))
        # DNSSEC back on while every device runs: the resolver is handed back,
        # and leaving the fallback that now answers nobody is not held back.
        self.router(ipv6=True, dnssec=True)
        self.system.events.clear()
        for _ in range(8):
            status = self.tick()
        self.assertIn('stop', self.system.events)
        self.assertEqual('captured', status['dns_scope'])
        self.assertIn(m.IPV6_DNSSEC_NOTE, status['dns_note'])

    def test_the_applied_configuration_is_read_only_when_it_changes(self):
        self.activate('captured')
        self.router(ipv6=True, prefix=False)
        reads = []
        original = Path.read_bytes

        def counted(path):
            if path == self.manager.config_file:
                reads.append(path)
            return original(path)

        with mock.patch.object(Path, 'read_bytes', counted):
            for _ in range(4):
                self.tick()
        self.assertEqual([], reads)

    def test_a_restart_after_a_change_keeps_the_scope_and_when_it_changed(self):
        self.activate('captured')
        self.router(ipv6=True)
        self.tick()
        self.tick()
        changed = self.observation()['changed']
        for action in ('restart', 'start', 'boot'):
            with self.subTest(action=action):
                self.clock.now += 60
                self.manager.dispatch(action)
                status = self.manager.dispatch('status')
                self.assertEqual((True, 'all', m.IPV6_NOTE),
                                 (status['dns_active'], status['dns_scope'], status['dns_note']))
                self.assertEqual({'ipv6_reaching': True, 'changed': changed}, self.observation())
        # The wait back to captured devices still counts from the change.
        self.router(ipv6=False)
        self.clock.now = changed + m.SCOPE_CHANGE_INTERVAL - 15
        self.tick()
        self.assertEqual('all', self.tick()['dns_scope'])
        self.assertEqual('captured', self.tick(10)['dns_scope'])
        # A stored time from before a reboot holds nothing back.
        self.router(ipv6=True)
        self.tick(m.IPV6_POLL)
        self.tick()
        record = self.observation()
        self.manager.dns_scope_file.write_text(json.dumps(dict(record, changed=self.clock() + 10 ** 6)))
        self.router(ipv6=False)
        self.tick(m.IPV6_POLL)
        self.assertEqual('captured', self.tick()['dns_scope'])

    def test_a_crash_after_a_change_to_every_device_restores_direct_dns_whatever_the_fallback(self):
        self.activate('captured')
        self.manager.write_settings(dict(self.manager.settings(), dns_fallback=False))
        self.router(ipv6=True)
        self.tick()
        self.assertTrue(self.tick()['dns_active'])
        self.system.alive = False
        self.system.events.clear()
        status = self.tick()
        self.assertIn('dns-off', self.system.events)
        self.assertFalse(self.system.forwarded)
        self.assertFalse(status['dns_active'])

    def test_router_dns_reports_a_later_ipv6_offer_as_its_own_error(self):
        dot = self.manager.path('/var/unbound/etc/dot.conf')
        dot.parent.mkdir(parents=True, exist_ok=True)
        dot.write_text('forward-addr: 1.1.1.1@853\n')
        self.activate('captured')
        self.request(router_dns=True)
        self.assertEqual('captured', self.manager.dispatch('status')['dns_scope'])
        self.router(ipv6=True)
        self.system.events.clear()
        for _ in range(3):
            status = self.tick()
            self.assertIn('IPv6 is now being advertised', status['error'])
            self.assertEqual('captured', status['dns_scope'])
        # The error is router DNS's own answer: no scope change restarts anything.
        self.assertEqual([], self.system.events)

    def test_the_status_keeps_the_scope_through_the_mirror_and_the_watchdog(self):
        self.activate('captured')
        self.manager.dispatch('start')
        self.assertEqual('captured', self.status()['dns_scope'])
        self.assertEqual('captured', self.manager.watchdog_tick()['dns_scope'])
        self.assertEqual('captured', self.status()['dns_scope'])
        self.manager.dispatch('stop')
        self.assertEqual(('off', ''), (self.status()['dns_scope'], self.status()['dns_note']))

    def status(self):
        return json.loads(self.manager.status_file.read_bytes())

    def test_a_crashed_captured_core_withdraws_capture_without_touching_unbound(self):
        self.activate('captured')
        for fallback in (True, False):
            with self.subTest(dns_fallback=fallback):
                self.manager.write_settings(dict(self.manager.settings(), dns_fallback=fallback))
                self.system.alive = False
                self.system.events.clear()
                status = self.manager.watchdog_tick()
                self.assertEqual(['destroy-tun'], self.system.events)
                self.assertFalse(status['dns_active'])
                self.assertEqual('off', status['dns_scope'])
                self.manager.dispatch('start')

    def test_a_captured_scope_answering_every_device_fails_open_whatever_the_fallback(self):
        # The page hides Restore direct DNS on exit for a captured scope, so the
        # switch must not decide a crash while that scope runs as all devices.
        self.router(ipv6=True)
        self.activate('captured')
        self.manager.write_settings(dict(self.manager.settings(), dns_fallback=False))
        self.assertTrue(self.system.forwarded)
        self.system.alive = False
        self.system.events.clear()
        status = self.manager.watchdog_tick()
        self.assertIn('dns-off', self.system.events)
        self.assertFalse(self.system.forwarded)
        self.assertFalse(status['dns_active'])
        # All devices still follows the switch.
        self.manager.dispatch('start')
        self.request(dns_scope='all')
        self.assertTrue(self.system.forwarded)
        self.system.alive = False
        self.assertTrue(self.manager.watchdog_tick()['dns_active'])
        self.assertTrue(self.system.forwarded)

    def test_the_scope_matrix(self):
        full = {'tun': {'enable': True}, 'dns': {'enable': True, 'listen': '127.0.0.1:1053'}}
        tun_only = {'tun': {'enable': True}, 'dns': {'enable': False, 'listen': ''}}
        proxy = {'tun': {'enable': False}, 'dns': {'enable': False, 'listen': ''}}
        moved = {'tun': {'enable': True}, 'dns': {'enable': True, 'listen': '127.0.0.1:1054'}}
        carried = {'ipv6': True, 'tun': {'enable': True},
                   'dns': {'enable': True, 'listen': '127.0.0.1:1053', 'ipv6': True}}
        for scope in m.DNS_SCOPES:
            for router_dns in (False, True):
                for ipv6 in (False, True):
                    settings = {'dns_scope': scope, 'router_dns': router_dns}
                    with self.subTest(scope=scope, router_dns=router_dns, ipv6=ipv6):
                        expected = scope
                        if scope == 'captured' and ipv6:
                            expected = 'all'
                        if expected == 'all' and router_dns:
                            expected = 'off'
                        found = m.effective_dns_scope(settings, full, ipv6)
                        self.assertEqual(expected, found[0])
                        self.assertEqual(expected == 'all', m.dns_requested(settings, full, ipv6))
                        note = (m.IPV6_ROUTER_DNS_NOTE if scope == 'captured' and ipv6 and router_dns
                                else m.ROUTER_DNS_NOTE if expected == 'off' and scope != 'off'
                                else m.IPV6_NOTE if scope == 'captured' and ipv6 else '')
                        self.assertEqual(note, found[1])
                        # Mihomo carrying IPv6 lifts the fallback.
                        self.assertEqual('captured' if scope == 'captured' else expected,
                                         m.effective_dns_scope(settings, carried, ipv6)[0])
                        for shape in (tun_only, moved):
                            self.assertEqual(('off', m.PRESET_NOTE if scope != 'off' else ''),
                                             m.effective_dns_scope(settings, shape, ipv6))
                        self.assertEqual(('off', ''), m.effective_dns_scope(settings, proxy, ipv6))
        # Without a stored scope a router answers every device, as before.
        self.assertEqual(('all', ''), m.effective_dns_scope({}, full))

    def test_the_redirect_hook_check_covers_a_captured_scope(self):
        with tempfile.TemporaryDirectory() as state, mock.patch.object(m, 'STATE', state):
            system = m.System()
            config = {'tun': {'enable': True}, 'dns': {'enable': True, 'listen': '127.0.0.1:1053'}}
            hooked = []

            def run(args, **kwargs):
                self.assertEqual(['/sbin/pfctl', '-sn'], args)
                return subprocess.CompletedProcess(args, 0, b''.join(hooked), b'')

            with mock.patch.object(system, 'run', side_effect=run) as called:
                for scope, listen, expected in (('captured', '127.0.0.1:1053', True), ('all', '127.0.0.1:1053', False),
                                                ('off', '127.0.0.1:1053', False), ('captured', '127.0.0.1:1054', False)):
                    with self.subTest(scope=scope, listen=listen):
                        (Path(state) / 'settings.json').write_text(json.dumps({'dns_scope': scope}))
                        config['dns']['listen'] = listen
                        (Path(state) / 'config.yaml').write_text(yaml.safe_dump(config))
                        self.assertEqual(expected, system.redirect_hook_missing())
                hooked.append(b'rdr-anchor "mihomo" all\n')
                config['dns']['listen'] = '127.0.0.1:1053'
                (Path(state) / 'settings.json').write_text(json.dumps({'dns_scope': 'captured'}))
                (Path(state) / 'config.yaml').write_text(yaml.safe_dump(config))
                self.assertFalse(system.redirect_hook_missing())
                # Nothing to redirect needs no look at the ruleset.
                self.assertEqual(2, called.call_count)


class Ipv6RestrictedTests(unittest.TestCase):
    """The declaration that captured devices get no IPv6: stored, and what it changes once IPv6 is detected."""

    setUp = DnsScopeTests.setUp
    tick = DnsScopeTests.tick
    observation = DnsScopeTests.observation
    router = DnsScopeTests.router
    request = DnsScopeTests.request
    stored = DnsScopeTests.stored
    activate = DnsScopeTests.activate

    def upstreams(self):
        dot = self.manager.path('/var/unbound/etc/dot.conf')
        dot.parent.mkdir(parents=True, exist_ok=True)
        dot.write_text('forward-addr: 1.1.1.1@853\n')

    def policy(self):
        return m.parse_yaml(self.manager.config_file.read_bytes())['dns'].get('nameserver-policy') or {}

    def test_it_is_off_until_stored_and_a_submission_without_it_keeps_it(self):
        # Neither a fresh installation nor an upgrade stores it.
        self.assertNotIn('ipv6_clients_restricted', self.stored())
        self.assertFalse(m.ipv6_restricted(self.manager.settings()))
        self.manager.initialize(upgrade=True)
        self.assertNotIn('ipv6_clients_restricted', self.stored())
        self.request(ipv6_clients_restricted=True)
        self.assertIs(True, self.stored()['ipv6_clients_restricted'])
        # A partial submission, an upgrade and a reinstall keep it.
        self.request(secret='another-secret', router_dns=False, dns_fallback=True, dns_scope='off')
        self.assertIs(True, self.stored()['ipv6_clients_restricted'])
        for upgrade in (True, False):
            self.manager.initialize(upgrade=upgrade)
            self.assertIs(True, self.stored()['ipv6_clients_restricted'])
        # Only a boolean is stored, and a refusal changes nothing.
        before = self.stored()
        events = list(self.system.events)
        for invalid in ('yes', 'true', 1, 0, '', None, [True]):
            with self.subTest(invalid=invalid), self.assertRaisesRegex(m.Error, 'boolean'):
                self.request(ipv6_clients_restricted=invalid)
            self.assertEqual(before, self.stored())
            self.assertEqual(events, self.system.events)
        self.request(ipv6_clients_restricted=False)
        self.assertIs(False, self.stored()['ipv6_clients_restricted'])
        self.assertIn('ipv6_clients_restricted', m.BACKUP_KEYS)

    def test_router_dns_starts_with_a_declared_ipv6_offer_and_the_status_notes_it(self):
        self.upstreams()
        self.activate('captured')
        self.router(ipv6=True)
        # Without the declaration router DNS refuses the offer, as it always has.
        before = self.stored()
        with self.assertRaisesRegex(m.Error, 'offered IPv6'):
            self.request(router_dns=True)
        self.assertEqual(before, self.stored())
        self.system.events.clear()
        self.request(router_dns=True, ipv6_clients_restricted=True)
        self.assertTrue(self.manager.settings()['transparent'])
        self.assertIn('check-router-dns', self.system.events)
        self.assertNotIn('dns-on', self.system.events)
        # An offer the configuration's scope does not fall back over is recorded as no.
        self.assertIs(False, self.observation()['ipv6_reaching'])
        status = self.manager.dispatch('status')
        self.assertEqual(('captured', ''), (status['dns_scope'], status['error']))
        self.assertIn(m.IPV6_RESTRICTED_NOTE, status['dns_note'])
        self.assertNotIn(m.IPV6_ROUTER_DNS_NOTE, status['dns_note'])
        # Every scope starts with it, and says so.
        for scope, effective in (('all', 'off'), ('off', 'off'), ('captured', 'captured')):
            with self.subTest(scope=scope):
                self.request(dns_scope=scope)
                status = self.manager.dispatch('status')
                self.assertEqual((effective, ''), (status['dns_scope'], status['error']))
                self.assertIn(m.IPV6_RESTRICTED_NOTE, status['dns_note'])
                self.assertNotIn(m.IPV6_RESTRICTED_ALL_NOTE, status['dns_note'])
        # Nothing to note without an offer, nor while Mihomo carries IPv6.
        self.router(ipv6=False)
        self.assertNotIn(m.IPV6_RESTRICTED_NOTE, self.manager.dispatch('status')['dns_note'])
        self.router(ipv6=True)
        self.request(ipv6=True)
        self.assertNotIn(m.IPV6_RESTRICTED_NOTE, self.manager.dispatch('status')['dns_note'])
        self.request(ipv6=False)
        # Nor once the service stops.
        self.manager.dispatch('stop')
        self.assertEqual('', self.manager.dispatch('status')['dns_note'])
        self.manager.dispatch('start')
        # Taking the declaration back brings the refusal back.
        before = self.stored()
        with self.assertRaisesRegex(m.Error, 'offered IPv6'):
            self.request(ipv6_clients_restricted=False)
        self.assertEqual(before, self.stored())

    def test_the_watchdog_notes_a_declared_offer_that_appears_later_instead_of_failing(self):
        self.upstreams()
        self.activate('captured')
        self.request(router_dns=True, ipv6_clients_restricted=True)
        # Router DNS answers the offer on its own terms whatever the scope.
        for scope, effective in (('captured', 'captured'), ('all', 'off'), ('off', 'off')):
            with self.subTest(scope=scope):
                self.router(ipv6=False)
                self.request(dns_scope=scope, ipv6_clients_restricted=True)
                self.assertNotIn(m.IPV6_RESTRICTED_NOTE, self.manager.dispatch('status')['dns_note'])
                self.router(ipv6=True)
                self.system.events.clear()
                for _ in range(3):
                    status = self.tick(m.IPV6_POLL)
                    self.assertEqual(('', effective), (status['error'], status['dns_scope']))
                    self.assertIn(m.IPV6_RESTRICTED_NOTE, status['dns_note'])
                self.assertEqual([], self.system.events)
                # Without the declaration the same offer is router DNS's own error again.
                self.manager.write_settings(dict(self.manager.settings(), ipv6_clients_restricted=False))
                status = self.tick()
                self.assertIn('IPv6 is now being advertised', status['error'])
                self.assertNotIn(m.IPV6_RESTRICTED_NOTE, status['dns_note'])
                self.assertEqual([], self.system.events)

    def test_the_offer_is_noted_only_where_it_would_have_been_refused_or_fallen_back_over(self):
        # Without router DNS, only a captured scope would have fallen back.
        self.router(ipv6=True)
        self.request(ipv6_clients_restricted=True)
        self.activate('off')
        status = self.manager.dispatch('status')
        self.assertEqual(('off', ''), (status['dns_scope'], status['error']))
        self.assertNotIn(m.IPV6_RESTRICTED_NOTE, status['dns_note'])
        self.assertNotIn(m.IPV6_RESTRICTED_ALL_NOTE, status['dns_note'])
        self.request(dns_scope='captured')
        self.assertIn(m.IPV6_RESTRICTED_NOTE, self.manager.dispatch('status')['dns_note'])

    def test_the_watchdog_reads_config_xml_for_the_note_only_when_it_changes(self):
        self.router(ipv6=True)
        self.request(ipv6_clients_restricted=True)
        self.activate('captured')
        config = self.manager.path('/conf/config.xml')
        offers, parses = [], []
        detect, parse = m.advertises_ipv6, m.ElementTree.fromstring

        def counted_offer(content):
            offers.append(content)
            return detect(content)

        def counted_parse(content, *args, **kwargs):
            parses.append(content)
            return parse(content, *args, **kwargs)

        # The backup mirror reads the router's identity from it every tick on
        # its own account, as 1.4.1 did; left out of the count.
        with mock.patch.object(m, 'advertises_ipv6', counted_offer), \
                mock.patch.object(m.ElementTree, 'fromstring', counted_parse), \
                mock.patch.object(self.manager, '_consent_scope', return_value=''):
            # A new identity: one parse for the offer and one for DNSSEC, then none.
            config.write_text(config.read_text().replace('<opnsense>', '<opnsense><!-- saved -->'))
            for _ in range(4):
                status = self.tick()
                self.assertEqual('captured', status['dns_scope'])
                self.assertIn(m.IPV6_RESTRICTED_NOTE, status['dns_note'])
                self.assertNotIn(m.CAPTURED_DNSSEC_NOTE, status['dns_note'])
            self.assertEqual(1, len(offers))
            self.assertEqual(2, len(parses))
            # DNSSEC switched on is seen at the next change of the file.
            config.write_text(config.read_text().replace('<dots/>', '<general><dnssec>1</dnssec></general><dots/>'))
            for _ in range(3):
                self.assertIn(m.CAPTURED_DNSSEC_NOTE, self.tick()['dns_note'])
            self.assertEqual(2, len(offers))
            self.assertEqual(4, len(parses))

    def test_a_captured_scope_never_falls_back_over_a_declared_offer(self):
        self.router(ipv6=True)
        self.request(ipv6_clients_restricted=True)
        reads = self.system.address_reads
        self.activate('captured')
        # Captured devices are declared to get no IPv6, so nobody looks.
        self.assertEqual(reads, self.system.address_reads)
        self.assertNotIn('dns-on', self.system.events)
        self.assertFalse(self.system.forwarded)
        self.assertIs(False, self.observation()['ipv6_reaching'])
        self.assertIn('+.10.in-addr.arpa', self.policy())
        status = self.manager.dispatch('status')
        self.assertEqual(('captured', False), (status['dns_scope'], status['dns_active']))
        self.assertNotIn(m.IPV6_NOTE, status['dns_note'])
        self.assertIn(m.IPV6_RESTRICTED_NOTE, status['dns_note'])
        # A record that says reaching changes nothing either: the status and
        # the routing adapter decide with the same settings.
        self.manager.dns_scope_file.write_text(json.dumps({'ipv6_reaching': True, 'changed': self.clock()}))
        self.assertEqual('captured', self.manager.publish_status()['dns_scope'])
        self.manager.dispatch('restart')
        self.assertIs(False, self.observation()['ipv6_reaching'])
        # Without the declaration the same router falls back, as before.
        self.system.events.clear()
        self.request(ipv6_clients_restricted=False)
        self.assertIn('dns-on', self.system.events)
        status = self.manager.dispatch('status')
        self.assertEqual(('all', m.IPV6_NOTE), (status['dns_scope'], status['dns_note']))
        self.assertTrue(self.observation()['ipv6_reaching'])
        # Declared again while it runs as every device: the restart keeps no
        # yes and the scope is captured again at once.
        self.system.events.clear()
        self.request(ipv6_clients_restricted=True)
        self.assertNotIn('dns-on', self.system.events)
        self.assertFalse(self.system.forwarded)
        self.assertIs(False, self.observation()['ipv6_reaching'])
        self.assertEqual('captured', self.manager.dispatch('status')['dns_scope'])
        self.assertIn('+.10.in-addr.arpa', self.policy())

    def test_a_start_with_the_declaration_looks_at_no_interface(self):
        # Neither the filter reload that writes a missing routing context nor ifconfig.
        self.router(ipv6=True)
        (self.manager.state / 'routing-context.json').unlink()
        self.system.ensure_routing_context = lambda: self.system.events.append('filter-reload')
        self.request(ipv6_clients_restricted=True)
        reads = self.system.address_reads
        self.system.events.clear()
        self.activate('captured')
        self.assertNotIn('filter-reload', self.system.events)
        self.assertEqual(reads, self.system.address_reads)
        self.assertEqual('captured', self.manager.dispatch('status')['dns_scope'])
        # Without it the start has the filter write the context before it looks.
        self.system.events.clear()
        self.request(ipv6_clients_restricted=False)
        self.assertIn('filter-reload', self.system.events)
        self.assertLess(reads, self.system.address_reads)

    def test_the_watchdog_follows_ipv6_only_without_the_declaration(self):
        self.activate('captured')
        self.request(ipv6_clients_restricted=True)
        reads = self.system.address_reads
        self.router(ipv6=True)
        self.system.events.clear()
        for seconds in (5.0, 5.0, m.IPV6_POLL, m.IPV6_POLL, m.SCOPE_CHANGE_INTERVAL):
            status = self.tick(seconds)
            self.assertEqual(('captured', ''), (status['dns_scope'], status['error']))
            self.assertIn(m.IPV6_RESTRICTED_NOTE, status['dns_note'])
        self.assertEqual([], self.system.events)
        self.assertEqual(reads, self.system.address_reads)
        self.assertIsNone(self.manager._reach)
        self.assertNotIn('waiting', self.observation())
        # A change a dead watchdog left unfinished is settled as captured.
        self.manager.scope_move_file.write_text('{"ipv6_reaching": true}\n')
        status = self.tick()
        self.assertEqual('captured', status['dns_scope'])
        self.assertFalse(self.manager.scope_move_file.exists())
        self.assertNotIn('dns-on', self.system.events)
        # The same router without it: two looks, then every device, as before.
        self.manager.write_settings(dict(self.manager.settings(), ipv6_clients_restricted=False))
        self.system.events.clear()
        self.assertEqual('captured', self.tick()['dns_scope'])
        status = self.tick()
        self.assertEqual(('all', m.IPV6_NOTE), (status['dns_scope'], status['dns_note']))
        self.assertIn('dns-on', self.system.events)

    def test_the_status_hints_that_every_device_answered_without_ipv6_defeats_it(self):
        self.upstreams()
        self.activate('all')
        self.assertNotIn(m.IPV6_RESTRICTED_ALL_NOTE, self.manager.dispatch('status')['dns_note'])
        self.request(ipv6_clients_restricted=True)
        # With or without an offer detected: the declaration says some devices get IPv6.
        for ipv6 in (False, True):
            with self.subTest(ipv6=ipv6):
                self.router(ipv6=ipv6)
                status = self.manager.dispatch('status')
                self.assertEqual(('all', True), (status['dns_scope'], status['dns_active']))
                self.assertIn(m.IPV6_RESTRICTED_ALL_NOTE, status['dns_note'])
                self.assertNotIn(m.IPV6_RESTRICTED_NOTE, status['dns_note'])
        # Not while Mihomo answers AAAA, nor where every device is not answered by it.
        self.request(ipv6=True)
        self.assertNotIn(m.IPV6_RESTRICTED_ALL_NOTE, self.manager.dispatch('status')['dns_note'])
        self.request(ipv6=False)
        self.router(ipv6=False, dnssec=True)
        self.manager.dispatch('restart')
        status = self.manager.dispatch('status')
        self.assertEqual('off', status['dns_scope'])
        self.assertNotIn(m.IPV6_RESTRICTED_ALL_NOTE, status['dns_note'])
        self.router(ipv6=False)
        for change, effective in (({'router_dns': True}, 'off'), ({'router_dns': False, 'dns_scope': 'captured'}, 'captured'),
                                  ({'dns_scope': 'off'}, 'off')):
            with self.subTest(change=change):
                self.request(**change)
                status = self.manager.dispatch('status')
                self.assertEqual(effective, status['dns_scope'])
                self.assertNotIn(m.IPV6_RESTRICTED_ALL_NOTE, status['dns_note'])
        # Nor without the declaration.
        self.request(dns_scope='all', ipv6_clients_restricted=False)
        self.assertEqual('all', self.manager.dispatch('status')['dns_scope'])
        self.assertNotIn(m.IPV6_RESTRICTED_ALL_NOTE, self.manager.dispatch('status')['dns_note'])

    def test_the_declaration_only_removes_the_fallback(self):
        full = {'tun': {'enable': True}, 'dns': {'enable': True, 'listen': '127.0.0.1:1053'}}
        carried = {'ipv6': True, 'tun': {'enable': True},
                   'dns': {'enable': True, 'listen': '127.0.0.1:1053', 'ipv6': True}}
        tun_only = {'tun': {'enable': True}, 'dns': {'enable': False, 'listen': ''}}
        for scope in m.DNS_SCOPES:
            for router_dns in (False, True):
                for reaching in (False, True):
                    settings = {'dns_scope': scope, 'router_dns': router_dns}
                    declared = dict(settings, ipv6_clients_restricted=True)
                    with self.subTest(scope=scope, router_dns=router_dns, reaching=reaching):
                        for shape in (full, carried, tun_only):
                            # Whatever reaches captured devices, as if nothing did.
                            self.assertEqual(m.effective_dns_scope(settings, shape, False),
                                             m.effective_dns_scope(declared, shape, reaching))
                            self.assertEqual(m.dns_requested(settings, shape, False),
                                             m.dns_requested(declared, shape, reaching))
                            self.assertFalse(m.ipv6_matters(declared, shape))
                            # Only a stored true declares it.
                            for value in (False, 'true', 1, None):
                                self.assertEqual(m.effective_dns_scope(settings, shape, reaching),
                                                 m.effective_dns_scope(dict(settings, ipv6_clients_restricted=value),
                                                                       shape, reaching))
        self.assertFalse(m.ipv6_restricted({}))
        self.assertTrue(m.carries_ipv6(carried))
        self.assertFalse(m.carries_ipv6(full))
        self.assertFalse(m.carries_ipv6({'ipv6': True, 'dns': {'ipv6': False}}))


class Ipv6ReachRuleTests(unittest.TestCase):
    """What counts as IPv6 reaching captured devices, and when a new answer changes the scope."""

    # ifconfig -a as FreeBSD 15 prints it on OPNsense 26.7, trimmed.
    IFCONFIG = (b'vtnet0: flags=1008843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST,LOWER_UP> metric 0 mtu 1500\n'
                b'\toptions=4c079b<RXCSUM,TXCSUM,VLAN_MTU,VLAN_HWTAGGING,VLAN_HWCSUM,TSO4,TSO6,LRO>\n'
                b'\tether 52:54:00:12:34:56\n'
                b'\tinet 203.0.113.2 netmask 0xffffff00 broadcast 203.0.113.255\n'
                b'\tinet6 fe80::5054:ff:fe12:3456%vtnet0 prefixlen 64 scopeid 0x1\n'
                b'\tinet6 2a01:4f8:ffff::2 prefixlen 128\n'
                b'\tmedia: Ethernet autoselect (10Gbase-T <full-duplex>)\n'
                b'\tstatus: active\n'
                b'\tnd6 options=23<PERFORMNUD,ACCEPT_RTADV,AUTO_LINKLOCAL>\n'
                b'vtnet1: flags=1008843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST,LOWER_UP> metric 0 mtu 1500\n'
                b'\tinet 10.0.0.1 netmask 0xffffff00 broadcast 10.0.0.255\n'
                b'\tinet6 fe80::1:1%vtnet1 prefixlen 64 scopeid 0x2\n'
                b'\tinet6 2001:470:1f05::1 prefixlen 64 tentative\n'
                b'vtnet1.20: flags=1008843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST,LOWER_UP> metric 0 mtu 1500\n'
                b'\tinet6 fd00:20::1 prefixlen 64\n'
                b'lo0: flags=1008049<UP,LOOPBACK,RUNNING,MULTICAST,LOWER_UP> metric 0 mtu 16384\n'
                b'\tinet 127.0.0.1 netmask 0xff000000\n'
                b'\tinet6 ::1 prefixlen 128\n'
                b'\tinet6 fe80::1%lo0 prefixlen 64 scopeid 0x3\n'
                b'tun_mihomo: flags=1008051<UP,POINTOPOINT,RUNNING,MULTICAST,LOWER_UP> metric 0 mtu 1420\n'
                b'\tinet 198.18.0.1 --> 198.18.0.2 netmask 0xfffffffc\n'
                b'enc0: flags=0 metric 0 mtu 1536\n')

    def test_ifconfig_output_is_read_per_interface(self):
        self.assertEqual({'vtnet0': ['fe80::5054:ff:fe12:3456', '2a01:4f8:ffff::2'],
                          'vtnet1': ['fe80::1:1', '2001:470:1f05::1'],
                          'vtnet1.20': ['fd00:20::1'],
                          'lo0': ['::1', 'fe80::1'],
                          'tun_mihomo': [], 'enc0': []}, m.interface_ipv6(self.IFCONFIG.decode()))
        self.assertEqual({}, m.interface_ipv6(''))

    def test_the_system_reads_ifconfig_and_reports_what_it_cannot_read(self):
        system = m.System()
        for result, expected in (
                (subprocess.CompletedProcess([], 0, self.IFCONFIG, b''), m.interface_ipv6(self.IFCONFIG.decode())),
                (subprocess.CompletedProcess([], 1, b'', b'ifconfig: failed'), None),
                (m.Error('A system operation failed or timed out.'), None)):
            with self.subTest(result=result), mock.patch.object(
                    system, 'run', side_effect=[result] if isinstance(result, Exception) else None,
                    return_value=result) as run:
                self.assertEqual(expected, system.ipv6_addresses())
                self.assertEqual(['/sbin/ifconfig', '-a'], run.call_args.args[0])

    def test_only_global_unicast_counts(self):
        for address, expected in (('2001:470:1f05::1', True), ('2a01:4f8::1', True), ('2606:4700::1111', True),
                                  ('fe80::1', False), ('fe80::1%vtnet1', False), ('fd00::1', False),
                                  ('fc00::1', False), ('2001:db8::1', False),
                                  ('2002:c000:204::1', False), ('2001::1', False), ('::1', False),
                                  ('::ffff:198.51.100.1', False), ('64:ff9b::198.51.100.1', False),
                                  ('ff02::1', False), ('198.51.100.1', False), ('', False), (None, False)):
            with self.subTest(address=address):
                self.assertEqual(expected, m.global_ipv6(address))

    def test_only_a_captured_scope_without_router_dns_or_mihomo_ipv6_depends_on_it(self):
        full = {'tun': {'enable': True}, 'dns': {'enable': True, 'listen': '127.0.0.1:1053'}}
        carried = {'ipv6': True, 'tun': {'enable': True},
                   'dns': {'enable': True, 'listen': '127.0.0.1:1053', 'ipv6': True}}
        tun_only = {'tun': {'enable': True}, 'dns': {'enable': False, 'listen': ''}}
        self.assertTrue(m.ipv6_matters({'dns_scope': 'captured'}, full))
        for settings, shape in (({'dns_scope': 'all'}, full), ({'dns_scope': 'off'}, full),
                                ({'dns_scope': 'captured', 'router_dns': True}, full),
                                ({'dns_scope': 'captured'}, carried), ({'dns_scope': 'captured'}, tun_only)):
            with self.subTest(settings=settings, shape=shape):
                self.assertFalse(m.ipv6_matters(settings, shape))

    def test_a_new_answer_needs_two_looks_and_waits_only_on_the_way_back(self):
        now, interval = 50000.0, m.SCOPE_CHANGE_INTERVAL
        # The same answer as the scope in force: nothing pending.
        self.assertEqual((0, 'stay'), m.reach_verdict(False, False, 1, now, now - 1))
        self.assertEqual((0, 'stay'), m.reach_verdict(True, True, 5, now, now - 1))
        # One look is a blip.
        self.assertEqual((1, 'confirm'), m.reach_verdict(False, True, 0, now, now - 1))
        self.assertEqual((1, 'confirm'), m.reach_verdict(True, False, 0, now, None))
        # Towards every device at once, however recent the last change.
        self.assertEqual((2, 'move'), m.reach_verdict(False, True, 1, now, now - 1))
        self.assertEqual((2, 'move'), m.reach_verdict(False, True, 1, now, now))
        # Back to captured devices at most once per interval.
        self.assertEqual((2, 'hold'), m.reach_verdict(True, False, 1, now, now - interval + 1))
        self.assertEqual((7, 'hold'), m.reach_verdict(True, False, 6, now, now))
        self.assertEqual((2, 'move'), m.reach_verdict(True, False, 1, now, now - interval))
        # Unknown, or from before a reboot, holds nothing back.
        self.assertEqual((2, 'move'), m.reach_verdict(True, False, 1, now, None))
        self.assertEqual((2, 'move'), m.reach_verdict(True, False, 1, now, now + 1))
        # A failed change waits for its retry in both directions.
        for current in (False, True):
            self.assertEqual((2, 'hold'), m.reach_verdict(current, not current, 1, now, None, now + 1))
            self.assertEqual((2, 'move'), m.reach_verdict(current, not current, 1, now, None, now))
        self.assertEqual(2, m.IPV6_CONFIRM)
        self.assertEqual((600.0, 30.0), (m.SCOPE_CHANGE_INTERVAL, m.IPV6_POLL))

    def test_a_change_that_keeps_failing_backs_off_to_an_hour(self):
        # Towards every device a minute, doubling; back to captured devices
        # never sooner than the change interval; neither beyond an hour.
        self.assertEqual([60.0, 120.0, 240.0, 480.0, 960.0, 1920.0, 3600.0, 3600.0],
                         [m.retry_delay(failures, True) for failures in range(1, 9)])
        self.assertEqual([600.0, 600.0, 600.0, 600.0, 960.0, 1920.0, 3600.0, 3600.0],
                         [m.retry_delay(failures, False) for failures in range(1, 9)])
        self.assertEqual(3600.0, m.retry_delay(10 ** 6, True))


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
