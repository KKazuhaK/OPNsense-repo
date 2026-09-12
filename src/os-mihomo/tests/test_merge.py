"""Exercise merge policy, transport pins, and real System error boundaries."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from test_mihomo import m, SUBSCRIPTION
import test_mihomo as fixtures


class MergeTests(unittest.TestCase):
    def setUp(self):
        self.settings = {'transparent': True, 'secret': 'state-secret', 'router_dns': False}
        self.data = m.parse_yaml(SUBSCRIPTION)
        self.overlay = m.parse_yaml((m.Path(m.__file__).resolve().parents[3] / 'share/mihomo/presets/full.yaml').read_bytes())

    def generated(self, overlay=None, **kwargs):
        return m.parse_yaml(m.render(self.data, self.settings, overlay=self.overlay if overlay is None else overlay, **kwargs))

    def test_deep_mapping_plain_replacement_and_all_six_extensions(self):
        base = {'dns': {'nameserver-policy': {'home.test': ['127.0.0.1']}, 'listen': ':1053'}, 'rules': ['MATCH,DIRECT'], 'proxies': ['old'], 'proxy-groups': ['old-group']}
        overlay = {'dns': {'listen': '127.0.0.1:1053'}, 'prepend-rules': ['FIRST'], 'append-rules': ['LAST'], 'prepend-proxies': ['first'], 'append-proxies': ['last'], 'prepend-proxy-groups': ['first-group'], 'append-proxy-groups': ['last-group']}
        merged = m.merge_yaml(base, overlay)
        self.assertEqual({'home.test': ['127.0.0.1']}, merged['dns']['nameserver-policy'])
        self.assertEqual(['FIRST', 'MATCH,DIRECT', 'LAST'], merged['rules'])
        self.assertEqual(['first', 'old', 'last'], merged['proxies'])
        self.assertEqual(['first-group', 'old-group', 'last-group'], merged['proxy-groups'])
        self.assertEqual(['replacement'], m.merge_yaml(base, {'rules': ['replacement']})['rules'])
        self.assertEqual({}, m.merge_yaml(base, {'dns': {'nameserver-policy': {}}})['dns']['nameserver-policy'])
        self.assertEqual(['MATCH,DIRECT'], base['rules'])

    def test_all_presets_preserve_admin_gate_device_and_secret(self):
        for preset in ('full', 'tun-only', 'proxy-only'):
            overlay = m.parse_yaml((m.Path(m.__file__).resolve().parents[3] / ('share/mihomo/presets/' + preset + '.yaml')).read_bytes())
            overlay.update(secret='unsafe-merge-secret')
            overlay['tun']['device'] = 'wrong_tun'
            generated = self.generated(overlay)
            self.assertEqual('tun_mihomo', generated['tun']['device'])
            self.assertEqual('state-secret', generated['secret'])
            self.settings['transparent'] = False
            off = self.generated(overlay)
            self.assertFalse(off['tun']['enable'])
            self.assertFalse(off['dns']['enable'])
            self.assertEqual([], off['tun']['dns-hijack'])
            self.settings['transparent'] = True

    def test_port_53_is_rejected_in_provider_and_merge_listeners(self):
        for key in ('port', 'socks-port', 'mixed-port', 'redir-port', 'tproxy-port'):
            overlay = m.merge_yaml(self.overlay, {key: 53})
            with self.assertRaises(m.Error): self.generated(overlay)
        for overlay in ({'dns': {'listen': '[::1]:53'}}, {'dns': {'listen': '127.0.0.1:053'}}, {'external-controller': '127.0.0.1:53'}, {'external-controller': '127.0.0.1:domain'}, {'listeners': [{'port': 53}]}, {'listeners': [{'port': '0x35'}]}):
            with self.assertRaises(m.Error): self.generated(m.merge_yaml(self.overlay, overlay))
        self.data['port'] = 53
        with self.assertRaises(m.Error): self.generated()

    def test_router_dns_supplies_four_keys_without_changing_dns_mode(self):
        original = self.generated()
        self.settings['router_dns'] = True
        generated = self.generated(upstreams='forward-addr: 192.0.2.53@853#gateway.test\nforward-addr: 2001:db8::53@853#gateway.test\n')
        for key in ('nameserver', 'proxy-server-nameserver', 'default-nameserver'):
            self.assertEqual(['127.0.0.1'], generated['dns'][key])
        self.assertEqual({}, generated['dns']['nameserver-policy'])
        self.assertEqual(original['tun']['dns-hijack'], generated['tun']['dns-hijack'])
        self.assertEqual(original['dns']['enhanced-mode'], generated['dns']['enhanced-mode'])
        self.assertEqual(['IP-CIDR,192.0.2.53/32,DIRECT,no-resolve', 'IP-CIDR6,2001:db8::53/128,DIRECT,no-resolve', 'DST-PORT,853,DIRECT'], generated['rules'][:3])
        self.assertEqual(self.data['rules'], generated['rules'][3:])

    def test_transport_pins_precede_merge_catchall_and_follow_new_upstreams(self):
        self.settings['router_dns'] = True
        overlay = m.merge_yaml(self.overlay, {'prepend-rules': ['MATCH,Proxy']})
        first = self.generated(overlay, upstreams='forward-addr: 192.0.2.53@853')
        second = self.generated(overlay, upstreams='forward-addr: 192.0.2.54@853')
        self.assertEqual('IP-CIDR,192.0.2.53/32,DIRECT,no-resolve', first['rules'][0])
        self.assertEqual('IP-CIDR,192.0.2.54/32,DIRECT,no-resolve', second['rules'][0])
        self.assertEqual('MATCH,Proxy', first['rules'][2])
        with self.assertRaises(m.Error): self.generated(upstreams='forward-addr: gateway.test@853')
        with self.assertRaises(m.Error): self.generated(upstreams='')

    def test_ipv6_guard_refuses_ra_and_dhcpv6_mismatch_without_aaaa_changes(self):
        self.settings['router_dns'] = True
        self.data['ipv6'] = False
        self.data['dns']['ipv6'] = False
        self.generated(upstreams='forward-addr: 192.0.2.53@853', ipv6_advertised=False)
        with self.assertRaises(m.Error): self.generated(upstreams='forward-addr: 192.0.2.53@853', ipv6_advertised=True)
        self.data['ipv6'] = self.data['dns']['ipv6'] = True
        self.generated(upstreams='forward-addr: 192.0.2.53@853', ipv6_advertised=True)
        self.assertFalse(m.advertises_ipv6(b'<opnsense><radvd/><dhcpdv6/></opnsense>'))
        self.assertTrue(m.advertises_ipv6(b'<opnsense><radvd><lan><mode>assisted</mode></lan></radvd></opnsense>'))
        self.assertTrue(m.advertises_ipv6(b'<opnsense><dhcpdv6><lan><enable/></lan></dhcpdv6></opnsense>'))
        self.assertTrue(m.advertises_ipv6(b'<opnsense><OPNsense><Kea><dhcp6><general><enabled>1</enabled></general></dhcp6></Kea></OPNsense></opnsense>'))

    def test_provider_fallback_is_not_silent_when_router_dns_enabled(self):
        self.settings['router_dns'] = True
        self.data['dns']['fallback'] = ['https://example.invalid/dns-query']
        with self.assertRaises(m.Error): self.generated(upstreams='forward-addr: 192.0.2.53@853')
        self.generated(m.merge_yaml(self.overlay, {'dns': {'fallback': []}}), upstreams='forward-addr: 192.0.2.53@853')


class RuntimeBoundaryTests(unittest.TestCase):
    setUp = fixtures.StateTests.setUp

    def test_stop_failure_still_stops_core_and_tears_down_tun(self):
        self.manager.apply(SUBSCRIPTION)
        self.manager.dispatch('enable-transparent')
        self.system.dns = lambda *args: (_ for _ in ()).throw(m.Error('Injected reload failure.'))
        with self.assertRaises(m.Error): self.manager.dispatch('stop')
        self.assertFalse(self.system.alive)
        self.assertFalse(self.manager.settings()['service_enabled'])
        self.assertTrue(json.loads(self.manager.status_file.read_bytes())['dns_active'])

    def test_tun_only_crash_tears_down_routes_without_dns_redirect(self):
        self.manager.apply(SUBSCRIPTION)
        overlay = m.parse_yaml(self.manager.merge_file.read_bytes())
        overlay['dns']['enable'] = False
        overlay['tun']['dns-hijack'] = []
        self.manager.apply(SUBSCRIPTION, overlay=overlay)
        self.manager.dispatch('enable-transparent')
        self.assertFalse(self.system.forwarded)
        self.system.alive = False
        self.system.events.clear()
        self.manager.watchdog_tick()
        self.assertIn('destroy-tun', self.system.events)

    def test_fresh_merge_can_be_saved_without_a_subscription(self):
        overlay = m.parse_yaml(self.manager.merge_file.read_bytes())
        overlay['mixed-port'] = 17890
        request = self.manager.state / 'request.yaml'
        request.write_bytes(m.yaml.safe_dump(overlay).encode())
        self.manager.dispatch('save-merge', str(request))
        generated = m.parse_yaml(self.manager.config_file.read_bytes())
        self.assertEqual(['MATCH,DIRECT'], generated['rules'])
        self.assertEqual(17890, generated['mixed-port'])
        self.assertFalse(generated['tun']['enable'])

    def test_dns_upstream_change_refreshes_pins_while_running(self):
        self.manager.apply(SUBSCRIPTION)
        settings = self.manager.settings()
        settings['router_dns'] = True
        self.manager.router_context = lambda settings: ('forward-addr: 192.0.2.53@853', False)
        self.manager.apply(SUBSCRIPTION, settings)
        self.manager.router_context = lambda settings: ('forward-addr: 192.0.2.54@853', False)
        self.manager.watchdog_tick()
        rules = m.parse_yaml(self.manager.config_file.read_bytes())['rules']
        self.assertEqual('IP-CIDR,192.0.2.54/32,DIRECT,no-resolve', rules[0])

    def test_subscription_url_never_reaches_logs_for_success_or_failure(self):
        settings = self.manager.settings()
        settings['subscription_url'] = 'https://example.invalid/sub/PRIVATE_TOKEN'
        self.manager.write_settings(settings)
        with patch.object(m, 'fetch_subscription', return_value=SUBSCRIPTION) as fetch:
            self.manager.update()
            self.assertEqual(settings['subscription_url'], fetch.call_args.args[0])
        with patch.object(m, 'fetch_subscription', side_effect=m.Error('HTTP 404.')):
            with self.assertRaises(m.Error): self.manager.update()
        logs = self.manager.path('/var/log/mihomo_sub.log').read_text()
        self.assertNotIn('PRIVATE_TOKEN', logs)
        self.assertNotIn(settings['subscription_url'], logs)
        self.assertNotIn(settings['secret'], logs)

    def test_configctl_zero_exit_error_and_timeout_are_failures(self):
        system = m.System()
        for stdout, stderr in ((b'Execute error', b''), (b'', b'Execute error')):
            with patch.object(m.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, stdout, stderr)):
                with self.assertRaises(m.Error): system.run(['/usr/local/sbin/configctl', 'filter', 'reload'])
        with patch.object(m.subprocess, 'run', side_effect=subprocess.TimeoutExpired([], 1)):
            with self.assertRaises(m.Error): system.run(['/bin/ps'])

    def test_validator_diagnostics_are_not_returned(self):
        with patch.object(m.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, b'PRIVATE_TOKEN', b'state-secret')):
            with self.assertRaises(m.Error) as error: m.System().validate(Path('/private-candidate.yaml'))
        self.assertNotIn('PRIVATE_TOKEN', str(error.exception))
        self.assertNotIn('state-secret', str(error.exception))

    def test_dns_readiness_cannot_hide_missing_tun_routes(self):
        config = self.manager.state / 'ready.yaml'
        config.write_text("tun: {enable: true, auto-route: true}\ndns: {enable: true, listen: '127.0.0.1:1053'}\n")
        system = m.System()
        def run(args, **kwargs):
            rc = 1 if args[0] in {'/usr/sbin/service', '/usr/bin/pgrep'} else 0
            return subprocess.CompletedProcess(args, rc, b'interface: lo1', b'')
        with patch.object(system, 'run', side_effect=run), patch.object(system, 'running', side_effect=[False] + [True] * 30), patch.object(system, 'destroy_tun'), patch.object(system, 'stop') as stop, patch.object(m.time, 'sleep'), patch.object(m.socket, 'create_connection') as dns:
            with self.assertRaises(m.Error): system.start(config, True)
            stop.assert_called_once()
            dns.assert_not_called()

    def test_pid_reuse_with_path_in_another_program_is_not_killed(self):
        pid = self.manager.state / 'pid'
        pid.write_text('12345')
        system = m.System()
        with patch.object(system, 'run', return_value=subprocess.CompletedProcess([], 0, b'/usr/bin/vim /usr/local/bin/mihomo\n', b'')):
            self.assertIsNone(system.valid_pid(str(pid), '/usr/local/bin/mihomo'))
        with patch.object(system, 'run', return_value=subprocess.CompletedProcess([], 0, b'/usr/local/bin/mihomo -f config.yaml\n', b'')):
            self.assertEqual(12345, system.valid_pid(str(pid), '/usr/local/bin/mihomo'))
