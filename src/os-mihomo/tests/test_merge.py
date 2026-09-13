"""Exercise merge policy, transport pins, and real System error boundaries."""
import copy
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

    def generated(self, overlay=None, settings=None, **kwargs):
        return m.parse_yaml(m.render(self.data, settings or self.settings,
            overlay=self.overlay if overlay is None else overlay, **kwargs))

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
        for overlay in ({'dns': {'listen': '[::1]:53'}}, {'dns': {'listen': '127.0.0.1:053'}}, {'listeners': [{'port': 53}]}, {'listeners': [{'port': '0x35'}]}):
            with self.assertRaises(m.Error): self.generated(m.merge_yaml(self.overlay, overlay))
        # The controller is settings policy now, so a merge YAML value never reaches render.
        for controller in ('127.0.0.1:53', '127.0.0.1:domain'):
            with self.assertRaises(m.Error):
                self.generated(self.overlay, settings=dict(self.settings, controller=controller))
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
        # The switch owns IPv6, so the subscription alone no longer satisfies the guard.
        self.data['ipv6'] = self.data['dns']['ipv6'] = True
        with self.assertRaises(m.Error): self.generated(upstreams='forward-addr: 192.0.2.53@853', ipv6_advertised=True)
        self.settings['ipv6'] = True
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


class SwitchTests(unittest.TestCase):
    """The simple switches own dns.ipv6, dns.enhanced-mode and tun.dns-hijack."""

    def setUp(self):
        self.settings = {'transparent': True, 'secret': 'state-secret', **m.SWITCH_DEFAULTS}
        self.data = m.parse_yaml(SUBSCRIPTION)
        preset = m.Path(m.__file__).resolve().parents[3] / 'share/mihomo/presets/full.yaml'
        self.overlay = m.parse_yaml(preset.read_bytes())
        m.absorb_switches(self.overlay, self.settings)

    def generated(self, overlay=None, **switches):
        settings = {**self.settings, **switches}
        return m.parse_yaml(m.render(self.data, settings,
            overlay=copy.deepcopy(self.overlay if overlay is None else overlay)))

    def test_each_switch_reaches_the_rendered_configuration(self):
        default = self.generated()
        self.assertEqual(m.HIJACK_TARGETS, default['tun']['dns-hijack'])
        self.assertEqual('fake-ip', default['dns']['enhanced-mode'])
        self.assertIs(False, default['dns']['ipv6'])
        self.assertIs(False, default['ipv6'])
        self.assertEqual([], self.generated(dns_hijack=False)['tun']['dns-hijack'])
        self.assertEqual('redir-host', self.generated(dns_mode='redir-host')['dns']['enhanced-mode'])
        both = self.generated(ipv6=True)
        self.assertIs(True, both['ipv6'])
        self.assertIs(True, both['dns']['ipv6'])

    def test_the_shipped_presets_state_no_key_a_switch_owns(self):
        for preset in ('full', 'tun-only', 'proxy-only'):
            path = m.Path(m.__file__).resolve().parents[3] / ('share/mihomo/presets/' + preset + '.yaml')
            overlay = m.parse_yaml(path.read_bytes())
            lifted = m.absorb_switches(overlay, self.settings)
            self.assertEqual([], m.switch_overrides(overlay), preset)
            # Only the full preset captures client DNS; the other two leave the router resolver alone.
            self.assertIs(preset == 'full', lifted['dns_hijack'], preset)

    def test_a_value_no_switch_can_express_stays_in_the_yaml_and_is_reported(self):
        overlay = copy.deepcopy(self.overlay)
        overlay.setdefault('tun', {})['dns-hijack'] = ['udp://any:53']
        settings = dict(self.settings, dns_hijack=False)
        lifted = m.absorb_switches(overlay, settings)
        self.assertEqual(['udp://any:53'], overlay['tun']['dns-hijack'])
        self.assertIs(False, lifted['dns_hijack'])
        self.assertEqual(['dns_hijack'], m.switch_overrides(overlay))
        rendered = self.generated(overlay, dns_hijack=False)
        self.assertEqual(['udp://any:53'], rendered['tun']['dns-hijack'])
        self.assertEqual(['dns_hijack'], m.switch_conflicts(rendered, settings))

    def test_disagreeing_ipv6_statements_are_left_for_the_operator(self):
        overlay = {'ipv6': True, 'dns': {'ipv6': False}}
        lifted = m.absorb_switches(overlay, self.settings)
        self.assertEqual({'ipv6': True, 'dns': {'ipv6': False}}, overlay)
        self.assertIs(False, lifted['ipv6'])
        self.assertEqual(['ipv6'], m.switch_overrides(overlay))

    def test_an_unknown_dns_mode_is_never_absorbed(self):
        overlay = {'dns': {'enhanced-mode': 'nonsense'}}
        lifted = m.absorb_switches(overlay, self.settings)
        self.assertEqual('fake-ip', lifted['dns_mode'])
        self.assertEqual(['dns_mode'], m.switch_overrides(overlay))

    def test_an_upgrade_adopts_the_behaviour_the_installation_already_had(self):
        rendered = {'ipv6': True, 'dns': {'enable': True, 'ipv6': True, 'enhanced-mode': 'redir-host'},
                    'tun': {'enable': True, 'dns-hijack': []}}
        adopted = m.adopt_switches(rendered, m.SWITCH_DEFAULTS)
        self.assertEqual({'ipv6': True, 'dns_mode': 'redir-host', 'dns_hijack': False},
                         {k: adopted[k] for k in ('ipv6', 'dns_mode', 'dns_hijack')})
        # A configuration that states none of them leaves the defaults alone.
        self.assertEqual(dict(m.SWITCH_DEFAULTS), m.adopt_switches({'proxies': []}, m.SWITCH_DEFAULTS))
        # An inert section is render() enforcing transparent-off, never an intent.
        inert = {'dns': {'enable': False, 'enhanced-mode': 'normal'}, 'tun': {'enable': False, 'dns-hijack': []}}
        self.assertEqual(dict(m.SWITCH_DEFAULTS), m.adopt_switches(inert, m.SWITCH_DEFAULTS))
        # A rendered file only reports the outcome, so the stored overlay still wins.
        overlay = {'tun': {'dns-hijack': list(m.HIJACK_TARGETS)}}
        self.assertIs(True, m.absorb_switches(overlay, adopted)['dns_hijack'])

    def test_transparent_routing_off_forces_every_switch_inert(self):
        settings = dict(self.settings, transparent=False, dns_hijack=True, ipv6=True)
        rendered = m.parse_yaml(m.render(self.data, settings, overlay=copy.deepcopy(self.overlay)))
        self.assertEqual([], rendered['tun']['dns-hijack'])
        self.assertIs(False, rendered['tun']['enable'])
        self.assertIs(False, rendered['dns']['enable'])


class ControllerTests(unittest.TestCase):
    """The bind address is settings policy, like the secret, not a merge YAML key."""

    def setUp(self):
        self.settings = {'transparent': True, 'secret': 'state-secret', **m.SWITCH_DEFAULTS}
        self.data = m.parse_yaml(SUBSCRIPTION)
        self.preset = m.parse_yaml((m.Path(m.__file__).resolve().parents[3]
            / 'share/mihomo/presets/full.yaml').read_bytes())

    def rendered(self, overlay, **settings):
        overlay = m.merge_yaml(copy.deepcopy(self.preset), overlay)
        return m.parse_yaml(m.render(self.data, {**self.settings, **settings}, overlay=overlay))

    def test_the_merge_yaml_cannot_move_the_controller(self):
        overlay = {'external-controller': '192.0.2.1:9090'}
        self.assertEqual(m.LOOPBACK_CONTROLLER, self.rendered(dict(overlay))['external-controller'])
        self.assertEqual(m.ANY_CONTROLLER,
                         self.rendered(dict(overlay), controller=m.ANY_CONTROLLER)['external-controller'])

    def test_an_inert_controller_key_is_lifted_out_of_the_merge_yaml(self):
        overlay = {'external-controller': m.ANY_CONTROLLER, 'mixed-port': 7890}
        lifted = m.absorb_switches(overlay, self.settings)
        self.assertEqual(m.ANY_CONTROLLER, lifted['controller'])
        self.assertEqual({'mixed-port': 7890}, overlay)
        # An address the switch cannot express stays put rather than being rewritten.
        kept = {'external-controller': '192.0.2.1:9090'}
        self.assertNotIn('controller', m.absorb_switches(kept, self.settings))
        self.assertEqual({'external-controller': '192.0.2.1:9090'}, kept)

    def test_binding_every_interface_is_allowed_but_still_needs_a_secret(self):
        manager = m.Manager.__new__(m.Manager)
        self.settings.update(dns_fallback=True, service_enabled=True, device='router', subscription_url='')
        manager.check_settings(dict(self.settings, controller=m.ANY_CONTROLLER))
        manager.check_settings(dict(self.settings, controller='192.168.1.1:9090'))
        for bad in ('0.0.0.0:53', '0.0.0.0', 'localhost:9090', '0.0.0.0:70000'):
            with self.assertRaises(m.Error, msg=bad):
                manager.check_settings(dict(self.settings, controller=bad))
        with self.assertRaises(m.Error):
            manager.check_settings(dict(self.settings, controller=m.ANY_CONTROLLER, secret=''))


class BaselineTests(unittest.TestCase):
    """A bare subscription gets a DNS policy; a complete one is never blended."""

    def setUp(self):
        self.settings = {'transparent': True, 'secret': 'state-secret', **m.SWITCH_DEFAULTS}
        self.preset = m.parse_yaml((m.Path(m.__file__).resolve().parents[3]
            / 'share/mihomo/presets/full.yaml').read_bytes())

    def generated(self, data, **settings):
        return m.parse_yaml(m.render(data, {**self.settings, **settings},
            overlay=copy.deepcopy(self.preset)))

    def test_a_subscription_without_dns_is_given_the_baseline(self):
        data = m.parse_yaml(SUBSCRIPTION)
        data.pop('dns')
        dns = self.generated(data)['dns']
        self.assertEqual(['system'], dns['nameserver-policy']['geosite:private'])
        self.assertEqual(['223.5.5.5', '119.29.29.29'], dns['default-nameserver'])
        self.assertIn('geosite:private', dns['fake-ip-filter'])

    def test_a_subscription_with_dns_keeps_its_own_policy_whole(self):
        data = m.parse_yaml(SUBSCRIPTION)
        data['dns'] = {'enable': True, 'listen': '127.0.0.1:1053',
                       'nameserver': ['https://example.invalid/dns-query'],
                       'nameserver-policy': {'geosite:cn': ['223.6.6.6']}}
        dns = self.generated(data)['dns']
        self.assertEqual(['https://example.invalid/dns-query'], dns['nameserver'])
        self.assertEqual({'geosite:cn': ['223.6.6.6']}, dns['nameserver-policy'])
        # None of the baseline leaks in beside it.
        self.assertNotIn('default-nameserver', dns)
        self.assertNotIn('fake-ip-filter', dns)

    def test_the_selected_rule_database_reaches_the_configuration(self):
        data = m.parse_yaml(SUBSCRIPTION)
        generated = self.generated(data)
        self.assertEqual(m.GEO_SOURCES['metacubex'], generated['geox-url'])
        self.assertIs(True, generated['geodata-mode'])
        self.assertEqual(m.GEO_UPDATE_HOURS, generated['geo-update-interval'])
        other = self.generated(data, geo_source='loyalsoldier-cdn')
        self.assertEqual(m.GEO_SOURCES['loyalsoldier-cdn'], other['geox-url'])
        for urls in m.GEO_SOURCES.values():
            self.assertTrue(all(u.startswith('https://') for u in urls.values()))

    def test_a_known_url_set_is_absorbed_and_a_custom_one_is_reported(self):
        overlay = {'geox-url': dict(m.GEO_SOURCES['loyalsoldier'])}
        lifted = m.absorb_switches(overlay, self.settings)
        self.assertEqual('loyalsoldier', lifted['geo_source'])
        self.assertNotIn('geox-url', overlay)
        custom = {'geox-url': {'geoip': 'https://example.invalid/geoip.dat'}}
        self.assertEqual(m.SWITCH_DEFAULTS['geo_source'],
                         m.absorb_switches(custom, self.settings)['geo_source'])
        self.assertEqual(['geo_source'], m.switch_overrides(custom))

    def test_an_unknown_rule_database_is_refused(self):
        manager = m.Manager.__new__(m.Manager)
        base = dict(self.settings, dns_fallback=True, service_enabled=True,
                    device='router', subscription_url='')
        manager.check_settings(dict(base, geo_source='loyalsoldier'))
        with self.assertRaises(m.Error):
            manager.check_settings(dict(base, geo_source='nonexistent'))


class DnsServerFieldTests(unittest.TestCase):
    """Stated upstreams replace the subscription's; an empty field inherits them."""

    def setUp(self):
        self.settings = {'transparent': True, 'secret': 'state-secret', **m.SWITCH_DEFAULTS}
        self.data = m.parse_yaml(SUBSCRIPTION)
        self.data['dns'].update(nameserver=['https://provider.invalid/dns-query'],
                                **{'default-nameserver': ['9.9.9.9'],
                                   'proxy-server-nameserver': ['https://provider.invalid/dns-query']})
        self.preset = m.parse_yaml((m.Path(m.__file__).resolve().parents[3]
            / 'share/mihomo/presets/full.yaml').read_bytes())

    def generated(self, **settings):
        return m.parse_yaml(m.render(self.data, {**self.settings, **settings},
            overlay=copy.deepcopy(self.preset), upstreams='forward-addr: 192.0.2.53@853'))

    def test_an_empty_field_leaves_the_subscription_servers_alone(self):
        dns = self.generated()['dns']
        self.assertEqual(['https://provider.invalid/dns-query'], dns['nameserver'])
        self.assertEqual(['9.9.9.9'], dns['default-nameserver'])

    def test_a_stated_field_replaces_them(self):
        dns = self.generated(dns_nameserver=['tls://223.5.5.5', 'https://doh.pub/dns-query'],
                             dns_default=['223.6.6.6'])['dns']
        self.assertEqual(['tls://223.5.5.5', 'https://doh.pub/dns-query'], dns['nameserver'])
        self.assertEqual(['223.6.6.6'], dns['default-nameserver'])
        # Untouched fields still come from the subscription.
        self.assertEqual(['https://provider.invalid/dns-query'], dns['proxy-server-nameserver'])

    def test_router_dns_keeps_every_upstream_even_when_fields_are_stated(self):
        dns = self.generated(router_dns=True, dns_nameserver=['tls://223.5.5.5'],
                             dns_default=['223.6.6.6'])['dns']
        for key in ('nameserver', 'proxy-server-nameserver', 'default-nameserver'):
            self.assertEqual(['127.0.0.1'], dns[key], key)

    def test_a_bootstrap_server_addressed_by_name_is_refused(self):
        manager = m.Manager.__new__(m.Manager)
        base = dict(self.settings, dns_fallback=True, service_enabled=True,
                    device='router', subscription_url='')
        manager.check_settings(dict(base, dns_default=['223.5.5.5', 'https://1.1.1.1/dns-query']))
        # Nothing can resolve the name of the server that resolves names.
        for bad in (['https://dns.alidns.com/dns-query'], ['tls://dot.pub'], ['system']):
            with self.assertRaises(m.Error, msg=bad):
                manager.check_settings(dict(base, dns_default=bad))
        # Other fields accept names and the system resolver.
        manager.check_settings(dict(base, dns_nameserver=['https://dns.alidns.com/dns-query', 'system']))
        for bad in (['1.1.1.1 2.2.2.2'], [''], ['a'] * 9, 'not-a-list'):
            with self.assertRaises(m.Error, msg=bad):
                manager.check_settings(dict(base, dns_nameserver=bad))

    def test_servers_written_by_hand_are_absorbed_into_the_fields(self):
        overlay = {'dns': {'nameserver': ['tls://223.5.5.5'], 'enhanced-mode': 'fake-ip'}}
        lifted = m.absorb_switches(overlay, self.settings)
        self.assertEqual(['tls://223.5.5.5'], lifted['dns_nameserver'])
        self.assertNotIn('dns', overlay)
        self.assertEqual([], m.switch_overrides({'dns': {}}))
        self.assertEqual(['dns_nameserver'],
                         m.switch_overrides({'dns': {'nameserver': 'not-a-list'}}))


class FakeIpRange6Tests(unittest.TestCase):
    """Enabling IPv6 under fake-ip must also give AAAA answers a pool to draw from."""

    def setUp(self):
        self.settings = {'transparent': True, 'secret': 'state-secret', **m.SWITCH_DEFAULTS}
        self.data = m.parse_yaml(SUBSCRIPTION)
        self.preset = m.parse_yaml((m.Path(m.__file__).resolve().parents[3]
            / 'share/mihomo/presets/full.yaml').read_bytes())
        # An installed overlay has had the switch-owned keys absorbed out of it.
        m.absorb_switches(self.preset, self.settings)

    def generated(self, overlay=None, **settings):
        base = m.merge_yaml(copy.deepcopy(self.preset), overlay or {})
        return m.parse_yaml(m.render(self.data, {**self.settings, **settings}, overlay=base))

    def test_ipv6_under_fake_ip_gets_a_range(self):
        self.assertNotIn('fake-ip-range6', self.generated()['dns'])
        self.assertEqual(m.FAKE_IP_RANGE6_DEFAULT,
                         self.generated(ipv6=True)['dns']['fake-ip-range6'])

    def test_a_stated_range_is_kept_and_a_routable_one_refused(self):
        kept = self.generated({'dns': {'fake-ip-range6': 'fd00::/64'}}, ipv6=True)
        self.assertEqual('fd00::/64', kept['dns']['fake-ip-range6'])
        for bad in ('2606:4700::/64', '198.18.0.0/16', 'nonsense'):
            with self.assertRaises(m.Error, msg=bad):
                self.generated({'dns': {'fake-ip-range6': bad}}, ipv6=True)

    def test_other_dns_modes_need_no_pool(self):
        self.assertNotIn('fake-ip-range6', self.generated(ipv6=True, dns_mode='normal')['dns'])


class OrphanPolicyTests(unittest.TestCase):
    """An override that lands on no provider key is reported, not silently added."""

    def test_a_matching_key_is_not_an_orphan(self):
        base = {'dns': {'nameserver-policy': {'geosite:cn': ['1.1.1.1'], 'geosite:private': ['system']}}}
        overlay = {'dns': {'nameserver-policy': {'geosite:cn': ['tls://dot.test']}}}
        self.assertEqual([], m.orphan_policy_keys(base, overlay))

    def test_a_renamed_provider_key_leaves_the_override_dangling(self):
        base = {'dns': {'nameserver-policy': {'geosite:cn,steam@cn': ['1.1.1.1']}}}
        overlay = {'dns': {'nameserver-policy': {'geosite:cn': ['tls://dot.test']}}}
        self.assertEqual(['geosite:cn'], m.orphan_policy_keys(base, overlay))

    def test_a_typo_is_caught_the_same_way(self):
        base = {'dns': {'nameserver-policy': {'geosite:geolocation-!cn': ['1.1.1.1']}}}
        overlay = {'dns': {'nameserver-policy': {'geosite:geolocation!cn': ['tls://dot.test']}}}
        self.assertEqual(['geosite:geolocation!cn'], m.orphan_policy_keys(base, overlay))

    def test_absent_or_malformed_sections_report_nothing(self):
        for base, overlay in (({}, {}), ({'dns': 'x'}, {'dns': {'nameserver-policy': 'y'}}),
                              ({'dns': {}}, {'dns': {}}), ({'dns': {'nameserver-policy': {}}}, {})):
            self.assertEqual([], m.orphan_policy_keys(base, overlay))

    def test_a_subscription_without_dns_is_compared_against_the_baseline(self):
        data = m.parse_yaml(SUBSCRIPTION)
        data.pop('dns')
        base = m.merge_yaml(m.baseline(data), data)
        # The baseline supplies geosite:private, so overriding it is not an orphan.
        self.assertEqual([], m.orphan_policy_keys(base, {'dns': {'nameserver-policy': {'geosite:private': ['system']}}}))
        self.assertEqual(['geosite:nowhere'],
                         m.orphan_policy_keys(base, {'dns': {'nameserver-policy': {'geosite:nowhere': ['1.1.1.1']}}}))


class DevicePolicyTests(unittest.TestCase):
    """Which sources the proxy may carry, expressed so matching order works."""

    def setUp(self):
        self.settings = {'transparent': True, 'secret': 'state-secret', **m.SWITCH_DEFAULTS}
        self.data = m.parse_yaml(SUBSCRIPTION)
        self.preset = m.parse_yaml((m.Path(m.__file__).resolve().parents[3]
            / 'share/mihomo/presets/full.yaml').read_bytes())
        m.absorb_switches(self.preset, self.settings)

    def rendered(self, **settings):
        return m.parse_yaml(m.render(self.data, {**self.settings, **settings},
            overlay=copy.deepcopy(self.preset)))

    def test_off_leaves_the_provider_rules_alone(self):
        base = self.rendered()['rules']
        self.assertEqual(base, self.rendered(device_mode='off',
                                             device_list=['192.168.10.50'])['rules'])
        # An empty list is the same as off, whatever the mode says.
        self.assertEqual(base, self.rendered(device_mode='whitelist', device_list=[])['rules'])

    def test_a_blacklist_sends_only_the_listed_sources_direct(self):
        rules = self.rendered(device_mode='blacklist',
                              device_list=['192.168.10.50', '192.168.10.0/24'])['rules']
        self.assertEqual(['SRC-IP-CIDR,192.168.10.50/32,DIRECT',
                          'SRC-IP-CIDR,192.168.10.0/24,DIRECT'], rules[:2])

    def test_a_whitelist_matches_everything_it_does_not_list(self):
        # Matching ends at the first hit, so the listed sources cannot be the
        # ones matched: they are what is left over once everything else is out.
        rules = self.rendered(device_mode='whitelist', device_list=['192.168.10.50'])['rules']
        self.assertEqual('NOT,((SRC-IP-CIDR,192.168.10.50/32)),DIRECT', rules[0])
        several = self.rendered(device_mode='whitelist',
                                device_list=['192.168.10.50', '10.0.0.0/8'])['rules']
        self.assertEqual('NOT,((OR,((SRC-IP-CIDR,192.168.10.50/32),'
                         '(SRC-IP-CIDR,10.0.0.0/8)))),DIRECT', several[0])

    def test_the_device_rules_sit_ahead_of_the_provider_rules(self):
        rules = self.rendered(device_mode='blacklist', device_list=['192.168.10.50'])['rules']
        self.assertEqual('SRC-IP-CIDR,192.168.10.50/32,DIRECT', rules[0])
        self.assertIn('MATCH', rules[-1])

    def test_the_router_dns_pins_stay_ahead_of_the_device_rules(self):
        # Those pins keep the router's own encrypted DNS out of the tunnel; a
        # device rule in front of them would decide that traffic instead.
        settings = dict(self.settings, router_dns=True, device_mode='blacklist',
                        device_list=['192.168.10.50'])
        rules = m.parse_yaml(m.render(self.data, settings, overlay=copy.deepcopy(self.preset),
            upstreams='forward-addr: 192.0.2.53@853'))['rules']
        self.assertTrue(rules[0].startswith('IP-CIDR,192.0.2.53/32,DIRECT'), rules[0])
        self.assertIn('SRC-IP-CIDR,192.168.10.50/32,DIRECT', rules[:6])

    def test_entries_that_are_not_addresses_are_refused(self):
        manager = m.Manager.__new__(m.Manager)
        base = dict(self.settings, dns_fallback=True, service_enabled=True,
                    device='router', subscription_url='')
        manager.check_settings(dict(base, device_mode='whitelist',
                                    device_list=['192.168.10.50', 'fd00::/64']))
        for bad in (['not-an-ip'], ['192.168.10.50 '], [''], ['192.168.10.300'],
                    ['1.2.3.4'] * (m.DEVICE_LIMIT + 1)):
            with self.assertRaises(m.Error, msg=bad):
                manager.check_settings(dict(base, device_mode='blacklist', device_list=bad))
        with self.assertRaises(m.Error):
            manager.check_settings(dict(base, device_mode='nonsense'))


class StaleForwarderTests(unittest.TestCase):
    """A generated file that still points at a stopped core must be rewritten."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.generated = Path(self.temp.name) / 'dot.conf'
        self.system = m.System()
        self.ran = []

        def record(args, **kwargs):
            self.ran.append(args)
            stdout = b'Mihomo integration unchanged.' if args[0].endswith('php') else b''
            return subprocess.CompletedProcess(args, 0, stdout, b'')

        self.record = record
        state = Path(self.temp.name) / 'state'
        state.mkdir()
        self.patches = [patch.object(m, 'UNBOUND_GENERATED', str(self.generated)),
                        patch.object(m, 'STATE', str(state))]
        for entry in self.patches:
            entry.start()
            self.addCleanup(entry.stop)

    def reloaded(self):
        return any('template' in [str(part) for part in args] for args in self.ran)

    def test_an_agreeing_file_lets_an_unchanged_answer_skip_the_reload(self):
        self.generated.write_text('forward-addr: 8.8.8.8@853\n')
        with patch.object(self.system, 'run', side_effect=self.record):
            self.system.dns(False, {'dns_fallback': True})
        self.assertFalse(self.reloaded())

    def test_a_stale_file_is_rewritten_even_when_the_answer_is_unchanged(self):
        # This is the state that took DNS down twice: the configuration had
        # already been reverted, so the helper reported nothing to do, while the
        # file Unbound reads still forwarded to a core that was no longer there.
        self.generated.write_text('forward-addr: %s\n' % m.FORWARDER)
        with patch.object(self.system, 'run', side_effect=self.record):
            self.system.dns(False, {'dns_fallback': True})
        self.assertTrue(self.reloaded())

    def test_enabling_against_a_file_without_the_forwarder_also_reloads(self):
        self.generated.write_text('forward-addr: 8.8.8.8@853\n')
        with patch.object(self.system, 'run', side_effect=self.record):
            self.system.dns(True, {'dns_fallback': True})
        self.assertTrue(self.reloaded())

    def test_a_missing_file_counts_as_not_forwarding(self):
        self.assertFalse(self.system.forwarded())
