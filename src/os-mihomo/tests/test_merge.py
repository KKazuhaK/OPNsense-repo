"""Exercise merge policy, transport pins, and real System error boundaries."""
import copy
import json
import shutil
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
        candidate = self.manager.state / 'private-candidate.yaml'
        candidate.write_text('tun: {enable: false}\n')
        with patch.object(m.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, b'PRIVATE_TOKEN', b'state-secret')):
            with self.assertRaises(m.Error) as error: m.System().validate(candidate)
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
        # 'log-level' is no switch of ours, so it must survive absorption.
        overlay = {'external-controller': m.ANY_CONTROLLER, 'log-level': 'warning'}
        lifted = m.absorb_switches(overlay, self.settings)
        self.assertEqual(m.ANY_CONTROLLER, lifted['controller'])
        self.assertEqual({'log-level': 'warning'}, overlay)
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


class DeviceDiscoveryTests(unittest.TestCase):
    """What the picker offers, and what it must refuse to offer."""

    ARP = (b'? (192.168.10.90) at d2:f3:58:35:50:e2 on vtnet0 expires in 1181 seconds [ethernet]\n'
           b'? (192.168.10.39) at 28:c5:d2:d4:0c:4c on vtnet0 expires in 595 seconds [ethernet]\n'
           b'? (50.98.231.1) at 20:e0:9c:03:e1:95 on vtnet1 expires in 900 seconds [ethernet]\n'
           b'? (192.168.8.1) at bc:24:11:a2:3e:42 on vtnet0 permanent [ethernet]\n')
    NDP = b'fe80::be24:11ff:fea2:3e42%vtnet0 bc:24:11:a2:3e:42 vtnet0 23h59m58s R\n'
    IFCONFIG = b'vtnet0: flags=8843\n\tinet 192.168.8.1 netmask 0xffffff00\n'
    ROUTE = b'   route to: default\n  interface: vtnet1\n'

    def runner(self, args, **kwargs):
        name = ' '.join(args)
        payload = (self.ARP if 'arp' in name else self.NDP if 'ndp' in name
                   else self.IFCONFIG if 'ifconfig' in name else self.ROUTE)
        return subprocess.CompletedProcess(args, 0, payload, b'')

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'var/db').mkdir(parents=True)
        (self.root / 'conf').mkdir()
        (self.root / 'var/db/dnsmasq.leases').write_text(
            '1789000000 d2:f3:58:35:50:e2 192.168.10.90 iPhone 01:d2:f3:58:35:50:e2\n'
            '1789000000 28:c5:d2:d4:0c:4c 192.168.10.39 * *\n'
            '00:01:00:01:32:37:be:ee:bc:24:11:a2:3e:42\n')
        (self.root / 'conf/config.xml').write_text(
            '<opnsense><dnsmasq><hosts><hwaddr>28:C5:D2:D4:0C:4C</hwaddr>'
            '<ip>192.168.10.39</ip></hosts></dnsmasq></opnsense>')

    def found(self):
        return {d['address']: d for d in m.known_devices(self.runner, self.root)}

    def test_only_devices_on_our_own_links_are_offered(self):
        found = self.found()
        # The uplink's neighbours are the ISP's, a link-local address names an
        # interface rather than a device, and the router is not a device to steer.
        self.assertEqual(['192.168.10.39', '192.168.10.90'], sorted(found))

    def test_a_lease_names_the_device_and_a_reservation_pins_it(self):
        found = self.found()
        self.assertEqual('iPhone', found['192.168.10.90']['hostname'])
        self.assertEqual('', found['192.168.10.39']['hostname'], 'the * placeholder is not a name')
        self.assertIs(True, found['192.168.10.39']['reserved'])
        self.assertIs(False, found['192.168.10.90']['reserved'])

    def test_a_rotating_hardware_address_is_pointed_out(self):
        # Phones present a different address per network and change it over
        # time, so a rule written against whatever address it holds today is a
        # rule that stops matching without saying so.
        found = self.found()
        self.assertIs(True, found['192.168.10.90']['randomised_mac'])
        self.assertIs(False, found['192.168.10.39']['randomised_mac'])

    def test_the_lease_file_survives_lines_that_are_not_leases(self):
        self.assertEqual(2, len(m.read_leases(self.root)), 'the DUID line is not a lease')


class ServiceSwitchTests(unittest.TestCase):
    """The proxy ports, LAN binding and TUN parameters as first-class settings."""

    def setUp(self):
        self.settings = {'transparent': True, 'secret': 'state-secret', **m.SWITCH_DEFAULTS}
        self.data = m.parse_yaml(SUBSCRIPTION)
        self.preset = m.parse_yaml((m.Path(m.__file__).resolve().parents[3]
            / 'share/mihomo/presets/full.yaml').read_bytes())

    # The fixture subscription listens on :53, which render() refuses; the
    # presets normally override it. These tests must not also state the keys
    # under test, because a merge value deliberately beats a switch.
    MINIMAL = {'dns': {'listen': '127.0.0.1:1053'}}

    def generated(self, overlay=None, **settings):
        return m.parse_yaml(m.render(self.data, {**self.settings, **settings},
            overlay=copy.deepcopy(self.MINIMAL if overlay is None else overlay)))

    def test_the_switches_reach_the_configuration(self):
        generated = self.generated(mixed_port=8080, socks_port=8081, allow_lan=True,
                                   bind_address='192.168.8.1', tun_stack='system', tun_mtu=1400)
        self.assertEqual(8080, generated['mixed-port'])
        self.assertEqual(8081, generated['socks-port'])
        self.assertIs(True, generated['allow-lan'])
        self.assertEqual('192.168.8.1', generated['bind-address'])
        self.assertEqual('system', generated['tun']['stack'])
        self.assertEqual(1400, generated['tun']['mtu'])

    def test_a_merge_yaml_value_is_lifted_into_the_switch_it_belongs_to(self):
        # Otherwise the form shows a value the running configuration contradicts,
        # which is the whole reason these are absorbed rather than merely merged.
        overlay = {'mixed-port': 8080, 'socks-port': 8081, 'allow-lan': True,
                   'bind-address': '192.168.8.1', 'tun': {'stack': 'mixed', 'mtu': 1300}}
        lifted = m.absorb_switches(overlay, self.settings)
        self.assertEqual(8080, lifted['mixed_port'])
        self.assertEqual(8081, lifted['socks_port'])
        self.assertIs(True, lifted['allow_lan'])
        self.assertEqual('192.168.8.1', lifted['bind_address'])
        self.assertEqual('mixed', lifted['tun_stack'])
        self.assertEqual(1300, lifted['tun_mtu'])
        self.assertEqual({}, overlay, 'an absorbed key must not keep overriding')
        # And the lifted values render back to exactly what was written.
        generated = m.parse_yaml(m.render(self.data, lifted, overlay=copy.deepcopy(self.MINIMAL)))
        self.assertEqual(8080, generated['mixed-port'])
        self.assertEqual('mixed', generated['tun']['stack'])

    def test_a_value_the_switch_cannot_express_keeps_winning_and_is_reported(self):
        overlay = {'tun': {'stack': 'nonesuch'}}
        lifted = m.absorb_switches(copy.deepcopy(overlay), self.settings)
        self.assertEqual('gvisor', lifted['tun_stack'], 'an unknown stack must not be adopted')
        self.assertIn('tun_stack', m.switch_overrides(overlay))

    def test_true_is_not_a_port(self):
        # YAML booleans are ints in Python, so "mixed-port: true" would absorb
        # as port 1 and quietly move the proxy.
        overlay = {'mixed-port': True}
        lifted = m.absorb_switches(overlay, self.settings)
        self.assertEqual(m.SWITCH_DEFAULTS['mixed_port'], lifted['mixed_port'])
        self.assertEqual({'mixed-port': True}, overlay)

    def test_an_upgrade_keeps_the_ports_it_was_running(self):
        rendered = {'mixed-port': 8080, 'socks-port': 8081, 'allow-lan': True,
                    'bind-address': '10.0.0.1', 'tun': {'enable': True, 'stack': 'system', 'mtu': 1300}}
        seeded = m.adopt_switches(rendered, {})
        self.assertEqual(8080, seeded['mixed_port'])
        self.assertEqual('10.0.0.1', seeded['bind_address'])
        self.assertEqual('system', seeded['tun_stack'])

    def test_a_stopped_tun_states_no_intent_to_adopt(self):
        # render() forces these off when transparent routing is off, so reading
        # them back would record the enforcement as if it were a choice.
        seeded = m.adopt_switches({'tun': {'enable': False, 'stack': 'system', 'mtu': 1300}}, {})
        self.assertNotIn('tun_stack', seeded)
        self.assertNotIn('tun_mtu', seeded)


class BaselineTests(unittest.TestCase):
    """A bare subscription gets a DNS policy; a complete one is never blended."""

    def setUp(self):
        self.settings = {'transparent': True, 'secret': 'state-secret', **m.SWITCH_DEFAULTS}
        self.preset = m.parse_yaml((m.Path(m.__file__).resolve().parents[3]
            / 'share/mihomo/presets/full.yaml').read_bytes())

    def generated(self, data, **settings):
        return m.parse_yaml(m.render(data, {**self.settings, **settings},
            overlay=copy.deepcopy(self.preset)))

    def test_group_selections_survive_a_restart(self):
        # Without this the core forgets which proxy each group is set to, and a
        # group falls back to whatever its provider listed first -- usually
        # DIRECT. A subscription update, a reboot and every transparent routing
        # change restart the core, so the node picked in the panel would
        # silently stop being used.
        self.assertIs(True, self.generated(m.parse_yaml(SUBSCRIPTION))['profile']['store-selected'])

    def test_a_subscription_that_states_the_profile_keeps_it(self):
        data = m.parse_yaml(SUBSCRIPTION)
        data['profile'] = {'store-selected': False}
        self.assertIs(False, self.generated(data)['profile']['store-selected'])

    def test_other_profile_keys_are_left_beside_it(self):
        data = m.parse_yaml(SUBSCRIPTION)
        data['profile'] = {'store-fake-ip': True}
        profile = self.generated(data)['profile']
        self.assertIs(True, profile['store-fake-ip'])
        self.assertIs(True, profile['store-selected'])

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


class ConfigctlContractTests(unittest.TestCase):
    """configctl answers in a vocabulary the caller has to read correctly."""

    def test_a_bare_err_is_a_failure(self):
        # It carries no other marker, so a check looking only for "Execute
        # error" reads a failed reload as a success and carries on.
        system = m.System()
        with patch.object(m.subprocess, 'run',
                          return_value=subprocess.CompletedProcess([], 0, b'ERR\n', b'')):
            with self.assertRaises(m.Error):
                system.run(['/usr/local/sbin/configctl', 'template', 'reload', 'x'])
        with patch.object(m.subprocess, 'run',
                          return_value=subprocess.CompletedProcess([], 0, b'OK\n', b'')):
            system.run(['/usr/local/sbin/configctl', 'template', 'reload', 'x'])

    def test_only_configctl_answers_are_read_this_way(self):
        # Another program printing ERR is not making the same statement.
        system = m.System()
        with patch.object(m.subprocess, 'run',
                          return_value=subprocess.CompletedProcess([], 0, b'ERR\n', b'')):
            system.run(['/usr/local/sbin/unbound-checkconf', '/dev/null'])

    def test_the_resolver_is_validated_by_its_own_start_script(self):
        # OPNsense pairs unbound-checkconf with the repair its failure calls
        # for: a corrupt root.key is deleted and re-fetched. Running the check
        # here copies it without the repair, against a trust anchor file the
        # running resolver rewrites on its own schedule.
        source = (Path(m.__file__)).read_text()
        self.assertNotIn('unbound-checkconf', source.split('# unbound-checkconf')[0])

    def test_the_unbound_templates_are_reloaded_by_their_container(self):
        # The templates live in sub-containers; the bare name matches nothing,
        # generates no file, and answers ERR.
        calls = []

        def record(args, **kwargs):
            calls.append(args)
            return subprocess.CompletedProcess(args, 0, b'', b'')

        state = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, str(state), True)
        generated = state / 'dot.conf'
        generated.write_text('forward-addr: %s\n' % m.FORWARDER)
        with patch.object(m, 'STATE', str(state)), patch.object(m, 'UNBOUND_GENERATED', str(generated)):
            system = m.System()
            with patch.object(system, 'run', side_effect=record):
                system.dns(False, {'dns_fallback': True})
        reloads = [args for args in calls if 'template' in args]
        self.assertEqual(1, len(reloads), calls)
        self.assertEqual('OPNsense/Unbound/*', reloads[0][-1])


class AnchorOrderingTests(unittest.TestCase):
    """The anchor must be read before the restart that can destroy it."""

    MANAGED = b'; autotrust trust anchor file\n;;id: . 1\n'

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.anchor = root / 'root.key'
        self.anchor.write_bytes(self.MANAGED)
        (root / 'state').mkdir()
        (root / 'dot.conf').write_text('forward-addr: 8.8.8.8@853\n')
        for entry in (patch.object(m, 'ROOT_ANCHOR', str(self.anchor)),
                      patch.object(m, 'STATE', str(root / 'state')),
                      patch.object(m, 'UNBOUND_GENERATED', str(root / 'dot.conf')),
                      patch.object(m.os, 'chown')):
            entry.start()
            self.addCleanup(entry.stop)
        self.system = m.System()

    def test_the_anchor_read_precedes_the_restart(self):
        # The start script deletes root.key whenever it cannot check the
        # configuration, so a snapshot taken afterwards captures the damage
        # rather than the file worth restoring.
        seen = []

        def record(args, **kwargs):
            name = ' '.join(str(part) for part in args)
            if 'unbound' in name and 'restart' in name:
                seen.append(('restart', self.anchor.exists()))
                if len([step for step, _ in seen if step == 'restart']) == 1:
                    # The changeover fails one restart, unbound-checkconf says
                    # so, and the start script answers by replacing the anchor
                    # with what unbound-anchor writes when it cannot resolve.
                    self.anchor.write_bytes(b'. IN DS 20326 8 2 E06D\n. IN DS 38696 8 2 683D\n')
            if args[0].endswith('pgrep'):
                # The resolver comes up only with an anchor it can read.
                return subprocess.CompletedProcess(
                    args, 0 if self.anchor.read_bytes().startswith(b'; autotrust') else 1, b'', b'')
            return subprocess.CompletedProcess(args, 0, b'', b'')

        real = m.System.anchor_snapshot

        def watched():
            seen.append(('read', self.anchor.exists()))
            return real()

        with patch.object(m.System, 'anchor_snapshot', staticmethod(watched)):
            with patch.object(self.system, 'run', side_effect=record):
                self.system.dns(True, {'dns_fallback': True})
        self.assertEqual(['read', 'restart'], [step for step, _ in seen][:2])
        self.assertTrue(seen[1][1], 'the restart must still have had the anchor to destroy')
        self.assertTrue(self.anchor.exists(), 'the destroyed anchor must be restored')


class ResolverRepairTests(unittest.TestCase):
    """A router whose resolver refused to start has no DNS at all."""

    MANAGED = b'; autotrust trust anchor file\n;;id: . 1\n. 86400 IN DNSKEY 257 3 8 AwEAAaz\n'
    # What unbound-anchor writes when it cannot reach a resolver: the root DS
    # records in plain form, with no autotrust header. auto-trust-anchor-file
    # reports the anchor for '.' presented twice and the validator never
    # initialises, so this shape is a resolver that can no longer start.
    DAMAGED = b'. IN DS 20326 8 2 E06D\n. IN DS 38696 8 2 683D\n'

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.anchor = Path(self.temp.name) / 'root.key'
        self.anchor.write_bytes(self.MANAGED)
        entry = patch.object(m, 'ROOT_ANCHOR', str(self.anchor))
        entry.start()
        self.addCleanup(entry.stop)
        chown = patch.object(m.os, 'chown')
        chown.start()
        self.addCleanup(chown.stop)
        self.system = m.System()

    def runner(self, alive):
        """alive is consulted per pgrep call, so a repair can change the answer."""
        self.calls = []

        def run(args, **kwargs):
            self.calls.append(args)
            if args[0].endswith('pgrep'):
                return subprocess.CompletedProcess(args, 0 if alive.pop(0) else 1, b'', b'')
            return subprocess.CompletedProcess(args, 0, b'', b'')
        return run

    def test_a_running_resolver_is_left_alone(self):
        with patch.object(self.system, 'run', side_effect=self.runner([True])):
            self.system.repair_resolver(self.MANAGED)
        self.assertEqual(self.MANAGED, self.anchor.read_bytes())
        self.assertEqual(1, len(self.calls))

    def test_a_dead_resolver_has_its_anchor_put_back_and_is_restarted(self):
        # The restart is what damaged it: the start script deletes the anchor
        # whenever it cannot check the configuration, and re-fetches it with
        # nothing able to answer.
        self.anchor.write_bytes(self.DAMAGED)
        with patch.object(self.system, 'run', side_effect=self.runner([False, True])):
            self.system.repair_resolver(self.MANAGED)
        self.assertEqual(self.MANAGED, self.anchor.read_bytes())
        self.assertIn(['/usr/local/sbin/configctl', 'unbound', 'restart'], self.calls)

    def test_the_anchor_is_never_deleted(self):
        # Deleting it is what turns a failed restart into a resolver that can
        # never start: the re-fetch has no resolver to ask.
        with patch.object(self.system, 'run', side_effect=self.runner([False, True])):
            self.system.repair_resolver(self.MANAGED)
        self.assertTrue(self.anchor.exists())

    def test_a_resolver_that_stays_down_is_reported(self):
        # Silence here would leave the operator with a working-looking page and
        # a network that cannot resolve anything.
        with patch.object(self.system, 'run', side_effect=self.runner([False, False])):
            with self.assertRaises(m.Error):
                self.system.repair_resolver(self.MANAGED)

    def test_a_managed_anchor_is_worth_snapshotting(self):
        self.assertEqual(self.MANAGED, self.system.anchor_snapshot())

    def test_an_already_damaged_anchor_is_not_snapshotted(self):
        # Putting this shape back would only reinstate the damage.
        self.anchor.write_bytes(self.DAMAGED)
        self.assertIsNone(self.system.anchor_snapshot())

    def test_a_missing_anchor_is_not_snapshotted(self):
        self.anchor.unlink()
        self.assertIsNone(self.system.anchor_snapshot())

    def test_a_dead_resolver_with_no_good_anchor_is_still_restarted(self):
        with patch.object(self.system, 'run', side_effect=self.runner([False, True])):
            self.system.repair_resolver(None)
        self.assertIn(['/usr/local/sbin/configctl', 'unbound', 'restart'], self.calls)
