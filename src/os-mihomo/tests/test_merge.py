"""Exercise merge policy, transport pins, and real System error boundaries."""
import copy
import fcntl
import json
import os
import shutil
from pathlib import Path
import subprocess
import tempfile
import threading
import time
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

    def test_ipv6_guard_reads_opnsense_26_7_sources(self):
        def config(interfaces='', opnsense='', dnsmasq=''):
            return ('<opnsense><interfaces>%s</interfaces><OPNsense>%s</OPNsense>%s</opnsense>'
                    % (interfaces, opnsense, dnsmasq)).encode()
        v4_pool = ('<dnsmasq><enable>1</enable><dhcp><enable_ra>1</enable_ra></dhcp>'
                   '<dhcp_ranges uuid="r"><interface>lan</interface><start_addr>192.168.2.1</start_addr>'
                   '<end_addr>192.168.2.199</end_addr><constructor/><ra_mode/></dhcp_ranges></dnsmasq>')
        wan = '<wan><enable>1</enable><ipaddr>dhcp</ipaddr><ipaddrv6>dhcp6</ipaddrv6></wan>'
        # Shapes of the production routers: the global enable-ra switch with an
        # IPv4-only pool sends nothing, and identity association only numbers
        # the router's own LAN address.
        self.assertFalse(m.advertises_ipv6(config(wan + '<lan><enable>1</enable><ipaddrv6/></lan>',
                                                  '<radvd version="1.0.1"/>', v4_pool)))
        self.assertFalse(m.advertises_ipv6(config(wan + '<lan><enable>1</enable><ipaddrv6>idassoc6</ipaddrv6>'
                                                  '<track6-interface>wan</track6-interface></lan>', '', v4_pool)))
        # Dnsmasq advertises only through an IPv6 range, and only while it runs.
        v6_range = '<dhcp_ranges uuid="6"><start_addr>::</start_addr><constructor>lan</constructor><ra_mode>slaac</ra_mode></dhcp_ranges>'
        self.assertTrue(m.advertises_ipv6(config(dnsmasq='<dnsmasq><enable>1</enable>' + v6_range + '</dnsmasq>')))
        self.assertTrue(m.advertises_ipv6(config(dnsmasq='<dnsmasq><enable>1</enable><dhcp_ranges uuid="c">'
                                                 '<start_addr/><constructor>lan</constructor></dhcp_ranges></dnsmasq>')))
        self.assertFalse(m.advertises_ipv6(config(dnsmasq='<dnsmasq><enable>0</enable>' + v6_range + '</dnsmasq>')))
        # radvd: an enabled entry on an enabled interface advertises.
        lan = '<lan><enable>1</enable><ipaddr>192.168.0.1</ipaddr></lan>'
        entry = '<radvd><entries uuid="e"><interface>lan</interface><enabled>%s</enabled></entries></radvd>'
        self.assertTrue(m.advertises_ipv6(config(lan, entry % '1')))
        self.assertFalse(m.advertises_ipv6(config('<lan><ipaddr>192.168.0.1</ipaddr></lan>', entry % '1')))
        self.assertFalse(m.advertises_ipv6(config(lan, entry % '')))
        # track6 advertises automatically unless it is handed off or explicitly silenced.
        track = '<lan><enable>1</enable><ipaddrv6>track6</ipaddrv6><track6-interface>wan</track6-interface>%s</lan>'
        self.assertTrue(m.advertises_ipv6(config(wan + track % '')))
        self.assertFalse(m.advertises_ipv6(config(wan + track % '<dhcpd6track6allowoverride>1</dhcpd6track6allowoverride>')))
        self.assertFalse(m.advertises_ipv6(config(wan + track % '', entry % '')))
        self.assertFalse(m.advertises_ipv6(config(wan + '<lan><ipaddrv6>track6</ipaddrv6></lan>')))
        # A relay counts only when it forwards to an IPv6 server.
        relay = ('<DHCRelay><relays uuid="r"><enabled>%s</enabled><interface>lan</interface><destination>d</destination></relays>'
                 '<destinations uuid="d"><name>up</name><server>%s</server></destinations></DHCRelay>')
        self.assertTrue(m.advertises_ipv6(config(lan, relay % ('1', '2001:db8::53'))))
        self.assertFalse(m.advertises_ipv6(config(lan, relay % ('1', '192.0.2.53'))))
        self.assertFalse(m.advertises_ipv6(config(lan, relay % ('0', '2001:db8::53'))))
        self.assertFalse(m.advertises_ipv6(config('<lan><ipaddr>192.168.0.1</ipaddr></lan>', relay % ('1', '2001:db8::53'))))
        # Interface groups are virtual and never advertise on their own.
        self.assertFalse(m.advertises_ipv6(config(wan + '<openvpn><enable>1</enable><virtual>1</virtual>'
                                                  '<ipaddrv6>track6</ipaddrv6></openvpn>')))
        # Kea's high-availability switch is not its DHCPv6 server.
        self.assertFalse(m.advertises_ipv6(config(opnsense='<Kea><dhcp6><general><enabled>0</enabled></general>'
                                                  '<ha><enabled>1</enabled></ha></dhcp6></Kea>')))

    def test_a_declared_ipv6_offer_does_not_stop_router_dns(self):
        self.settings['router_dns'] = True
        self.data['ipv6'] = False
        self.data['dns']['ipv6'] = False
        upstreams = 'forward-addr: 192.0.2.53@853'
        with self.assertRaisesRegex(m.Error, 'offered IPv6'):
            self.generated(upstreams=upstreams, ipv6_advertised=True)
        # Only a stored true declares that captured devices get no IPv6.
        for value in (False, 'true', 1, None):
            with self.subTest(value=value), self.assertRaisesRegex(m.Error, 'offered IPv6'):
                self.generated(settings=dict(self.settings, ipv6_clients_restricted=value),
                               upstreams=upstreams, ipv6_advertised=True)
        self.settings['ipv6_clients_restricted'] = True
        generated = self.generated(upstreams=upstreams, ipv6_advertised=True)
        # The offer changes nothing else: Mihomo still gives no AAAA.
        self.assertEqual(self.generated(upstreams=upstreams, ipv6_advertised=False), generated)
        self.assertFalse(generated['ipv6'])
        self.assertFalse(generated['dns']['ipv6'])
        self.assertEqual('IP-CIDR,192.0.2.53/32,DIRECT,no-resolve', generated['rules'][0])
        # The provider fallback check is not the IPv6 guard, and still refuses.
        self.data['dns']['fallback'] = ['https://example.invalid/dns-query']
        with self.assertRaisesRegex(m.Error, 'fallback'):
            self.generated(upstreams=upstreams, ipv6_advertised=True)

    def test_ipv6_for_chosen_devices_is_still_detected_as_offered(self):
        # How an administrator gives IPv6 to one device on OPNsense 26.7: a
        # Dnsmasq DHCPv6 range built from the LAN's delegated prefix that
        # serves static reservations only, a reservation by MAC, and Router
        # Advertisements in Managed mode. The declaration that captured devices
        # get none changes what follows detection, never detection itself.
        wan = ('<wan><enable>1</enable><if>igc0</if><ipaddr>dhcp</ipaddr><ipaddrv6>dhcp6</ipaddrv6>'
               '<dhcp6-ia-pd-len>3</dhcp6-ia-pd-len></wan>')
        lan = ('<lan><enable>1</enable><if>igc1</if><ipaddr>192.168.0.1</ipaddr><subnet>24</subnet>'
               '<ipaddrv6>track6</ipaddrv6><track6-interface>wan</track6-interface>'
               '<track6-prefix-id>0</track6-prefix-id>%s</lan>')
        # The manual adjustment that hands the LAN's DHCPv6 and RA to other services.
        manual = '<dhcpd6track6allowoverride>1</dhcpd6track6allowoverride>'
        host = ('<hosts uuid="3d1e8a52-6d0b-4c1e-9a55-0a4f5f2b1c01"><host>nas</host><domain/><local>0</local>'
                '<ip>::4</ip><cnames/><client_id/><hwaddr>00:11:32:0a:0b:0c</hwaddr><lease_time/>'
                '<ignore>0</ignore><set_tag/><descr>NAS</descr><comments/><aliases/></hosts>')
        v4_range = ('<dhcp_ranges uuid="7b0f3c14-1f4e-4d61-8e1b-2d2c1c0a9e01"><interface>lan</interface><set_tag/>'
                    '<start_addr>192.168.0.100</start_addr><end_addr>192.168.0.199</end_addr><subnet_mask/>'
                    '<constructor/><mode/><prefix_len/><lease_time/><domain_type>range</domain_type><domain/>'
                    '<nosync>0</nosync><ra_mode/><ra_priority/><ra_mtu/><ra_interval/><ra_router_lifetime/>'
                    '<description/></dhcp_ranges>')
        static_range = ('<dhcp_ranges uuid="c2a6d1b0-44f1-4e0c-b1d7-5b8e0f7a6c02"><interface>lan</interface>'
                        '<set_tag/><start_addr>%s</start_addr><end_addr>%s</end_addr><subnet_mask/>'
                        '<constructor>lan</constructor><mode>static</mode><prefix_len>64</prefix_len>'
                        '<lease_time/><domain_type>range</domain_type><domain/><nosync>0</nosync><ra_mode/>'
                        '<ra_priority/><ra_mtu/><ra_interval/><ra_router_lifetime/>'
                        '<description>NAS only</description></dhcp_ranges>')
        dnsmasq = ('<dnsmasq version="1.0.9"><enable>%s</enable><dhcp><no_interface/><fqdn>1</fqdn><domain/>'
                   '<local>1</local><lease_max/><authoritative>0</authoritative>'
                   '<default_fw_rules>1</default_fw_rules><reply_delay/><enable_ra>0</enable_ra>'
                   '<host_ping>1</host_ping><nosync>0</nosync><log_dhcp>0</log_dhcp><log_quiet>0</log_quiet>'
                   '</dhcp>' + host + '%s</dnsmasq>')
        entry = ('<entries uuid="0e6a2f4c-9d3b-4b8a-a1f0-6c7d8e9f0a03"><enabled>%s</enabled>'
                 '<interface>lan</interface><Base6Interface/><mode>%s</mode><DeprecatePrefix/><RemoveAdvOnExit/>'
                 '<RemoveRoute/><routes/><RDNSS/><DNSSL/><dns>1</dns><MinRtrAdvInterval>200</MinRtrAdvInterval>'
                 '<MaxRtrAdvInterval>600</MaxRtrAdvInterval><AdvDNSSLLifetime/><AdvDefaultLifetime/>'
                 '<AdvLinkMTU/><AdvPreferredLifetime/><AdvRDNSSLifetime/><AdvRouteLifetime/>'
                 '<AdvValidLifetime/><AdvDefaultPreference>medium</AdvDefaultPreference><nat64prefix/>'
                 '<AdvCurHopLimit>64</AdvCurHopLimit></entries>')

        def config(lan_extra=manual, radvd='', ranges=''):
            return ('<opnsense><interfaces>%s%s</interfaces><OPNsense><radvd version="1.0.1">%s</radvd>'
                    '</OPNsense>%s</opnsense>' % (wan, lan % lan_extra, radvd, dnsmasq % ('1', v4_range + ranges))
                    ).encode()

        # Nothing but the IPv4 pool, and the LAN handed off: no offer.
        self.assertFalse(m.advertises_ipv6(config()))
        # The static-only range offers IPv6, whichever suffix it starts at.
        for start, end in (('::', ''), ('::4', '::4'), ('::4', '')):
            with self.subTest(start=start, end=end):
                self.assertTrue(m.advertises_ipv6(config(ranges=static_range % (start, end))))
        # Only while Dnsmasq runs.
        disabled = config(ranges=static_range % ('::', '')).replace(b'<enable>1</enable><dhcp>',
                                                                    b'<enable>0</enable><dhcp>')
        self.assertFalse(m.advertises_ipv6(disabled))
        # A Managed entry advertises on its own, on a tracking LAN handed off
        # or on one with a static IPv6 address; switched off, it silences a
        # tracking LAN that would otherwise advertise automatically.
        for mode in ('managed', 'assist', 'stateless', 'unmanaged', 'router'):
            with self.subTest(mode=mode):
                self.assertTrue(m.advertises_ipv6(config(radvd=entry % ('1', mode))))
        static_lan = config(radvd=entry % ('1', 'managed')).replace(
            b'<ipaddrv6>track6</ipaddrv6>', b'<ipaddrv6>2001:470:1f05::1</ipaddrv6><subnetv6>64</subnetv6>')
        self.assertTrue(m.advertises_ipv6(static_lan))
        self.assertFalse(m.advertises_ipv6(config(radvd=entry % ('0', 'managed'))))
        self.assertFalse(m.advertises_ipv6(config(lan_extra='', radvd=entry % ('0', 'managed'))))
        self.assertTrue(m.advertises_ipv6(config(lan_extra='')))
        # Both together, as on the router this is for.
        self.assertTrue(m.advertises_ipv6(config(radvd=entry % ('1', 'managed'), ranges=static_range % ('::', ''))))

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
        self.manager.router_context = lambda settings, reaching=None: ('forward-addr: 192.0.2.53@853', False)
        self.manager.apply(SUBSCRIPTION, settings)
        self.manager.router_context = lambda settings, reaching=None: ('forward-addr: 192.0.2.54@853', False)
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

    def test_dns_readiness_cannot_hide_missing_tun_interface(self):
        config = self.manager.state / 'ready.yaml'
        config.write_text("tun: {enable: true, auto-route: false}\ndns: {enable: true, listen: '127.0.0.1:1053'}\n")
        system = m.System()
        owner = unittest.mock.Mock()
        owner.record_started.return_value = {'owned': True}
        def run(args, **kwargs):
            rc = 1 if args[0] in {'/usr/sbin/service', '/usr/bin/pgrep', '/sbin/ifconfig'} else 0
            return subprocess.CompletedProcess(args, rc, b'interface: lo1', b'')
        with patch.object(system, 'run', side_effect=run), patch.object(system, 'running', side_effect=[False] + [True] * 30), patch.object(system, '_core_group', return_value=owner), patch.object(system, 'destroy_tun'), patch.object(system, 'stop') as stop, patch.object(m.time, 'sleep'), patch.object(m.socket, 'create_connection') as dns:
            with self.assertRaises(m.Error): system.start(config, True)
            stop.assert_called_once()
            dns.assert_not_called()

    def test_worker_check_requires_exact_executable_and_nul_argv(self):
        pid = self.manager.state / 'pid'
        pid.write_text('12345')
        expected = ['/usr/local/bin/python3', m.SCRIPT, 'sub-update']
        base = {'pid': 12345, 'ppid': 1, 'uid': os.geteuid(), 'birth': '1:1',
                'executable': expected[0], 'argv': expected, 'stopped': False}
        system = m.System(process_reader=lambda unused: dict(
            base, executable='/usr/bin/vim', argv=['/usr/bin/vim', expected[0]]))
        self.assertFalse(system.process_running(str(pid), expected[0], expected))
        system = m.System(process_reader=lambda unused: base)
        self.assertTrue(system.process_running(str(pid), expected[0], expected))


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
        self.assertEqual('redir-host', default['dns']['enhanced-mode'])
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
        self.assertEqual('redir-host', lifted['dns_mode'])
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


class RedirectListenerTests(unittest.TestCase):
    """The fast TCP path's loopback listener is plugin policy, like the controller."""
    OWNED = {'name': m.REDIRECT_LISTENER, 'type': 'redir', 'port': m.REDIRECT_PORT, 'listen': '127.0.0.1'}

    def setUp(self):
        self.settings = {'transparent': True, 'secret': 'state-secret', **m.SWITCH_DEFAULTS,
                         'tcp_redirect': True}
        self.data = m.parse_yaml(SUBSCRIPTION)
        self.data.pop('dns', None)

    def rendered(self, overlay=None, preset='full', **settings):
        base = m.parse_yaml((m.Path(m.__file__).resolve().parents[3]
                             / ('share/mihomo/presets/' + preset + '.yaml')).read_bytes())
        merged = m.merge_yaml(base, overlay or {})
        return m.parse_yaml(m.render(self.data, {**self.settings, **settings}, overlay=merged))

    def owned(self, generated):
        return [item for item in generated.get('listeners') or [] if item.get('name') == m.REDIRECT_LISTENER]

    def test_listener_exists_only_for_the_transparent_tun_with_the_setting_on(self):
        self.assertEqual([self.OWNED], self.owned(self.rendered()))
        self.assertEqual([self.OWNED], self.owned(self.rendered(preset='tun-only')))
        self.assertEqual([], self.owned(self.rendered(tcp_redirect=False)))
        self.assertEqual([], self.owned(self.rendered(transparent=False)))
        self.assertEqual([], self.owned(self.rendered(preset='proxy-only')))
        self.settings.pop('tcp_redirect')
        generated = self.rendered()
        self.assertEqual([], self.owned(generated))
        self.assertNotIn('listeners', generated)

    def test_merge_yaml_cannot_drop_move_or_claim_the_listener(self):
        user = {'name': 'lan-socks', 'type': 'socks', 'port': 7900, 'listen': '0.0.0.0'}
        self.assertEqual([user, self.OWNED], self.rendered({'listeners': [user]})['listeners'])
        self.assertEqual([self.OWNED], self.rendered({'listeners': []})['listeners'])
        self.assertEqual([self.OWNED], self.rendered({'listeners': None})['listeners'])
        with self.assertRaisesRegex(m.Error, 'reserved'):
            self.rendered({'listeners': [dict(self.OWNED, port=7999)]})
        with self.assertRaisesRegex(m.Error, 'must be a list'):
            self.rendered({'listeners': {'name': 'lan-socks'}})
        # LAN exposure settings never move it off loopback.
        self.assertEqual([self.OWNED], self.owned(self.rendered(allow_lan=True, bind_address='*')))

    def test_a_taken_port_leaves_the_listener_out_without_failing_the_render(self):
        collisions = [({'redir-port': m.REDIRECT_PORT}, {}), ({'tproxy-port': m.REDIRECT_PORT}, {}),
                      ({'port': m.REDIRECT_PORT}, {}),
                      ({'listeners': [{'name': 'lan-socks', 'type': 'socks', 'port': m.REDIRECT_PORT}]}, {}),
                      ({'external-controller-tls': '127.0.0.1:%d' % m.REDIRECT_PORT}, {}),
                      ({'mixed-port': m.REDIRECT_PORT}, {}), ({'socks-port': m.REDIRECT_PORT}, {}),
                      ({}, {'controller': '127.0.0.1:%d' % m.REDIRECT_PORT})]
        for overlay, settings in collisions:
            with self.subTest(overlay=overlay, settings=settings):
                self.assertEqual([], self.owned(self.rendered(overlay, **settings)))
        self.assertIsNone(m.redirect_conflict({'mixed-port': 7890, 'dns': {'listen': '127.0.0.1:1053'}}))
        self.assertEqual('dns.listen', m.redirect_conflict({'dns': {'listen': '127.0.0.1:%d' % m.REDIRECT_PORT}}))


class CaptureInterfaceTests(unittest.TestCase):
    """Which interfaces transparent routing may capture from, and how that reads."""

    CONTEXT = {'interfaces': [
        {'name': 'wan', 'device': 'igc1', 'networks': ['104.52.226.170/23'], 'wan': True, 'descr': 'WAN'},
        {'name': 'opt7', 'device': 'pppoe0', 'networks': ['198.51.100.7/32'], 'wan': True, 'descr': 'WAN2'},
        {'name': 'opt10', 'device': 'igc4', 'networks': ['10.30.0.1/16'], 'wan': False, 'descr': 'Lab'},
        {'name': 'lan', 'device': 'bridge0', 'networks': ['192.168.0.1/22', 'fe80::1/64'], 'wan': False, 'descr': 'LAN'},
        {'name': 'opt2', 'device': 'igc2', 'networks': [], 'wan': False, 'descr': 'LAN2'},
        {'name': 'opt5', 'device': 'vlan0.20', 'networks': ['192.168.20.1/24'], 'wan': False},
        {'name': 'openvpn', 'device': 'openvpn', 'networks': [], 'wan': False, 'virtual': True, 'descr': 'OpenVPN'},
        {'name': 'opt8', 'device': 'tun_mihomo', 'networks': ['198.18.0.1/30'], 'wan': False},
        {'name': 'lo0', 'device': 'lo0', 'networks': ['127.0.0.1/8'], 'wan': False},
        {'name': 'bad name', 'device': 'igc9', 'networks': [], 'wan': False},
        {'name': 'opt9', 'device': 'igc5', 'networks': [], 'wan': 'no'}],
        'local_addresses': []}

    def candidates(self, context):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'routing-context.json'
            if context is not None:
                path.write_text(context if isinstance(context, str) else json.dumps(context))
            return m.capture_candidates(path)

    def test_selection_is_validated_and_deduplicated(self):
        self.assertEqual([], m.capture_interfaces(None))
        self.assertEqual([], m.capture_interfaces([]))
        self.assertEqual(['opt5', 'lan'], m.capture_interfaces(['opt5', 'lan', 'opt5']))
        for invalid in ('lan', ['lan;pfctl'], ['Array'.lower() + ' x'], [7], [''], ['x' * 40], ['1lan'],
                        ['opt%d' % n for n in range(m.CAPTURE_LIMIT + 1)]):
            with self.assertRaises(m.Error, msg=invalid):
                m.capture_interfaces(invalid)

    def test_only_internal_interfaces_are_offered_in_a_stable_order(self):
        found = self.candidates(self.CONTEXT)
        self.assertEqual(['lan', 'opt2', 'opt5', 'opt10'], [item['name'] for item in found])
        self.assertEqual({'name': 'lan', 'device': 'bridge0', 'descr': 'LAN', 'networks': ['192.168.0.1/22']}, found[0])
        # A bridge member is offered but shows it has nothing to capture from.
        self.assertEqual([], found[1]['networks'])
        self.assertEqual('OPT5', found[2]['descr'])
        for broken in (None, '', '{', '[]', json.dumps({'interfaces': 'x'})):
            self.assertEqual([], self.candidates(broken), broken)

    def test_policy_summary_names_the_scope_and_what_it_cannot_capture(self):
        settings = {'transparent': True, 'device_mode': 'whitelist', 'device_list': ['192.168.3.0/24']}
        found = self.candidates(self.CONTEXT)
        automatic = m.device_routing_policy(settings, found)
        self.assertEqual(['Enter TUN: 192.168.3.0/24', 'Other devices bypass TUN.',
                          'Router traffic and WAN connections bypass TUN.',
                          'DNS: with the full preset, Mihomo answers every device that uses the router DNS, '
                          'bypassed devices included.'], automatic)
        settings['capture_interfaces'] = ['lan', 'opt5']
        self.assertEqual(['Capture only from: LAN (lan), OPT5 (opt5).'] + automatic,
                         m.device_routing_policy(settings, found))
        settings['capture_interfaces'] = ['lan', 'opt7', 'opt99']
        self.assertEqual(['Capture only from: LAN (lan), opt7, opt99.',
                          'Not captured because they are missing, disabled or WAN-like: opt7, opt99.'] + automatic,
                         m.device_routing_policy(settings, found))
        settings['capture_interfaces'] = ['opt2']
        self.assertEqual('None of the selected interfaces has an address to capture from.',
                         m.device_routing_policy(settings, found)[1])
        # An IPv6-only interface captures nothing while Mihomo IPv6 is off.
        v6 = [{'name': 'opt6', 'device': 'igc6', 'descr': 'V6', 'networks': ['2001:db8:6::1/64']}]
        settings['capture_interfaces'] = ['opt6']
        self.assertEqual('None of the selected interfaces has an address to capture from.',
                         m.device_routing_policy(settings, v6)[1])
        self.assertEqual('Enter TUN: 192.168.3.0/24', m.device_routing_policy(dict(settings, ipv6=True), v6)[1])
        settings['capture_interfaces'] = ['opt2']
        # Without the context the summary still states the selection.
        self.assertEqual('Capture only from: opt2.', m.device_routing_policy(settings)[0])
        self.assertEqual([], m.device_routing_policy(dict(settings, transparent=False), found))

    def test_policy_summary_says_who_mihomo_answers_through_the_router_dns(self):
        settings = {'transparent': True, 'device_mode': 'off', 'device_list': []}
        captured = ('DNS: Mihomo answers the router DNS for devices captured above; '
                    'other devices and this router use the router DNS.')
        router = 'DNS: every device that uses the router DNS is answered by it.'
        for scope, router_dns, expected in (
                ('captured', False, captured), ('captured', True, captured),
                ('off', False, router), ('off', True, router),
                # Router DNS with 'all' counts as off rather than looping.
                ('all', True, router)):
            with self.subTest(scope=scope, router_dns=router_dns):
                summary = m.device_routing_policy(dict(settings, dns_scope=scope, router_dns=router_dns))
                self.assertEqual(expected, summary[-1])
                self.assertEqual('Internal devices may enter TUN.', summary[0])


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
        dns = self.generated(dns_override=True,
                             dns_nameserver=['tls://223.5.5.5', 'https://doh.pub/dns-query'],
                             dns_default=['223.6.6.6'])['dns']
        self.assertEqual(['tls://223.5.5.5', 'https://doh.pub/dns-query'], dns['nameserver'])
        self.assertEqual(['223.6.6.6'], dns['default-nameserver'])
        # Untouched fields still come from the subscription.
        self.assertEqual(['https://provider.invalid/dns-query'], dns['proxy-server-nameserver'])

    def test_manual_fields_only_replace_subscription_dns_when_enabled(self):
        manual = ['tls://dot.example.net']
        inherited = self.generated(dns_override=False, dns_nameserver=manual)['dns']
        overridden = self.generated(dns_override=True, dns_nameserver=manual)['dns']
        self.assertEqual(['https://provider.invalid/dns-query'], inherited['nameserver'])
        self.assertEqual(manual, overridden['nameserver'])

    def test_unbound_style_dot_tls_name_is_normalized_without_claiming_an_interface(self):
        settings = m.routing_settings({**self.settings, 'dns_override': True,
            'dns_nameserver': ['tls://162.159.36.5#v5brh3pn84.cloudflare-gateway.com'],
            'dns_proxy_nameserver': [
                'tls://[2606:4700:4700::1111]:8853#resolver.example.net&disable-ipv6=true',
                'tls://192.0.2.53#vtnet1', 'tls://192.0.2.54#RULES']})
        self.assertEqual(['tls://v5brh3pn84.cloudflare-gateway.com'],
                         settings['dns_nameserver'])
        self.assertEqual([
            'tls://resolver.example.net:8853#disable-ipv6=true',
            'tls://192.0.2.53#vtnet1', 'tls://192.0.2.54#RULES'],
            settings['dns_proxy_nameserver'])
        dns = self.generated(**settings)['dns']
        self.assertEqual(settings['dns_nameserver'], dns['nameserver'])
        self.assertEqual(settings['dns_proxy_nameserver'], dns['proxy-server-nameserver'])

    def test_bootstrap_repairs_unbound_style_tls_name_without_a_dependency_loop(self):
        manager = m.Manager.__new__(m.Manager)
        base = dict(self.settings, dns_fallback=True, service_enabled=True,
                    device='router', subscription_url='')
        stated = 'tls://162.159.36.5#v5brh3pn84.cloudflare-gateway.com'
        manager.check_settings(dict(base, dns_default=[stated]))
        self.assertEqual(['162.159.36.5'],
                         m.routing_settings(dict(base, dns_default=[stated]))['dns_default'])

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
        self.assertTrue(lifted['dns_override'])
        self.assertNotIn('dns', overlay)
        self.assertEqual([], m.switch_overrides({'dns': {}}))
        self.assertEqual(['dns_nameserver'],
                         m.switch_overrides({'dns': {'nameserver': 'not-a-list'}}))


class TransparentDNSSelectionTests(unittest.TestCase):
    """A bypassed device must receive addresses usable outside TUN."""

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

    def test_a_legacy_fake_ip_selection_uses_real_addresses_for_both_families(self):
        for ipv6 in (False, True):
            data = self.generated(dns_mode='fake-ip', ipv6=ipv6)
            self.assertEqual('redir-host', data['dns']['enhanced-mode'])
            self.assertEqual(ipv6, data['dns']['ipv6'])

    def test_merge_yaml_cannot_reenable_placeholder_answers_or_global_capture(self):
        data = self.generated({'dns': {'enhanced-mode': 'fake-ip', 'fake-ip-range6': 'fd00::/64'},
            'tun': {'auto-route': True, 'strict-route': True, 'auto-redirect': True}}, ipv6=True)
        self.assertEqual('redir-host', data['dns']['enhanced-mode'])
        for field in ('auto-route', 'strict-route', 'auto-redirect'):
            self.assertFalse(data['tun'][field])

    def test_normal_dns_remains_available(self):
        self.assertEqual('normal', self.generated(ipv6=True, dns_mode='normal')['dns']['enhanced-mode'])

    def test_transparent_device_selection_does_not_inject_direct_rules(self):
        expected = self.generated()['rules']
        for mode in ('blacklist', 'whitelist'):
            self.assertEqual(expected, self.generated(device_mode=mode,
                device_list=['192.168.10.50', 'fd00::/64'])['rules'])


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
    """Device selection never changes rules seen by explicit proxy clients."""

    def setUp(self):
        self.settings = {'transparent': False, 'secret': 'state-secret', **m.SWITCH_DEFAULTS}
        self.data = m.parse_yaml(SUBSCRIPTION)
        self.preset = m.parse_yaml((m.Path(m.__file__).resolve().parents[3]
            / 'share/mihomo/presets/full.yaml').read_bytes())
        m.absorb_switches(self.preset, self.settings)

    def rendered(self, **settings):
        return m.parse_yaml(m.render(self.data, {**self.settings, **settings},
            overlay=copy.deepcopy(self.preset)))

    def test_every_device_mode_leaves_the_provider_rules_alone(self):
        base = self.rendered()['rules']
        for mode, entries in (('off', ['192.168.10.50']),
                              ('blacklist', ['192.168.10.50', '192.168.10.0/24']),
                              ('whitelist', ['192.168.10.50', '10.0.0.0/8']),
                              ('whitelist', [])):
            with self.subTest(mode=mode, entries=entries):
                self.assertEqual(base, self.rendered(device_mode=mode,
                                                     device_list=entries)['rules'])

    def test_router_dns_pins_do_not_reintroduce_device_rules(self):
        settings = dict(self.settings, router_dns=True, device_mode='blacklist',
                        device_list=['192.168.10.50'])
        rules = m.parse_yaml(m.render(self.data, settings, overlay=copy.deepcopy(self.preset),
            upstreams='forward-addr: 192.0.2.53@853'))['rules']
        self.assertTrue(rules[0].startswith('IP-CIDR,192.0.2.53/32,DIRECT'), rules[0])
        self.assertFalse(any(rule.startswith(('SRC-IP-CIDR,', 'NOT,(')) for rule in rules[:6]))

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
        # The geometry the router actually has: the template engine writes its
        # targets outside the chroot and only a restart copies them in, so a
        # fixture that lets the engine write into the chroot proves nothing.
        self.render_root = Path(self.temp.name) / 'unbound'
        (self.render_root / 'etc').mkdir(parents=True)
        (self.render_root / 'unbound.conf').write_text(
            f'include: {self.render_root}/advanced.conf\n'
            f'include: {self.render_root}/etc/*.conf\n')
        self.generated = self.render_root / 'etc/zz-mihomo.conf'
        self.render_advanced = self.render_root / 'advanced.conf'
        self.render_advanced.write_text('server:\n  cache-min-ttl: 0\n')
        # The chroot copy the resolver reads, and the source the engine writes.
        self.chroot_dot = self.render_root / 'etc/dot.conf'
        self.chroot_dot.write_text('forward-zone:\n  name: "."\n  forward-addr: 192.0.2.53@853\n')
        self.source_root = Path(self.temp.name) / 'unbound.opnsense.d'
        self.source_root.mkdir()
        self.source_dot = self.source_root / 'dot.conf'
        self.source_dot.write_text(self.chroot_dot.read_text())
        self.template_root = Path(self.temp.name) / 'templates'
        (self.template_root / 'core').mkdir(parents=True)
        self.targets = self.template_root / 'core/+TARGETS'
        self.targets.write_text(f'dot.conf:{self.source_dot}\n'
                                f'advanced.conf:{self.render_advanced}\n')
        self.system = m.System()
        self.ran = []

        def record(args, **kwargs):
            self.ran.append(args)
            effective = args[2] == 'enable' if args[0].endswith('php') else False
            stdout = (b'Mihomo integration unchanged.\nMihomo integration state: '
                      + json.dumps({'effective_forwarding': effective, 'dns_changed': False,
                                    'integration_changed': False, 'filter_changed': False,
                                    'cron_changed': False}).encode() + b'\n') if args[0].endswith('php') else b''
            return subprocess.CompletedProcess(args, 0, stdout, b'')

        self.record = record
        state = Path(self.temp.name) / 'state'
        state.mkdir()
        self.patches = [patch.object(m, 'UNBOUND_GENERATED', str(self.generated)),
                        patch.object(m, 'UNBOUND_CONFIG_ROOT', str(self.render_root)),
                        patch.object(m, 'UNBOUND_TEMPLATE_ROOT', str(self.template_root)),
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

    def test_the_helper_is_told_to_fail_open_for_a_captured_scope_whatever_the_switch(self):
        # A captured scope answering every device while clients are offered
        # IPv6 hides Restore direct DNS on exit, so the switch cannot keep
        # Unbound from resolving on its own when Mihomo stops answering.
        self.generated.write_text('forward-addr: 8.8.8.8@853\n')
        for settings, expected in (({'dns_fallback': True, 'dns_scope': 'all'}, '1'),
                                   ({'dns_fallback': False, 'dns_scope': 'all'}, '0'),
                                   ({'dns_fallback': False}, '0'),
                                   ({'dns_fallback': False, 'dns_scope': 'captured'}, '1')):
            with self.subTest(settings=settings), patch.object(self.system, 'run', side_effect=self.record):
                self.ran.clear()
                self.system.dns(True, settings)
                self.assertEqual([expected], [args[3] for args in self.ran if args[0].endswith('php')])

    def test_enabling_against_a_file_without_the_forwarder_also_reloads(self):
        self.generated.write_text('forward-addr: 8.8.8.8@853\n')
        with patch.object(self.system, 'run', side_effect=self.record):
            self.system.dns(True, {'dns_fallback': True})
        self.assertTrue(self.reloaded())

    def effective_record(self, effective):
        def record(args, **kwargs):
            result = self.record(args, **kwargs)
            if args[0].endswith('php'):
                result.stdout = b'Mihomo integration unchanged.\nMihomo integration state: ' + json.dumps(
                    {'effective_forwarding': effective, 'dns_changed': False,
                     'integration_changed': False, 'filter_changed': False,
                     'cron_changed': False}).encode() + b'\n'
            return result
        return record

    def test_dnssec_effective_disabled_skips_an_unchanged_enable_restart(self):
        with patch.object(self.system, 'run', side_effect=self.effective_record(False)):
            # The caller publishes this answer, not what it asked for.
            self.assertIs(False, self.system.dns(True, {'dns_fallback': True}))
        self.assertFalse(self.reloaded())
        self.assertFalse(any(args[1:3] == ['unbound', 'restart'] for args in self.ran))

    def test_dnssec_effective_disabled_still_repairs_stale_generated_forwarding(self):
        self.generated.write_text('forward-addr: %s\n' % m.FORWARDER)
        with patch.object(self.system, 'run', side_effect=self.effective_record(False)):
            self.assertIs(False, self.system.dns(True, {'dns_fallback': True}))
        self.assertTrue(self.reloaded())
        self.assertTrue(any(args[1:3] == ['unbound', 'restart'] for args in self.ran))

    def test_effective_enabled_still_repairs_a_missing_generated_forwarder(self):
        with patch.object(self.system, 'run', side_effect=self.effective_record(True)):
            self.assertIs(True, self.system.dns(True, {'dns_fallback': True}))
        self.assertTrue(self.reloaded())
        self.assertTrue(any(args[1:3] == ['unbound', 'restart'] for args in self.ran))

    def test_pending_dns_reload_is_not_skipped_when_dnssec_forwarding_agrees(self):
        (Path(m.STATE) / 'dns-reload-pending').write_text('pending\n')
        with patch.object(self.system, 'run', side_effect=self.effective_record(False)):
            self.assertIs(False, self.system.dns(True, {'dns_fallback': True}))
        self.assertTrue(self.reloaded())

    def test_an_unchanged_active_forwarder_reports_forwarding_without_a_reload(self):
        self.generated.write_text('forward-addr: %s\n' % m.FORWARDER)
        with patch.object(self.system, 'run', side_effect=self.effective_record(True)):
            self.assertIs(True, self.system.dns(True, {'dns_fallback': True}))
        self.assertFalse(self.reloaded())

    def test_invalid_effective_forwarding_metadata_fails_closed_and_keeps_receipt(self):
        for invalid in ('false', 0, None):
            self.ran.clear()
            with patch.object(self.system, 'run', side_effect=self.effective_record(invalid)), \
                    self.assertRaises(m.Error):
                self.system.dns(True, {'dns_fallback': True})
            self.assertFalse(self.reloaded(), invalid)
            self.assertTrue((Path(m.STATE) / 'dns-reload-pending').exists())
            (Path(m.STATE) / 'dns-reload-pending').unlink()

    def integration_record(self, change_render=None, filter_changed=True,
                           dns_changed=False):
        def record(args, **kwargs):
            result = self.record(args, **kwargs)
            if args[0].endswith('php'):
                result.stdout = b'Mihomo integration updated.\nMihomo integration state: ' + json.dumps(
                    {'effective_forwarding': False, 'dns_changed': dns_changed,
                     'integration_changed': True, 'filter_changed': filter_changed,
                     'cron_changed': False}).encode() + b'\n'
            elif 'template' in args and change_render is not None:
                change_render()
            return result
        return record

    def test_tun_only_change_reloads_filter_without_restarting_unchanged_resolver(self):
        with patch.object(self.system, 'run', side_effect=self.integration_record()), \
                patch.object(self.system, 'resolver_running', return_value=True):
            self.assertIs(False, self.system.dns(False, {'dns_fallback': True}))
        self.assertTrue(self.reloaded())
        self.assertTrue(any(args[1:3] == ['filter', 'reload'] for args in self.ran))
        self.assertFalse(any(args[1:3] == ['unbound', 'restart'] for args in self.ran))
        self.assertFalse((Path(m.STATE) / 'dns-reload-pending').exists())

    def test_dns_only_change_restarts_resolver_without_global_filter_reload(self):
        with patch.object(self.system, 'run', side_effect=self.integration_record(
                filter_changed=False, dns_changed=True)):
            self.system.dns(False, {'dns_fallback': True})
        self.assertTrue(any(args[1:3] == ['unbound', 'restart'] for args in self.ran))
        self.assertFalse(any(args[1:3] == ['filter', 'reload'] for args in self.ran))

    def test_a_reload_that_only_rewrites_a_source_file_still_restarts_resolver(self):
        # DNS over TLS upstreams replaced and saved without Apply: the reload
        # rewrites dot.conf where the engine keeps it, the copy inside the
        # chroot still names the dead servers, and only a restart copies it in.
        def changed():
            self.source_dot.write_text('forward-zone:\n  name: "."\n  forward-addr: 192.0.2.99@853\n')
        with patch.object(self.system, 'run', side_effect=self.integration_record(changed)):
            self.system.dns(False, {'dns_fallback': True})
        self.assertTrue(any(args[1:3] == ['unbound', 'restart'] for args in self.ran))

    def test_a_source_file_the_reload_creates_from_nothing_also_restarts_resolver(self):
        safesearch = self.source_root / 'safesearch.conf'
        self.targets.write_text(self.targets.read_text() + f'safesearch.conf:{safesearch}\n')
        def changed():
            safesearch.write_text('server:\n  local-zone: "example.test" redirect\n')
        with patch.object(self.system, 'run', side_effect=self.integration_record(changed)):
            self.system.dns(False, {'dns_fallback': True})
        self.assertTrue(any(args[1:3] == ['unbound', 'restart'] for args in self.ran))

    def test_top_level_generated_include_change_also_restarts_resolver(self):
        def changed():
            self.render_advanced.write_text('server:\n  cache-min-ttl: 300\n')
        with patch.object(self.system, 'run', side_effect=self.integration_record(changed)):
            self.system.dns(False, {'dns_fallback': True})
        self.assertTrue(any(args[1:3] == ['unbound', 'restart'] for args in self.ran))

    def test_the_targets_are_read_from_the_engine_map_and_never_guessed(self):
        self.assertEqual([self.source_dot, self.render_advanced],
                         self.system.unbound_template_targets())
        # A mapping that expands per model node names no fixed set of files.
        self.targets.write_text('zone.conf:/var/unbound/z-[OPNsense.unbound.x.%.id].conf\n')
        self.assertIsNone(self.system.unbound_template_targets())

    def test_an_unreadable_target_map_cannot_prove_a_restart_unnecessary(self):
        # Gone and present-but-unreadable are the same answer: a map that cannot
        # be parsed names no files, and a digest blind to what the reload writes
        # must never be the reason the resolver is left serving the old policy.
        # The read is deliberately exercised through dns(), because the helper
        # raises and only its caller turns that into the conservative restart.
        for break_map in (self.targets.unlink, self.targets.mkdir):
            with self.subTest(break_map.__name__):
                self.ran.clear()
                break_map()
                with patch.object(self.system, 'run', side_effect=self.integration_record()):
                    self.system.dns(False, {'dns_fallback': True})
                self.assertTrue(any(args[1:3] == ['unbound', 'restart'] for args in self.ran))

    def test_unknown_external_include_cannot_prove_a_restart_unnecessary(self):
        external = Path(self.temp.name) / 'operator.conf'
        external.write_text('server:\n  interface: 127.0.0.1\n')
        (self.render_root / 'unbound.conf').write_text(f'include: {external}\n')
        with patch.object(self.system, 'run', side_effect=self.integration_record()):
            self.system.dns(False, {'dns_fallback': True})
        self.assertTrue(any(args[1:3] == ['unbound', 'restart'] for args in self.ran))

    def test_missing_generated_configuration_cannot_prove_a_restart_unnecessary(self):
        (self.render_root / 'unbound.conf').unlink()
        with patch.object(self.system, 'run', side_effect=self.integration_record()):
            self.system.dns(False, {'dns_fallback': True})
        self.assertTrue(any(args[1:3] == ['unbound', 'restart'] for args in self.ran))

    def test_tun_only_change_with_pending_reload_still_restarts_resolver(self):
        (Path(m.STATE) / 'dns-reload-pending').write_text('pending\n')
        with patch.object(self.system, 'run', side_effect=self.integration_record()):
            self.system.dns(False, {'dns_fallback': True})
        self.assertTrue(any(args[1:3] == ['unbound', 'restart'] for args in self.ran))

    def test_tun_only_change_does_not_skip_restart_of_a_stopped_resolver(self):
        with patch.object(self.system, 'run', side_effect=self.integration_record()), \
                patch.object(self.system, 'resolver_running', side_effect=[False, True]):
            self.system.dns(False, {'dns_fallback': True})
        self.assertTrue(any(args[1:3] == ['unbound', 'restart'] for args in self.ran))

    def test_filter_reload_failure_keeps_pending_and_retry_restarts_conservatively(self):
        base_record = self.integration_record()
        def failed(args, **kwargs):
            result = base_record(args, **kwargs)
            if args[1:3] == ['filter', 'reload']:
                raise m.Error('The filter reload failed.')
            return result
        with patch.object(self.system, 'run', side_effect=failed), \
                patch.object(self.system, 'resolver_running', return_value=True):
            with self.assertRaises(m.Error):
                self.system.dns(False, {'dns_fallback': True})
        self.assertTrue((Path(m.STATE) / 'dns-reload-pending').exists())
        self.ran.clear()
        with patch.object(self.system, 'run', side_effect=base_record):
            self.system.dns(False, {'dns_fallback': True})
        self.assertTrue(any(args[1:3] == ['unbound', 'restart'] for args in self.ran))
        self.assertFalse((Path(m.STATE) / 'dns-reload-pending').exists())

    def test_a_missing_file_counts_as_not_forwarding(self):
        self.assertFalse(self.system.forwarded())


class DnsJournalOwnershipTests(unittest.TestCase):
    def test_new_private_address_ownership_survives_backup_validation(self):
        saved = {'forwarding': '0', 'roots': {}, 'had_fake_ip_private_address': True,
                 'removed_fake_ip_private_address': False}
        raw = json.dumps(saved)
        self.assertEqual(raw, m.Manager._journal('dns_state', raw))

    def test_private_address_ownership_rejects_non_boolean_coercion(self):
        for invalid in ('false', 0, None):
            with self.subTest(invalid=invalid):
                saved = {'forwarding': '0', 'roots': {}, 'had_fake_ip_private_address': True,
                         'removed_fake_ip_private_address': invalid}
                with self.assertRaises(m.Error):
                    m.Manager._journal('dns_state', json.dumps(saved))


class IntegrationReloadTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.state = Path(self.temp.name)
        self.patch = patch.object(m, 'STATE', str(self.state))
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.system = m.System()
        self.calls = []

    @staticmethod
    def output(**changes):
        value = {'effective_forwarding': False, 'dns_changed': False,
                 'integration_changed': False, 'filter_changed': False,
                 'cron_changed': False}
        value.update(changes)
        return (b'Mihomo integration unchanged.\nMihomo integration state: '
                + json.dumps(value).encode() + b'\n')

    def runner(self, helper=None, fail_filter=False):
        helper = self.output() if helper is None else helper

        def run(args, **kwargs):
            self.calls.append(args)
            if args[0].endswith('php'):
                return subprocess.CompletedProcess(args, 0, helper, b'')
            if args[0].endswith('configctl') and args[1:3] == ['filter', 'reload'] and fail_filter:
                raise m.Error('injected filter failure')
            return subprocess.CompletedProcess(args, 0, b'', b'')
        return run

    def filter_reloads(self):
        return [args for args in self.calls if args[0].endswith('configctl')
                and args[1:3] == ['filter', 'reload']]

    def cron_restarts(self):
        return [args for args in self.calls if args[0].endswith('configctl')
                and args[1:3] == ['cron', 'restart']]

    def test_unchanged_tun_with_context_avoids_global_filter_reload(self):
        (self.state / 'routing-context.json').write_text('{}')
        with patch.object(self.system, 'run', side_effect=self.runner()):
            self.system.tun()
        self.assertEqual([], self.filter_reloads())
        self.assertFalse((self.state / 'filter-reload-pending.json').exists())

    def test_missing_context_or_filter_change_forces_exactly_one_reload(self):
        for name, output, context in (
                ('missing-context', self.output(), False),
                ('filter-change', self.output(integration_changed=True, filter_changed=True), True)):
            with self.subTest(name=name):
                self.calls.clear()
                (self.state / 'routing-context.json').unlink(missing_ok=True)
                if context:
                    (self.state / 'routing-context.json').write_text('{}')
                with patch.object(self.system, 'run', side_effect=self.runner(output)):
                    self.system.tun()
                self.assertEqual(1, len(self.filter_reloads()))

    def test_redirect_listener_reloads_the_filter_until_its_rdr_hook_exists(self):
        (self.state / 'routing-context.json').write_text('{}')
        listener = {'name': m.REDIRECT_LISTENER, 'type': 'redir', 'port': m.REDIRECT_PORT, 'listen': '127.0.0.1'}
        base = self.runner()

        def with_hook(hooked):
            def run(args, **kwargs):
                if args == ['/sbin/pfctl', '-sn']:
                    self.calls.append(args)
                    hooks = b'rdr-anchor "acme-client/*" all\n' + (b'rdr-anchor "mihomo" all\n' if hooked else b'')
                    return subprocess.CompletedProcess(args, 0, hooks, b'')
                return base(args, **kwargs)
            return run

        # A package upgrade renders the listener but never reloads the filter.
        (self.state / 'config.yaml').write_text(m.yaml.safe_dump({'listeners': [listener]}))
        with patch.object(self.system, 'run', side_effect=with_hook(False)):
            self.system.tun()
        self.assertEqual(1, len(self.filter_reloads()))
        self.calls.clear()
        with patch.object(self.system, 'run', side_effect=with_hook(True)):
            self.system.tun()
        self.assertEqual([], self.filter_reloads())
        self.calls.clear()
        (self.state / 'config.yaml').write_text('listeners: []\n')
        with patch.object(self.system, 'run', side_effect=with_hook(False)):
            self.system.tun()
        self.assertEqual([], self.filter_reloads())
        self.assertNotIn(['/sbin/pfctl', '-sn'], self.calls)

    def test_failed_filter_reload_keeps_receipt_and_retry_cannot_skip_it(self):
        (self.state / 'routing-context.json').write_text('{}')
        changed = self.output(integration_changed=True, filter_changed=True)
        with patch.object(self.system, 'run', side_effect=self.runner(changed, fail_filter=True)), \
                self.assertRaises(m.Error):
            self.system.tun()
        receipt = self.state / 'filter-reload-pending.json'
        self.assertEqual({'action': 'enable-tun', 'version': 1}, json.loads(receipt.read_text()))
        self.calls.clear()
        with patch.object(self.system, 'run', side_effect=self.runner()):
            self.system.tun()
        self.assertEqual(1, len(self.filter_reloads()))
        self.assertFalse(receipt.exists())

    def test_invalid_or_duplicate_helper_decision_fails_closed_with_receipt(self):
        invalid = [b'Mihomo integration unchanged.\n',
                   b'Mihomo integration state: {"effective_forwarding":false}\n',
                   (b'Mihomo integration state: {"effective_forwarding":false,'
                    b'"effective_forwarding":true,"dns_changed":false,'
                    b'"integration_changed":false,"filter_changed":false,'
                    b'"cron_changed":false}\n')]
        for output in invalid:
            with self.subTest(output=output):
                (self.state / 'filter-reload-pending.json').unlink(missing_ok=True)
                with patch.object(self.system, 'run', side_effect=self.runner(output)), \
                        self.assertRaises(m.Error):
                    self.system.tun()
                self.assertTrue((self.state / 'filter-reload-pending.json').exists())

    def test_remove_reloads_only_changed_subsystems(self):
        cases = [('none', self.output(), 0, 0),
                 ('filter', self.output(integration_changed=True, filter_changed=True), 1, 0),
                 ('cron', self.output(integration_changed=True, cron_changed=True), 0, 1)]
        for name, output, filters, crons in cases:
            with self.subTest(name=name):
                self.calls.clear()
                with patch.object(self.system, 'run', side_effect=self.runner(output)):
                    self.system.remove()
                self.assertEqual(filters, len(self.filter_reloads()))
                self.assertEqual(crons, len(self.cron_restarts()))
                self.assertFalse((self.state / 'filter-reload-pending.json').exists())
                self.assertFalse((self.state / 'cron-reload-pending.json').exists())

    def test_restore_cron_receipt_forces_retry_after_a_reload_failure(self):
        changed = self.output(integration_changed=True, cron_changed=True)

        def fail(args, **kwargs):
            self.calls.append(args)
            if args[0].endswith('php'):
                return subprocess.CompletedProcess(args, 0, changed, b'')
            raise m.Error('injected cron failure')

        with patch.object(self.system, 'run', side_effect=fail), self.assertRaises(m.Error):
            self.system.restore_cron()
        receipt = self.state / 'cron-reload-pending.json'
        self.assertTrue(receipt.exists())
        self.calls.clear()
        with patch.object(self.system, 'run', side_effect=self.runner()):
            self.system.restore_cron()
        self.assertEqual(1, len(self.cron_restarts()))
        self.assertFalse(receipt.exists())


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
            stdout = (b'Mihomo integration unchanged.\nMihomo integration state: '
                      b'{"effective_forwarding":false,"dns_changed":false,'
                      b'"integration_changed":false,"filter_changed":false,'
                      b'"cron_changed":false}\n') if args[0].endswith('php') else b''
            return subprocess.CompletedProcess(args, 0, stdout, b'')

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
            stdout = (b'Mihomo integration updated.\nMihomo integration state: '
                      b'{"effective_forwarding":true,"dns_changed":true,'
                      b'"integration_changed":true,"filter_changed":false,'
                      b'"cron_changed":false}\n') if args[0].endswith('php') else b''
            return subprocess.CompletedProcess(args, 0, stdout, b'')

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


class ResolverCacheTests(unittest.TestCase):
    """What Unbound cached before its forwarding changed must not answer after it.

    OPNsense 26.7 keeps the cache across a restart unless the operator set
    "Flush DNS Cache during reload": the stop dumps it, and start.sh loads it
    into the new process in the background, under /tmp/unbound_start.lock,
    after 'configctl unbound restart' has already returned. The configd flush
    only deletes the dump. On a real guest a flush issued straight after the
    restart landed while the load was still running, and AAAA records cached
    before the scope moved to all devices kept being answered.
    """

    RESTART = '/usr/local/sbin/configctl unbound restart'
    DUMP = '/usr/local/sbin/configctl unbound cache flush'
    LIVE = '/usr/local/sbin/unbound-control -c /var/unbound/unbound.conf flush_zone .'
    LOADED = 'start script loaded the dumped cache'

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        (root / 'state').mkdir()
        self.lock = root / 'unbound_start.lock'
        self.lock.touch()
        # No forwarder in the file yet, so asking for one restarts the resolver.
        self.generated = root / 'zz-mihomo.conf'
        for entry in (patch.object(m, 'STATE', str(root / 'state')),
                      patch.object(m, 'UNBOUND_GENERATED', str(self.generated)),
                      patch.object(m, 'UNBOUND_START_LOCK', str(self.lock)),
                      patch.object(m, 'ROOT_ANCHOR', str(root / 'root.key'))):
            entry.start()
            self.addCleanup(entry.stop)
        self.system = m.System()
        self.events = []

    def start_script(self, seconds):
        """Hold the lock as start.sh does: from before the restart returns until its load is done."""
        held = threading.Event()

        def body():
            with self.lock.open('rb') as handle:
                fcntl.flock(handle, fcntl.LOCK_EX)
                held.set()
                time.sleep(seconds)
                self.events.append(self.LOADED)
                fcntl.flock(handle, fcntl.LOCK_UN)
        thread = threading.Thread(target=body)
        thread.start()
        self.addCleanup(thread.join)
        self.assertTrue(held.wait(5))

    def runner(self, loading=0.0, alive=None, changed=True, fail_control=False, lock_free=True,
               control_exit=0, fail_dump=False):
        alive = [True] if alive is None else alive
        state = {'effective_forwarding': True, 'dns_changed': changed, 'integration_changed': changed,
                 'filter_changed': changed, 'cron_changed': False}

        def run(args, **kwargs):
            name = ' '.join(str(part) for part in args)
            self.events.append(name)
            if args[0].endswith('php'):
                return subprocess.CompletedProcess(args, 0, b'Mihomo integration state: '
                                                   + json.dumps(state).encode() + b'\n', b'')
            if name == self.RESTART and loading:
                self.start_script(loading)
            if name in (self.DUMP, self.LIVE) and lock_free:
                # A start that overlaps the flush must still get the lock:
                # one that finds it held skips itself and leaves no resolver.
                with self.lock.open('rb') as handle:
                    try:
                        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except BlockingIOError:
                        self.fail(name + ' ran while the start lock was held')
            if args[0].endswith('pgrep'):
                return subprocess.CompletedProcess(args, 0 if alive.pop(0) else 1, b'', b'')
            if name == self.LIVE and fail_control:
                raise m.Error('A system operation failed or timed out.')
            if name == self.LIVE:
                return subprocess.CompletedProcess(args, control_exit, b'', b'')
            if name == self.DUMP and fail_dump:
                raise m.Error('A system operation failed; the previous configuration was retained.')
            return subprocess.CompletedProcess(args, 0, b'', b'')
        return run

    def test_the_cache_is_emptied_only_once_the_start_script_has_loaded_the_dump(self):
        with patch.object(self.system, 'run', side_effect=self.runner(loading=0.4)):
            self.assertIs(True, self.system.dns(True, {'dns_fallback': True}))
        order = [self.events.index(step) for step in (self.RESTART, self.LOADED, self.DUMP, self.LIVE)]
        self.assertEqual(sorted(order), order, self.events)
        # Before the filter reload, so the old answers do not also outlive its length.
        self.assertLess(order[-1], self.events.index('/usr/local/sbin/configctl filter reload'))
        self.assertFalse((Path(m.STATE) / 'dns-reload-pending').exists())

    def test_every_restart_for_a_forwarding_change_empties_the_cache(self):
        # Towards Mihomo, and back to Unbound's own upstreams, where the
        # cache holds Mihomo's answers, its hosts entries and empty AAAA.
        self.generated.write_text('forward-addr: %s\n' % m.FORWARDER)
        for enabled in (True, False):
            with self.subTest(enabled=enabled), patch.object(self.system, 'run', side_effect=self.runner()):
                self.events.clear()
                self.system.dns(enabled, {'dns_fallback': True})
                self.assertEqual(1, self.events.count(self.RESTART))
                self.assertEqual(1, self.events.count(self.DUMP))
                self.assertEqual(1, self.events.count(self.LIVE))

    def test_nothing_is_flushed_when_the_forwarding_stays(self):
        self.generated.write_text('forward-addr: %s\n' % m.FORWARDER)
        with patch.object(self.system, 'run', side_effect=self.runner(changed=False)):
            self.assertIs(True, self.system.dns(True, {'dns_fallback': True}))
        self.assertEqual([], [name for name in self.events if 'flush' in name or 'restart' in name])

    def finishes(self, operation, seconds=5):
        """Run operation in a thread: whether it returned, without raising, within seconds.

        A wait that blocks for good then fails the test instead of hanging it.
        """
        done = threading.Event()

        def body():
            operation()
            done.set()
        worker = threading.Thread(target=body, daemon=True)
        worker.start()
        worker.join(seconds)
        return done.is_set()

    def test_a_start_script_that_does_not_finish_holds_the_flush_back_only_for_a_while(self):
        with self.lock.open('rb') as handle, patch.object(m, 'UNBOUND_START_WAIT', 0.3), \
                patch.object(self.system, 'run', side_effect=self.runner(lock_free=False)):
            fcntl.flock(handle, fcntl.LOCK_EX)
            began = time.monotonic()
            self.assertTrue(self.finishes(lambda: self.system.dns(True, {'dns_fallback': True})))
            waited = time.monotonic() - began
        self.assertGreaterEqual(waited, 0.3)
        self.assertLess(waited, 5)
        self.assertIn(self.DUMP, self.events)
        self.assertIn(self.LIVE, self.events)

    def test_a_lock_path_that_is_no_regular_file_holds_nothing_back(self):
        # Opening a FIFO for reading waits for a writer that never comes, and
        # anyone can leave one in /tmp before the start script first runs.
        self.lock.unlink()
        os.mkfifo(self.lock)
        with patch.object(m, 'UNBOUND_START_WAIT', 30):
            began = time.monotonic()
            self.assertTrue(self.finishes(m.System.wait_for_resolver_start))
            self.assertLess(time.monotonic() - began, 5)

    def test_the_start_lock_is_never_created_or_followed(self):
        # The start script creates it; with none there, nothing is loading.
        self.lock.unlink()
        m.System.wait_for_resolver_start()
        self.assertFalse(self.lock.exists())
        target = Path(self.temp.name) / 'elsewhere'
        self.lock.symlink_to(target)
        m.System.wait_for_resolver_start()
        self.assertFalse(target.exists())

    def test_a_resolver_that_cannot_be_flushed_keeps_the_change(self):
        # Stale records are the lesser harm: failing here would roll back a
        # change that is already in place and working.
        with patch.object(self.system, 'run', side_effect=self.runner(fail_control=True)):
            self.assertIs(True, self.system.dns(True, {'dns_fallback': True}))
        self.assertIn(self.LIVE, self.events)
        self.assertFalse((Path(m.STATE) / 'dns-reload-pending').exists())

    def test_a_running_resolver_left_with_its_cache_is_reported(self):
        # Nothing retries the flush, so the log is the only trace of it.
        for failure in ({'fail_control': True}, {'control_exit': 1}):
            with self.subTest(**failure):
                reports = []
                self.system.report = reports.append
                with patch.object(self.system, 'run', side_effect=self.runner(alive=[True, True], **failure)):
                    self.assertIs(True, self.system.dns(True, {'dns_fallback': True}))
                self.assertEqual([m.RESOLVER_CACHE_KEPT_LOG], reports)
                self.assertFalse((Path(m.STATE) / 'dns-reload-pending').exists())

    def test_only_a_cache_that_is_left_is_reported(self):
        reports = []
        self.system.report = reports.append
        # Flushed, and no resolver left to hold anything.
        for failure, alive in (({}, []), ({'control_exit': 1}, [False])):
            with self.subTest(**failure), \
                    patch.object(self.system, 'run', side_effect=self.runner(alive=alive, **failure)):
                self.system.drop_resolver_cache()
                self.assertEqual([], alive)
        self.assertEqual([], reports)

    def test_a_dump_that_cannot_be_deleted_does_not_skip_the_repair(self):
        # The restart left no resolver. Deleting the dump fails, so the
        # repair's start loads it; the cache is then emptied after that start.
        with patch.object(self.system, 'run', side_effect=self.runner(alive=[False, True], fail_dump=True)):
            self.assertIs(True, self.system.dns(True, {'dns_fallback': True}))
        restarts = [index for index, name in enumerate(self.events) if name == self.RESTART]
        self.assertEqual(2, len(restarts), self.events)
        self.assertIn('/usr/local/sbin/configctl filter reload', self.events)
        self.assertGreater(len(self.events) - 1 - self.events[::-1].index(self.LIVE), restarts[1])
        self.assertFalse((Path(m.STATE) / 'dns-reload-pending').exists())

    def test_the_service_logs_a_cache_it_could_not_empty(self):
        root = Path(self.temp.name) / 'root'
        manager = m.Manager(root)
        manager.system.report(m.RESOLVER_CACHE_KEPT_LOG)
        self.assertIn(m.RESOLVER_CACHE_KEPT_LOG, (root / 'var/log/mihomo.log').read_text())

    def test_the_dump_is_gone_before_a_repair_starts_the_resolver_again(self):
        # The repair's start finds no running resolver to dump, so it would
        # load whatever dump is left.
        with patch.object(self.system, 'run', side_effect=self.runner(alive=[False, True])):
            self.system.dns(True, {'dns_fallback': True})
        restarts = [index for index, name in enumerate(self.events) if name == self.RESTART]
        self.assertEqual(2, len(restarts), self.events)
        self.assertLess(restarts[0], self.events.index(self.DUMP))
        self.assertLess(self.events.index(self.DUMP), restarts[1])
        # And whatever that start found is emptied once it is done.
        self.assertEqual([self.DUMP, self.LIVE], [name for name in self.events[restarts[1]:]
                                                  if name in (self.DUMP, self.LIVE)])


class FailedArmRecoveryTests(unittest.TestCase):
    """A start that cannot arm routing fails loudly and stays failed."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.system = fixtures.FakeSystem()
        self.manager = m.Manager(Path(self.temp.name), self.system)
        self.manager.initialize()
        self.manager.dispatch('start')
        self.manager.apply(SUBSCRIPTION)
        self.manager.dispatch('enable-transparent')
        self.watches = []
        self.system.watch = lambda: self.watches.append('watch')

    def refuse_to_arm(self):
        raise m.Error('Transparent routing could not be armed.')

    def status(self):
        return json.loads(self.manager.status_file.read_bytes())

    def test_an_arm_that_fails_leaves_no_watchdog_retrying_it(self):
        # A watchdog started before arming would retry the failing arm every few
        # seconds. That is how a single uptime consumed two thousand kernel
        # routing tables, and the retry buys nothing anyway: the watchdog's first
        # tick republishes ground truth and erases the reason recorded below. So
        # the watchdog starts only after arming has succeeded.
        self.system.tun = self.refuse_to_arm
        with self.assertRaises(m.Error):
            self.manager.start()
        self.assertEqual([], self.watches)

    def test_the_status_a_failed_arm_leaves_behind_names_the_reason(self):
        self.system.tun = self.refuse_to_arm
        with self.assertRaises(m.Error):
            self.manager.start()
        self.assertEqual('Transparent routing could not be armed.', self.status()['error'])
        self.assertFalse(self.status()['running'])

    def test_a_start_that_arms_publishes_a_clean_status_and_one_watchdog(self):
        self.manager.start()
        self.assertEqual('', self.status()['error'])
        self.assertEqual(['watch'], self.watches)
        self.assertIn('assign-tun', self.system.events)


class LocalNameTests(unittest.TestCase):
    """A captured scope without router DNS sends the router's local names back to the router DNS."""

    # The shape of a stock 26.7 installation, as read on a fresh guest.
    STOCK = ('<opnsense><system><hostname>OPNsense</hostname><domain>internal</domain></system>'
             '<OPNsense><unboundplus><general><enabled>1</enabled><regdhcp>0</regdhcp><regdhcpdomain/>'
             '</general><hosts/><aliases/><dots/></unboundplus>'
             '<Kea><dhcp4><general><enabled>0</enabled></general></dhcp4></Kea></OPNsense>'
             '<dnsmasq><enable>1</enable><dhcp><domain/></dhcp>'
             '<dhcp_ranges uuid="4"><interface>lan</interface><start_addr>192.168.1.100</start_addr><domain/></dhcp_ranges>'
             '<dhcp_ranges uuid="6"><interface>lan</interface><start_addr>::1000</start_addr><domain/></dhcp_ranges>'
             '</dnsmasq></opnsense>')

    def setUp(self):
        self.settings = {'transparent': True, 'secret': 'state-secret', 'router_dns': False,
                         'dns_scope': 'captured'}
        # No dns block, so the baseline policy with geosite:private applies.
        self.data = {'proxies': [{'name': 'Test', 'type': 'socks5', 'server': 'example.invalid', 'port': 1080}],
                     'proxy-groups': [{'name': 'Proxy', 'type': 'select', 'proxies': ['Test']}],
                     'rules': ['MATCH,Proxy']}
        self.overlay = m.parse_yaml((m.Path(m.__file__).resolve().parents[3] / 'share/mihomo/presets/full.yaml').read_bytes())
        self.names = m.local_domains(self.STOCK.encode())

    def policy(self, settings=None, overlay=None, data=None, **kwargs):
        generated = m.parse_yaml(m.render(self.data if data is None else data, settings or self.settings,
                                          overlay=self.overlay if overlay is None else overlay,
                                          local_names=kwargs.pop('local_names', self.names), **kwargs))
        return generated['dns'].get('nameserver-policy')

    def own(self, names=None):
        return ['+.' + name for name in (self.names if names is None else names)]

    def test_a_stock_installation_contributes_its_domain_and_the_private_reverse_zones(self):
        self.assertEqual(sorted(('internal',) + m.PRIVATE_REVERSE_ZONES), self.names)
        # The public reverse trees stay with Mihomo, so public PTR lookups do too.
        for public in ('in-addr.arpa', 'ip6.arpa', 'arpa', '172.in-addr.arpa', '100.in-addr.arpa'):
            self.assertNotIn(public, self.names)
        for private in ('10.in-addr.arpa', '16.172.in-addr.arpa', '31.172.in-addr.arpa', '168.192.in-addr.arpa',
                        '254.169.in-addr.arpa', 'c.f.ip6.arpa', 'd.f.ip6.arpa', '8.e.f.ip6.arpa',
                        'b.e.f.ip6.arpa', 'home.arpa'):
            self.assertIn(private, self.names)
        self.assertNotIn('15.172.in-addr.arpa', self.names)
        self.assertNotIn('32.172.in-addr.arpa', self.names)
        # Unreadable configuration still keeps the reverse zones local.
        self.assertEqual(sorted(m.PRIVATE_REVERSE_ZONES), m.local_domains(b'<opnsense'))

    def test_the_26_7_sources_each_contribute_and_switched_off_ones_do_not(self):
        config = ('<opnsense><system><domain>Home.Example.</domain></system><OPNsense><unboundplus>'
                  '<general><regdhcp>1</regdhcp><regdhcpdomain>leases.test</regdhcpdomain></general><hosts>'
                  '<host uuid="h1"><enabled>1</enabled><hostname>nas</hostname><domain>www.google.com</domain></host>'
                  '<host uuid="h2"><enabled>1</enabled><hostname>*</hostname><domain>wild.test</domain></host>'
                  '<host uuid="h3"><enabled>1</enabled><hostname/><domain>apex.test</domain></host>'
                  '<host uuid="h4"><enabled>0</enabled><hostname>off</hostname><domain>disabled.test</domain></host>'
                  '<host uuid="h5"><hostname>implicit</hostname><domain>default-on.test</domain></host>'
                  '<host><hostname>nouuid</hostname><domain>plain.test</domain></host>'
                  '</hosts><aliases>'
                  '<alias uuid="a1"><enabled>1</enabled><host>h1</host><hostname>files</hostname><domain/></alias>'
                  '<alias uuid="a2"><enabled>1</enabled><host>h1</host><hostname>media</hostname><domain>alias.test</domain></alias>'
                  '<alias uuid="a3"><enabled>1</enabled><host>h4</host><hostname>gone</hostname><domain>parent-off.test</domain></alias>'
                  '</aliases><dots>'
                  '<dot uuid="d1"><enabled>1</enabled><type>forward</type><domain>corp.example</domain><server>10.0.0.53</server></dot>'
                  '<dot uuid="d2"><enabled>1</enabled><type>dot</type><domain>secure.example</domain><server>10.0.0.54</server></dot>'
                  '<dot uuid="d3"><enabled>0</enabled><type>forward</type><domain>off.example</domain></dot>'
                  '<dot uuid="d4"><enabled>1</enabled><type>dot</type><domain/><server>1.1.1.1</server></dot>'
                  '<dot uuid="d5"><enabled>1</enabled><type>forward</type><domain>1.168.192.in-addr.arpa</domain></dot>'
                  '</dots></unboundplus>'
                  '<Kea><dhcp4><general><enabled>1</enabled></general><subnets>'
                  '<subnet4 uuid="s"><option_data><domain_name>kea.test</domain_name>'
                  '<domain_search>search.example</domain_search></option_data>'
                  '<ddns_forward_zone>ddns.test</ddns_forward_zone></subnet4></subnets><reservations>'
                  '<reservation uuid="r"><hostname>tv</hostname><option_data><domain_name>reserved.test</domain_name>'
                  '</option_data></reservation></reservations></dhcp4></Kea></OPNsense>'
                  '<dnsmasq><enable>1</enable><regdhcpdomain>forwarder.test</regdhcpdomain>'
                  '<dhcp><domain>dhcp.test</domain></dhcp>'
                  '<dhcp_ranges uuid="x"><domain>range.test</domain></dhcp_ranges>'
                  '<hosts uuid="y"><host>printer</host><domain>office.example</domain></hosts>'
                  '<hosts uuid="z"><host>bare</host><domain/></hosts>'
                  '<domainoverrides uuid="o"><domain>override.example</domain></domainoverrides></dnsmasq>'
                  '<dhcpd><lan><enable/><domain>isc.test</domain></lan>'
                  '<opt1><enable>0</enable><domain>isc-off.test</domain></opt1>'
                  '<opt2><domain>isc-absent.test</domain></opt2></dhcpd></opnsense>')
        names = set(m.local_domains(config.encode())) - set(m.PRIVATE_REVERSE_ZONES)
        self.assertEqual({
            'home.example', 'leases.test',
            # Host overrides and their aliases by exact name: Unbound answers
            # only these from local data and the rest of google.com as usual.
            'nas.www.google.com', 'files.www.google.com', 'media.alias.test',
            'wild.test', 'apex.test', 'implicit.default-on.test', 'nouuid.plain.test',
            'corp.example', 'secure.example',
            'kea.test', 'ddns.test', 'reserved.test',
            'forwarder.test', 'dhcp.test', 'range.test', 'printer.office.example', 'override.example',
            'isc.test'}, names)
        # A forward for part of a private reverse zone is inside it already.
        self.assertNotIn('1.168.192.in-addr.arpa', m.local_domains(config.encode()))
        self.assertNotIn('google.com', names)
        # Switched off, a service adds nothing.
        silent = (config.replace('<general><regdhcp>', '<general><enabled>0</enabled><regdhcp>')
                  .replace('<dnsmasq><enable>1</enable>', '<dnsmasq><enable>0</enable>')
                  .replace('<dhcp4><general><enabled>1</enabled>', '<dhcp4><general><enabled>0</enabled>'))
        self.assertEqual({'home.example', 'isc.test'},
                         set(m.local_domains(silent.encode())) - set(m.PRIVATE_REVERSE_ZONES))

    def test_values_that_are_not_plain_domain_names_are_skipped_and_covered_suffixes_dropped(self):
        config = ('<opnsense><system><domain>lan</domain></system><OPNsense><unboundplus><dots>'
                  + ''.join('<dot><domain>%s</domain></dot>' % value for value in (
                      'a.lan', 'b.c.lan', 'two words', 'comma,split', '*.star', '-leading.test',
                      'x' * 64 + '.test', 'ok_underscore.test', 'Upper.TEST', 'trailing.test.'))
                  + '</dots></unboundplus></OPNsense></opnsense>')
        names = set(m.local_domains(config.encode())) - set(m.PRIVATE_REVERSE_ZONES)
        self.assertEqual({'lan', 'ok_underscore.test', 'upper.test', 'trailing.test'}, names)

    def test_the_block_leads_the_policy_ahead_of_geosite_private(self):
        policy = self.policy()
        keys = list(policy)
        self.assertEqual(self.own(), keys[:len(self.names)])
        self.assertEqual({key: ['127.0.0.1'] for key in self.own()},
                         {key: policy[key] for key in self.own()})
        self.assertEqual(list(m.BASELINE_DNS['nameserver-policy']), keys[len(self.names):])
        self.assertEqual(['system'], policy['geosite:private'])

    def test_a_subscription_policy_keeps_its_entries_behind_the_block(self):
        data = dict(self.data, dns={'enable': True, 'nameserver': ['https://dns.example/dns-query'],
                                    'nameserver-policy': {'rule-set:private': ['192.0.2.1'],
                                                          '+.internal': ['https://provider.example/dns-query'],
                                                          'geosite:cn': ['223.5.5.5']}})
        policy = self.policy(data=data)
        keys = list(policy)
        self.assertEqual(self.own(), keys[:len(self.names)])
        # A provider key naming a local domain is the router's to answer.
        self.assertEqual(['127.0.0.1'], policy['+.internal'])
        self.assertEqual(['rule-set:private', 'geosite:cn'], keys[len(self.names):])

    def test_the_merge_yaml_still_wins_for_a_key_it_states(self):
        overlay = m.merge_yaml(self.overlay, {'dns': {'nameserver-policy': {
            '+.internal': ['192.0.2.53'], '+.merge.test': ['192.0.2.54']}}})
        policy = self.policy(overlay=overlay)
        keys = list(policy)
        self.assertEqual(self.own(), keys[:len(self.names)])
        self.assertEqual(['192.0.2.53'], policy['+.internal'])
        self.assertEqual(['192.0.2.54'], policy['+.merge.test'])
        # An emptied policy clears the provider's, not the router's.
        policy = self.policy(overlay=m.merge_yaml(self.overlay, {'dns': {'nameserver-policy': {}}}))
        self.assertEqual(self.own(), list(policy))

    def test_never_where_the_router_dns_forwards_to_mihomo_or_mihomo_asks_it_anyway(self):
        baseline = list(m.BASELINE_DNS['nameserver-policy'])
        for name, settings, kwargs in (
                # The loop the block would close: Unbound forwards to Mihomo.
                ('all', dict(self.settings, dns_scope='all'), {}),
                ('off', dict(self.settings, dns_scope='off'), {}),
                # Captured falling back to all for IPv6 is the same loop.
                ('IPv6 fallback', self.settings, {'ipv6_advertised': True}),
                ('transparent off', dict(self.settings, transparent=False), {})):
            with self.subTest(name):
                self.assertEqual(baseline, list(self.policy(settings, **kwargs)))
        # Router DNS already asks the router for everything.
        self.assertEqual({}, self.policy(dict(self.settings, router_dns=True),
                                         upstreams='forward-addr: 192.0.2.53@853'))
        # Without Mihomo DNS on its listener nobody is captured.
        tun_only = m.parse_yaml((m.Path(m.__file__).resolve().parents[3] / 'share/mihomo/presets/tun-only.yaml').read_bytes())
        self.assertNotIn('+.internal', self.policy(overlay=tun_only) or {})
        # With Mihomo carrying IPv6 the captured scope stands, and so does the block.
        carried = dict(self.settings, ipv6=True)
        self.assertEqual(self.own(), list(self.policy(carried, ipv6_advertised=True))[:len(self.names)])

    def test_the_block_is_no_override_and_no_orphan(self):
        generated = m.parse_yaml(m.render(self.data, self.settings, overlay=self.overlay, local_names=self.names))
        self.assertEqual([], m.switch_conflicts(generated, self.settings))
        self.assertEqual([], m.orphan_policy_keys(m.merge_yaml(m.baseline(self.data), self.data), self.overlay))
        self.assertEqual([], m.switch_overrides(self.overlay))


class LocalNameRenderTests(unittest.TestCase):
    """The manager reads the router's local names whenever it renders, and only for this scope."""

    setUp = fixtures.StateTests.setUp

    def config(self, domain):
        path = self.manager.path('/conf/config.xml')
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('<opnsense><system><domain>%s</domain></system></opnsense>' % domain)

    def policy(self):
        return m.parse_yaml(self.manager.config_file.read_bytes())['dns'].get('nameserver-policy') or {}

    def request(self, **values):
        payload = self.manager.state / 'request.json'
        payload.write_text(json.dumps(values))
        return self.manager.dispatch('set-settings', str(payload))

    def test_start_and_apply_read_the_names_and_other_scopes_never_do(self):
        self.config('first.test')
        self.manager.apply(SUBSCRIPTION)
        self.request(dns_scope='captured')
        self.manager.dispatch('enable-transparent')
        self.assertEqual(['127.0.0.1'], self.policy()['+.first.test'])
        # Read when a configuration is rendered, not by the watchdog.
        self.config('second.test')
        self.manager.watchdog_tick()
        self.assertIn('+.first.test', self.policy())
        self.manager.dispatch('restart')
        self.assertNotIn('+.first.test', self.policy())
        self.assertIn('+.second.test', self.policy())
        for values in ({'dns_scope': 'all'}, {'dns_scope': 'off'}, {'dns_scope': 'captured', 'router_dns': True}):
            with self.subTest(values=values):
                if values.get('router_dns'):
                    dot = self.manager.path('/var/unbound/etc/dot.conf')
                    dot.parent.mkdir(parents=True, exist_ok=True)
                    dot.write_text('forward-addr: 192.0.2.53@853\n')
                self.request(**values)
                self.assertFalse([key for key in self.policy() if key.endswith('.arpa') or key == '+.second.test'])
                self.request(router_dns=False)
