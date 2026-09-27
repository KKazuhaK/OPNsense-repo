"""Check the MVC controllers against the contracts they have to honour.

The controllers themselves need OPNsense's framework to run, so these are static
checks over their source: the framework is what the native environment supplies,
but the contracts below are ones a wrong call satisfies silently. Each of these
has already been violated once.
"""
import ast
import json
import re
import shutil
import subprocess
from pathlib import Path
import unittest
from xml.etree import ElementTree

ROOT = Path(__file__).resolve().parents[1]
CONTROLLERS = sorted((ROOT / 'src/usr/local/opnsense/mvc/app/controllers/OPNsense/Mihomo').rglob('*.php'))
VIEW = ROOT / 'src/usr/local/opnsense/mvc/app/views/OPNsense/Mihomo/index.volt'
ACTIONS = ROOT / 'src/usr/local/opnsense/service/conf/actions.d/actions_mihomo.conf'
BACKUP_MODEL = ROOT / 'src/usr/local/opnsense/mvc/app/models/OPNsense/Mihomo/Backup.xml'
MANAGER = ROOT / 'src/usr/local/opnsense/scripts/mihomo/mihomo.py'


def configd_contract():
    """Which configd actions exist, and which of them take an argument."""
    text = ACTIONS.read_text()
    found = {}
    for name, body in re.findall(r'\[([a-z-]+)\]\n(.*?)(?=\n\[|\Z)', text, re.S):
        found[name] = 'parameters:%s' in body
    return found


class ConfigdContractTests(unittest.TestCase):
    def test_actions_needing_an_argument_are_given_a_staged_file(self):
        # The backend reads its argument as a path. Passing the value inline
        # fails for every one of them, and a subscription would not survive a
        # command line even if it did not.
        settings = (ROOT / 'src/usr/local/opnsense/mvc/app/controllers/OPNsense/Mihomo/Api/SettingsController.php').read_text()
        self.assertIn('tempnam', settings)
        self.assertIn('configdpRun', settings)
        staged = re.search(r'configdpRun\(.*?\[(\$\w+)\]', settings)
        self.assertIsNotNone(staged, 'the argument must be a variable holding a path')
        self.assertEqual('$staged', staged.group(1))

    def test_wan_events_forward_their_address_family(self):
        # Without the family the manager cannot tell a DHCPv6 renewal from an
        # IPv4 change, and every renewal resets all proxied connections.
        hook = (ROOT / 'src/usr/local/etc/inc/plugins.inc.d/mihomo.inc').read_text()
        self.assertTrue(configd_contract()['wan-restart'])
        self.assertIn("configctl mihomo wan-restart ' . escapeshellarg($restart)", hook)
        self.assertIn("$family = is_string($family) ? $family : '';", hook)
        self.assertIn('action == "wan-restart" and argument == "inet6"', MANAGER.read_text())

    def test_argument_less_actions_use_the_plain_runner(self):
        service = (ROOT / 'src/usr/local/opnsense/mvc/app/controllers/OPNsense/Mihomo/Api/ServiceController.php').read_text()
        known = configd_contract()
        table = re.search(r'PLAIN = \[(.*?)\];', service, re.S)
        self.assertIsNotNone(table, 'the action table must stay declarative')
        pairs = re.findall(r"'(\w+)' => '([a-z-]+)'", table.group(1))
        self.assertTrue(pairs, 'no actions found in the table')
        for verb, command in pairs:
            self.assertIn(command, known, verb)
            self.assertFalse(known[command], '%s takes an argument and cannot use the plain runner' % command)


class FrameworkApiTests(unittest.TestCase):
    def test_every_mirrored_setting_exists_in_the_native_backup_model(self):
        tree = ast.parse(MANAGER.read_text())
        assignment = next(node for node in tree.body
                          if isinstance(node, ast.Assign)
                          and any(isinstance(target, ast.Name) and target.id == 'BACKUP_KEYS'
                                  for target in node.targets))
        mirrored = set(ast.literal_eval(assignment.value))
        modeled = {node.tag for node in ElementTree.parse(BACKUP_MODEL).findall('./items/*')}
        self.assertEqual(set(), mirrored - modeled,
                         'config_mirror.php drops unmodeled fields but retains their checksum')

    def test_no_controller_calls_a_phalcon_request_method(self):
        # OPNsense has its own Request. Calling Phalcon's helpers raises at
        # runtime and surfaces as "Unexpected error, check log for details".
        allowed = {'getClientAddress', 'getHeader', 'getJsonRawBody', 'getMethod',
                   'getPost', 'getQuery', 'getRawBody', 'getScheme', 'getURI', 'isPost'}
        for path in CONTROLLERS:
            for method in re.findall(r'\$this->request->(\w+)\(', path.read_text()):
                self.assertIn(method, allowed, '%s in %s' % (method, path.name))

    def test_every_read_is_decoded_on_arrival(self):
        # Array responses are HTML-escaped by the framework as an XSS defence,
        # so a value is only intact once it is decoded. Decoding at each call
        # site is what shipped a dashboard link whose "&" had become "&amp;":
        # the panel read one parameter instead of three, fell back to loopback
        # with no secret, and reported the backend unreachable. One wrapper on
        # the way in cannot be forgotten the next time a field is added.
        view = VIEW.read_text()
        self.assertIn('function decoded(', view)
        self.assertEqual(1, view.count('ajaxGet('),
                         'every read must go through the decoding wrapper')
        self.assertIn('ajaxGet(url, {}, function (data) { done(decoded(data)); });', view)
        self.assertIn('data = decoded(data) || {}', view)
        self.assertEqual(1, view.count('htmlDecode('),
                         'decoding belongs in the wrapper, not at each element')

    def test_a_pressed_button_reports_that_it_is_working(self):
        # A restart or a transparent routing change takes seconds, and without
        # a state of its own the page looks identical throughout.
        view = VIEW.read_text()
        self.assertIn('fa-spinner fa-spin', view)
        for handler in re.findall(r"call\((api\.\w+|'/api/[^']+'.*?)\);", view):
            self.assertIn('$(this)', handler, handler)
        self.assertNotIn('onclick=', view,
                         'a button that forwards to another shows its spinner on the wrong one')

    def test_the_reachable_dashboard_switch_is_derived_back(self):
        # It is stored as the address the control API binds to, not as a flag,
        # so a getter that only echoes storage renders the box unchecked
        # however the setting stands and turning it on looks like a no-op.
        settings = [p for p in CONTROLLERS if p.name == 'SettingsController.php'][0].read_text()
        self.assertIn("$settings['dashboard_any']", settings)

    def test_manual_dns_has_an_explicit_runtime_override_switch(self):
        view = VIEW.read_text()
        settings = [p for p in CONTROLLERS if p.name == 'SettingsController.php'][0].read_text()
        self.assertIn('id="dns_override"', view)
        self.assertIn("'dns_override'", settings)
        self.assertIn("$('#dns_override,#router_dns').on('change', updateDnsControls);", view)
        for field in ('dns_default', 'dns_nameserver', 'dns_proxy_nameserver'):
            self.assertIn('id="effective_' + field + '"', view)


class FastTcpPathTests(unittest.TestCase):
    """The redirect needs its anchor hooked for translation, a form switch and a status."""

    def test_the_anchor_is_registered_for_filtering_and_for_redirects(self):
        hook = (ROOT / 'src/usr/local/etc/inc/plugins.inc.d/mihomo.inc').read_text()
        body = re.search(r'function mihomo_firewall\(.*?\n}\n', hook, re.S).group(0)
        calls = re.findall(r'\$fw->registerAnchor\(([^)]*)\);', body)
        # A quick rdr-anchor does not parse and would stop the whole ruleset
        # loading; tail placement keeps the operator's port forwards first.
        self.assertEqual(["'mihomo', 'fw', 1, 'head', false", "'mihomo', 'rdr', 1, 'tail', false"], calls)

    def test_the_switch_travels_through_form_controller_backup_and_status(self):
        view = VIEW.read_text()
        settings = [p for p in CONTROLLERS if p.name == 'SettingsController.php'][0].read_text()
        self.assertIn('id="tcp_redirect"', view)
        self.assertIn('data-for="help_for_tcpredirect"', view)
        self.assertEqual(2, view.count("'allow_lan', 'tcp_redirect'].forEach"))
        self.assertIn('id="mihomo-tcp-redirect"', view)
        self.assertIn('state.tcp_redirect_note', view)
        self.assertRegex(settings, r"FLAGS = \[[^\]]*'tcp_redirect'")
        self.assertIsNotNone(ElementTree.parse(BACKUP_MODEL).find('./items/tcp_redirect'))
        self.assertIn('127.0.0.1 port 7894', view)


class DnsScopeWordingTests(unittest.TestCase):
    """The documentation must describe the DNS integration the code performs."""

    def test_no_text_claims_bypassed_devices_keep_their_dns(self):
        # Full mode forwards Unbound's root to Mihomo, and the request reads
        # neither the device policy nor the capture interfaces, so every client
        # of the router resolver is answered by Mihomo, bypassed ones included.
        # These sentences said the opposite.
        stale = [(ROOT / 'README.US.md', 'Bypassed devices keep their existing DNS path'),
                 (VIEW, 'Bypassed devices keep their existing DNS path'),
                 (ROOT / 'README.md', '绕过设备继续使用原有 DNS 路径'),
                 (ROOT.parents[1] / 'DEPLOYMENT.md', 'existing routes and DNS'),
                 (ROOT / 'DESIGN.md', 'No global AAAA suppression'),
                 # True only with router DNS on; with the integration active
                 # Mihomo's IPv6 switch decides AAAA for every client.
                 (ROOT / 'README.US.md', 'The plugin does not suppress AAAA or configure RA/DHCPv6'),
                 (ROOT / 'README.md', '插件不抑制 AAAA 或修改 RA/DHCPv6')]
        for path, sentence in stale:
            with self.subTest(path=path.name, sentence=sentence):
                self.assertNotIn(sentence, path.read_text())

    def test_the_readmes_state_the_dnssec_exception_and_the_aaaa_effect(self):
        # 'AAAA' alone would match the claim these sentences replaced.
        for path, aaaa in ((ROOT / 'README.US.md', 'receives AAAA records for the names Unbound forwards to Mihomo'),
                           (ROOT / 'README.md', '拿不到 Unbound 转发给 Mihomo 的域名的 AAAA 记录')):
            with self.subTest(path=path.name):
                text = path.read_text()
                self.assertIn('DNSSEC', text)
                self.assertIn(aaaa, text)
                self.assertIn('Pi-hole', text)

    def test_the_status_explains_an_integration_that_is_not_active(self):
        view = VIEW.read_text()
        self.assertIn('id="mihomo-dns-note"', view)
        self.assertIn("$('#mihomo-dns-note').text(state.dns_note || '');", view)
        self.assertIn('"dns_note": dns_note', MANAGER.read_text())


class DnsScopeSettingTests(unittest.TestCase):
    """The scope travels through form, controller, backup and status, and never widens by omission."""

    def setUp(self):
        self.view = VIEW.read_text()
        self.settings = [p for p in CONTROLLERS if p.name == 'SettingsController.php'][0].read_text()

    def test_the_form_offers_the_three_scopes_under_their_names(self):
        select = re.search(r'<select id="dns_scope"[^>]*>(.*?)</select>', self.view, re.S)
        self.assertIsNotNone(select)
        options = re.findall(r'<option value="([a-z]+)">\{\{ lang._\(\'([^\']+)\'\) \}\}</option>', select.group(1))
        self.assertEqual([('all', 'All devices'),
                          ('captured', 'Only devices captured by transparent routing'),
                          ('off', 'No devices')], options)
        self.assertIn('id="help_for_dnsscope"', self.view)
        self.assertIn('data-for="help_for_dnsscope"', self.view)

    def test_a_missing_value_loads_as_all_and_the_choice_is_saved(self):
        # Falling back to the first option would silently pick whatever is
        # listed first; the store from before the setting means every device.
        self.assertIn("$('#dns_scope').val(s.dns_scope || 'all');", self.view)
        # jQuery reads a select whose chosen option is disabled as null, and
        # router DNS disables all devices; the element's own value is kept.
        self.assertIn("dns_scope: $('#dns_scope').prop('value'),", self.view)
        self.assertNotIn("$('#dns_scope').val()", self.view)
        self.assertNotIn("'device_mode', 'tun_stack', 'dns_scope'", self.view)

    def test_router_dns_greys_out_all_devices_and_explains_the_loop(self):
        self.assertIn('$(\'#dns_scope option[value="all"]\').prop(\'disabled\', routerDns);', self.view)
        # Whatever is chosen: a greyed-out option needs its reason beside it.
        self.assertIn("$('#dns_scope_loop').toggle(routerDns);", self.view)
        loop = re.search(r'<div id="dns_scope_loop"[^>]*>(.*?)</div>', self.view, re.S).group(1)
        self.assertIn('loop', loop)
        self.assertIn('treated as off', loop)
        self.assertIn("$('#dns_scope').on('change', updateDnsControls);", self.view)

    def test_the_exit_policy_is_offered_only_for_all_devices(self):
        self.assertIn('<tr id="dns_fallback_row">', self.view)
        self.assertIn("$('#dns_fallback_row').toggle(!routerDns && ($('#dns_scope').prop('value') || 'all') === 'all');",
                      self.view)

    def test_the_controller_forwards_the_scope_only_when_the_post_carries_it(self):
        # A default here would turn a captured router into a resolver-wide one
        # on any stale page or partial API submission.
        choices = re.search(r'CHOICES = \[(.*?)\];', self.settings, re.S).group(1)
        self.assertNotIn('dns_scope', choices)
        self.assertNotIn('dns_scope', re.search(r'FLAGS = \[(.*?)\];', self.settings, re.S).group(1))
        self.assertIn("if (isset($given['dns_scope'])) {\n            $payload['dns_scope'] = (string)$given['dns_scope'];",
                      self.settings)
        self.assertIn("'dns_scope'", MANAGER.read_text().split('if action == "set-settings":', 1)[1].split('for key in', 1)[1][:400])

    def test_the_scope_is_mirrored_into_the_native_backup(self):
        self.assertIsNotNone(ElementTree.parse(BACKUP_MODEL).find('./items/dns_scope'))

    def test_the_status_names_who_mihomo_answers(self):
        manager = MANAGER.read_text()
        for field in ('"dns_scope": dns_scope', '"dns_redirect": dns_redirect'):
            self.assertIn(field, manager)
        self.assertIn("const dnsScope = state.dns_scope || (state.dns_active ? 'all' : 'off');", self.view)
        for label in ('All devices', 'Captured devices', 'Paused'):
            self.assertIn("'{{ lang._('%s') }}'" % label, self.view)
        # A captured scope whose redirect the watchdog withdrew, or has not
        # armed yet, reads as paused, with the note saying why.
        self.assertIn("const paused = dnsScope === 'captured' && !state.dns_redirect;", self.view)
        self.assertIn("$('#mihomo-dns-note').text(state.dns_note || '');", self.view)

    def test_the_scope_help_is_short_and_points_to_the_details(self):
        help_text = re.search(r'data-for="help_for_dnsscope">(.*?)</div>', self.view, re.S).group(1)
        self.assertLessEqual(len(help_text.split()), 140)
        for phrase in ('an upgrade keeps it', 'the default of a fresh installation',
                       'runs as all devices while captured devices get IPv6 addresses from this router',
                       'switching back on its own',
                       'router DNS as well', '127.0.0.1 port 1053 without a gateway', 'Who gets Mihomo DNS'):
            self.assertIn(phrase, help_text)
        self.assertIn('\n## Who gets Mihomo DNS\n', (ROOT / 'README.US.md').read_text())

    def test_the_readmes_name_the_zones_the_watchdog_probes(self):
        probe = (MANAGER.parent / 'dns_probe.py').read_text()
        zones = ast.literal_eval(re.search(r'^UPSTREAM_DOMAINS = (\(.*?\))$', probe, re.M).group(1))
        for readme in ('README.US.md', 'README.md'):
            for zone in zones:
                with self.subTest(readme=readme, zone=zone):
                    self.assertIn(zone, (ROOT / readme).read_text())


class Ipv6RestrictedSettingTests(unittest.TestCase):
    """The IPv6 declaration travels through form, controller and backup, and never changes by omission."""

    def setUp(self):
        self.view = VIEW.read_text()
        self.settings = [p for p in CONTROLLERS if p.name == 'SettingsController.php'][0].read_text()

    def test_the_controller_forwards_it_only_when_the_post_carries_it(self):
        # A flag is always posted, as false when missing, which would take the
        # declaration back on any partial API submission.
        self.assertNotIn('ipv6_clients_restricted', re.search(r'FLAGS = \[(.*?)\];', self.settings, re.S).group(1))
        # Read strictly: on is the less safe side, so a posted "false" must not
        # turn it on, and a value that is no boolean reaches the backend's refusal.
        self.assertIn("if (isset($given['ipv6_clients_restricted'])) {\n"
                      "            $restricted = filter_var($given['ipv6_clients_restricted'], FILTER_VALIDATE_BOOLEAN, "
                      "FILTER_NULL_ON_FAILURE);\n"
                      "            $payload['ipv6_clients_restricted'] = $restricted ?? $given['ipv6_clients_restricted'];",
                      self.settings)
        manager = MANAGER.read_text()
        self.assertIn("'ipv6_clients_restricted'",
                      manager.split('if action == "set-settings":', 1)[1].split('if key in value', 1)[0])
        self.assertIsNotNone(ElementTree.parse(BACKUP_MODEL).find('./items/ipv6_clients_restricted'))

    def test_the_controller_turns_it_on_only_for_a_true_value(self):
        # The one block that reads it, run as it stands; the rest of the
        # controller needs the framework.
        php = shutil.which('php')
        if not php:
            self.skipTest('PHP is verified separately on FreeBSD.')
        block = re.search(r"\n( +if \(isset\(\$given\['ipv6_clients_restricted'\]\)\) \{\n.*?\n +\}\n)",
                          self.settings, re.S).group(1)
        script = '$payload = []; $given = json_decode($argv[1], true);\n' + block + 'echo json_encode($payload);'
        # JSON as the page posts it, and strings as a form-encoded post carries them.
        for given, expected in (({'ipv6_clients_restricted': True}, True), ({'ipv6_clients_restricted': 1}, True),
                                ({'ipv6_clients_restricted': '1'}, True), ({'ipv6_clients_restricted': 'true'}, True),
                                ({'ipv6_clients_restricted': False}, False), ({'ipv6_clients_restricted': 0}, False),
                                ({'ipv6_clients_restricted': '0'}, False), ({'ipv6_clients_restricted': 'false'}, False),
                                ({'ipv6_clients_restricted': ''}, False),
                                # No boolean: the backend refuses what arrives unchanged.
                                ({'ipv6_clients_restricted': 'maybe'}, 'maybe'),
                                ({'ipv6_clients_restricted': [True]}, [True])):
            with self.subTest(given=given):
                result = subprocess.run([php, '-r', script, json.dumps(given)], capture_output=True, check=True)
                self.assertEqual({'ipv6_clients_restricted': expected}, json.loads(result.stdout))
        # Absent, or null, keeps whatever is stored.
        for given in ({}, {'ipv6_clients_restricted': None}):
            with self.subTest(given=given):
                result = subprocess.run([php, '-r', script, json.dumps(given)], capture_output=True, check=True)
                self.assertEqual([], json.loads(result.stdout))

    def test_the_form_loads_saves_and_explains_it_beside_the_dns_settings(self):
        rows = [self.view.index(marker) for marker in
                ('id="router_dns"', 'id="dns_scope"', 'id="ipv6_clients_restricted"', 'id="mihomo-save-dns"')]
        self.assertEqual(sorted(rows), rows)
        self.assertIn("$('#ipv6_clients_restricted').prop('checked', s.ipv6_clients_restricted === true);", self.view)
        self.assertIn("ipv6_clients_restricted: $('#ipv6_clients_restricted').is(':checked') ? 1 : 0,", self.view)
        for flags in re.findall(r"\['dns_fallback'[^\]]*\]", self.view):
            self.assertNotIn('ipv6_clients_restricted', flags)
        help_text = re.search(r'data-for="help_for_ipv6restricted">(.*?)</div>', self.view, re.S).group(1)
        self.assertIn('id="help_for_ipv6restricted"', self.view)
        self.assertLessEqual(len(help_text.split()), 140)
        for phrase in ('Default off', 'does not check it', 'bypass the proxy over IPv6', 'no longer stops router DNS',
                       'no longer runs as all devices', 'router DNS off, Mihomo withholds AAAA records from every device',
                       'Managed mode with DNS off', 'router advertisements off', 'the stock IPv6 range deleted',
                       'per-MAC reservations', 'constructor range', 'pass IPv6 only for those devices',
                       'IPv6 only for uncaptured devices'):
            self.assertIn(phrase, help_text)
        self.assertIn('\n## IPv6 only for uncaptured devices\n', (ROOT / 'README.US.md').read_text())
        # Beside the switch: every device answered without IPv6 answers defeats it.
        self.assertIn('<div id="ipv6_restricted_all" class="text-warning" style="display:none">', self.view)
        self.assertIn("$('#ipv6_restricted_all').toggle($('#ipv6_clients_restricted').is(':checked') && !routerDns\n"
                      "            && !ipv6Overridden && !$('#ipv6').is(':checked') && ($('#dns_scope').prop('value') || 'all') === 'all');",
                      self.view)
        # The box does not show an IPv6 value the merge YAML sets, so the status note speaks then.
        self.assertIn("ipv6Overridden = (data.overrides || []).indexOf('ipv6') !== -1;\n            updateDnsControls();",
                      self.view)
        self.assertIn("$('#ipv6_clients_restricted,#ipv6').on('change', updateDnsControls);", self.view)
        # The two helps it relaxes say so.
        for key in ('help_for_routerdns', 'help_for_dnsscope'):
            text = re.search(r'data-for="%s">(.*?)</div>' % key, self.view, re.S).group(1)
            self.assertIn('IPv6 only for uncaptured devices', text)

    def test_every_document_describes_it(self):
        for path in (ROOT / 'README.US.md', ROOT / 'README.md', ROOT / 'DESIGN.md', ROOT.parents[1] / 'DEPLOYMENT.md'):
            with self.subTest(path=path.name):
                text = path.read_text()
                self.assertIn('ipv6_clients_restricted', text)
                self.assertIn('Managed', text)


class CaptureInterfaceViewTests(unittest.TestCase):
    """The interface picker must never lose a stored selection or offer an uplink."""

    def setUp(self):
        self.view = VIEW.read_text()

    def test_picker_is_a_multi_select_with_an_automatic_empty_state_and_help(self):
        picker = re.search(r'<select id="capture_interfaces"[^>]*>', self.view)
        self.assertIsNotNone(picker)
        self.assertIn(' multiple ', picker.group(0))
        self.assertIn('Automatic (all internal interfaces)', picker.group(0))
        self.assertIn('id="help_for_captureif"', self.view)
        self.assertIn('data-for="help_for_captureif"', self.view)

    def test_stored_selection_survives_either_response_order_and_missing_interfaces(self):
        # Settings and candidates arrive separately; the picker must not
        # report its own empty state before the stored selection is applied.
        self.assertIn('const current = captureReady ? (select.val() || []) : storedCapture;', self.view)
        self.assertIn('storedCapture = s.capture_interfaces || [];', self.view)
        self.assertIn('renderCaptureInterfaces((found || {}).interfaces);', self.view)
        self.assertIn('if (!known[name])', self.view, 'a vanished interface must stay selected and visible')
        self.assertEqual(1, self.view.count('get(api.devices'), 'one fetch serves the devices and the picker')

    def test_selection_is_saved_and_carried_through_the_controllers(self):
        self.assertIn("capture_interfaces: ($('#capture_interfaces').val() || []).join(','),", self.view)
        settings = [p for p in CONTROLLERS if p.name == 'SettingsController.php'][0].read_text()
        lists = re.search(r'LISTS = \[(.*?)\];', settings, re.S).group(1)
        self.assertIn("'capture_interfaces'", lists)
        service = [p for p in CONTROLLERS if p.name == 'ServiceController.php'][0].read_text()
        self.assertIn("'interfaces' => $found['interfaces'] ?? []", service)


class DeviceTabTests(unittest.TestCase):
    """The device policy is its own tab, and it has to survive a long list."""

    def setUp(self):
        self.view = VIEW.read_text()

    def test_the_policy_has_a_tab_of_its_own(self):
        self.assertIn('href="#devices"', self.view)
        self.assertIn('<div id="devices" class="tab-pane', self.view)

    def test_a_long_list_can_be_narrowed(self):
        # A household can carry a hundred devices; a flat list of checkboxes
        # stops being usable well before that.
        for control in ('mihomo-device-search', 'mihomo-device-selected-only',
                        'mihomo-device-count'):
            self.assertIn(control, self.view)

    def test_a_whole_segment_can_be_chosen_at_once(self):
        # One entry for a segment replaces one per device and keeps covering
        # them as they come and go, which an address from a lease cannot.
        self.assertIn('function segmentOf(', self.view)
        self.assertIn('mihomo-segment', self.view)
        # Addresses the segment already covers are dropped, because a rule
        # behind a segment that matches first can never be reached.
        self.assertIn("segmentOf(entry) !== segment", self.view)

    def test_filtering_does_not_refetch(self):
        # The list comes from configd; re-reading it on every keystroke would
        # put a shell behind the search box.
        self.assertIn('renderDevices(lastDevices)', self.view)


class ViewTests(unittest.TestCase):
    def test_tabs_and_panes_agree(self):
        view = VIEW.read_text()
        self.assertEqual(re.findall(r'data-toggle="tab" href="#([a-z]+)"', view),
                         re.findall(r'<div id="([a-z]+)" class="tab-pane', view))

    def test_every_pane_sits_inside_the_tab_container(self):
        # Comparing the tab list with the pane list says nothing about nesting.
        # One stray closing tag ends the container early, and every pane after
        # it renders on whichever tab is open -- which is how the device policy
        # came to appear at the bottom of Status.
        view = VIEW.read_text()
        body = view[view.index('<ul class="nav nav-tabs'):]
        self.assertEqual(len(re.findall(r'<div\b', body)), len(re.findall(r'</div>', body)),
                         'the pane markup does not balance')
        depth = 0
        depths = []
        for token in re.findall(r'<div\b[^>]*>|</div>', body):
            if token == '</div>':
                depth -= 1
            else:
                if 'class="tab-pane' in token:
                    depths.append(depth)
                depth += 1
        self.assertTrue(depths, 'no panes found')
        self.assertEqual(1, len(set(depths)),
                         'panes sit at differing depths: %s' % depths)

    def test_every_tab_can_show_its_help(self):
        # The framework scopes the whole-page toggle to the nearest ancestor
        # form whose id starts with frm. With no such form it toggles nothing,
        # silently, and a toggle rendered on one tab reaches no other.
        view = VIEW.read_text()
        panes = re.findall(r'<div id="([a-z]+)" class="tab-pane', view)
        for pane in panes:
            self.assertIn('<form id="frm%s">' % pane, view, pane)
            self.assertIn('id="show_all_help_%s"' % pane, view, pane)
        self.assertEqual(len(panes), view.count('</form>'))
        # They post nowhere, so Enter in a field must not reload the page.
        self.assertIn("$('form[id^=\"frm\"]').on('submit'", view)

    def test_ids_are_unique(self):
        ids = re.findall(r'id="([^"{]+)"', VIEW.read_text())
        self.assertEqual([], sorted({i for i in ids if ids.count(i) > 1}))

    def test_the_view_declares_no_colour(self):
        # Three themes ship, one of them dark; a declared colour survives none.
        self.assertEqual([], re.findall(r'(?:color|background)\s*:\s*(?:#|rgb)', VIEW.read_text()))

    def test_no_legacy_page_remains(self):
        self.assertEqual([], sorted((ROOT / 'src/usr/local/www').glob('*.php'))
                         if (ROOT / 'src/usr/local/www').is_dir() else [])
