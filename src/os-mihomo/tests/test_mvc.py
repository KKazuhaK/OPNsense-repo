"""Check the MVC controllers against the contracts they have to honour.

The controllers themselves need OPNsense's framework to run, so these are static
checks over their source: the framework is what the native environment supplies,
but the contracts below are ones a wrong call satisfies silently. Each of these
has already been violated once.
"""
import ast
import re
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
