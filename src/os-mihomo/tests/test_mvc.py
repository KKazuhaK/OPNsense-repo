"""Check the MVC controllers against the contracts they have to honour.

The controllers themselves need OPNsense's framework to run, so these are static
checks over their source: the framework is what the native environment supplies,
but the contracts below are ones a wrong call satisfies silently. Each of these
has already been violated once.
"""
import re
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
CONTROLLERS = sorted((ROOT / 'src/usr/local/opnsense/mvc/app/controllers/OPNsense/Mihomo').rglob('*.php'))
VIEW = ROOT / 'src/usr/local/opnsense/mvc/app/views/OPNsense/Mihomo/index.volt'
ACTIONS = ROOT / 'src/usr/local/opnsense/service/conf/actions.d/actions_mihomo.conf'


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
