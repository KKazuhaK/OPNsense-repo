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

    def test_text_from_the_api_is_decoded_before_display(self):
        # Array responses are HTML-escaped by the framework as an XSS defence;
        # htmlDecode is the matching helper on the way in.
        view = VIEW.read_text()
        for field in re.findall(r"ajaxGet\(api\.(\w*[Ll]og\w*)", view):
            pattern = r'ajaxGet\(api\.%s.*?htmlDecode' % field
            self.assertRegex(view, pattern, field)


class ViewTests(unittest.TestCase):
    def test_tabs_and_panes_agree(self):
        view = VIEW.read_text()
        self.assertEqual(re.findall(r'data-toggle="tab" href="#([a-z]+)"', view),
                         re.findall(r'<div id="([a-z]+)" class="tab-pane', view))

    def test_ids_are_unique(self):
        ids = re.findall(r'id="([^"{]+)"', VIEW.read_text())
        self.assertEqual([], sorted({i for i in ids if ids.count(i) > 1}))

    def test_the_view_declares_no_colour(self):
        # Three themes ship, one of them dark; a declared colour survives none.
        self.assertEqual([], re.findall(r'(?:color|background)\s*:\s*(?:#|rgb)', VIEW.read_text()))

    def test_no_legacy_page_remains(self):
        self.assertEqual([], sorted((ROOT / 'src/usr/local/www').glob('*.php'))
                         if (ROOT / 'src/usr/local/www').is_dir() else [])
