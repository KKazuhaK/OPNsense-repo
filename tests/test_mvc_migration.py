"""Check MVC routes and package integration independently of a router session.

These checks complement native API and browser tests: a route that worked after
copying files manually must still ship in the package and stay reachable through
its menu, ACL and Volt view.
"""
import configparser
from html.parser import HTMLParser
from pathlib import Path
import re
import shlex
import unittest
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
MVC = Path('src/usr/local/opnsense/mvc/app')
PLUGINS = {
    'os-staticarp': ('Staticarp', 'staticarp'),
    'os-pftop': ('Pftop', 'pftop'),
    'os-lucky': ('Lucky', 'lucky'),
    'os-easytier': ('EasyTier', 'easytier'),
    'os-ddns-go': ('Ddnsgo', 'ddnsgo'),
    'os-lang': ('LangTool', 'langtool'),
    'os-ttyd': ('Ttyd', 'ttyd'),
    'os-speedtest': ('Speedtest', 'speedtest'),
    'os-sing-box': ('SingBox', 'singbox'),
}
# Public methods verified against the real OPNsense 26.7 Request.php. Phalcon
# methods such as getHttpHost are absent, even though its examples use them.
REQUEST_METHODS = {
    'getClientAddress', 'getHeader', 'getJsonRawBody', 'getMethod', 'getPost',
    'getQuery', 'getRawBody', 'getScheme', 'getURI', 'hasQuery', 'isPost', 'isGet',
    'isPut', 'isDelete', 'isHead', 'isPatch', 'isOptions', 'has', 'hasPost', 'get',
}


class Markup(HTMLParser):
    def __init__(self, text):
        super().__init__()
        self.ids = []
        self.inputs = []
        self.actions = []
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if 'id' in attrs:
            self.ids.append(attrs['id'])
        if tag == 'input':
            self.inputs.append(attrs)
        if 'data-action' in attrs:
            self.actions.append(attrs['data-action'])


class MvcMigrationTests(unittest.TestCase):
    def packages(self):
        for package, (module, route) in PLUGINS.items():
            yield ROOT / 'src' / package, module, route

    def test_legacy_pages_are_removed_and_mvc_entry_points_ship(self):
        for package, module, _ in self.packages():
            with self.subTest(package=package.name):
                self.assertEqual([], list((package / 'src/usr/local/www').glob('*.php')))
                controller = package / MVC / 'controllers/OPNsense' / module / 'IndexController.php'
                view = package / MVC / 'views/OPNsense' / module / 'index.volt'
                self.assertTrue(controller.is_file(), str(controller))
                self.assertTrue(view.is_file(), str(view))
                source = controller.read_text()
                self.assertIn('namespace OPNsense\\' + module + ';', source)
                self.assertRegex(source, r'extends\s+\\OPNsense\\Base\\IndexController')
                self.assertIn("pick('OPNsense/" + module + "/index')", source)
                self.assertTrue(list((controller.parent / 'Api').glob('*Controller.php')))

    def test_menu_and_acl_register_both_page_and_api(self):
        for package, module, route in self.packages():
            with self.subTest(package=package.name):
                models = package / MVC / 'models/OPNsense' / module
                menu = ET.parse(models / 'Menu/Menu.xml').getroot()
                urls = {element.get('url') for element in menu.iter() if element.get('url')}
                self.assertIn('/ui/' + route, urls)
                self.assertIn('/ui/' + route + '/*', urls)
                self.assertFalse(any('.php' in url for url in urls), urls)
                acl = ET.parse(models / 'ACL/ACL.xml').getroot()
                patterns = {element.text for element in acl.iter('pattern')}
                self.assertIn('ui/' + route + '/*', patterns)
                self.assertIn('api/' + route + '/*', patterns)
                self.assertFalse(any('.php' in pattern for pattern in patterns), patterns)

    def test_api_controllers_use_the_real_request_and_configd(self):
        for package, module, _ in self.packages():
            controllers = package / MVC / 'controllers/OPNsense' / module / 'Api'
            commands = {}
            for path in (package / 'src/usr/local/opnsense/service/conf/actions.d').glob('actions_*.conf'):
                config = configparser.ConfigParser(interpolation=None)
                config.read(path)
                commands[path.stem.removeprefix('actions_')] = set(config.sections())
            for path in controllers.glob('*Controller.php'):
                with self.subTest(controller=str(path.relative_to(ROOT))):
                    source = path.read_text()
                    self.assertIn('namespace OPNsense\\' + module + '\\Api;', source)
                    self.assertRegex(source, r'extends\s+(?:\\OPNsense\\Base\\)?ApiControllerBase')
                    methods = set(re.findall(r'\$this->request->([a-zA-Z_][a-zA-Z0-9_]*)\s*\(', source))
                    self.assertEqual(set(), methods - REQUEST_METHODS, 'Unsupported Request methods')
                    self.assertRegex(source, r'configd(?:p)?Run\s*\(')
                    for command in re.findall(r'configd(?:p)?Run\s*\(\s*[\x27\x22]([^\x27\x22]+)[\x27\x22]', source):
                        parts = command.split()
                        self.assertIn(parts[0], commands, 'Unknown configd action group')
                        if len(parts) > 1:
                            self.assertIn(parts[1], commands[parts[0]], 'Unregistered configd command: ' + command)
                    self.assertNotRegex(source, r'\b(?:require(?:_once)?|include(?:_once)?|exec|shell_exec|passthru)\s*\(')
                    self.assertNotIn('/usr/local/etc/inc/', source)

    def test_volt_markup_and_referenced_api_actions(self):
        for package, module, route in self.packages():
            with self.subTest(package=package.name):
                text = (package / MVC / 'views/OPNsense' / module / 'index.volt').read_text()
                self.assertNotIn('<?', text)
                self.assertNotRegex(text, r'(?:color|background(?:-color)?)\s*:', 'The view declares a theme color')
                markup = Markup(text)
                self.assertEqual(len(markup.ids), len(set(markup.ids)), 'Duplicate page IDs')
                self.assertTrue(all(attrs.get('type') for attrs in markup.inputs), 'An input has no explicit type')
                api = package / MVC / 'controllers/OPNsense' / module / 'Api'
                controllers = {path.stem.removesuffix('Controller').lower(): path.read_text() for path in api.glob('*Controller.php')}
                endpoints = re.findall(r'/api/' + re.escape(route) + r'/([a-zA-Z]+)/([a-zA-Z][a-zA-Z0-9_]*)', text)
                if '/api/' + route + '/' in text:
                    endpoints += re.findall(r'[\x27\x22](service|settings)/([a-zA-Z][a-zA-Z0-9_]*)[\x27\x22]', text)
                self.assertTrue(endpoints, 'The view does not reference a registered API')
                for controller, action in endpoints:
                    self.assertIn(controller.lower(), controllers, 'Missing API controller')
                    self.assertRegex(controllers[controller.lower()], r'public\s+function\s+' + re.escape(action) + r'Action\s*\(', 'Missing API action: ' + action)
                for action in markup.actions:
                    self.assertRegex(controllers.get('service', ''), r'public\s+function\s+' + re.escape(action) + r'Action\s*\(', 'Missing button API action: ' + action)

    def test_configd_commands_reference_packaged_helpers(self):
        for package, _, _ in self.packages():
            with self.subTest(package=package.name):
                configs = list((package / 'src/usr/local/opnsense/service/conf/actions.d').glob('actions_*.conf'))
                self.assertTrue(configs, 'No configd actions are packaged')
                helpers = []
                for path in configs:
                    actions = configparser.ConfigParser(interpolation=None)
                    actions.read(path)
                    self.assertTrue(actions.sections(), str(path))
                    for section in actions.sections():
                        self.assertIn(actions[section].get('type'), ('script', 'script_output'))
                        command = actions[section].get('command', '')
                        self.assertTrue(command, 'Configd action has no command: ' + section)
                        for token in shlex.split(command):
                            if token.startswith('/usr/local/opnsense/scripts/'):
                                helper = package / 'src' / token.lstrip('/')
                                self.assertTrue(helper.is_file(), 'Unpackaged configd helper: ' + token)
                                helpers.append(helper)
                self.assertTrue(helpers, 'The migrated backend helper is not registered in configd')

    def test_build_preconditions_and_install_hooks_have_no_stale_page_paths(self):
        for package, _, _ in self.packages():
            with self.subTest(package=package.name):
                build = (package / 'build.sh').read_text()
                for relative in re.findall(r'^\s*need_file\s+[\x27\x22]([^\x27\x22]+)[\x27\x22]', build, re.MULTILINE):
                    if '$' not in relative:
                        self.assertTrue((package / relative).exists(), 'Missing required build file: ' + relative)
                for relative in ['+MANIFEST.in', '+POST_INSTALL', '+PRE_DEINSTALL', '+POST_DEINSTALL', 'pkg-descr']:
                    self.assertTrue((package / 'packaging/freebsd' / relative).is_file(), relative)
                hook = (package / 'packaging/freebsd/+POST_INSTALL').read_text()
                for source in [build, hook]:
                    source = source.replace('\\\n', ' ')
                    for command in re.findall(r'^\s*chmod\s+[^\n]+', source, re.MULTILINE):
                        self.assertNotRegex(command, r'/usr/local/www/[^\s\x22\x27]+\.php\b', 'Obsolete page chmod: ' + command)
                        for path in re.findall(r'/usr/local/etc/inc/[^\s\x22\x27]+', command):
                            self.assertTrue((package / 'src' / path.lstrip('/')).is_file(), 'Obsolete helper chmod: ' + path)


if __name__ == '__main__':
    unittest.main()
