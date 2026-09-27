"""Check that every piece of WAN Guard is wired to the others and to the release tooling."""
import configparser
import json
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import unittest
import xml.etree.ElementTree as ET

PACKAGE = Path(__file__).resolve().parents[1]
REPOSITORY = PACKAGE.parents[1]
SRC = PACKAGE / 'src'
OPNSENSE = SRC / 'usr/local/opnsense'
MVC = OPNSENSE / 'mvc/app'
SCRIPTS = OPNSENSE / 'scripts/wanguard'
sys.path.insert(0, str(SCRIPTS))
import guard  # noqa: E402


def read(relative):
    return (SRC / relative).read_text()


class ConfigdTests(unittest.TestCase):
    def actions(self):
        parser = configparser.ConfigParser(interpolation=None)
        parser.read(OPNSENSE / 'service/conf/actions.d/actions_wanguard.conf')
        return parser

    def test_actions_resolve_to_packaged_files(self):
        actions = self.actions()
        self.assertEqual(set(actions.sections()), {'start', 'stop', 'restart', 'status', 'reload', 'state', 'retry'})
        verbs = {'start': 'start', 'stop': 'onestop', 'restart': 'restart', 'status': 'onestatus', 'reload': 'reload'}
        for section in actions.sections():
            with self.subTest(action=section):
                words = shlex.split(actions[section]['command'])
                if section in verbs:
                    self.assertEqual(words, ['/usr/local/etc/rc.d/wanguard', verbs[section]])
                else:
                    # -B: no __pycache__ left under the package's own script
                    # directory, which pkg does not track and pkg delete
                    # cannot remove on its own.
                    self.assertEqual(words, ['/usr/local/bin/python3', '-B',
                                             '/usr/local/opnsense/scripts/wanguard/wanguard.py', section])
                for word in words[:2]:
                    if word.startswith('/usr/local/') and word != '/usr/local/bin/python3':
                        self.assertTrue((SRC / word.lstrip('/')).is_file(), word)
                self.assertEqual(actions[section].get('parameters', ''), '%s' if section == 'retry' else '')
                self.assertIn(actions[section]['type'], ('script', 'script_output'))

    def test_status_action_tolerates_a_stopped_service(self):
        # rc.d onestatus exits 1 when stopped (RcScriptTests in test_hooks.py
        # asserts this is by design). configd's script_output action raises
        # and reports 'Execute error' on a non-zero exit unless the action
        # says otherwise; 'errors:no' is that core convention (also used by,
        # for example, core's own monit and syslog-ng actions). Without it,
        # the base service controller's statusAction() -- which parses this
        # action's captured text for 'is running'/'not running' -- never sees
        # that text for an enabled-but-stopped service, and reports 'unknown'
        # instead of 'stopped', with a traceback in the configd log on every
        # poll. test_hooks.py's test_configd_status_action_never_raises_on_a_
        # stopped_service reproduces configd's own subprocess call on both
        # sides of this flag.
        self.assertEqual(self.actions()['status'].get('errors', '').strip().lower(), 'no')
        for section in set(self.actions().sections()) - {'status'}:
            # A real failure starting, stopping, restarting, reloading, or
            # reading state or a retry answer must still surface as one.
            self.assertEqual(self.actions()[section].get('errors', ''), '')

    def test_no_configd_action_reaches_the_helper(self):
        # Only the daemon calls helper.php, so no API path can re-request a
        # lease around the safety rules.
        actions = self.actions()
        self.assertNotIn('helper.php', (OPNSENSE / 'service/conf/actions.d/actions_wanguard.conf').read_text())
        for section in actions.sections():
            words = shlex.split(actions[section]['command'])
            self.assertFalse({'redhcp', 'restore', 'observe', 'run'} & set(words), section)
            self.assertFalse({'redhcp', 'restore', 'observe'} & {section})

    def test_status_wording_matches_what_the_service_base_class_parses(self):
        rc = read('usr/local/etc/rc.d/wanguard')
        self.assertIn('echo "wanguard is running as pid', rc)
        self.assertIn('echo "wanguard is not running."', rc)
        self.assertGreater('wanguard is not running.'.find('not running'), 0)
        self.assertGreater('wanguard is running as pid 1.'.find('is running'), 0)

    def test_controllers_call_only_registered_actions(self):
        registered = set(self.actions().sections())
        for path in (MVC / 'controllers/OPNsense/Wanguard/Api').glob('*.php'):
            for command in re.findall(r'configdp?Run\(\s*\'([^\']+)\'', path.read_text()):
                group, action = command.split()
                self.assertEqual(group, 'wanguard')
                self.assertIn(action, registered)
        # The service base class runs these for start, stop, restart, status and a soft reconfigure.
        self.assertTrue({'start', 'stop', 'restart', 'status', 'reload'} <= registered)
        service = (MVC / 'controllers/OPNsense/Wanguard/Api/ServiceController.php').read_text()
        self.assertRegex(service, r'function reconfigureForceRestart\(\)\s*\{\s*return 0;')
        self.assertIn("$internalServiceTemplate = 'OPNsense/Wanguard'", service)
        for action in ['start', 'stop', 'restart', 'reconfigure', 'retry']:
            body = re.search(r'public function %sAction\(\)\s*\{(.*?)\n    \}' % action, service, re.S).group(1)
            self.assertTrue('throwReadOnly' in body or 'mutation()' in body, action)


class RouteTests(unittest.TestCase):
    def test_menu_pages_have_views_and_the_acl_covers_every_route(self):
        menu = ET.parse(MVC / 'models/OPNsense/Wanguard/Menu/Menu.xml').getroot()
        urls = {node.get('url') for node in menu.iter() if node.get('url')}
        self.assertEqual(urls, {'/ui/wanguard', '/ui/wanguard/*', '/ui/diagnostics/log/core/wanguard'})
        heading = menu.find('Services/Wanguard')
        self.assertEqual((heading.get('VisibleName'), heading.get('order'), heading.get('cssClass')),
                         ('WAN Guard', '92', 'fa fa-shield fa-fw'))
        self.assertTrue((MVC / 'controllers/OPNsense/Wanguard/IndexController.php').is_file())
        self.assertTrue((MVC / 'views/OPNsense/Wanguard/index.volt').is_file())
        acl = ET.parse(MVC / 'models/OPNsense/Wanguard/ACL/ACL.xml').getroot()
        self.assertEqual(acl[0].tag, 'page-services-wanguard')
        self.assertEqual(acl[0].find('name').text, 'Services: WAN Guard')
        patterns = [pattern.text for pattern in acl.iter('pattern')]
        self.assertEqual(patterns, ['ui/wanguard/*', 'api/wanguard/*', 'ui/diagnostics/log/core/wanguard/*',
                                    'api/diagnostics/log/core/wanguard/*'])

        def allowed(url):
            # OPNsense's ACL::urlMatch: a trailing /* also matches the bare path.
            for pattern in patterns:
                regex = re.escape(pattern).replace(r'\*', '.*')
                regex = re.sub(r'/\.\*$', '(/.*)?', regex)
                if re.fullmatch('/' + regex, url):
                    return True
            return False
        view = (MVC / 'views/OPNsense/Wanguard/index.volt').read_text()
        routes = set(re.findall(r'/api/wanguard/[a-z]+/[a-zA-Z]+', view)) | {url.rstrip('/*') for url in urls}
        routes |= {'/api/wanguard/service/status', '/api/wanguard/service/start', '/api/wanguard/service/stop',
                   '/api/wanguard/service/restart', '/api/diagnostics/log/core/wanguard'}
        self.assertTrue({'/api/wanguard/settings/get', '/api/wanguard/settings/set', '/api/wanguard/service/state',
                         '/api/wanguard/service/retry', '/api/wanguard/service/reconfigure'} <= routes)
        for route in routes:
            self.assertTrue(allowed(route), route)
        self.assertFalse(allowed('/api/core/firmware/status'))

    def test_the_view_declares_no_colours_and_escapes_backend_text(self):
        view = (MVC / 'views/OPNsense/Wanguard/index.volt').read_text()
        self.assertNotRegex(view, r'(?:color|background(?:-color)?)\s*:')
        self.assertNotIn('.html(row', view)
        self.assertIn("updateServiceControlUI('wanguard')", view)
        self.assertIn("'data_endpoint': '/api/wanguard/service/reconfigure'", view)


class ModelTests(unittest.TestCase):
    def test_model_fields_defaults_and_filters(self):
        model = ET.parse(MVC / 'models/OPNsense/Wanguard/General.xml').getroot()
        self.assertEqual(model.find('mount').text, '//OPNsense/wanguard/general')
        self.assertEqual(model.find('version').text, '1.0.0')
        items = model.find('items')
        fields = {item.tag: item for item in items}
        self.assertEqual(list(fields), ['enabled', 'interfaces', 'networks', 'private_ranges'])
        self.assertEqual({tag: item.get('type') for tag, item in fields.items()},
                         {'enabled': 'BooleanField', 'interfaces': 'InterfaceField', 'networks': 'NetworkField',
                          'private_ranges': 'BooleanField'})
        self.assertEqual(fields['enabled'].find('Default').text, '0')
        self.assertEqual(fields['private_ranges'].find('Default').text, '0')
        self.assertEqual(fields['interfaces'].find('Default').text, 'wan')
        self.assertEqual(fields['interfaces'].find('Multiple').text, 'Y')
        self.assertIsNone(fields['networks'].find('Default'))
        self.assertEqual(fields['interfaces'].find('filters/ipaddr').text, '/^dhcp$/')
        self.assertEqual(fields['interfaces'].find('filters/enable').text, '/^(?!0).*$/')
        for key, value in {'AsList': 'Y', 'NetMaskRequired': 'Y', 'AddressFamily': 'ipv4',
                           'WildcardEnabled': 'N', 'Strict': 'Y', 'FieldSeparator': ','}.items():
            self.assertEqual(fields['networks'].find(key).text, value, key)
        php = (MVC / 'models/OPNsense/Wanguard/General.php').read_text()
        self.assertIn('const MAX_NETWORKS = %d;' % guard.MAX_NETWORKS, php)
        self.assertIn('const MIN_PREFIX = %d;' % guard.MIN_PREFIX, php)

    def test_the_form_shows_exactly_the_model_fields(self):
        form = ET.parse(MVC / 'controllers/OPNsense/Wanguard/forms/general.xml').getroot()
        ids = [field.find('id').text for field in form.iter('field')]
        self.assertEqual(ids, ['general.enabled', 'general.interfaces', 'general.networks', 'general.private_ranges'])
        help_text = ' '.join(field.find('help').text for field in form.iter('field'))
        self.assertIn('With CGNAT (100.64.0.0/10) this would retry forever.', help_text)
        settings = (MVC / 'controllers/OPNsense/Wanguard/Api/SettingsController.php').read_text()
        self.assertIn("$internalModelName = 'general'", settings)
        self.assertIn("$internalModelClass = '\\OPNsense\\Wanguard\\General'", settings)

    def test_the_rc_template_follows_the_enable_setting(self):
        try:
            import jinja2
        except ImportError:
            self.skipTest('Jinja2 is not installed')
        templates = OPNSENSE / 'service/templates/OPNsense/Wanguard'
        self.assertEqual((templates / '+TARGETS').read_text(), 'rc.conf.d:/etc/rc.conf.d/wanguard\n')

        class Helpers:
            def __init__(self, data):
                self.data = data

            def exists(self, path):
                node = self.data
                for part in path.split('.'):
                    if not isinstance(node, dict) or part not in node:
                        return False
                    node = node[part]
                return True
        template = jinja2.Environment().from_string((templates / 'rc.conf.d').read_text())
        for general, expected in [({'enabled': '1'}, 'YES'), ({'enabled': '0'}, 'NO'), (None, 'NO')]:
            data = {'OPNsense': {'wanguard': {'general': general}}} if general else {'OPNsense': {}}
            output = template.render(helpers=Helpers(data), **data)
            self.assertEqual(output.strip(), 'wanguard_enable="%s"' % expected)


class LoggingTests(unittest.TestCase):
    def test_one_program_name_everywhere(self):
        local = OPNSENSE / 'service/templates/OPNsense/Syslog/local/wanguard.conf'
        self.assertRegex(local.read_text(), r'filter f_local_wanguard \{\s*program\("wanguard"\);\s*\};')
        self.assertIn("syslog.openlog('wanguard', 0, syslog.LOG_DAEMON)", (SCRIPTS / 'wanguard.py').read_text())
        self.assertIn("openlog('wanguard', LOG_ODELAY, LOG_DAEMON)", (SCRIPTS / 'helper.php').read_text())
        self.assertIn('-S -T wanguard', read('usr/local/etc/rc.d/wanguard'))
        plugin = read('usr/local/etc/inc/plugins.inc.d/wanguard.inc')
        self.assertIn("$logfacilities['wanguard'] = [\n        'facility' => ['wanguard'],", plugin)
        self.assertIn("'newwanip' => ['wanguard_newwanip:3']", plugin)
        self.assertIn("'pidfile' => '/var/run/wanguard.pid'", plugin)


class SafetyWiringTests(unittest.TestCase):
    def test_the_helper_only_ever_restarts_the_ipv4_dhcp_client(self):
        helper = (SCRIPTS / 'helper.php').read_text()
        code = re.sub(r'/\*.*?\*/', '', helper, flags=re.S)
        for forbidden in ['interface_configure(', 'interface_reconfigure', 'interface_dhcpv6_configure',
                          'interface_bring_down', 'interfaces_addresses_flush', 'dhcp6c', 'rtsold',
                          'configctl', 'rc.newwanip', 'mwexec', 'exec(', 'system(', 'passthru', 'shell_exec']:
            self.assertNotIn(forbidden, code, forbidden)
        self.assertEqual(re.findall(r'killbypid\(([^)]*)\)', code), ["$pidfile, 'TERM', false"])
        self.assertIn('$pidfile = "/var/run/dhclient.{$device}.pid";', code)
        self.assertEqual(code.count('interface_dhcp_configure($name)'), 3)
        self.assertIn("return ['result' => 'refused:address-changed'];", code)
        # The DHCP client it starts must not inherit the action lock.
        self.assertIn("fopen(WANGUARD_RUN . '/action.lock', 'ce')", code)

    def test_the_hook_only_wakes_the_daemon(self):
        plugin = read('usr/local/etc/inc/plugins.inc.d/wanguard.inc')
        body = plugin[plugin.index('function wanguard_newwanip('):]
        for forbidden in ['exec(', 'configctl', 'interface_', 'killbypid', 'mwexec']:
            self.assertNotIn(forbidden, body)
        self.assertIn("wanguard_wake('/var/run/wanguard', $targets)", body)

    @unittest.skipUnless(shutil.which('php'), 'PHP is not installed')
    def test_php_sources_parse(self):
        paths = sorted([*SRC.rglob('*.php'), *SRC.rglob('*.inc'), *(PACKAGE / 'tests/native').glob('*.php')])
        self.assertTrue(paths)
        for path in paths:
            with self.subTest(path=path.name):
                result = subprocess.run(['php', '-l', str(path)], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


class ReleaseWiringTests(unittest.TestCase):
    def build_value(self, name):
        text = (PACKAGE / 'build.sh').read_text()
        return re.search(r'^%s="\$\{%s:-([^}"]+)\}"' % (name, name), text, re.M).group(1)

    def test_versions_agree_everywhere(self):
        version = self.build_value('VERSION')
        self.assertEqual(version, '1.0.0')
        metadata = json.loads(read('usr/local/opnsense/version/wanguard'))
        self.assertEqual(metadata, {'product_abi': '26.7', 'product_arch': 'amd64',
                                    'product_email': 'https://github.com/KKazuhaK/', 'product_id': 'os-wanguard',
                                    'product_name': 'wanguard', 'product_tier': '4', 'product_version': version,
                                    'product_website': 'https://github.com/KKazuhaK/OPNsense-repo'})
        self.assertRegex((PACKAGE / 'Makefile').read_text(), r'VERSION\?=\t%s\n' % re.escape(version))
        record = json.loads((REPOSITORY / 'packaging/plugins.json').read_text())['plugins']['os-wanguard']
        self.assertEqual(record, {'staging': 'tree', 'abi': 'independent', 'version': version, 'stage': {'src': '/'},
                                  'deps': {'python313': 'lang/python313'},
                                  'version_file': {'path': '/usr/local/opnsense/version/wanguard', 'format': 'json'}})
        manifest = (PACKAGE / 'packaging/freebsd/+MANIFEST.in').read_text()
        self.assertIn('deps: { python313: { origin: "lang/python313", version: ">=0" } }', manifest)
        # ABI independent: pure PHP, Python and shell, no native executable.
        self.assertIn('TARGET_ABI="${TARGET_ABI:-${ABI:-FreeBSD:*:amd64}}"', (PACKAGE / 'build.sh').read_text())
        self.assertIn('TARGET_ABI?=\tFreeBSD:*:amd64', (PACKAGE / 'Makefile').read_text())

    def test_the_build_requires_every_committed_file(self):
        build = (PACKAGE / 'build.sh').read_text()
        required = set(re.findall(r'^need_file "([^"]+)"', build, re.M))
        committed = {path.relative_to(PACKAGE).as_posix() for path in SRC.rglob('*')
                     if path.is_file() and '__pycache__' not in path.parts and path.name != '.DS_Store'}
        self.assertEqual(committed - required, set())
        self.assertEqual({item for item in required if item.startswith('src/')} - committed, set())
        for hook in ['+MANIFEST.in', '+PRE_INSTALL', '+POST_INSTALL', '+PRE_DEINSTALL', '+POST_DEINSTALL', 'pkg-descr']:
            self.assertIn('packaging/freebsd/' + hook, required)

    def test_the_repository_suites_and_ci_know_the_plugin(self):
        runner = (REPOSITORY / 'tests/run.py').read_text()
        self.assertIn("'src/os-wanguard/tests/native/test-newwanip.php'", runner)
        self.assertIn("'src/os-wanguard/tests/native/test-model.php'", runner)
        self.assertIn("'src/os-wanguard/tests/native/test-core-contract.php'", runner)
        packages = (REPOSITORY / 'tests/test_plugin_packages.py').read_text()
        self.assertIn("'os-wanguard': {", packages)
        self.assertIn("'os-wanguard': ('Wanguard', 'wanguard')", (REPOSITORY / 'tests/test_mvc_migration.py').read_text())
        ci = (REPOSITORY / '.github/workflows/ci.yml').read_text()
        self.assertRegex(ci, r'for plugin in [^\n]* wanguard;')
        self.assertIn('sh -n src/os-wanguard/src/usr/local/etc/rc.d/wanguard', ci)


if __name__ == '__main__':
    unittest.main()
