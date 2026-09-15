"""Render the shipped templates with real Jinja filters and fixture model data."""
import copy
import json
from pathlib import Path
import unittest

from jinja2 import DictLoader, Environment, FileSystemLoader, ChoiceLoader

PACKAGE = Path(__file__).resolve().parents[1]
TEMPLATES = PACKAGE / 'src/usr/local/opnsense/service/templates'


class Helpers:
    def __init__(self, data):
        self.data = data
    def value(self, path):
        value = self.data
        for name in path.split('.'):
            if not isinstance(value, dict) or name not in value:
                return None
            value = value[name]
        return value
    def exists(self, path):
        return self.value(path) is not None
    def empty(self, path):
        return self.value(path) in (None, '', '0', False, [])
    def toList(self, path):
        value = self.value(path)
        return value if isinstance(value, list) else [value] if isinstance(value, dict) else []


class TemplateTests(unittest.TestCase):
    def setUp(self):
        self.environment = Environment(loader=ChoiceLoader([
            FileSystemLoader(str(TEMPLATES)), DictLoader({'OPNsense/Macros/interface.macro':
                '{% macro physical_interface(name) %}physical-{{ name }}{% endmacro %}'})]),
            extensions=['jinja2.ext.do'])
        self.data = {'OPNsense': {'DynDNS': {'general': {'enabled': '1', 'verbose': '0',
                 'allowipv6': '1', 'daemon_delay': '120', 'backend': 'opnsense'},
            'accounts': {'account': [self.account()]}}}}

    def account(self, **changes):
        return {'@uuid': 'fixture-account', 'enabled': '1', 'service': 'aliyun', 'protocol': 'dyndns2',
                'server': '', 'resourceId': '默认', 'username': 'fixture-user',
                'password': 'SENTINEL_"\\&秘密', 'hostnames': 'router.example.invalid',
                'wildcard': '0', 'zone': 'example.invalid', 'checkip': 'if6', 'interface': 'wan',
                'dynipv6host': '::1000', 'checkip_timeout': '10', 'force_ssl': '1', 'ttl': '300',
                'description': 'quoted "caption" / 中文', **changes}

    def render(self, name):
        return self.environment.get_template('OPNsense/ddclient/' + name).render(
            **self.data, helpers=Helpers(self.data))

    def test_native_json_preserves_credentials_and_quoted_unicode_text(self):
        rendered = json.loads(self.render('ddclient.json'))
        expected = self.data['OPNsense']['DynDNS']['accounts']['account'][0]
        self.assertEqual(rendered['accounts'][0]['password'], expected['password'])
        self.assertEqual(rendered['accounts'][0]['resourceId'], expected['resourceId'])
        self.assertEqual(rendered['accounts'][0]['description'], expected['description'])
        self.assertEqual(rendered['accounts'][0]['interface'], 'physical-wan')
        self.assertEqual(rendered['general']['daemon_delay'], 120)
        self.assertTrue(rendered['general']['enabled'])
        self.assertTrue(rendered['general']['allowipv6'])
        self.assertFalse(rendered['general']['verbose'])

    def test_disabled_accounts_and_an_absent_list_emit_valid_json_without_credentials(self):
        account = self.data['OPNsense']['DynDNS']['accounts']['account'][0]
        account['enabled'] = '0'
        rendered = self.render('ddclient.json')
        self.assertEqual(json.loads(rendered)['accounts'], [])
        self.assertNotIn('SENTINEL_', rendered)
        del self.data['OPNsense']['DynDNS']['accounts']
        self.assertEqual(json.loads(self.render('ddclient.json'))['accounts'], [])

    def test_backend_switch_enables_exactly_one_daemon_and_global_disable_enables_neither(self):
        general = self.data['OPNsense']['DynDNS']['general']
        for backend, native, legacy in [('opnsense', 'YES', 'NO'), ('ddclient', 'NO', 'YES')]:
            with self.subTest(backend=backend):
                general['backend'] = backend
                self.assertIn('ddclient_opn_enable="' + native + '"', self.render('ddclient_opn.rc.conf.d'))
                self.assertIn('ddclient_opnwall_perl_enable="' + legacy + '"', self.render('ddclient_opnwall_perl.rc.conf.d'))
                self.assertIn('ddclient_enable="NO"', self.render('rc.conf.d'))
        general['enabled'] = '0'
        self.assertIn('ddclient_opn_enable="NO"', self.render('ddclient_opn.rc.conf.d'))
        self.assertIn('ddclient_enable="NO"', self.render('rc.conf.d'))
        self.assertIn('ddclient_opnwall_perl_enable="NO"', self.render('ddclient_opnwall_perl.rc.conf.d'))

    def test_legacy_backend_ipv6_interface_and_disabled_account_selection(self):
        self.data['OPNsense']['DynDNS']['general']['backend'] = 'ddclient'
        accounts = self.data['OPNsense']['DynDNS']['accounts']['account']
        accounts[0] = self.account(service='tencentcloud', password='SENTINEL_LEGACY_TOKEN')
        accounts.append(self.account(enabled='0', password='SENTINEL_DISABLED_TOKEN'))
        text = self.render('ddclient.conf')
        self.assertIn('usev6=ifv6, ifv6=physical-wan', text)
        self.assertIn('protocol=tencentcloud', text)
        self.assertIn('zone=example.invalid', text)
        self.assertIn('ttl=300', text)
        self.assertIn('password=SENTINEL_LEGACY_TOKEN', text)
        self.assertNotIn('SENTINEL_DISABLED_TOKEN', text)


if __name__ == '__main__':
    unittest.main()
