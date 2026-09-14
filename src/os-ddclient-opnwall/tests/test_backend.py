"""Exercise the native DDNS backend without DNS queries or provider connections."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

PACKAGE = Path(__file__).resolve().parents[1]
LIBRARY = PACKAGE / 'src/usr/local/opnsense/scripts/ddclient/lib'
spec = importlib.util.spec_from_file_location('ddclient_test_lib', LIBRARY / '__init__.py',
                                            submodule_search_locations=[str(LIBRARY)])
library = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = library
spec.loader.exec_module(library)
from ddclient_test_lib import address, poller
from ddclient_test_lib.account import BaseAccount
from ddclient_test_lib.account.aliyun import Aliyun
from ddclient_test_lib.account.dnspod_cn import DNSPod_CN
from ddclient_test_lib.account.dyndns2 import DynDNS2
from ddclient_test_lib.account.cloudflare import Cloudflare


def account(service='custom', **changes):
    return {'id': 'fixture-account', 'service': service, 'description': 'isolated fixture',
            'username': 'fixture-user', 'password': 'SENTINEL_PRIVATE_CREDENTIAL',
            'hostnames': 'router.example.invalid', 'zone': 'example.invalid',
            'checkip': 'if', 'checkip_timeout': 10, 'force_ssl': True, 'ttl': '300', **changes}


class BackendTests(unittest.TestCase):
    def setUp(self):
        # Any HTTP request not explicitly stood in for is a test failure.
        guard = patch('requests.sessions.Session.request', side_effect=AssertionError('Unexpected network request.'))
        guard.start()
        self.addCleanup(guard.stop)
        log = patch('syslog.syslog')
        self.log = log.start()
        self.addCleanup(log.stop)

    def test_factory_selects_community_providers_and_unknown_services_are_not_guessed(self):
        factory = library.AccountFactory()
        for service, handler in [('aliyun', Aliyun), ('tencentcloud', DNSPod_CN),
                                 ('dnspodcn', DNSPod_CN), ('custom', DynDNS2), ('cloudflare', Cloudflare)]:
            with self.subTest(service=service):
                self.assertIsInstance(factory.get(account(service)), handler)
                self.assertIn(service, factory.known_services())
        self.assertIsNone(factory.get(account('nonexistent-provider')))

    def test_account_updates_only_for_address_or_credential_changes(self):
        first = BaseAccount(account())
        with patch('ddclient_test_lib.account.checkip', return_value='8.8.8.8'):
            self.assertTrue(first.execute())
            first.update_state('8.8.8.8')
            self.assertFalse(first.execute())
            same = BaseAccount(account(description='changed caption', checkip='web_ipify-ipv4'))
            same.state = copy.deepcopy(first.state)
            self.assertFalse(same.execute())
            changed = BaseAccount(account(password='SENTINEL_CHANGED_CREDENTIAL'))
            changed.state = copy.deepcopy(first.state)
            self.assertTrue(changed.execute())
        self.assertNotIn('SENTINEL_', str(first.state))

    def test_failed_address_detection_keeps_last_successful_state(self):
        handler = BaseAccount(account())
        handler.update_state('8.8.8.8')
        before = copy.deepcopy(handler.state)
        with patch('ddclient_test_lib.account.checkip', return_value=''):
            self.assertFalse(handler.execute())
        self.assertEqual(handler.state, before)

    def test_custom_request_substitution_and_authentication_follow_the_config(self):
        handler = DynDNS2(account(protocol='post', server='https://provider.invalid/__HOSTNAME__?ip=__MYIP__'))
        response = Mock(status_code=200, text='good 8.8.8.8')
        with patch('ddclient_test_lib.account.checkip', return_value='8.8.8.8'), \
             patch('ddclient_test_lib.account.dyndns2.requests.request', return_value=response) as request:
            self.assertTrue(handler.execute())
        parameters = request.call_args.kwargs
        self.assertEqual(parameters['method'], 'post')
        self.assertEqual(parameters['url'], 'https://provider.invalid/router.example.invalid?ip=8.8.8.8')
        self.assertEqual(parameters['auth'].password, 'SENTINEL_PRIVATE_CREDENTIAL')
        self.assertEqual(handler.state['status'], 'good')
        self.assertNotIn('SENTINEL_', json.dumps(handler.state))

    def test_provider_http_failure_does_not_replace_successful_ip_or_timestamp(self):
        handler = DynDNS2(account('dyndns2'))
        handler.update_state('8.8.4.4')
        before = copy.deepcopy(handler.state)
        with patch('ddclient_test_lib.account.checkip', return_value='8.8.8.8'), \
             patch('ddclient_test_lib.account.dyndns2.requests.get', return_value=Mock(status_code=503, text='unavailable')):
            self.assertFalse(handler.execute())
        self.assertEqual(handler.state, before)

    def test_aliyun_updates_matching_record_and_creates_a_missing_record(self):
        handler = Aliyun(account('aliyun', hostnames='example.invalid,router.example.invalid'))
        replies = [
            {'DomainRecords': {'Record': [{'RR': '@', 'Type': 'A', 'RecordId': 'existing'}]}},
            {'RecordId': 'existing'}, {'DomainRecords': {'Record': []}}, {'RecordId': 'created'}]
        with patch('ddclient_test_lib.account.checkip', return_value='8.8.8.8'), \
             patch.object(handler, 'request', side_effect=replies) as request:
            self.assertTrue(handler.execute())
        calls = request.call_args_list
        self.assertEqual(calls[1].args[0], 'UpdateDomainRecord')
        self.assertEqual(calls[1].args[1]['RR'], '@')
        self.assertEqual(calls[1].args[1]['RecordId'], 'existing')
        self.assertEqual(calls[3].args[0], 'AddDomainRecord')
        self.assertEqual(calls[3].args[1]['RR'], 'router')
        self.assertEqual(calls[3].args[1]['DomainName'], 'example.invalid')
        self.assertEqual(handler.state['ip'], '8.8.8.8')

    def test_aliyun_signed_transport_preserves_unicode_and_reserved_characters(self):
        handler = Aliyun(account('aliyun', password='fixture-secret'))
        response = Mock(json=Mock(return_value={'RecordId': 'fixture-record'}))
        with patch('ddclient_test_lib.account.aliyun.time.strftime', return_value='2026-01-01T00:00:00Z'), \
             patch('ddclient_test_lib.account.aliyun.uuid.uuid4', return_value='fixture-nonce'), \
             patch('ddclient_test_lib.account.aliyun.requests.get', return_value=response) as request:
            self.assertEqual(handler.request('AddDomainRecord', {'DomainName': 'example.invalid',
                'RR': '路由 +/~', 'Type': 'A', 'Value': '8.8.8.8'}), {'RecordId': 'fixture-record'})
        parameters = request.call_args.kwargs
        self.assertEqual(request.call_args.args[0], 'https://alidns.aliyuncs.com/')
        self.assertEqual(parameters['params']['RR'], '路由 +/~')
        # Fixed-clock golden vectors catch escaping and signing regressions.
        self.assertEqual(parameters['params']['Signature'], '4X5PpKLzhn9ox7Hy4EBZ0AIg8Ms=')
        self.assertEqual(parameters['timeout'], 10)

    def test_tencent_signed_transport_uses_exact_transmitted_payload_and_scope(self):
        handler = DNSPod_CN(account('tencentcloud', password='fixture-secret'))
        response = Mock()
        payload = {'Domain': 'example.invalid', 'SubDomain': '路由 +/~',
                   'RecordType': 'A', 'Value': '8.8.8.8'}
        with patch('ddclient_test_lib.account.dnspod_cn.time.time', return_value=1767225600), \
             patch('ddclient_test_lib.account.dnspod_cn.requests.post', return_value=response) as request:
            self.assertIs(handler.send_request('CreateRecord', payload, region='fixture-region',
                                              token='fixture-token'), response)
        parameters = request.call_args.kwargs
        self.assertEqual(parameters['url'], 'https://dnspod.tencentcloudapi.com')
        self.assertEqual(parameters['data'], json.dumps(payload))
        self.assertEqual(parameters['headers']['Authorization'],
            'TC3-HMAC-SHA256 Credential=fixture-user/2026-01-01/dnspod/tc3_request, '
            'SignedHeaders=content-type;host;x-tc-action, '
            'Signature=2617444015e861534cfcc503dfec764b1125e836a0f55cec8a56d6a9cf7a8e42')
        self.assertEqual(parameters['headers']['X-TC-Region'], 'fixture-region')
        self.assertEqual(parameters['headers']['X-TC-Token'], 'fixture-token')
        self.assertEqual(parameters['headers']['X-TC-Timestamp'], '1767225600')
        self.assertEqual(parameters['timeout'], 10)

    def test_tencent_ipv6_record_line_and_ttl_floor_survive_create_and_modify(self):
        handler = DNSPod_CN(account('tencentcloud', hostnames='example.invalid,router.example.invalid', ttl='60'))
        replies = [{'Response': {'RecordList': []}}, {'Response': {'RecordId': 1}},
                   {'Response': {'RecordList': [{'Name': 'router', 'Type': 'AAAA', 'RecordId': 2, 'Line': 'existing-line'}]}},
                   {'Response': {'RecordId': 2}}]
        with patch('ddclient_test_lib.account.checkip', return_value='2606:4700:4700::1111'), \
             patch.object(handler, 'json_request', side_effect=replies) as request:
            self.assertTrue(handler.execute())
        first, second = request.call_args_list[1], request.call_args_list[3]
        self.assertEqual(first.kwargs['action'], 'CreateRecord')
        self.assertEqual(first.kwargs['payload']['SubDomain'], '@')
        self.assertEqual(first.kwargs['payload']['TTL'], 600)
        self.assertEqual(second.kwargs['action'], 'ModifyRecord')
        self.assertEqual(second.kwargs['payload']['RecordId'], 2)
        self.assertEqual(second.kwargs['payload']['RecordLine'], 'existing-line')
        self.assertEqual(second.kwargs['payload']['RecordType'], 'AAAA')

    def test_tencent_missing_record_error_means_create_but_other_errors_do_not(self):
        handler = DNSPod_CN(account('tencentcloud'))
        for code, expected in [('ResourceNotFound.NoDataOfRecord', {'Response': {'RecordList': []}}),
                               ('AuthFailure.SignatureFailure', None)]:
            with self.subTest(code=code), patch.object(handler, 'send_request', return_value=Mock(
                    json=Mock(return_value={'Response': {'Error': {'Code': code, 'Message': 'unavailable'}}}))):
                self.assertEqual(handler.json_request('DescribeRecordList', {}), expected)

    def test_tencent_partial_failure_does_not_mark_all_hostnames_updated(self):
        handler = DNSPod_CN(account('tencentcloud', hostnames='one.example.invalid,two.example.invalid'))
        with patch('ddclient_test_lib.account.checkip', return_value='8.8.8.8'), \
             patch.object(handler, 'json_request', side_effect=[{'Response': {'RecordList': []}},
                       {'Response': {'RecordId': 1}}, None]):
            self.assertFalse(handler.execute())
        self.assertEqual(handler.state, {})

    def test_cloudflare_bearer_authentication_updates_all_hosts_before_committing_state(self):
        handler = Cloudflare(account('cloudflare', hostnames='one.example.invalid,two.example.invalid'))
        responses = [Mock(json=Mock(return_value={'success': True, 'result': [{'id': 'zone'}]})),
                     Mock(json=Mock(return_value={'success': True, 'result': [{'id': 'one'}]})),
                     Mock(json=Mock(return_value={'success': True, 'result': [{'id': 'two'}]}))]
        with patch('ddclient_test_lib.account.checkip', return_value='8.8.8.8'), \
             patch('ddclient_test_lib.account.cloudflare.requests.get', side_effect=responses) as get, \
             patch('ddclient_test_lib.account.cloudflare.requests.patch', side_effect=[
                 Mock(json=Mock(return_value={'success': True, 'result': {'content': '8.8.8.8'}})),
                 Mock(json=Mock(return_value={'success': False, 'errors': []})),]) as update:
            self.assertFalse(handler.execute())
        self.assertEqual(handler.state, {})
        self.assertEqual(update.call_count, 2)
        self.assertEqual(get.call_args_list[0].kwargs['headers']['Authorization'], 'Bearer SENTINEL_PRIVATE_CREDENTIAL')


class AddressTests(unittest.TestCase):
    def test_extraction_skips_server_address_and_rejects_invalid_candidates(self):
        self.assertEqual(address.extract_address('1.1.1.1', 'server 1.1.1.1 invalid 999.1.2.3 ip=8.8.8.8'), '8.8.8.8')
        self.assertEqual(address.extract_address(None, 'ip=2606:4700:4700::1111'), '2606:4700:4700::1111')
        self.assertEqual(address.extract_address(None, 'no address'), '')

    def test_ipv6_interface_identifier_preserves_prefix(self):
        self.assertEqual(str(address.transform_ip('2001:4860:1:2::abcd', '::1000')), '2001:4860:1:2::1000')
        self.assertEqual(str(address.transform_ip('8.8.8.8', '::1000')), '8.8.8.8')
        with self.assertRaises(ValueError):
            address.transform_ip('not-an-address')

    def test_interface_check_uses_only_global_address_of_selected_family(self):
        output = '\tinet 192.168.1.2 netmask 0xffffff00\n\tinet 8.8.8.8 netmask 0xffffff00\n' \
                 '\tinet6 fe80::1%em0 prefixlen 64\n\tinet6 2606:4700:4700::1111 prefixlen 64\n'
        with patch.object(address.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, stdout=output)) as run:
            self.assertEqual(address.checkip('if', interface='em0'), '8.8.8.8')
            self.assertEqual(address.checkip('if6', interface='em0'), '2606:4700:4700::1111')
            self.assertEqual(run.call_args.args[0], ['/sbin/ifconfig', 'em0'])

    def test_web_check_binds_interface_and_applies_timeout_without_a_shell(self):
        with patch.object(address.subprocess, 'run', return_value=Mock(stdout='ip=8.8.8.8')) as run:
            self.assertEqual(address.checkip('web_cloudflare-ipv4', timeout='17', interface='em0'), '8.8.8.8')
        self.assertEqual(run.call_args.args[0], ['/usr/local/bin/curl', '-m', '17', '--interface', 'em0',
                                               'https://1.1.1.1/cdn-cgi/trace'])
        self.assertNotIn('shell', run.call_args.kwargs)


class PollerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='ddclient-poller-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def create(self, state=None):
        config, status = self.root / 'config.json', self.root / 'status.json'
        config.write_text(json.dumps({'general': {'enabled': True, 'verbose': False, 'daemon_delay': 120},
                                      'accounts': [account('duckdns')]}))
        if state is not None:
            status.write_text(json.dumps(state))
        with patch.object(poller.Poller, 'run'), patch('syslog.openlog'):
            return poller.Poller(config, status)

    def test_startup_restores_only_matching_account_state_and_flush_has_no_credentials(self):
        instance = self.create({'fixture-account': {'ip': '8.8.8.8', 'mtime': 10},
                                'removed-account': {'ip': '8.8.4.4'}})
        self.assertEqual(instance.poll_interval, 120)
        self.assertEqual(instance._accounts['fixture-account'].state['ip'], '8.8.8.8')
        instance.flush_status()
        saved = (self.root / 'status.json').read_text()
        self.assertEqual(set(json.loads(saved)), {'fixture-account'})
        self.assertNotIn('SENTINEL_', saved)

    def test_corrupt_status_keeps_accounts_usable_and_logs_safe_file_error(self):
        instance = self.create()
        (self.root / 'status.json').write_text('{bad json')
        with patch('syslog.syslog') as log:
            instance.startup()
        self.assertEqual(instance._accounts['fixture-account'].state, {})
        self.assertTrue(log.called)

    def test_one_poll_flushes_only_success_and_advances_failed_attempt_time(self):
        instance = self.create()
        handler = instance._accounts['fixture-account']
        handler.execute = Mock(side_effect=RuntimeError('isolated provider failure'))
        with patch('syslog.syslog'), patch.object(instance, 'flush_status') as flush, \
             patch.object(poller.time, 'sleep', side_effect=InterruptedError('end isolated poll')):
            with self.assertRaises(InterruptedError):
                instance.run()
        self.assertFalse(flush.called)
        self.assertGreater(handler.atime, 0)


if __name__ == '__main__':
    unittest.main()
