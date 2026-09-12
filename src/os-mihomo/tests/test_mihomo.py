"""Exercise subscription failures and routing transitions without changing the host."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'src/usr/local/opnsense/scripts/mihomo/mihomo.py'
spec = importlib.util.spec_from_file_location('mihomo', SCRIPT)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

SUBSCRIPTION = b'''proxy-groups:
- name: Proxy
  type: select
  proxies: ["\\U0001F1F9\\U0001F1FC Taiwan", ON]
proxies:
- {name: "\\U0001F1F9\\U0001F1FC Taiwan", type: socks5, server: example.invalid, port: 1080}
- {type: socks5, password: "x, name: INJECTED", name: ON, server: example.invalid, port: 1080}
rules: ["MATCH,Proxy"]
dns: {enable: true, listen: ':53', enhanced-mode: fake-ip, fake-ip-range: 198.18.0.1/16}
'''


class FakeSystem:
    def __init__(self):
        self.alive = False
        self.forwarded = False
        self.events = []
        self.fail_start = 0
        self.reject = False

    def running(self): return self.alive
    def validate(self, candidate):
        self.events.append('validate')
        if self.reject:
            raise m.Error('Rejected test config.')
    def start(self, config, transparent):
        self.events.append('start-transparent' if transparent else 'start-proxy')
        if self.fail_start:
            self.fail_start -= 1
            raise m.Error('Injected startup failure.')
        self.alive = True
    def stop(self):
        self.events.append('stop')
        self.alive = False
    def dns(self, enabled, settings):
        self.events.append('dns-on' if enabled else 'dns-off')
        self.forwarded = enabled
    def watch(self): pass
    def stop_watch(self): pass
    def destroy_tun(self): self.events.append('destroy-tun')
    def remove(self): self.events.append('remove-owned-integration')


class StateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.system = FakeSystem()
        self.manager = m.Manager(Path(self.temp.name), self.system)
        self.manager.initialize()
        self.manager.dispatch('start')

    def snapshot(self):
        return {p.name: p.read_bytes() for p in self.manager.state.iterdir() if p.is_file()}

    def test_fresh_install_is_proxy_only_and_cannot_enable_without_subscription(self):
        self.assertTrue(self.system.alive)
        self.assertFalse(self.system.forwarded)
        config = m.parse_yaml(self.manager.config_file.read_bytes())
        self.assertFalse(config['tun']['enable'])
        self.assertFalse(config['dns']['enable'])
        self.assertEqual([], config['tun']['dns-hijack'])
        self.assertNotIn('dns-on', self.system.events)
        with self.assertRaises(m.Error): self.manager.dispatch('enable-transparent')

    def test_provider_semantics_and_secret_survive_refresh_and_upgrade(self):
        secret = self.manager.settings()['secret']
        self.manager.apply(SUBSCRIPTION)
        self.manager.dispatch('enable-transparent')
        original = m.parse_yaml(SUBSCRIPTION)
        config = m.parse_yaml(self.manager.config_file.read_bytes())
        for key in ['proxies', 'proxy-groups', 'rules']:
            self.assertEqual(original[key], config[key])
        self.assertEqual('ON', config['proxies'][1]['name'])
        self.assertEqual(config['proxies'][0]['name'], config['proxy-groups'][0]['proxies'][0])
        self.assertTrue(self.system.forwarded)
        self.manager.apply(SUBSCRIPTION)
        self.manager.dispatch('suspend')
        self.manager.initialize(upgrade=True)
        self.manager.dispatch('boot')
        self.assertTrue(self.system.forwarded)
        self.assertEqual(secret, self.manager.settings()['secret'])
        self.assertEqual(secret, m.parse_yaml(self.manager.config_file.read_bytes())['secret'])

    def test_rejected_subscription_never_changes_live_files_or_restarts(self):
        self.manager.apply(SUBSCRIPTION)
        before = self.snapshot()
        events = list(self.system.events)
        for bad in [b'<html>SECRET</html>', b'proxy-groups: [{proxies: [x]}]\nrules: [MATCH,DIRECT]',
                    SUBSCRIPTION + b'dns: {listen: 53}\n']:
            with self.assertRaises(m.Error): self.manager.apply(bad)
            self.assertEqual(before, self.snapshot())
            self.assertEqual(events, self.system.events)
        self.system.reject = True
        with self.assertRaises(m.Error): self.manager.apply(SUBSCRIPTION)
        self.assertEqual(before, self.snapshot())
        self.assertTrue(self.system.alive)

    def test_restart_failure_restores_active_config_source_and_secret(self):
        self.manager.apply(SUBSCRIPTION)
        self.manager.dispatch('enable-transparent')
        before = self.snapshot()
        settings = self.manager.settings()
        settings['secret'] = 'replacement-secret'
        self.system.fail_start = 1
        with self.assertRaises(m.Error): self.manager.apply(SUBSCRIPTION, settings)
        self.assertEqual(before, self.snapshot())
        self.assertTrue(self.system.alive)
        self.assertTrue(self.system.forwarded)

    def test_failed_rollback_keeps_direct_dns_and_original_files(self):
        self.manager.apply(SUBSCRIPTION)
        self.manager.dispatch('enable-transparent')
        before = self.snapshot()
        self.system.fail_start = 2
        with self.assertRaises(m.Error): self.manager.apply(SUBSCRIPTION)
        self.assertEqual(before, self.snapshot())
        self.assertFalse(self.system.alive)
        self.assertFalse(self.system.forwarded)
        self.assertIn('Direct DNS', json.loads(self.manager.status_file.read_bytes())['error'])

    def test_dns_is_restored_before_core_stop_and_wan_does_not_revive_stop(self):
        self.manager.apply(SUBSCRIPTION)
        self.manager.dispatch('enable-transparent')
        self.system.events.clear()
        self.manager.dispatch('stop')
        self.assertLess(self.system.events.index('dns-off'), self.system.events.index('stop'))
        self.manager.dispatch('wan-restart')
        self.manager.dispatch('boot')
        self.assertFalse(self.system.alive)

    def test_crash_fallback_is_per_router_and_keeps_opt_in(self):
        self.manager.apply(SUBSCRIPTION)
        self.manager.dispatch('enable-transparent')
        self.system.alive = False
        status = self.manager.watchdog_tick()
        self.assertFalse(status['dns_active'])
        self.assertFalse(self.system.forwarded)
        self.assertTrue(self.manager.settings()['transparent'])
        self.manager.dispatch('start')
        settings = self.manager.settings()
        settings['dns_fallback'] = False
        self.manager.write_settings(settings)
        self.system.alive = False
        self.assertTrue(self.manager.watchdog_tick()['dns_active'])
        self.assertTrue(self.system.forwarded)

    def test_settings_on_fresh_proxy_restart_with_same_transaction(self):
        payload = self.manager.state / 'request.json'
        payload.write_text(json.dumps({'secret': 'new-secret'}))
        self.manager.dispatch('set-settings', str(payload))
        self.assertEqual('new-secret', m.parse_yaml(self.manager.config_file.read_bytes())['secret'])
        self.assertIn('stop', self.system.events)
        self.assertFalse(self.manager.source_file.exists())

    def test_invalid_fake_ip_range_does_not_enable_transparency(self):
        self.manager.apply(SUBSCRIPTION.replace(b'198.18.0.1/16', b'28.0.0.1/8'))
        before = self.snapshot()
        with self.assertRaises(m.Error): self.manager.dispatch('enable-transparent')
        self.assertEqual(before, self.snapshot())
        self.assertFalse(self.system.forwarded)

    def test_log_failure_does_not_block_an_operation(self):
        path = self.manager.path('/var/log/mihomo_sub.log')
        path.mkdir(parents=True)
        self.manager.log('Safe diagnostic.')
        self.manager.apply(SUBSCRIPTION)
        self.assertTrue(self.system.alive)


class RecoveryTests(unittest.TestCase):
    setUp = StateTests.setUp
    snapshot = StateTests.snapshot

    def test_cleanup_failure_cannot_prevent_file_and_secret_rollback(self):
        self.manager.apply(SUBSCRIPTION)
        self.manager.dispatch('enable-transparent')
        before = self.snapshot()
        original_start = self.system.start
        original_dns = self.system.dns
        fail = {'cleanup': False}
        def start(config, transparent):
            if self.system.fail_start:
                fail['cleanup'] = True
            return original_start(config, transparent)
        def dns(enabled, settings):
            if not enabled and fail['cleanup']:
                fail['cleanup'] = False
                raise m.Error('Injected cleanup failure.')
            return original_dns(enabled, settings)
        self.system.start = start
        self.system.dns = dns
        self.system.fail_start = 1
        settings = self.manager.settings()
        settings['secret'] = 'should-not-survive-rollback'
        with self.assertRaises(m.Error): self.manager.apply(SUBSCRIPTION, settings)
        self.assertEqual(before, self.snapshot())
        self.assertTrue(self.system.alive)
        self.assertTrue(self.system.forwarded)


class ConcurrentUpdateTests(unittest.TestCase):
    setUp = StateTests.setUp
    def test_watchdog_can_recover_while_download_waits_and_latest_secret_is_used(self):
        from unittest.mock import patch
        self.manager.apply(SUBSCRIPTION)
        self.manager.dispatch('enable-transparent')
        def fetch(*args):
            with self.manager.lock(blocking=False):
                self.system.alive = False
                self.manager.watchdog_tick()
                settings = self.manager.settings()
                settings['secret'] = 'secret-changed-during-download'
                self.manager.write_settings(settings)
            return SUBSCRIPTION
        with patch.object(m, 'fetch_subscription', fetch):
            self.manager.update()
        self.assertFalse(self.system.forwarded)
        self.assertEqual('secret-changed-during-download', self.manager.settings()['secret'])
        self.assertEqual('secret-changed-during-download', m.parse_yaml(self.manager.config_file.read_bytes())['secret'])

    def test_changed_url_discards_old_download(self):
        from unittest.mock import patch
        before = self.manager.config_file.read_bytes()
        def fetch(*args):
            with self.manager.lock(blocking=False):
                settings = self.manager.settings()
                settings['subscription_url'] = 'https://example.invalid/new-subscription'
                self.manager.write_settings(settings)
            return SUBSCRIPTION
        with patch.object(m, 'fetch_subscription', fetch):
            with self.assertRaises(m.Error): self.manager.update()
        self.assertEqual(before, self.manager.config_file.read_bytes())


class FetchTests(unittest.TestCase):
    def request(self, results, proxy='127.0.0.1:7891'):
        calls = []
        def run(args, **kwargs):
            calls.append(args)
            self.assertNotIn('PRIVATE_TOKEN', ' '.join(args))
            config = Path(args[args.index('--config') + 1])
            self.assertEqual(0o600, config.stat().st_mode & 0o777)
            self.assertIn('PRIVATE_TOKEN', config.read_text())
            result = results.pop(0)
            if result == (0, '200'):
                Path(args[args.index('--output') + 1]).write_bytes(SUBSCRIPTION)
            return subprocess.CompletedProcess(args, result[0], result[1].encode(), b'PRIVATE_TOKEN')
        return calls, lambda: m.fetch_subscription('https://example.invalid/sub/PRIVATE_TOKEN', 'OPNsense-Mihomo/1 (test)',
                                                    proxy, run=run, sleep=lambda _: None)

    def test_all_4xx_stop_after_one_request_without_fallback(self):
        for code in ['400', '401', '403', '404', '408', '429']:
            calls, fetch = self.request([(0, code)])
            with self.assertRaises(m.Error) as raised: fetch()
            self.assertEqual(1, len(calls))
            self.assertNotIn('PRIVATE_TOKEN', str(raised.exception))

    def test_timeout_and_5xx_allow_bounded_retries_then_proxy(self):
        calls, fetch = self.request([(28, '000'), (0, '503'), (0, '200')])
        self.assertEqual(SUBSCRIPTION, fetch())
        self.assertEqual(3, len(calls))
        self.assertNotIn('--socks5-hostname', calls[0])
        self.assertIn('--socks5-hostname', calls[2])

    def test_nonretryable_tls_or_dns_failures_are_not_repeated(self):
        for error in [6, 7, 35, 60]:
            calls, fetch = self.request([(error, '000')])
            with self.assertRaises(m.Error): fetch()
            self.assertEqual(1, len(calls))

    def test_four_requests_are_the_upper_bound(self):
        calls, fetch = self.request([(0, '503')] * 4)
        with self.assertRaises(m.Error): fetch()
        self.assertEqual(4, len(calls))


class YamlTests(unittest.TestCase):
    def test_alias_merge_is_valid_and_duplicate_explicit_keys_are_rejected(self):
        data = m.parse_yaml(b'default: &d {enabled: true, label: ON}\ncopy: {<<: *d, enabled: false}')
        self.assertEqual({'enabled': False, 'label': 'ON'}, data['copy'])
        with self.assertRaises(m.Error): m.parse_yaml(b'dns: {}\ndns: {}')
        with self.assertRaises(m.Error): m.parse_yaml(b'loop: &x {nested: *x}')



class IntegrationHelperTests(unittest.TestCase):
    def setUp(self):
        import shutil
        self.php = shutil.which('php')
        if not self.php:
            self.skipTest('PHP is verified separately on FreeBSD.')
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = self.root / 'conf/config.xml'
        self.config.parent.mkdir()
        self.config.write_text('''<opnsense><interfaces><lan><if>em1</if></lan></interfaces><filter/>
<OPNsense><unboundplus><forwarding><enabled>1</enabled></forwarding>
<advanced><privateaddress>10.0.0.0/8,198.18.0.0/15</privateaddress></advanced>
<dots><dot uuid="owner-dot"><enabled>1</enabled><type>dot</type><domain/><server>1.1.1.1</server><port>853</port></dot>
<dot uuid="private-dot"><enabled>1</enabled><type>forward</type><domain>home.test</domain><server>192.0.2.1</server><port>53</port></dot></dots>
</unboundplus></OPNsense></opnsense>''')
        self.original = self.xml()
        self.dot = self.root / 'var/unbound/etc/dot.conf'
        self.dot.parent.mkdir(parents=True)
        self.dot.write_text('OWNER DNS OVER TLS CONFIGURATION')

    def xml(self):
        import xml.etree.ElementTree as ET
        return ET.canonicalize(self.config.read_text(), strip_text=True)

    def helper(self, action, fallback='1'):
        return subprocess.run([self.php, str(SCRIPT.with_name('setup_unbound.php')), action, fallback],
                              env=dict(os.environ, OS_MIHOMO_ROOT=str(self.root)), capture_output=True, text=True)

    def test_enable_disable_remove_restores_owner_dot_and_only_removes_owned_interface(self):
        import xml.etree.ElementTree as ET
        self.assertEqual(0, self.helper('enable').returncode)
        root = ET.parse(self.config).getroot()
        self.assertEqual('0', root.findtext('./OPNsense/unboundplus/dots/dot[@uuid="owner-dot"]/enabled'))
        self.assertEqual('1', root.findtext('./OPNsense/unboundplus/dots/dot[@uuid="private-dot"]/enabled'))
        own = root.find('./OPNsense/unboundplus/dots/dot[@uuid="b126bf65-a985-49ca-a9d2-16f156aac198"]')
        self.assertEqual('1', own.findtext('forward_first'))
        self.assertEqual(0, self.helper('enable').returncode)
        root = ET.parse(self.config).getroot()
        self.assertEqual(1, len(root.findall('./filter/rule')))
        self.assertEqual(0, self.helper('disable').returncode)
        self.assertEqual('1', ET.parse(self.config).getroot().findtext('./OPNsense/unboundplus/dots/dot[@uuid="owner-dot"]/enabled'))
        self.assertEqual(0, self.helper('remove').returncode)
        self.assertEqual(self.original, self.xml())
        self.assertEqual('OWNER DNS OVER TLS CONFIGURATION', self.dot.read_text())
        self.assertEqual(0, self.helper('remove').returncode)
        self.assertEqual(self.original, self.xml())

    def test_disable_preserves_dns_entries_added_by_owner_while_enabled(self):
        import xml.etree.ElementTree as ET
        self.assertEqual(0, self.helper('enable', '0').returncode)
        root = ET.parse(self.config).getroot()
        dots = root.find('./OPNsense/unboundplus/dots')
        extra = ET.SubElement(dots, 'dot', uuid='new-owner-dot')
        ET.SubElement(extra, 'enabled').text = '1'
        ET.SubElement(extra, 'domain').text = 'example.test'
        ET.SubElement(extra, 'server').text = '192.0.2.2'
        ET.ElementTree(root).write(self.config)
        self.assertEqual(0, self.helper('disable').returncode)
        root = ET.parse(self.config).getroot()
        self.assertIsNotNone(root.find('./OPNsense/unboundplus/dots/dot[@uuid="new-owner-dot"]'))

    def test_state_saved_before_failed_xml_commit_is_reconciled_next_enable(self):
        import xml.etree.ElementTree as ET
        state = self.root / 'var/db/os-mihomo'
        state.mkdir(parents=True)
        (state / 'tun-state.json').write_text(json.dumps({'interface': 'opt0', 'created_interface': True, 'created_rule': True}))
        self.assertEqual(0, self.helper('enable').returncode)
        root = ET.parse(self.config).getroot()
        self.assertEqual('tun_mihomo', root.findtext('./interfaces/opt0/if'))
        self.assertEqual(1, len(root.findall('./filter/rule')))


class CronMigrationTests(unittest.TestCase):
    setUp = IntegrationHelperTests.setUp
    xml = IntegrationHelperTests.xml
    helper = IntegrationHelperTests.helper
    def test_restore_cron_is_idempotent_and_does_not_touch_dns(self):
        state = self.root / 'var/db/os-mihomo/migrate'
        state.mkdir(parents=True)
        legacy = self.config.read_text().replace('</opnsense>', '<cron><item><command>mihomolocal repair</command><minutes>30</minutes><hours>*/12</hours></item></cron></opnsense>')
        (state / 'config.xml').write_text(legacy)
        self.assertEqual(0, self.helper('restore-cron').returncode)
        first = self.xml()
        self.assertEqual(0, self.helper('restore-cron').returncode)
        self.assertEqual(first, self.xml())
        import xml.etree.ElementTree as ET
        root = ET.parse(self.config).getroot()
        self.assertEqual('mihomo sub-update', root.findtext('./cron/item/command'))
        self.assertEqual('1', root.findtext('./OPNsense/unboundplus/dots/dot[@uuid="owner-dot"]/enabled'))

    def test_uninstall_removes_only_mihomo_cron(self):
        self.config.write_text(self.config.read_text().replace('</opnsense>', '<cron><item><command>mihomo sub-update</command></item><item><command>cert renew</command></item></cron></opnsense>'))
        self.assertEqual(0, self.helper('remove').returncode)
        import xml.etree.ElementTree as ET
        root = ET.parse(self.config).getroot()
        self.assertEqual(['cert renew'], [node.text for node in root.findall('./cron/item/command')])


if __name__ == '__main__': unittest.main()
