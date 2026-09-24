"""Restore native Mihomo intent without reviving transparent routing."""
import base64
import copy
import gzip
import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

from test_mihomo import m, FakeSystem, SUBSCRIPTION


class Store:
    def __init__(self):
        self.value, self.writes, self.fail = {}, 0, False
    def __call__(self, action, payload=None):
        if self.fail:
            raise OSError('private provider credential must never be printed')
        if action == 'import':
            return copy.deepcopy(self.value)
        payload = copy.deepcopy(payload)
        expected = payload.pop('_expected', None)
        if expected is not None and expected != hashlib.sha256(json.dumps(self.value, ensure_ascii=True, sort_keys=True, separators=(',', ':')).encode()).hexdigest():
            raise OSError('The stored configuration changed during export')
        changed = payload != self.value
        self.value = copy.deepcopy(payload)
        self.writes += changed
        return {'changed': changed}


class BackupSystem(FakeSystem):
    def restore_integration(self, settings, payload):
        self.events.append('restore-owned-integration')
        self.current_journals = {name: (self.state / name).read_bytes() for name in
                                 ('dns-state.json', 'tun-state.json') if (self.state / name).exists()}
        self.cleaned = {field.replace('_', '-') + '.json': value for field, value in
                        payload['journals'].items() if value is not None}
        self.payload = copy.deepcopy(payload)
        if payload['expected'] != m.Manager._backup_revision(self.store.value):
            raise m.Error('injected concurrent XML restore')
        if getattr(self, 'fail_cleanup', False):
            raise m.Error('injected cleanup failure')
        if payload['repair_checksum']:
            self.store('export', {**self.store.value, 'checksum': payload['repair_checksum'],
                                 '_expected': payload['expected']})
        for name in ('dns-state.json', 'tun-state.json'):
            (self.state / name).unlink(missing_ok=True)


class BackupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='mihomo-backup-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.system, self.store = BackupSystem(), Store()
        self.system.store = self.store
        self.groups = {'Proxy / 中文': {'type': 'Selector', 'all': ['first', 'second'], 'now': 'second'}}
        self.api_calls = []
        self.manager = m.Manager(self.root, self.system, self.store, self.api)
        self.system.state = self.manager.state
        m.atomic_write(self.manager.path('/conf/config.xml'),
                       b'<opnsense><system><uuid>system-A</uuid><hostname>router</hostname><domain>test.invalid</domain></system></opnsense>')
        self.manager.initialize()
    def api(self, method, path, payload=None):
        self.api_calls.append((method, path, payload))
        return {'proxies': copy.deepcopy(self.groups)} if method == 'GET' else {}
    def seed(self):
        self.subscription = SUBSCRIPTION + '# 原始订阅\r\n'.encode()
        self.manager.apply(self.subscription)
        self.merge = b'# exact CRLF overlay\r\nprepend-rules:\r\n- DOMAIN-SUFFIX,private.invalid,DIRECT\r\n'
        m.atomic_write(self.manager.merge_file, self.merge)
        settings = self.manager.settings()
        settings.update(subscription_url='https://provider.invalid/sub?token=private-provider-token',
                        secret='private-control-secret-中文', device='router-A', service_enabled=False,
                        transparent=True, transparent_consent=True, mixed_port=7895,
                        device_mode='whitelist', device_list=['192.0.2.10'], capture_interfaces=['lan', 'opt5'],
                        tcp_redirect=True)
        self.manager.write_settings(settings)
        self.journals = {
            'dns-state.json': b'{"forwarding":"1","roots":{"test-root-uuid":"1"},"had_fake_ip_private_address":true}\r\n',
            'tun-state.json': b'{"interface":"opt9","created_interface":true,"created_rule":true}\r\n'}
        for name, content in self.journals.items():
            m.atomic_write(self.manager.state / name, content)
        self.system.alive = True
        self.manager.proxy_tick()
        self.system.alive = False
        self.assertTrue(self.manager.mirror_backup()['ok'])
    def test_complete_credentials_raw_yaml_disable_and_journals_roundtrip(self):
        self.seed()
        original = copy.deepcopy(self.store.value)
        self.assertNotIn('private-provider-token', str(self.manager.publish_status()))
        shutil.rmtree(self.manager.state)
        result = self.manager.restore_backup()
        self.assertTrue(result['restored'], result)
        self.assertEqual(self.manager.source_file.read_bytes(), self.subscription)
        self.assertEqual(self.manager.merge_file.read_bytes(), self.merge)
        settings = self.manager.settings()
        self.assertEqual(settings['secret'], 'private-control-secret-中文')
        self.assertIn('private-provider-token', settings['subscription_url'])
        self.assertFalse(settings['service_enabled'])
        self.assertFalse(settings['transparent'])
        self.assertFalse(settings['transparent_consent'])
        self.assertEqual(settings['state_schema'], m.STATE_SCHEMA)
        self.assertEqual(settings['switch_schema'], m.SWITCH_SCHEMA)
        self.assertEqual(['lan', 'opt5'], settings['capture_interfaces'])
        self.assertIs(True, settings['tcp_redirect'])
        self.assertEqual(self.system.cleaned, {name: json.loads(raw) for name, raw in self.journals.items()})
        self.assertEqual(json.loads(self.manager.selections_file.read_bytes()), {'Proxy / 中文': 'second'})
        self.assertEqual(self.store.value, original, 'restore overwrote the saved XML before it was applied')
        rendered = m.parse_yaml(self.manager.config_file.read_bytes())
        self.assertFalse(rendered['tun']['enable'])
        self.assertFalse(rendered['dns']['enable'])
        self.assertEqual(rendered['mixed-port'], 7895)
        self.assertNotIn('start-transparent', self.system.events)
    def test_missing_partial_and_future_xml_fields_remain_usable(self):
        before = self.manager.settings_file.read_bytes()
        self.store.value = {}
        self.assertFalse(self.manager.restore_backup()['snapshot'])
        self.assertEqual(self.manager.settings_file.read_bytes(), before)
        self.store.value = {'secret': json.dumps('partial-backup-secret'), 'future_field': 'future exact bytes'}
        self.assertTrue(self.manager.restore_backup()['restored'])
        self.assertEqual(self.manager.settings()['secret'], 'partial-backup-secret')
        # A backup taken before capture interfaces existed means automatic.
        self.assertEqual([], self.manager.settings().get('capture_interfaces', []))
        self.assertFalse(self.manager.settings().get('tcp_redirect', False))
        self.assertTrue(self.manager.mirror_backup()['ok'])
        self.assertEqual(self.store.value['future_field'], 'future exact bytes')
        self.assertEqual(self.store.value['checksum'], self.manager._backup_checksum(self.store.value))
        self.assertFalse(self.manager.restore_backup()['restored'])
        writes = self.store.writes
        self.assertFalse(self.manager.mirror_backup()['changed'])
        self.assertEqual(self.store.writes, writes)
    def test_restore_between_import_and_export_cannot_be_overwritten(self):
        old_marker = self.manager.backup_marker.read_bytes()
        restored = copy.deepcopy(self.store.value)
        restored['secret'] = json.dumps('new-restored-native-secret')
        restored['checksum'] = self.manager._backup_checksum(restored)
        original_transport = self.manager.backup_transport
        def interleave(action, payload=None):
            if action == 'export':
                self.store.value = copy.deepcopy(restored)
            return original_transport(action, payload)
        self.manager.backup_transport = interleave
        self.assertFalse(self.manager.mirror_backup()['ok'])
        self.assertEqual(self.store.value, restored)
        self.assertEqual(self.manager.backup_marker.read_bytes(), old_marker)
        self.assertNotIn('_expected', self.store.value)
    def test_tamper_or_transport_failure_retains_xml_and_current_files_without_secrets(self):
        self.seed()
        self.store.value['checksum'] = '0' * 64
        current = self.manager.settings_file.read_bytes()
        saved = copy.deepcopy(self.store.value)
        with self.assertRaises(m.Error) as caught:
            self.manager.restore_backup()
        self.assertNotIn('private', str(caught.exception))
        self.assertEqual(self.manager.settings_file.read_bytes(), current)
        self.assertEqual(self.store.value, saved)
        self.store.fail = True
        result = self.manager.mirror_backup()
        self.assertFalse(result['ok'])
        self.assertNotIn('credential', result['warning'])
        self.assertTrue(self.manager.publish_status()['backup_warning'])
    def test_pending_restore_blocks_saves_and_watch_mirror_until_reconcile(self):
        old = copy.deepcopy(self.store.value)
        settings = self.manager.settings(); settings['secret'] = 'new-secret'
        self.manager.write_settings(settings)
        self.assertTrue(self.manager.mirror_backup()['changed'])
        self.store.value = old
        before = self.manager.settings_file.read_bytes()
        with self.assertRaises(m.Error):
            self.manager.apply(SUBSCRIPTION)
        self.assertEqual(self.manager.settings_file.read_bytes(), before)
        self.manager.watchdog_tick()
        self.assertEqual(self.store.value, old)
        self.assertTrue(self.manager.restore_backup()['restored'])
    def test_proxy_selections_replay_encoded_names_and_failed_replay_retains_pending(self):
        self.seed()
        self.groups['Proxy / 中文']['now'] = 'first'
        self.system.alive = True
        m.atomic_write(self.manager.replay_file, b'pending\n')
        self.manager.proxy_tick()
        expected_path = '/proxies/Proxy%20%2F%20%E4%B8%AD%E6%96%87'
        self.assertIn(('PUT', expected_path, {'name': 'second'}), self.api_calls)
        self.assertFalse(self.manager.replay_file.exists())
        m.atomic_write(self.manager.replay_file, b'pending\n')
        choices = self.manager.selections_file.read_bytes()
        def fail(method, path, payload=None): raise OSError('private API secret')
        self.manager.proxy_api = fail
        self.manager.proxy_tick()
        self.assertTrue(self.manager.replay_file.exists())
        self.assertEqual(self.manager.selections_file.read_bytes(), choices)
        self.assertTrue(self.manager.publish_status()['backup_warning'])
    def test_local_provider_files_bytes_modes_and_absence_roundtrip(self):
        source = SUBSCRIPTION + b'rule-providers:\n  local: {type: file, behavior: domain, path: custom/rules.yaml}\n  http: {type: http, path: generated/cache.yaml, url: https://provider.invalid/rules}\n'
        path = self.manager.path(m.HOME + '/custom/rules.yaml')
        m.atomic_write(path, b'payload:\n- private-domain.invalid\n', 0o640)
        self.manager.apply(source)
        original = path.read_bytes()
        path.unlink()
        self.assertTrue(self.manager.restore_backup(force=True)['restored'])
        self.assertEqual(path.read_bytes(), original)
        self.assertEqual(path.stat().st_mode & 0o777, 0o640)
        self.assertFalse(self.manager.path(m.HOME + '/generated/cache.yaml').exists())
    def test_local_provider_path_escape_or_missing_snapshot_is_refused(self):
        source = SUBSCRIPTION + b'rule-providers:\n  local: {type: file, behavior: domain, path: /conf/config.xml}\n'
        m.atomic_write(self.manager.source_file, source)
        self.assertFalse(self.manager.mirror_backup()['ok'])
        source = source.replace(b'/conf/config.xml', b'custom/rules.yaml')
        payload = copy.deepcopy(self.store.value)
        payload['subscription_snapshot'] = base64.b64encode(gzip.compress(source, mtime=0)).decode()
        payload.pop('local_files', None)
        payload['checksum'] = self.manager._backup_checksum(payload)
        self.store.value = payload
        with self.assertRaises(m.Error): self.manager.restore_backup()
    def test_cleanup_failure_rolls_back_local_file_modes_and_keeps_xml(self):
        source = SUBSCRIPTION + b'rule-providers:\n  local: {type: file, behavior: domain, path: custom/rules.yaml}\n'
        path = self.manager.path(m.HOME + '/custom/rules.yaml')
        m.atomic_write(path, b'saved local rules', 0o600)
        self.manager.apply(source)
        saved = copy.deepcopy(self.store.value)
        m.atomic_write(path, b'current local rules', 0o644)
        settings = self.manager.settings(); settings['secret'] = 'current-secret'
        self.manager.write_settings(settings)
        self.system.fail_cleanup = True
        with self.assertRaises(m.Error): self.manager.restore_backup(force=True)
        self.assertEqual(path.read_bytes(), b'current local rules')
        self.assertEqual(path.stat().st_mode & 0o777, 0o644)
        self.assertEqual(self.manager.settings()['secret'], 'current-secret')
        self.assertEqual(self.store.value, saved)
    def test_malformed_local_snapshot_and_core_cache_provider_touch_no_live_files(self):
        for document in [[], 1, {'version': 1, 'files': [None]}, {'version': 1, 'files': [{'path': 1}]}]:
            with self.subTest(document=document):
                payload = copy.deepcopy(self.store.value)
                payload['local_files'] = base64.b64encode(gzip.compress(json.dumps(document).encode(), mtime=0)).decode()
                payload['checksum'] = self.manager._backup_checksum(payload)
                self.store.value = payload
                before = self.manager.settings_file.read_bytes(), self.manager.backup_marker.read_bytes()
                with self.assertRaises(m.Error): self.manager.restore_backup(force=True)
                self.assertEqual((self.manager.settings_file.read_bytes(), self.manager.backup_marker.read_bytes()), before)
                self.assertEqual(self.store.value, payload)
        source = SUBSCRIPTION + b'rule-providers:\n  local: {type: file, behavior: domain, path: cache.db}\n'
        m.atomic_write(self.manager.source_file, source)
        self.assertFalse(self.manager.mirror_backup()['ok'])
    def test_derived_status_failure_does_not_misreport_committed_restore(self):
        settings = self.manager.settings(); settings['secret'] = 'external-secret'
        self.manager.write_settings(settings)
        with patch.object(self.manager, 'record_warnings', side_effect=OSError('derived write failed')):
            result = self.manager.restore_backup(force=True)
        self.assertTrue(result['restored'])
        self.assertTrue(result['warning'])
        self.assertEqual(self.manager.backup_marker.read_text().strip(), self.store.value['checksum'])
    def test_existing_outer_cli_and_watch_locks_do_not_deadlock(self):
        manager, original_class = self.manager, m.Manager
        def cli():
            m.Manager = lambda: manager
            sys.argv = ['mihomo.py', '--json', 'mirror-backup']
            with patch.object(m.os, 'geteuid', return_value=0):
                raise SystemExit(m.main())
        process = multiprocessing.get_context('fork').Process(target=cli)
        process.start(); process.join(3)
        if process.is_alive():
            process.kill(); process.join()
            self.fail('CLI dispatch deadlocked under its existing outer manager lock')
        self.assertEqual(process.exitcode, 0)
        with manager.lock():
            self.assertFalse(manager.dispatch('reconcile-backup')['restored'])
            manager.watchdog_tick()
        self.assertIs(m.Manager, original_class)
    def test_restart_stops_old_core_before_restoring_pending_xml_and_uses_proxy_only(self):
        self.seed()
        settings = self.manager.settings(); settings['secret'] = 'new-current-secret'
        self.manager.write_settings(settings)
        saved = copy.deepcopy(self.store.value)
        self.manager.backup_marker.unlink()
        self.system.alive = True
        self.system.events.clear()
        result = self.manager.dispatch('restart')
        self.assertTrue(result['running'])
        self.assertLess(self.system.events.index('stop'), self.system.events.index('restore-owned-integration'))
        self.assertIn('start-proxy', self.system.events)
        self.assertNotIn('start-transparent', self.system.events)
        self.assertEqual(self.manager.settings()['secret'], 'private-control-secret-中文')
        self.assertTrue(self.manager.settings()['service_enabled'], 'explicit restart is the user intent to run')
        self.assertNotEqual(self.store.value['checksum'], saved['checksum'])

    def test_mismatched_or_missing_scope_never_consumes_archived_journals(self):
        for scope in ('', '0' * 64):
            with self.subTest(scope=scope):
                self.seed()
                self.store.value['consent_scope'] = scope
                self.store.value['checksum'] = self.manager._backup_checksum(self.store.value)
                result = self.manager.restore_backup(force=True)
                self.assertTrue(result['restored'])
                self.assertIn('not applied', result['warning'])
                self.assertEqual(self.system.cleaned, {})
                self.assertFalse((self.manager.state / 'tun-state.json').exists())
                self.assertFalse(self.manager.settings()['transparent_consent'])

    def test_archived_journals_do_not_replace_current_ones_before_cleanup(self):
        self.seed()
        current = b'{"interface":"opt20","created_interface":false,"created_rule":false}'
        m.atomic_write(self.manager.state / 'tun-state.json', current)
        self.assertTrue(self.manager.restore_backup(force=True)['restored'])
        self.assertEqual(self.system.current_journals['tun-state.json'], current)
        self.assertEqual(self.system.cleaned['tun-state.json']['interface'], 'opt9')

    def test_core_rejection_and_marker_failure_leave_journals_and_xml_untouched(self):
        self.seed()
        originals = {path.name: path.read_bytes() for path in self.manager.state.iterdir() if path.is_file()}
        saved = copy.deepcopy(self.store.value)
        self.system.reject = True
        with self.assertRaises(m.Error): self.manager.restore_backup(force=True)
        self.assertNotIn('restore-owned-integration', self.system.events)
        self.assertEqual({path.name: path.read_bytes() for path in self.manager.state.iterdir() if path.is_file()}, originals)
        self.system.reject = False
        original_replace = m.os.replace
        def fail_marker(source, destination):
            if destination == self.manager.backup_marker:
                raise OSError('marker failed')
            return original_replace(source, destination)
        with patch.object(m.os, 'replace', side_effect=fail_marker):
            with self.assertRaises(m.Error): self.manager.restore_backup(force=True)
        self.assertNotIn('restore-owned-integration', self.system.events)
        self.assertEqual({path.name: path.read_bytes() for path in self.manager.state.iterdir() if path.is_file()}, originals)
        self.assertEqual(self.store.value, saved)

    def test_xml_restore_during_validation_rolls_back_files_and_journals(self):
        self.seed()
        settings = self.manager.settings(); settings['secret'] = 'new-current-secret'
        self.manager.write_settings(settings)
        originals = self.manager.settings_file.read_bytes(), self.manager.backup_marker.read_bytes()
        restored = copy.deepcopy(self.store.value)
        restored['secret'] = json.dumps('interleaved-system-restore')
        restored['checksum'] = self.manager._backup_checksum(restored)
        original_validate = self.system.validate
        def restore_during_validation(candidate):
            original_validate(candidate)
            self.store.value = restored
        self.system.validate = restore_during_validation
        with self.assertRaises(m.Error): self.manager.restore_backup(force=True)
        self.assertEqual((self.manager.settings_file.read_bytes(), self.manager.backup_marker.read_bytes()), originals)
        self.assertEqual((self.manager.state / 'tun-state.json').read_bytes(), self.journals['tun-state.json'])
        self.assertEqual(self.store.value, restored)

    def test_corrupt_checksum_start_uses_local_configuration_and_retains_saved_backup(self):
        self.manager.apply(SUBSCRIPTION)
        self.store.value['secret'] = json.dumps('edited-native-secret')
        self.store.value['checksum'] = '0' * 64
        saved = copy.deepcopy(self.store.value)
        local_secret = self.manager.settings()['secret']
        result = self.manager.dispatch('start')
        self.assertTrue(result['running'])
        self.assertEqual(self.manager.settings()['secret'], local_secret)
        self.assertEqual(self.store.value, saved)
        self.assertIn('Repair saved backup', self.manager.publish_status()['backup_warning'])
        with self.assertRaises(m.Error): self.manager.apply(SUBSCRIPTION)

    def test_upgrade_reconcile_and_initialization_retain_local_corrupt_mirror(self):
        self.store.value['checksum'] = '0' * 64
        saved = copy.deepcopy(self.store.value)
        secret = self.manager.settings()['secret']
        self.assertIn('warning', self.manager.dispatch('reconcile-backup'))
        self.manager.initialize(upgrade=True)
        self.assertEqual(self.manager.settings()['secret'], secret)
        self.assertEqual(self.store.value, saved)
        self.assertIn('Repair saved backup', self.manager.publish_status()['backup_warning'])

    def test_corrupt_mirror_crash_rescue_preserves_explicit_fail_closed_dns_policy(self):
        self.store.value['checksum'] = '0' * 64
        settings = self.manager.settings(); settings['dns_fallback'] = False
        self.manager.write_settings(settings)
        self.system.forwarded = True
        self.manager.publish_status(dns_active=True)
        self.system.events.clear()
        result = self.manager.watchdog_tick()
        self.assertIn('destroy-tun', self.system.events)
        self.assertNotIn('dns-off', self.system.events)
        self.assertTrue(result['dns_active'])
        m.atomic_write(self.manager.state / 'dns-reload-pending', b'pending\n')
        result = self.manager.watchdog_tick()
        self.assertIn('dns-off', self.system.events)
        self.assertFalse(result['dns_active'])

    def test_repair_validates_saved_content_before_fixing_checksum_and_releases_guard(self):
        self.seed()
        self.store.value['secret'] = json.dumps('edited-native-secret')
        self.store.value['checksum'] = '0' * 64
        result = self.manager.dispatch('repair-backup')
        self.assertTrue(result['restored'])
        self.assertEqual(self.manager.settings()['secret'], 'edited-native-secret')
        self.assertEqual(self.store.value['checksum'], self.manager._backup_checksum(self.store.value))
        self.assertEqual(self.manager.backup_marker.read_text().strip(), self.store.value['checksum'])
        self.assertFalse(self.manager.settings()['transparent'])
        self.assertFalse(self.manager.settings()['transparent_consent'])
        self.assertTrue(self.manager.mirror_backup()['ok'])

    def test_invalid_repair_or_cleanup_failure_keeps_original_bad_checksum_and_files(self):
        self.seed()
        for invalid in (True, False):
            with self.subTest(invalid_content=invalid):
                self.store.value['checksum'] = '0' * 64
                self.store.value['mixed_port'] = '53' if invalid else '7895'
                self.system.fail_cleanup = not invalid
                saved = copy.deepcopy(self.store.value)
                originals = self.manager.settings_file.read_bytes(), self.manager.backup_marker.read_bytes()
                with self.assertRaises(m.Error): self.manager.dispatch('repair-backup')
                self.assertEqual(self.store.value, saved)
                self.assertEqual((self.manager.settings_file.read_bytes(), self.manager.backup_marker.read_bytes()), originals)
                self.assertEqual((self.manager.state / 'tun-state.json').read_bytes(), self.journals['tun-state.json'])

    def test_fresh_corrupt_backup_has_actionable_repair_path(self):
        self.seed()
        self.store.value['checksum'] = '0' * 64
        shutil.rmtree(self.manager.state)
        with self.assertRaises(m.BackupIntegrityError) as caught:
            self.manager.dispatch('boot')
        self.assertIn('Repair saved backup', str(caught.exception))
        self.assertIn('Repair saved backup', self.manager.backup_warning_file.read_text())
        self.assertFalse(self.manager.settings_file.exists(), 'A failed first import must not manufacture defaults')
        self.assertFalse(self.system.running())
        self.assertTrue(self.manager.dispatch('repair-backup')['restored'])

    def test_pending_or_corrupt_backup_does_not_disable_crash_dns_and_tun_rescue(self):
        for corrupt in (False, True):
            with self.subTest(corrupt=corrupt):
                self.manager.apply(SUBSCRIPTION) if not corrupt else None
                if corrupt:
                    self.store.value['checksum'] = '0' * 64
                else:
                    self.manager.backup_marker.unlink()
                saved = copy.deepcopy(self.store.value)
                self.system.alive = False
                self.system.forwarded = True
                self.manager.publish_status(dns_active=True)
                self.system.events.clear()
                status = self.manager.watchdog_tick()
                self.assertIn('destroy-tun', self.system.events)
                self.assertIn('dns-off', self.system.events)
                self.assertFalse(self.system.forwarded)
                self.assertFalse(status['dns_active'])
                self.assertEqual(self.store.value, saved)


if __name__ == '__main__':
    unittest.main()
