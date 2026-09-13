"""Verify restore safety, native merge protocol and external-edit semantics."""
import base64
import copy
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('config_backup', Path(__file__).parents[1] / 'config_backup.py')
engine = importlib.util.module_from_spec(spec)
spec.loader.exec_module(engine)


class NativeStore:
    def __init__(self):
        self.value = {}
        self.saves = 0
    def __call__(self, action, payload=None):
        if action == 'import':
            return copy.deepcopy(self.value)
        payload = copy.deepcopy(payload)
        expected = payload.pop('_expected', None)
        if expected is not None and expected != engine.revision_token(self.value):
            raise engine.BackupError('The native configuration changed before its backup was saved.')
        changed = payload != self.value
        self.value = copy.deepcopy(payload)
        self.saves += changed
        return {'changed': changed}


class BackupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.env = patch.dict(os.environ, {'TEST_CONFIG_ROOT': self.temp.name})
        self.env.start()
        self.store = NativeStore()
        self.profile = {'module': 'Example', 'root_env': 'TEST_CONFIG_ROOT',
                        'trees': ['/usr/local/etc/example'], 'files': ['/etc/rc.conf.d/example'],
                        'excludes': ['*.log']}
        self.backup = engine.ConfigBackup(self.profile, transport=self.store)
    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()
    def write(self, path, value, mode=0o600):
        target = self.root / path.lstrip('/')
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(value)
        target.chmod(mode)
        return target
    def seed(self):
        self.a = self.write('/usr/local/etc/example/a', b'actual-password=private\x00bytes')
        self.b = self.write('/usr/local/etc/example/b', b'private-key\n')
        self.rc = self.write('/etc/rc.conf.d/example', b'example_enable="NO"\n')
        self.assertTrue(self.backup.mirror()['ok'])
    def encode_document(self, document):
        archive = gzip.compress(json.dumps(document).encode(), mtime=0)
        return {'schema': '1', 'archive': base64.b64encode(archive).decode(),
                'checksum': hashlib.sha256(archive).hexdigest()}
    def test_roundtrip_keeps_secrets_modes_disable_and_removes_stale_files(self):
        self.seed()
        original = self.a.read_bytes()
        self.a.write_bytes(b'overwritten')
        self.rc.unlink()
        extra = self.write('/usr/local/etc/example/stale', b'obsolete')
        log = self.write('/usr/local/etc/example/runtime.log', b'keep runtime log')
        result = self.backup.restore()
        self.assertTrue(result['ok'], result)
        self.assertEqual(original, self.a.read_bytes())
        self.assertEqual(self.a.stat().st_mode & 0o777, 0o600)
        self.assertIn(b'NO', self.rc.read_bytes())
        self.assertFalse(extra.exists())
        self.assertTrue(log.exists())
    def test_absence_is_not_a_default_and_missing_snapshot_keeps_legacy_files(self):
        path = self.write('/usr/local/etc/example/legacy', b'legacy')
        self.assertFalse(self.backup.restore()['snapshot'])
        self.assertTrue(path.exists())
        path.unlink()
        path.parent.rmdir()
        self.assertTrue(self.backup.mirror()['ok'])
        self.write('/usr/local/etc/example/legacy', b'new defaults')
        result = self.backup.restore()
        self.assertTrue(result['snapshot'])
        self.assertFalse(path.exists())
        self.assertFalse(path.parent.exists())
    def test_pending_system_restore_cannot_be_overwritten_by_newer_external_files(self):
        self.seed()
        older = copy.deepcopy(self.store.value)
        self.a.write_bytes(b'new external edit')
        self.assertFalse(self.backup.reconcile()['changed'])
        self.assertTrue(self.backup.mirror()['changed'])
        self.store.value = older
        result = self.backup.mirror()
        self.assertFalse(result['ok'])
        self.assertEqual(self.store.value, older)
        self.assertTrue(self.backup.reconcile()['changed'])
        self.assertNotEqual(self.a.read_bytes(), b'new external edit')
    def test_corrupt_and_path_escape_archives_touch_no_files(self):
        self.seed()
        before = self.a.read_bytes()
        original = copy.deepcopy(self.store.value)
        self.store.value['checksum'] = '0' * 64
        self.assertFalse(self.backup.restore()['ok'])
        self.assertEqual(self.a.read_bytes(), before)
        doc = json.loads(gzip.decompress(base64.b64decode(original['archive'])))
        doc['entries'][0]['path'] = '/conf/config.xml'
        archive = gzip.compress(json.dumps(doc).encode(), mtime=0)
        self.store.value = {'schema':'1','archive':base64.b64encode(archive).decode(),
                            'checksum':hashlib.sha256(archive).hexdigest()}
        self.assertFalse(self.backup.restore()['ok'])
        self.assertEqual(self.a.read_bytes(), before)
    def test_failure_after_first_replacement_rolls_back_every_original(self):
        self.seed()
        self.a.write_bytes(b'current-a')
        self.b.write_bytes(b'current-b')
        original_replace = os.replace
        count = 0
        def fail_once(source, destination):
            nonlocal count
            if Path(source).name.startswith('.config-backup-') and Path(destination).name == 'b':
                count += 1
                if count == 1:
                    raise OSError('injected device write failure')
            return original_replace(source, destination)
        with patch.object(engine.os, 'replace', fail_once):
            result = self.backup.restore()
        self.assertFalse(result['ok'])
        self.assertEqual(self.a.read_bytes(), b'current-a')
        self.assertEqual(self.b.read_bytes(), b'current-b')
        self.assertFalse(list(self.root.rglob('.config-backup-*')))
    def test_unchanged_snapshot_does_not_create_native_history_revision(self):
        self.seed()
        self.assertFalse(self.backup.mirror()['changed'])
        self.assertEqual(self.store.saves, 1)
    def test_shell_literals_are_preserved_and_expansion_is_never_executed(self):
        for raw, expected in [(b'config="/opt/name-\\$literal-\\`literal"', '/opt/name-$literal-`literal'),
                              (b"export config='/opt/name-$literal-`literal' # comment", '/opt/name-$literal-`literal'),
                              (b'config=/opt/name\\ with\\ spaces', '/opt/name with spaces')]:
            self.assertEqual(engine.rc_value(raw, 'config', '/default'), expected)
        for raw in [b'config="/opt/$HOME"', b'config=/opt/$(command)',
                    b'config="/opt/`command`"', b'config=/opt/file; command']:
            with self.assertRaises(engine.BackupError):
                engine.rc_value(raw, 'config', '/default')
    def test_symlink_escape_is_rejected_and_internal_relative_link_roundtrips(self):
        self.seed()
        link = self.a.parent / 'link'
        link.symlink_to('/etc/passwd')
        self.assertFalse(self.backup.mirror()['ok'])
        link.unlink()
        link.symlink_to('a')
        self.assertTrue(self.backup.mirror()['ok'])
        link.unlink()
        result = self.backup.restore()
        self.assertTrue(result['ok'], result)
        self.assertEqual(os.readlink(link), 'a')

    def test_directory_and_file_transitions_restore_exact_types_without_leftovers(self):
        self.seed()
        saved = self.write('/usr/local/etc/example/saved-dir/private', b'saved nested key')
        self.assertTrue(self.backup.mirror()['ok'])
        shutil.rmtree(saved.parent)
        saved.parent.write_bytes(b'live file replacing saved directory')
        self.a.unlink()
        self.a.mkdir()
        self.write('/usr/local/etc/example/a/nested/live', b'live private directory contents')
        self.rc.unlink()
        self.rc.mkdir()
        self.write('/etc/rc.conf.d/example/child', b'live rc directory contents')
        result = self.backup.restore()
        self.assertTrue(result['ok'], result)
        self.assertTrue(result['changed'])
        self.assertEqual(saved.read_bytes(), b'saved nested key')
        self.assertEqual(self.a.read_bytes(), b'actual-password=private\x00bytes')
        self.assertEqual(self.rc.read_bytes(), b'example_enable="NO"\n')
        self.assertFalse(list(self.root.rglob('.config-backup-*')))

    def test_live_file_can_be_replaced_by_saved_root_directory(self):
        self.seed()
        tree = self.a.parent
        shutil.rmtree(tree)
        tree.write_bytes(b'live file in place of tree')
        result = self.backup.restore()
        self.assertTrue(result['ok'], result)
        self.assertTrue(tree.is_dir())
        self.assertEqual(self.b.read_bytes(), b'private-key\n')
        self.assertFalse(list(self.root.rglob('.config-backup-*')))

    def test_type_transitions_roll_back_after_marker_failure(self):
        self.seed()
        saved = self.write('/usr/local/etc/example/saved-dir/private', b'saved key')
        self.assertTrue(self.backup.mirror()['ok'])
        marker = self.backup.marker.read_bytes()
        shutil.rmtree(saved.parent)
        saved.parent.write_bytes(b'live file before rollback')
        self.b.unlink()
        self.b.mkdir()
        live = self.write('/usr/local/etc/example/b/sub/key', b'live directory before rollback', 0o640)
        with patch.object(self.backup, '_set_marker', side_effect=OSError('injected marker failure')):
            result = self.backup.restore()
        self.assertFalse(result['ok'])
        self.assertEqual(saved.parent.read_bytes(), b'live file before rollback')
        self.assertEqual(live.read_bytes(), b'live directory before rollback')
        self.assertEqual(live.stat().st_mode & 0o777, 0o640)
        self.assertEqual(self.backup.marker.read_bytes(), marker)
        self.assertFalse(list(self.root.rglob('.config-backup-*')))

    def test_all_payloads_are_staged_before_any_original_is_moved(self):
        self.seed()
        expected = [e for e in self.backup._decode(self.store.value)[1].values() if e['kind'] != 'dir']
        self.a.write_bytes(b'live-a')
        self.b.write_bytes(b'live-b')
        replace = os.replace
        checked = False
        def inspect_first_move(source, destination):
            nonlocal checked
            if not checked and not Path(source).name.startswith('.config-backup-'):
                checked = True
                staged = list(self.root.rglob('.config-backup-*'))
                self.assertEqual(len(staged), len(expected))
                self.assertEqual(sorted(p.read_bytes() for p in staged),
                                 sorted(base64.b64decode(e['data']) for e in expected))
            return replace(source, destination)
        with patch.object(engine.os, 'replace', inspect_first_move):
            result = self.backup.restore()
        self.assertTrue(checked)
        self.assertTrue(result['ok'], result)

    def test_staging_failure_moves_no_original(self):
        self.seed()
        self.a.write_bytes(b'current-a')
        self.b.write_bytes(b'current-b')
        with patch.object(engine.os, 'fsync', side_effect=OSError('injected staging failure')):
            result = self.backup.restore()
        self.assertFalse(result['ok'])
        self.assertEqual(self.a.read_bytes(), b'current-a')
        self.assertEqual(self.b.read_bytes(), b'current-b')
        self.assertFalse(list(self.root.rglob('.config-backup-*')))

    def test_one_failed_rollback_retains_backup_and_recovers_other_originals(self):
        self.seed()
        self.a.write_bytes(b'current-a')
        self.b.write_bytes(b'current-b')
        replace = os.replace
        def fail_one_rollback(source, destination):
            if (Path(destination) == self.b and Path(source).name.startswith('.config-backup-') and
                    Path(source).read_bytes() == b'current-b'):
                raise OSError('injected rollback failure')
            return replace(source, destination)
        with patch.object(self.backup, '_set_marker', side_effect=OSError('injected commit failure')), \
                patch.object(engine.os, 'replace', fail_one_rollback):
            result = self.backup.restore()
        self.assertFalse(result['ok'])
        self.assertEqual(self.a.read_bytes(), b'current-a')
        retained = list(self.root.rglob('.config-backup-*'))
        self.assertEqual(len(retained), 1)
        self.assertEqual(retained[0].read_bytes(), b'current-b')

    def test_composed_symlink_escape_and_cycles_are_rejected_when_mirroring(self):
        self.seed()
        tree = self.a.parent
        (tree / 'redirect').symlink_to('.')
        (tree / 'escape').symlink_to('redirect/../outside')
        self.assertFalse(self.backup.mirror()['ok'])
        (tree / 'escape').unlink()
        (tree / 'redirect').unlink()
        (tree / 'first').symlink_to('second')
        (tree / 'second').symlink_to('first')
        self.assertFalse(self.backup.mirror()['ok'])

    def test_crafted_composed_symlink_archive_touches_no_destinations(self):
        self.seed()
        original = self.a.read_bytes()
        doc = json.loads(gzip.decompress(base64.b64decode(self.store.value['archive'])))
        for name, target in [('redirect', '.'), ('escape', 'redirect/../outside')]:
            doc['entries'].append({'path': '/usr/local/etc/example/' + name,
                                   'kind': 'link', 'mode': 0o777, 'target': target})
        self.store.value = self.encode_document(doc)
        self.assertFalse(self.backup.restore()['ok'])
        self.assertEqual(self.a.read_bytes(), original)
        self.assertFalse((self.a.parent / 'escape').is_symlink())

    def test_internal_parent_and_chained_links_roundtrip(self):
        self.seed()
        private = self.write('/usr/local/etc/example/private/key', b'internal private key')
        sub = self.a.parent / 'sub'
        sub.mkdir()
        (sub / 'link').symlink_to('../private/key')
        (self.a.parent / 'chain').symlink_to('sub/link')
        self.assertTrue(self.backup.mirror()['ok'])
        shutil.rmtree(self.a.parent)
        result = self.backup.restore()
        self.assertTrue(result['ok'], result)
        self.assertEqual((self.a.parent / 'chain').read_bytes(), private.read_bytes())

    def test_archive_cannot_claim_absent_tree_while_restoring_its_children(self):
        self.seed()
        doc = json.loads(gzip.decompress(base64.b64decode(self.store.value['archive'])))
        doc['entries'] = [e for e in doc['entries'] if e['path'] != '/usr/local/etc/example']
        for root in doc['roots']:
            if root['path'] == '/usr/local/etc/example':
                root['present'] = False
        self.store.value = self.encode_document(doc)
        self.assertFalse(self.backup.restore()['ok'])
        self.assertEqual(self.a.read_bytes(), b'actual-password=private\x00bytes')

    def test_system_restore_between_import_and_export_cannot_be_overwritten(self):
        self.seed()
        restored = copy.deepcopy(self.store.value)
        self.a.write_bytes(b'new runtime configuration')
        self.assertTrue(self.backup.mirror()['ok'])
        snapshot = self.backup._snapshot
        for absent in (False, True):
            with self.subTest(previous_section_absent=absent):
                if absent:
                    self.store.value = {}
                marker = self.backup._marker()
                def restore_during_collection():
                    payload = snapshot()
                    self.store.value = copy.deepcopy(restored)
                    return payload
                with patch.object(self.backup, '_snapshot', side_effect=restore_during_collection):
                    self.assertFalse(self.backup.mirror()['ok'])
                self.assertEqual(self.store.value, restored)
                self.assertEqual(self.backup._marker(), marker)
                self.assertTrue(self.backup.reconcile()['ok'])
                self.assertEqual(self.a.read_bytes(), b'actual-password=private\x00bytes')
                self.a.write_bytes(b'new runtime configuration')
                self.assertTrue(self.backup.mirror()['ok'])

    def test_empty_native_model_fields_are_not_a_saved_snapshot(self):
        self.write('/usr/local/etc/example/legacy', b'legacy settings')
        self.store.value = {'schema': '', 'archive': '', 'checksum': ''}
        self.assertEqual(self.backup.reconcile(), {'ok': True, 'changed': False, 'snapshot': False})
        self.assertTrue(self.backup.mirror()['ok'])
        self.assertTrue(self.backup.restore()['snapshot'])

    def test_new_archive_limit_retains_previous_snapshot_and_reads_larger_legacy_archive(self):
        self.seed()
        saved = copy.deepcopy(self.store.value)
        marker = self.backup._marker()
        self.a.write_bytes(os.urandom(engine.MAX_NEW_ARCHIVE + 4096))
        result = self.backup.mirror()
        self.assertFalse(result['ok'])
        self.assertEqual(self.store.value, saved)
        self.assertEqual(self.backup._marker(), marker)
        doc = json.loads(gzip.decompress(base64.b64decode(saved['archive'])))
        for entry in doc['entries']:
            if entry['path'] == '/usr/local/etc/example/a':
                entry['data'] = base64.b64encode(self.a.read_bytes()).decode()
        self.store.value = self.encode_document(doc)
        self.assertGreater(len(base64.b64decode(self.store.value['archive'])), engine.MAX_NEW_ARCHIVE)
        self.a.write_bytes(b'changed live file')
        self.assertTrue(self.backup.restore()['ok'])
        self.assertEqual(len(self.a.read_bytes()), engine.MAX_NEW_ARCHIVE + 4096)

    def test_traversal_counts_excluded_names_before_sorting_and_keeps_previous_backup(self):
        self.seed()
        saved = copy.deepcopy(self.store.value)
        for number in range(8):
            self.write('/usr/local/etc/example/' + str(number) + '.log', b'excluded')
        with patch.object(engine, 'MAX_ENTRIES', 8):
            self.assertFalse(self.backup.mirror()['ok'])
            with self.assertRaises(engine.BackupError):
                self.backup._fingerprint()
        self.assertEqual(self.store.value, saved)

    def test_deep_directory_tree_has_a_deterministic_limit(self):
        self.seed()
        self.write('/usr/local/etc/example/one/two/three/key', b'private')
        with patch.object(engine, 'MAX_DEPTH', 7):
            self.assertFalse(self.backup.mirror()['ok'])
            with self.assertRaises(engine.BackupError):
                self.backup._fingerprint()

    def test_dynamic_roots_cannot_target_startup_scripts_or_system_served_files(self):
        for path, kind in [('/etc/rc.conf.d', 'tree'), ('/etc/rc.conf.d/sshd', 'file'),
                           ('/usr/local/etc/rc.d', 'tree'), ('/etc/cron.d', 'tree'),
                           ('/var/etc', 'tree'), ('/usr/local/www/shell.php', 'file')]:
            with self.subTest(path=path), self.assertRaises(engine.BackupError):
                self.backup._safe_path(path, kind, True)

    def test_var_reset_does_not_reapply_stale_xml_and_legacy_marker_migrates(self):
        self.seed()
        marker = self.backup.marker.read_bytes()
        legacy = self.backup.state / 'applied.sha256'
        legacy.write_bytes(marker)
        self.backup.marker.unlink()
        self.a.write_bytes(b'new external settings')
        self.assertFalse(self.backup.reconcile()['changed'])
        self.assertEqual(self.backup.marker.read_bytes(), marker)
        shutil.rmtree(self.backup.state)
        restarted = engine.ConfigBackup(self.profile, transport=self.store)
        self.assertFalse(restarted.reconcile()['changed'])
        self.assertEqual(self.a.read_bytes(), b'new external settings')

    def test_system_restore_during_file_application_rolls_back_before_discarding_journal(self):
        self.seed()
        previous = copy.deepcopy(self.store.value)
        self.a.write_bytes(b'live-a')
        self.b.write_bytes(b'live-b')
        marker = self.backup._marker()
        replace = os.replace
        changed = False
        restored = copy.deepcopy(previous)
        restored['checksum'] = 'f' * 64
        def concurrent_restore(source, destination):
            nonlocal changed
            result = replace(source, destination)
            if not changed and Path(destination) == self.a and Path(source).name.startswith('.config-backup-'):
                self.store.value = copy.deepcopy(restored)
                changed = True
            return result
        with patch.object(engine.os, 'replace', concurrent_restore):
            result = self.backup.restore()
        self.assertFalse(result['ok'])
        self.assertEqual(self.store.value, restored)
        self.assertEqual(self.a.read_bytes(), b'live-a')
        self.assertEqual(self.b.read_bytes(), b'live-b')
        self.assertEqual(self.backup._marker(), marker)
        self.assertFalse(list(self.root.rglob('.config-backup-*')))

    def test_watcher_throttles_continuous_changes_across_process_restarts_but_manual_save_is_immediate(self):
        clock = {'now': 0}
        handlers = {}
        exports = []
        transport = self.backup.transport
        def timed_transport(action, payload=None):
            result = transport(action, payload)
            if action == 'export' and result['changed']:
                exports.append(clock['now'])
            return result
        self.backup.transport = timed_transport
        def run_watch(end, churn=False):
            def advance(seconds):
                clock['now'] += seconds
                if churn:
                    self.a.write_bytes(('edit-' + str(clock['now'])).encode())
                if clock['now'] >= end:
                    handlers[signal.SIGTERM](signal.SIGTERM, None)
            with patch.object(engine.time, 'sleep', advance):
                self.assertTrue(self.backup.watch()['ok'])
        with patch.object(engine.time, 'time', lambda: 1000 + clock['now']), \
                patch.object(engine.time, 'monotonic', lambda: clock['now']), \
                patch.object(engine.signal, 'signal', lambda signum, callback: handlers.update({signum: callback})):
            self.seed()
            run_watch(35, churn=True)
            self.assertEqual(exports, [0, 30])
            self.a.write_bytes(b'edit between watcher restarts')
            run_watch(55)
            self.assertEqual(exports, [0, 30])
            run_watch(65)
            self.assertEqual(exports, [0, 30, 60])
            self.a.write_bytes(b'explicit manual edit')
            self.assertTrue(self.backup.mirror()['ok'])
            self.assertEqual(exports, [0, 30, 60, 65])

    def test_old_snapshot_restores_after_new_fixed_roots_and_exclusions_are_added(self):
        self.seed()
        cache = self.write('/usr/local/etc/example/software.sample', b'old packaged software')
        self.assertTrue(self.backup.mirror()['ok'])
        new = self.write('/usr/local/etc/new-example/config', b'new configuration outside old snapshot')
        cache.write_bytes(b'new packaged software')
        self.a.write_bytes(b'edited private configuration')
        profile = dict(self.profile, files=[*self.profile['files'], '/usr/local/etc/new-example/config'],
                       excludes=[*self.profile['excludes'], '*.sample'])
        updated = engine.ConfigBackup(profile, transport=self.store)
        self.assertTrue(updated.restore()['ok'])
        self.assertEqual(cache.read_bytes(), b'new packaged software')
        self.assertEqual(new.read_bytes(), b'new configuration outside old snapshot')
        self.assertEqual(self.a.read_bytes(), b'actual-password=private\x00bytes')

    def test_export_confirmation_race_does_not_mark_foreign_xml_as_applied(self):
        self.seed()
        marker = self.backup._marker()
        self.a.write_bytes(b'new private configuration')
        transport = self.backup.transport
        foreign = copy.deepcopy(self.store.value)
        foreign['checksum'] = 'a' * 64
        def restore_after_export(action, payload=None):
            result = transport(action, payload)
            if action == 'export':
                self.store.value = copy.deepcopy(foreign)
            return result
        with patch.object(self.backup, 'transport', side_effect=restore_after_export):
            self.assertFalse(self.backup.mirror()['ok'])
        self.assertEqual(self.store.value, foreign)
        self.assertEqual(self.backup._marker(), marker)

    def test_reconcile_restores_only_erased_archive_roots_and_keeps_other_roots_newer_edits(self):
        self.seed()
        shutil.rmtree(self.a.parent)
        self.rc.write_bytes(b'example_enable="YES"\nnewer_flag="keep"\n')
        self.assertTrue(self.backup.reconcile()['changed'])
        self.assertEqual(self.a.read_bytes(), b'actual-password=private\x00bytes')
        self.assertEqual(self.rc.read_bytes(), b'example_enable="YES"\nnewer_flag="keep"\n')
        self.a.write_bytes(b'newer credentials remain')
        self.b.unlink()
        self.assertFalse(self.backup.reconcile()['changed'])
        self.assertEqual(self.a.read_bytes(), b'newer credentials remain')
        self.assertFalse(self.b.exists())

    def test_reinstall_after_all_configuration_roots_and_var_state_are_erased_restores_files(self):
        self.seed()
        checksum = self.backup._marker()
        shutil.rmtree(self.a.parent)
        self.rc.unlink()
        shutil.rmtree(self.backup.state)
        restarted = engine.ConfigBackup(self.profile, transport=self.store)
        self.assertTrue(restarted.reconcile()['changed'])
        self.assertEqual(self.a.read_bytes(), b'actual-password=private\x00bytes')
        self.assertEqual(self.rc.read_bytes(), b'example_enable="NO"\n')
        self.assertEqual(restarted._marker(), checksum)


if __name__ == '__main__':
    unittest.main()
