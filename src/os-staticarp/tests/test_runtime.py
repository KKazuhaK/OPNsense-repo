"""Run production PHP and shell entry points with private files and command doubles."""
import json
import copy
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest

PACKAGE = Path(__file__).resolve().parents[1]
PHP = shutil.which('php')
SETTINGS = PACKAGE / 'src/usr/local/opnsense/scripts/staticarp/settings.php'
CONTROL = PACKAGE / 'src/usr/local/sbin/staticarpctl'


@unittest.skipUnless(PHP, 'Requires a PHP CLI; no OPNsense installation is needed')
class SettingsRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='staticarp-settings-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.configuration = self.root / 'configuration'
        self.configuration.mkdir()
        self.events = self.root / 'events'
        includes = self.root / 'includes'
        includes.mkdir()
        (includes / 'config.inc').write_text('<?php $config=json_decode(getenv("STATICARP_TEST_CONFIG"),true);\n')
        (includes / 'interfaces.inc').write_text('<?php function get_interface_list() { '
                                                'return json_decode(getenv("STATICARP_TEST_DEVICES"),true); }\n')
        (includes / 'util.inc').write_text('<?php\n')
        self.config = {'interfaces': {
            'wan': {'if': 'vtnet0', 'gateway': 'WAN_GATEWAY', 'ipaddr': 'dhcp'},
            'lan': {'if': 'vtnet1', 'descr': 'Office LAN', 'ipaddr': '192.0.2.1', 'subnet': '24'},
            'opt1': {'if': 'vtnet2.20', 'gateway': 'dynamic', 'ipaddr': 'dhcp'},
            'opt2': {'if': 'vtnet3', 'gateway': 'none', 'ipaddr': '198.51.100.1', 'subnet': '25'},
            'loop': {'if': 'lo0'}, 'missing': {},
        }}
        self.devices = {'vtnet1': {'mac': 'aa:bb:cc:dd:ee:01', 'up': True},
                        'vtnet2.20': {'mac': 'aa:bb:cc:dd:ee:02', 'up': False}}
        self.environment = {**os.environ, 'STATICARP_TEST_EVENTS': str(self.events),
                            'STATICARP_TEST_DIR': str(self.configuration),
                            'STATICARP_TEST_CONFIG': json.dumps(self.config),
                            'STATICARP_TEST_DEVICES': json.dumps(self.devices),
                            'STATICARP_TEST_IFCONFIG': json.dumps(['vtnet1: flags', '    inet 192.0.2.1 netmask 0xffffff00',
                                                                  '    inet 127.0.0.1 netmask 0xff000000']),
                            'STATICARP_TEST_ARP': json.dumps([
                                '? (192.0.2.30) at AA:BB:CC:DD:EE:30 on vtnet1 expires in 100 seconds',
                                '? (192.0.2.5) at aa:bb:cc:dd:ee:05 on vtnet1 permanent',
                                '? (192.0.2.1) at aa:bb:cc:dd:ee:01 on vtnet1 permanent',
                                '? (192.0.2.9) at (incomplete) on vtnet1',
                                '? (192.0.2.5) at aa:bb:cc:dd:ee:55 on vtnet1 permanent',
                                'malformed', '? (2001:db8::1) at aa:bb:cc:dd:ee:01 on vtnet1'])}
        source = SETTINGS.read_text()
        needle = "const STATICARP_CONFIG_DIR = '/usr/local/etc/staticarp';"
        self.assertEqual(source.count(needle), 1)
        source = source.replace('<?php', '<?php\nnamespace StaticarpFixture;\n'
                                'use \\Throwable; use \\RuntimeException; use \\InvalidArgumentException;\n', 1)
        self.candidate = self.root / 'settings.php'
        source = source.replace(needle, "const STATICARP_CONFIG_DIR = '" + str(self.configuration) + "';", 1)
        lock = "const STATICARP_LOCK_FILE = '/var/db/os-staticarp-backup/settings.lock';"
        self.assertEqual(source.count(lock), 1)
        self.candidate.write_text(source.replace(lock, "const STATICARP_LOCK_FILE = '" + str(self.root / 'settings.lock') + "';", 1))
        self.driver = self.root / 'driver.php'
        self.driver.write_text('''<?php
namespace StaticarpFixture;
function exec($command, &$output = null, &$status = null) {
    $event = ['command' => $command];
    $status = 0;
    if ($command === '/sbin/ifconfig 2>/dev/null') {
        $output = json_decode(getenv('STATICARP_TEST_IFCONFIG'), true);
    } elseif ($command === '/usr/sbin/arp -an 2>/dev/null') {
        $output = json_decode(getenv('STATICARP_TEST_ARP'), true);
    } elseif (str_starts_with($command, '/usr/local/bin/python3 ') &&
              str_ends_with($command, ' mirror >/dev/null 2>&1')) {
        $output = [];
        foreach (['settings.conf','entries.conf','interfaces.conf'] as $name) {
            $event['saved'][$name] = file_get_contents(getenv('STATICARP_TEST_DIR') . '/' . $name);
        }
        $status = getenv('STATICARP_TEST_MIRROR_FAIL') ? 1 : 0;
    } else {
        throw new \\RuntimeException('An unexpected command escaped the fixture.');
    }
    file_put_contents(getenv('STATICARP_TEST_EVENTS'), json_encode($event) . "\\n", FILE_APPEND);
    return '';
}
function rename($source, $destination) {
    if (getenv('STATICARP_TEST_ROLLBACK_FAIL') === basename($destination) &&
        str_starts_with(basename($source), '.staticarp-rollback-')) { return false; }
    if (getenv('STATICARP_TEST_RENAME_FAIL') === basename($destination) && empty($GLOBALS['fault_injected'])) {
        $GLOBALS['fault_injected'] = true;
        return false;
    }
    $result = \\rename($source, $destination);
    if ($result && basename($destination) === 'settings.conf' && getenv('STATICARP_TEST_PAUSE') &&
        empty($GLOBALS['paused'])) {
        $GLOBALS['paused'] = true;
        touch(getenv('STATICARP_TEST_PAUSE'));
        $deadline = microtime(true) + 5;
        while (!file_exists(getenv('STATICARP_TEST_RELEASE')) && microtime(true) < $deadline) { usleep(10000); }
    }
    return $result;
}
function chmod($path, $mode) {
    $filename = getenv('STATICARP_TEST_ROLLBACK_CHMOD_FAIL');
    if ($filename && str_starts_with(basename($path), '.staticarp-rollback-' . $filename . '-')) {
        return false;
    }
    return \\chmod($path, $mode);
}
function file_put_contents($path, $content, $flags = 0) {
    if (getenv('STATICARP_TEST_STAGE_FAIL') && str_starts_with(basename($path), '.staticarp-') &&
        !str_starts_with(basename($path), '.staticarp-recovery-') && str_contains($content, '192.0.2.7')) { return false; }
    return \\file_put_contents($path, $content, $flags);
}
function unlink($path) {
    if (getenv('STATICARP_TEST_UNLINK_FAIL') === basename($path)) { return false; }
    return \\unlink($path);
}
set_include_path(__DIR__ . '/includes');
require __DIR__ . '/settings.php';
''')

    def run_action(self, action='get', payload=None, argument=None, failure=None):
        arguments = [PHP, str(self.driver), action]
        if payload is not None:
            path = self.root / 'payload.json'
            path.write_text(json.dumps(payload))
            arguments.append(str(path))
        elif argument is not None:
            arguments.append(argument)
        environment = {**self.environment, **(failure or {})}
        process = subprocess.run(arguments, env=environment, capture_output=True, text=True, timeout=10)
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(process.stderr, '')
        return json.loads(process.stdout)

    def calls(self):
        return [json.loads(line) for line in self.events.read_text().splitlines()] if self.events.exists() else []

    def state(self):
        return {path.name: (path.read_bytes(), path.stat().st_mode & 0o777)
                for path in self.configuration.iterdir() if path.is_file() and not path.name.startswith('.staticarp-')}

    def seed(self):
        for name, content, mode in [('settings.conf', b'enabled=NO\n', 0o600),
                                    ('entries.conf', b'192.0.2.8 aa:bb:cc:dd:ee:08\n', 0o640),
                                    ('interfaces.conf', b'lan vtnet1 normal\n', 0o644)]:
            path = self.configuration / name
            path.write_bytes(content)
            path.chmod(mode)
        return self.state()

    def make_backup(self):
        sys.path.insert(0, str(PACKAGE.parents[1] / 'src/common'))
        from config_backup import revision_token
        source = PACKAGE / 'src/usr/local/opnsense/scripts/staticarp/config_mirror.py'
        spec = importlib.util.spec_from_file_location('staticarp_recovery_backup', source)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        profile = {**module.PROFILE, 'root_env': 'STATICARP_TEST_BACKUP_ROOT', 'trees': ['/configuration'],
                   'files': [], 'data_lock': '/settings.lock'}
        previous = os.environ.get('STATICARP_TEST_BACKUP_ROOT')
        os.environ['STATICARP_TEST_BACKUP_ROOT'] = str(self.root)
        self.addCleanup(lambda: os.environ.pop('STATICARP_TEST_BACKUP_ROOT', None) if previous is None
                        else os.environ.__setitem__('STATICARP_TEST_BACKUP_ROOT', previous))
        fields = {}
        def transport(action, payload=None):
            if action == 'import':
                return copy.deepcopy(fields)
            payload = copy.deepcopy(payload)
            self.assertEqual(payload.pop('_expected'), revision_token(fields))
            changed = payload != fields
            fields.clear()
            fields.update(payload)
            return {'changed': changed}
        return module.StaticarpBackup(profile, transport=transport), fields

    def test_get_discovers_eligible_interfaces_and_filters_sorts_current_arp(self):
        self.seed()
        result = self.run_action()
        rows = {row['name']: row for row in result['interfaces']}
        self.assertEqual(set(rows), {'lan', 'opt1', 'opt2'})
        self.assertEqual(rows['lan'], {'name': 'lan', 'device': 'vtnet1', 'descr': 'Office LAN',
                                       'ipaddr': '192.0.2.1/24', 'mac': 'aa:bb:cc:dd:ee:01', 'status': 'up'})
        self.assertEqual(rows['opt1']['descr'], 'OPT1')
        self.assertEqual(rows['opt1']['status'], 'down')
        self.assertEqual(rows['opt2']['mac'], '')
        self.assertEqual(result['arp'], '192.0.2.5 aa:bb:cc:dd:ee:55\n192.0.2.30 aa:bb:cc:dd:ee:30')
        self.assertFalse(result['settings']['enabled'])
        self.assertEqual(result['settings']['modes'], {'lan': 'normal'})
        self.assertTrue(all(' mirror ' not in event['command'] for event in self.calls()))

    def test_set_normalizes_bindings_and_persists_all_eligible_modes_before_mirror(self):
        result = self.run_action('set', {'enabled': True, 'entries': '192.0.2.30 AA:BB:CC:DD:EE:30,\n'
                                 '192.0.2.1 aa:bb:cc:dd:ee:01\n192.0.2.5 aa:bb:cc:dd:ee:05\n'
                                 '192.0.2.5 aa:bb:cc:dd:ee:55',
                                 'modes': {'lan': 'staticarp', 'opt1': '-arp', 'wan': 'invalid-ignored'}})
        self.assertEqual(result, {'status': 'ok', 'enabled': True})
        self.assertEqual((self.configuration / 'settings.conf').read_text(), 'enabled=YES\n')
        self.assertEqual((self.configuration / 'entries.conf').read_text(),
                         '192.0.2.5 aa:bb:cc:dd:ee:55\n192.0.2.30 aa:bb:cc:dd:ee:30\n')
        self.assertEqual((self.configuration / 'interfaces.conf').read_text(),
                         'lan vtnet1 staticarp\nopt1 vtnet2.20 -arp\nopt2 vtnet3 normal\n')
        captured = [event['saved'] for event in self.calls() if 'saved' in event]
        self.assertEqual(len(captured), 1)
        self.assertEqual(captured[0], {name: (self.configuration / name).read_text()
                                     for name in ['settings.conf', 'entries.conf', 'interfaces.conf']})
        self.assertFalse(list(self.configuration.glob('.staticarp-*')))

    def test_disabled_empty_configuration_is_valid_and_invalid_inputs_leave_old_files(self):
        result = self.run_action('set', {'enabled': False, 'entries': '', 'modes': {}})
        self.assertEqual(result, {'status': 'ok', 'enabled': False})
        old = self.state()
        mirror_count = sum('saved' in event for event in self.calls())
        for given in [{'enabled': True, 'entries': ''}, {'enabled': True, 'entries': '192.0.2.1 aa:bb:cc:dd:ee:01'},
                      {'entries': 'invalid aa:bb:cc:dd:ee:ff'}, {'entries': '192.0.2.5 invalid'},
                      {'entries': '192.0.2.5 aa:bb:cc:dd:ee:05', 'modes': {'lan': 'bad mode'}},
                      {'entries': []}, {'entries': None}, {'modes': 'invalid'}, None]:
            with self.subTest(given=given):
                if given is None:
                    payload = self.root / 'invalid.json'
                    payload.write_text('not-json')
                    result = self.run_action('set', argument=str(payload))
                else:
                    result = self.run_action('set', given)
                self.assertEqual(result['status'], 'failed')
                self.assertEqual(self.state(), old)
        self.assertEqual(sum('saved' in event for event in self.calls()), mirror_count)

    def test_mirror_failure_reports_saved_state_without_claiming_write_rollback(self):
        result = self.run_action('set', {'enabled': False, 'entries': '192.0.2.7 aa:bb:cc:dd:ee:07'},
                                 failure={'STATICARP_TEST_MIRROR_FAIL': '1'})
        self.assertEqual(result['status'], 'failed')
        self.assertTrue(result['saved'])
        self.assertIn('backup failed', result['error'])
        self.assertIn('192.0.2.7', (self.configuration / 'entries.conf').read_text())

    def test_failed_second_or_third_replacement_restores_all_original_bytes_and_modes(self):
        for filename in ['entries.conf', 'interfaces.conf']:
            with self.subTest(filename=filename):
                old = self.seed()
                result = self.run_action('set', {'enabled': True, 'entries': '192.0.2.7 aa:bb:cc:dd:ee:07',
                                        'modes': {'lan': 'staticarp'}}, failure={'STATICARP_TEST_RENAME_FAIL': filename})
                self.assertEqual(result['status'], 'failed')
                self.assertEqual(self.state(), old)
                self.assertFalse(any('saved' in event for event in self.calls()))
                self.assertFalse(list(self.configuration.glob('.staticarp-*')))

    def test_failed_staging_changes_nothing_and_first_install_failure_restores_absence(self):
        old = self.seed()
        given = {'enabled': True, 'entries': '192.0.2.7 aa:bb:cc:dd:ee:07'}
        result = self.run_action('set', given, failure={'STATICARP_TEST_STAGE_FAIL': '1'})
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(self.state(), old)
        self.assertFalse(list(self.configuration.glob('.staticarp-*')))
        for path in self.configuration.iterdir():
            path.unlink()
        result = self.run_action('set', given, failure={'STATICARP_TEST_RENAME_FAIL': 'entries.conf'})
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(self.state(), {})
        self.assertFalse(list(self.configuration.glob('.staticarp-*')))
        self.assertFalse(any('saved' in event for event in self.calls()))

    def test_failed_rollback_keeps_private_original_and_does_not_mirror_partial_state(self):
        old = self.seed()
        engine, fields = self.make_backup()
        self.assertTrue(engine.mirror()['ok'])
        saved_xml = copy.deepcopy(fields)
        result = self.run_action('set', {'enabled': True, 'entries': '192.0.2.7 aa:bb:cc:dd:ee:07'},
                                 failure={'STATICARP_TEST_RENAME_FAIL': 'interfaces.conf',
                                          'STATICARP_TEST_ROLLBACK_FAIL': 'settings.conf'})
        self.assertEqual(result['status'], 'failed')
        originals = list(self.configuration.glob('.staticarp-recovery-*'))
        self.assertEqual(len(originals), 1)
        self.assertEqual(originals[0].read_bytes(), old['settings.conf'][0])
        self.assertEqual(originals[0].stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.state()['entries.conf'], old['entries.conf'])
        self.assertEqual(self.state()['interfaces.conf'], old['interfaces.conf'])
        self.assertFalse(any('saved' in event for event in self.calls()))
        self.assertFalse(engine.mirror()['ok'])
        self.assertEqual(fields, saved_xml, 'Watcher mirroring replaced the good native snapshot with a partial save.')
        self.assertTrue(engine.reconcile()['ok'])
        self.assertEqual(self.state(), old)
        self.assertFalse(list(self.configuration.glob('.staticarp-recovery-*')))
        self.assertTrue(engine.mirror()['ok'])

    def test_rollback_mode_failure_keeps_private_original_and_recovery_guard(self):
        old = self.seed()
        engine, fields = self.make_backup()
        self.assertTrue(engine.mirror()['ok'])
        saved_xml = copy.deepcopy(fields)
        result = self.run_action('set', {'enabled': True, 'entries': '192.0.2.7 aa:bb:cc:dd:ee:07'},
                                 failure={'STATICARP_TEST_RENAME_FAIL': 'interfaces.conf',
                                          'STATICARP_TEST_ROLLBACK_CHMOD_FAIL': 'entries.conf'})
        self.assertEqual(result['status'], 'failed')
        originals = list(self.configuration.glob('.staticarp-recovery-*'))
        self.assertEqual(len(originals), 1)
        self.assertEqual(originals[0].read_bytes(), old['entries.conf'][0])
        self.assertEqual(originals[0].stat().st_mode & 0o777, 0o600)
        self.assertFalse(list(self.configuration.glob('.staticarp-rollback-*')))
        self.assertEqual(self.state()['settings.conf'], old['settings.conf'])
        self.assertEqual(self.state()['interfaces.conf'], old['interfaces.conf'])
        self.assertIn(b'192.0.2.7', self.state()['entries.conf'][0])
        self.assertFalse(any('saved' in event for event in self.calls()))
        self.assertFalse(engine.mirror()['ok'])
        self.assertEqual(fields, saved_xml)
        control = StaticarpControlTests()
        control.setUp()
        self.addCleanup(control.doCleanups)
        candidate = control.script.read_text().replace(str(control.configuration), str(self.configuration))
        candidate = candidate.replace(str(control.root / 'settings.lock'), str(self.root / 'settings.lock'))
        control.script.write_text(candidate)
        result = control.run_action('apply')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('needs recovery', result.stderr)
        self.assertEqual(control.calls(), [])
        self.assertTrue(engine.reconcile()['ok'])
        self.assertEqual(self.state(), old)
        self.assertFalse(list(self.configuration.glob('.staticarp-recovery-*')))
        self.assertTrue(engine.mirror()['ok'])

    def test_explicit_successful_save_supersedes_recovery_and_unblocks_backup(self):
        self.seed()
        engine, fields = self.make_backup()
        self.assertTrue(engine.mirror()['ok'])
        result = self.run_action('set', {'enabled': True, 'entries': '192.0.2.7 aa:bb:cc:dd:ee:07'},
                                 failure={'STATICARP_TEST_RENAME_FAIL': 'interfaces.conf',
                                          'STATICARP_TEST_ROLLBACK_FAIL': 'settings.conf'})
        self.assertEqual(result['status'], 'failed')
        self.assertFalse(engine.mirror()['ok'])
        result = self.run_action('set', {'enabled': False, 'entries': '192.0.2.9 aa:bb:cc:dd:ee:09'})
        self.assertEqual(result['status'], 'ok')
        self.assertFalse(list(self.configuration.glob('.staticarp-recovery-*')))
        self.assertTrue(engine.mirror()['ok'])
        _, entries, _ = engine._decode(fields)
        import base64
        self.assertEqual(base64.b64decode(entries['/configuration/entries.conf']['data']),
                         b'192.0.2.9 aa:bb:cc:dd:ee:09\n')

    def test_recovery_without_any_xml_snapshot_refuses_mirror_and_boot_reconcile(self):
        recovery = self.configuration / '.staticarp-recovery-fixture'
        recovery.write_bytes(b'original private binding')
        recovery.chmod(0o600)
        engine, fields = self.make_backup()
        for operation in [engine.mirror, engine.reconcile]:
            result = operation()
            self.assertFalse(result['ok'])
            self.assertNotIn('original private binding', result['error'])
            self.assertEqual(fields, {})
            self.assertTrue(recovery.exists())

    def test_absent_original_failed_rollback_retains_marker_and_refuses_kernel_apply(self):
        engine, fields = self.make_backup()
        result = self.run_action('set', {'enabled': True, 'entries': '192.0.2.7 aa:bb:cc:dd:ee:07'},
                                 failure={'STATICARP_TEST_RENAME_FAIL': 'entries.conf',
                                          'STATICARP_TEST_UNLINK_FAIL': 'settings.conf'})
        self.assertEqual(result['status'], 'failed')
        originals = list(self.configuration.glob('.staticarp-recovery-*'))
        self.assertEqual(len(originals), 1)
        self.assertIn(b'Original file was absent: settings.conf', originals[0].read_bytes())
        self.assertEqual(originals[0].stat().st_mode & 0o777, 0o600)
        self.assertFalse(engine.mirror()['ok'])
        self.assertEqual(fields, {})
        control = StaticarpControlTests()
        control.setUp()
        self.addCleanup(control.doCleanups)
        candidate = control.script.read_text().replace(str(control.configuration), str(self.configuration))
        candidate = candidate.replace(str(control.root / 'settings.lock'), str(self.root / 'settings.lock'))
        control.script.write_text(candidate)
        result = control.run_action('apply')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('needs recovery', result.stderr)
        self.assertEqual(control.calls(), [])

    def test_nonregular_destination_is_rejected_before_any_original_moves(self):
        old = self.seed()
        (self.configuration / 'interfaces.conf').unlink()
        outside = self.root / 'outside'
        outside.write_text('UNOWNED CONTENT')
        (self.configuration / 'interfaces.conf').symlink_to(outside)
        result = self.run_action('set', {'enabled': True, 'entries': '192.0.2.7 aa:bb:cc:dd:ee:07'})
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(self.state()['settings.conf'], old['settings.conf'])
        self.assertEqual(self.state()['entries.conf'], old['entries.conf'])
        self.assertEqual(outside.read_text(), 'UNOWNED CONTENT')
        self.assertTrue((self.configuration / 'interfaces.conf').is_symlink())
        self.assertFalse(list(self.configuration.glob('.staticarp-*')))

    def test_client_script_uses_valid_interface_bindings_and_crlf_without_backend_mutations(self):
        self.seed()
        with (self.configuration / 'entries.conf').open('a') as output:
            output.write('not-an-address not-a-mac\n')
        result = self.run_action('script', argument='lan')
        self.assertEqual(result['filename'], 'arp_vtnet1.cmd')
        self.assertIn('arp -s 192.0.2.1 aa-bb-cc-dd-ee-01\r\n', result['script'])
        self.assertIn('arp -s 192.0.2.8 aa-bb-cc-dd-ee-08\r\n', result['script'])
        self.assertNotIn('not-an-address', result['script'])
        self.assertNotIn('\n', result['script'].replace('\r\n', ''))
        self.assertEqual(self.run_action('script', argument='wan')['status'], 'failed')
        self.assertEqual(self.run_action('script', argument='lan;id')['status'], 'failed')
        self.assertEqual(self.run_action('unknown')['status'], 'failed')
        self.assertEqual(self.calls(), [])

    def test_apply_and_backup_wait_for_complete_save_and_mirror_runs_after_unlock(self):
        self.seed()
        control = StaticarpControlTests()
        control.setUp()
        self.addCleanup(control.doCleanups)
        candidate = control.script.read_text().replace(str(control.configuration), str(self.configuration))
        candidate = candidate.replace(str(control.root / 'settings.lock'), str(self.root / 'settings.lock'))
        control.script.write_text(candidate)
        pause, release = self.root / 'paused', self.root / 'release'
        payload = self.root / 'payload.json'
        payload.write_text(json.dumps({'enabled': True, 'entries': '192.0.2.7 aa:bb:cc:dd:ee:07',
                                      'modes': {'lan': 'staticarp'}}))
        environment = {**self.environment, 'STATICARP_TEST_PAUSE': str(pause), 'STATICARP_TEST_RELEASE': str(release)}
        writer = subprocess.Popen([PHP, str(self.driver), 'set', str(payload)], env=environment,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.addCleanup(lambda: writer.kill() if writer.poll() is None else None)
        deadline = time.monotonic() + 5
        while not pause.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        self.assertTrue(pause.exists(), 'The real first replacement was never reached.')
        reader = subprocess.Popen(['sh', str(control.script), 'apply'],
                                  env={**os.environ, 'STATICARP_TEST_EVENTS': str(control.events)},
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.addCleanup(lambda: reader.kill() if reader.poll() is None else None)
        repository = PACKAGE.parents[1]
        sys.path.insert(0, str(repository / 'src/common'))
        from config_backup import ConfigBackup, revision_token
        exported = {}
        def transport(action, payload=None):
            if action == 'import':
                return copy.deepcopy(exported)
            self.assertEqual(payload['_expected'], revision_token(exported))
            exported.update({key: value for key, value in payload.items() if key != '_expected'})
            return {'changed': True}
        profile = {'module': 'Staticarp', 'root_env': 'STATICARP_TEST_BACKUP_ROOT', 'trees': ['/configuration'],
                   'files': [], 'rc_paths': [], 'excludes': ['.staticarp-*'], 'data_lock': '/settings.lock'}
        previous = os.environ.get('STATICARP_TEST_BACKUP_ROOT')
        os.environ['STATICARP_TEST_BACKUP_ROOT'] = str(self.root)
        self.addCleanup(lambda: os.environ.pop('STATICARP_TEST_BACKUP_ROOT', None) if previous is None
                        else os.environ.__setitem__('STATICARP_TEST_BACKUP_ROOT', previous))
        engine = ConfigBackup(profile, transport=transport)
        results = []
        backup = threading.Thread(target=lambda: results.append(engine.mirror()))
        backup.start()
        try:
            time.sleep(0.2)
            self.assertIsNone(reader.poll(), 'ARP apply observed the unfinished save.')
            self.assertEqual(control.calls(), [])
            self.assertEqual(results, [], 'Backup captured the unfinished save.')
        finally:
            release.touch()
        output, errors = writer.communicate(timeout=10)
        self.assertEqual(errors, b'')
        self.assertEqual(json.loads(output)['status'], 'ok')
        output, errors = reader.communicate(timeout=10)
        self.assertEqual((reader.returncode, output, errors), (0, b'OK\n', b''))
        backup.join(timeout=10)
        self.assertFalse(backup.is_alive())
        self.assertEqual(results, [{'ok': True, 'changed': True, 'snapshot': True}])
        load = next(event for event in control.calls() if event['command'] == 'arp' and event['args'][0] == '-f')
        self.assertEqual(load['entries'], '192.0.2.7 aa:bb:cc:dd:ee:07\n')
        self.assertIn(['vtnet1', 'staticarp'], [event['args'] for event in control.calls() if event['command'] == 'ifconfig'])
        _, entries, _ = engine._decode(exported)
        import base64
        for filename in ['settings.conf', 'entries.conf', 'interfaces.conf']:
            self.assertEqual(base64.b64decode(entries['/configuration/' + filename]['data']),
                             (self.configuration / filename).read_bytes())


class StaticarpControlTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='staticarp-control-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.configuration = self.root / 'configuration'
        self.configuration.mkdir()
        self.events = self.root / 'events'
        command = self.root / 'command.py'
        command.write_text('''import json,os,sys
from pathlib import Path
args=sys.argv[1:]
event={'command':args[0],'args':args[1:]}
if args[:2]==['arp','-f']:event['entries']=Path(args[2]).read_text()
with Path(os.environ['STATICARP_TEST_EVENTS']).open('a') as output:output.write(json.dumps(event)+'\\n')
if args==['ifconfig']:print('vtnet1: flags\\n    inet 192.0.2.1 netmask 0xffffff00')
if os.environ.get('STATICARP_TEST_MIRROR_FAIL') and args[0]=='mirror':sys.exit(1)
if os.environ.get('STATICARP_TEST_COMMAND_FAIL') and args[0] in ['arp','ifconfig']:sys.exit(1)
''')
        source = CONTROL.read_text()
        source = source.replace('CONFIG_DIR="/usr/local/etc/staticarp"', 'CONFIG_DIR="' + str(self.configuration) + '"', 1)
        source = source.replace('LOCK_FILE="/var/db/os-staticarp-backup/settings.lock"',
                                'LOCK_FILE="' + str(self.root / 'settings.lock') + '"', 1)
        if not (sys.platform.startswith('freebsd') and Path('/usr/bin/lockf').exists()):
            lock = self.root / 'lock.py'
            lock.write_text('''import fcntl,subprocess,sys
args=sys.argv[1:]
assert args[:3]==['-k','-t','10']
with open(args[3],'a') as stream:
    fcntl.flock(stream,fcntl.LOCK_EX)
    raise SystemExit(subprocess.run(args[4:]).returncode)
''')
            source = source.replace('/usr/bin/lockf', '"' + sys.executable + '" "' + str(lock) + '"', 1)
        # Replace every mutating absolute command, including discovery, before execution.
        invocation = '"' + sys.executable + '" "' + str(command) + '" '
        source = source.replace('/sbin/ifconfig', invocation + 'ifconfig')
        source = source.replace('if ifconfig |', 'if ' + invocation + 'ifconfig |')
        source = source.replace('/usr/sbin/arp', invocation + 'arp')
        source = source.replace('/usr/local/bin/python3 /usr/local/opnsense/scripts/staticarp/config_mirror.py mirror',
                                invocation + 'mirror')
        # Both Linux and FreeBSD accept the directory form; temporary ARP lists stay private.
        source = source.replace('mktemp -t staticarp', 'mktemp "' + str(self.root / 'arp-list.XXXXXX') + '"')
        self.assertNotIn('/sbin/ifconfig', source)
        self.assertNotIn('/usr/sbin/arp', source)
        self.assertNotIn('if ifconfig |', source)
        self.script = self.root / 'staticarpctl'
        self.script.write_text(source)

    def seed(self, enabled='YES', entries='192.0.2.1 aa:bb:cc:dd:ee:01\n192.0.2.7 aa:bb:cc:dd:ee:07\n'):
        (self.configuration / 'settings.conf').write_text('enabled=' + enabled + '\n')
        (self.configuration / 'entries.conf').write_text(entries)
        (self.configuration / 'interfaces.conf').write_text('# comment\nlan vtnet1 staticarp\nopt1 vtnet2 -arp\nopt2 vtnet3 normal\n')

    def run_action(self, action, failure=None):
        return subprocess.run(['sh', str(self.script), action], env={**os.environ, 'STATICARP_TEST_EVENTS': str(self.events),
                              **(failure or {})}, capture_output=True, text=True, timeout=10)

    def calls(self):
        return [json.loads(line) for line in self.events.read_text().splitlines()] if self.events.exists() else []

    def test_enabled_apply_filters_router_ip_then_loads_arp_and_sets_each_interface_mode(self):
        self.seed()
        result = self.run_action('apply')
        self.assertEqual((result.returncode, result.stdout), (0, 'OK\n'), result.stderr)
        calls = self.calls()
        load = next(event for event in calls if event['command'] == 'arp' and event['args'][0] == '-f')
        self.assertEqual(load['entries'], '192.0.2.7 aa:bb:cc:dd:ee:07\n')
        mutations = [event['args'] for event in calls if event['command'] == 'ifconfig' and event['args']]
        self.assertEqual(mutations, [['vtnet1', 'arp', '-staticarp'], ['vtnet1', 'staticarp'],
                                     ['vtnet2', 'arp', '-staticarp'], ['vtnet2', '-arp'], ['vtnet3', 'arp', '-staticarp']])
        self.assertEqual(calls[-1]['command'], 'mirror')
        self.assertFalse(list(self.root.glob('arp-list.*')))

    def test_disabled_apply_and_reset_only_clear_bindings_and_restore_normal_reply_modes(self):
        for action in ['apply', 'reset']:
            with self.subTest(action=action):
                self.seed(enabled='NO')
                self.events.unlink(missing_ok=True)
                result = self.run_action(action)
                self.assertEqual((result.returncode, result.stdout), (0, 'OK\n'))
                calls = self.calls()
                self.assertEqual([event['args'] for event in calls if event['command'] == 'arp'], [['-d', '-a']])
                self.assertEqual([event['args'] for event in calls if event['command'] == 'ifconfig'],
                                 [['vtnet1', 'arp', '-staticarp'], ['vtnet2', 'arp', '-staticarp'], ['vtnet3', 'arp', '-staticarp']])
                self.assertEqual(calls[-1]['command'], 'mirror')

    def test_empty_or_local_only_entries_never_flush_or_load_the_arp_table(self):
        for entries in ['', '# comment\n', '192.0.2.1 aa:bb:cc:dd:ee:01\n']:
            with self.subTest(entries=entries):
                self.seed(entries=entries)
                self.events.unlink(missing_ok=True)
                self.assertEqual(self.run_action('apply').returncode, 0)
                self.assertFalse(any(event['command'] == 'arp' for event in self.calls()))

    def test_kernel_commands_are_best_effort_but_backup_failure_cannot_report_ok(self):
        self.seed()
        result = self.run_action('apply', {'STATICARP_TEST_COMMAND_FAIL': '1'})
        self.assertEqual((result.returncode, result.stdout), (0, 'OK\n'))
        self.events.unlink(missing_ok=True)
        result = self.run_action('apply', {'STATICARP_TEST_MIRROR_FAIL': '1'})
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('OK', result.stdout)

    def test_status_and_unknown_actions_do_not_mutate_configuration_or_call_commands(self):
        self.seed(entries='# comment\n\n192.0.2.7 aa:bb:cc:dd:ee:07\n192.0.2.8 aa:bb:cc:dd:ee:08\n')
        result = self.run_action('status')
        self.assertEqual(result.stdout, 'enabled=YES\nentries=2\n')
        self.assertEqual(self.calls(), [])
        result = self.run_action('unknown')
        self.assertEqual(result.returncode, 64)
        self.assertIn('usage:', result.stderr)
        self.assertEqual(self.calls(), [])


if __name__ == '__main__':
    unittest.main()
