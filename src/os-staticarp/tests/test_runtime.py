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
        control.driver.write_text(control.driver.read_text().replace(str(control.configuration), str(self.configuration)))
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
        control.driver.write_text(control.driver.read_text().replace(str(control.configuration), str(self.configuration)))
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
        control.driver.write_text(control.driver.read_text().replace(str(control.configuration), str(self.configuration)))
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
                                  env=control.environment,
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
        load = next(event for event in control.calls() if event['command'] == 'arp' and event['args'][0] == '-i')
        self.assertEqual(load['args'], ['-i', 'vtnet1', '-s', '192.0.2.7', 'aa:bb:cc:dd:ee:07'])
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
        self.kernel = self.root / 'kernel.json'
        self.kernel.write_text(json.dumps({'bindings': {'vtnet0|198.51.100.1':
                              {'mac': 'aa:bb:cc:dd:ee:90', 'permanent': False, 'published': False}},
                              'modes': {'vtnet0': {'noarp': False, 'staticarp': False},
                                        'vtnet1': {'noarp': True, 'staticarp': False},
                                        'vtnet2': {'noarp': False, 'staticarp': True},
                                        'vtnet2.20': {'noarp': False, 'staticarp': False},
                                        'vtnet3': {'noarp': False, 'staticarp': False}}}))
        command = self.root / 'command.py'
        command.write_text(r'''import json,os,sys
from pathlib import Path
args=sys.argv[1:]
event={'command':args[0],'args':args[1:]}
with Path(os.environ['STATICARP_TEST_EVENTS']).open('a') as output:output.write(json.dumps(event)+'\n')
path=Path(os.environ['STATICARP_TEST_KERNEL'])
state=json.loads(path.read_text())
mutating=False
if args==['ifconfig','-a']:
    for device,mode in state['modes'].items():
        flags=['UP','BROADCAST']+(['NOARP'] if mode['noarp'] else [])+(['STATICARP'] if mode['staticarp'] else [])
        print(device+': flags=1<'+','.join(flags)+'>')
        if device=='vtnet1':print('    inet 192.0.2.1 netmask 0xffffff00')
elif args==['arp','-an']:
    for key,value in state['bindings'].items():
        device,ip=key.split('|')
        print('? ('+ip+') at '+value['mac']+' on '+device+(' permanent' if value['permanent'] else ' expires in 90 seconds')+(' published' if value['published'] else '')+' [ethernet]')
elif args[0]=='route':
    print('    interface: '+('vtnet0' if args[-1].startswith('198.51.100.') else 'vtnet1'))
    print('        flags: <UP,DONE>')
elif args[:2]==['arp','-i']:
    device,ip,mac=args[2],args[4],args[5]
    state['bindings'][device+'|'+ip]={'mac':mac,'permanent':True,'published':'pub' in args}
    mutating=True
elif args[0]=='delete':
    state['bindings'].pop(args[1],None)
    mutating=True
elif args[0]=='ifconfig':
    for flag in args[2:]:
        if flag in ('arp','-arp'):state['modes'][args[1]]['noarp']=flag=='-arp'
        elif flag in ('staticarp','-staticarp'):state['modes'][args[1]]['staticarp']=flag=='staticarp'
    mutating=True
elif args[0]=='mirror':
    if os.environ.get('STATICARP_TEST_MIRROR_FAIL'):sys.exit(1)
else:raise SystemExit('Uncaptured fixture command: '+repr(args))
if mutating:
    fault=os.environ.get('STATICARP_TEST_COMMAND_FAIL')
    if fault=='before' or (fault=='rollback' and args[0]=='delete'):sys.exit(1)
    path.write_text(json.dumps(state))
    if fault=='after' and args[0]!='delete':sys.exit(1)
    if fault=='rollback' and args[0]!='delete':sys.exit(1)
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
        invocation = '"' + sys.executable + '" "' + str(command) + '" '
        runtime = PACKAGE / 'src/usr/local/opnsense/scripts/staticarp/runtime.py'
        self.runtime_path = self.root / 'runtime.py'
        self.runtime_path.write_text(runtime.read_text())
        # Keep production discovery/parsing/mutations; redirect executables only.
        driver = self.root / 'runtime-driver.py'
        self.driver = driver
        driver.write_text('import sys\nimport runtime\n'
            + 'class FixtureSystem(runtime.System):\n'
            + '    def boot_id(self): return __import__("os").environ.get("STATICARP_TEST_BOOT","100:0")\n'
            + '    def interface_index(self,device): return int(__import__("os").environ.get("STATICARP_TEST_INDEX","10"))\n'
            + '    def run(self,*args):\n'
            + '        return super().run(sys.executable,' + repr(str(command)) + ',args[0].split("/")[-1],*args[1:])\n'
            + '    def mutate_binding(self,key,target):\n'
            + '        if target is None or not target["permanent"]: self.run("delete",key)\n'
            + '        else: super().mutate_binding(key,target)\n'
            + 'engine=runtime.Runtime(system=FixtureSystem(),config_dir=' + repr(str(self.configuration))
            + ',state_file=' + repr(str(self.root / 'state/runtime.json')) + ')\n'
            + 'if __import__("os").environ.get("STATICARP_TEST_JOURNAL_FAIL"):\n'
            + '    original=engine.save\n'
            + '    def fail_after_write():\n'
            + '        if any("pending" not in row and row["after"] != row["before"] for kind in ("bindings","modes") for row in engine.state[kind].values()): raise OSError("simulated journal disk failure")\n'
            + '        original()\n'
            + '    engine.save=fail_after_write\n'
            + 'engine.apply(reset=sys.argv[1]=="reset")\n')
        source = source.replace('/usr/local/bin/python3 /usr/local/opnsense/scripts/staticarp/runtime.py',
                                '"' + sys.executable + '" "' + str(driver) + '"')
        source = source.replace('/usr/local/bin/python3 /usr/local/opnsense/scripts/staticarp/config_mirror.py mirror',
                                invocation + 'mirror')
        self.script = self.root / 'staticarpctl'
        self.script.write_text(source)
        self.environment = {**os.environ, 'STATICARP_TEST_EVENTS': str(self.events),
                            'STATICARP_TEST_KERNEL': str(self.kernel)}

    def seed(self, enabled='YES', entries='192.0.2.1 aa:bb:cc:dd:ee:01\n192.0.2.7 aa:bb:cc:dd:ee:07\n'):
        (self.configuration / 'settings.conf').write_text('enabled=' + enabled + '\n')
        (self.configuration / 'entries.conf').write_text(entries)
        (self.configuration / 'interfaces.conf').write_text('# comment\nlan vtnet1 staticarp\nopt1 vtnet2 -arp\nopt2 vtnet3 normal\n')

    def run_action(self, action, failure=None):
        return subprocess.run(['sh', str(self.script), action], env={**self.environment, **(failure or {})},
                              capture_output=True, text=True, timeout=10)

    def calls(self):
        return [json.loads(line) for line in self.events.read_text().splitlines()] if self.events.exists() else []

    def kernel_state(self):
        return json.loads(self.kernel.read_text())

    def modify_kernel(self, callback):
        state = self.kernel_state()
        callback(state)
        self.kernel.write_text(json.dumps(state))

    def test_apply_journals_exact_changes_and_reset_restores_original_modes_without_foreign_loss(self):
        self.seed()
        before = self.kernel_state()
        result = self.run_action('apply')
        self.assertEqual((result.returncode, result.stdout), (0, 'OK\n'), result.stderr)
        after = self.kernel_state()
        self.assertEqual(after['bindings']['vtnet0|198.51.100.1'], before['bindings']['vtnet0|198.51.100.1'])
        self.assertEqual(after['bindings']['vtnet1|192.0.2.7']['mac'], 'aa:bb:cc:dd:ee:07')
        self.assertNotIn('vtnet1|192.0.2.1', after['bindings'])
        journal = self.root / 'state/runtime.json'
        self.assertEqual(journal.stat().st_mode & 0o777, 0o600)
        self.assertEqual(journal.parent.stat().st_mode & 0o777, 0o700)
        self.assertEqual(self.run_action('reset').returncode, 0)
        self.assertEqual(self.kernel_state(), before)
        self.assertFalse(any(event['args'] == ['-d', '-a'] for event in self.calls()))

    def test_new_disabled_apply_and_reset_do_not_mutate_any_neighbor_or_interface(self):
        self.seed(enabled='NO')
        before = self.kernel.read_bytes()
        for action in ('apply', 'reset'):
            result = self.run_action(action)
            self.assertEqual((result.returncode, result.stdout), (0, 'OK\n'), result.stderr)
            self.assertEqual(self.kernel.read_bytes(), before)
            self.assertFalse((self.root / 'state/runtime.json').exists())
        self.assertTrue(all(event['command'] == 'mirror' for event in self.calls()))

    def test_interface_flag_failure_cannot_report_ok_and_single_flag_journal_restores_prior_mode(self):
        self.seed()
        self.modify_kernel(lambda state: state['bindings'].update({'vtnet1|192.0.2.7':
                           {'mac': 'aa:bb:cc:dd:ee:07', 'permanent': True, 'published': False}}))
        before = self.kernel_state()
        for point in ('before', 'after'):
            with self.subTest(point=point):
                result = self.run_action('apply', {'STATICARP_TEST_COMMAND_FAIL': point})
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn('OK', result.stdout)
                self.assertEqual(self.run_action('reset').returncode, 0)
                self.assertEqual(self.kernel_state(), before)
        self.assertEqual(self.run_action('apply').returncode, 0)
        self.assertTrue(all(len(event['args']) == 2 for event in self.calls()
                            if event['command'] == 'ifconfig' and event['args'] != ['-a']))
        self.assertEqual(self.run_action('reset').returncode, 0)
        self.assertEqual(self.kernel_state(), before)

    def test_foreign_static_binding_is_restored_and_identical_foreign_binding_is_not_claimed(self):
        self.seed()
        original = {'mac': 'aa:bb:cc:dd:ee:99', 'permanent': True, 'published': False}
        self.modify_kernel(lambda state: state['bindings'].update({'vtnet1|192.0.2.7': original}))
        self.assertEqual(self.run_action('apply').returncode, 0)
        self.assertEqual(self.run_action('reset').returncode, 0)
        self.assertEqual(self.kernel_state()['bindings']['vtnet1|192.0.2.7'], original)
        self.seed(entries='192.0.2.7 aa:bb:cc:dd:ee:99\n')
        self.assertEqual(self.run_action('apply').returncode, 0)
        journal = json.loads((self.root / 'state/runtime.json').read_text())
        self.assertEqual(journal['bindings'], {})
        self.assertEqual(self.run_action('reset').returncode, 0)
        self.assertEqual(self.kernel_state()['bindings']['vtnet1|192.0.2.7'], original)

    def test_later_admin_binding_and_mode_changes_survive_reset_and_conflicting_apply_fails(self):
        self.seed()
        self.assertEqual(self.run_action('apply').returncode, 0)
        edited = {'mac': 'aa:bb:cc:dd:ee:88', 'permanent': True, 'published': False}
        self.modify_kernel(lambda state: (state['bindings'].update({'vtnet1|192.0.2.7': edited}),
                                         state['modes'].update({'vtnet1': {'noarp': False, 'staticarp': False}})))
        result = self.run_action('apply')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('OK', result.stdout)
        self.assertEqual(self.kernel_state()['bindings']['vtnet1|192.0.2.7'], edited)
        self.assertEqual(self.run_action('reset').returncode, 0)
        self.assertEqual(self.kernel_state()['bindings']['vtnet1|192.0.2.7'], edited)
        self.assertEqual(self.kernel_state()['modes']['vtnet1'], {'noarp': False, 'staticarp': False})

    def test_failed_kernel_operation_reports_failure_and_retains_recoverable_state(self):
        self.seed()
        before = self.kernel_state()
        for point in ('before', 'after'):
            result = self.run_action('apply', {'STATICARP_TEST_COMMAND_FAIL': point})
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn('OK', result.stdout)
            self.assertEqual(self.kernel_state(), before)
        self.assertEqual(self.run_action('apply').returncode, 0)
        self.assertEqual(self.run_action('reset').returncode, 0)
        self.assertEqual(self.kernel_state(), before)
        result = self.run_action('apply', {'STATICARP_TEST_MIRROR_FAIL': '1'})
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('OK', result.stdout)
        self.assertEqual(self.run_action('reset').returncode, 0)

    def test_crash_after_write_ahead_and_rollback_failure_recover_without_foreign_loss(self):
        self.seed()
        before = self.kernel_state()
        for failure in ({'STATICARP_TEST_COMMAND_FAIL': 'rollback'}, {'STATICARP_TEST_JOURNAL_FAIL': '1'}):
            with self.subTest(failure=failure):
                result = self.run_action('apply', failure)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn('OK', result.stdout)
                durable = json.loads((self.root / 'state/runtime.json').read_text())
                self.assertIn('pending', durable['bindings']['vtnet1|192.0.2.7'])
                self.assertEqual(self.kernel_state()['bindings']['vtnet0|198.51.100.1'], before['bindings']['vtnet0|198.51.100.1'])
                self.assertEqual(self.run_action('reset').returncode, 0)
                self.assertEqual(self.kernel_state(), before)

    def test_failed_initial_write_does_not_claim_or_remove_an_unchanged_dynamic_neighbor(self):
        self.seed()
        dynamic = {'mac': 'aa:bb:cc:dd:ee:07', 'permanent': False, 'published': False}
        self.modify_kernel(lambda state: state['bindings'].update({'vtnet1|192.0.2.7': dynamic}))
        before = self.kernel_state()
        self.assertNotEqual(self.run_action('apply', {'STATICARP_TEST_COMMAND_FAIL': 'before'}).returncode, 0)
        self.assertEqual(self.run_action('reset').returncode, 0)
        self.assertEqual(self.kernel_state(), before)

    def test_corrupt_or_non_private_journal_refuses_all_kernel_mutations(self):
        self.seed()
        before = self.kernel.read_bytes()
        directory = self.root / 'state'
        directory.mkdir(mode=0o700)
        journal = directory / 'runtime.json'
        journal.write_text('{not valid JSON')
        journal.chmod(0o600)
        self.assertNotEqual(self.run_action('apply').returncode, 0)
        self.assertEqual(self.kernel.read_bytes(), before)
        journal.write_text(json.dumps({'version': 1, 'bindings': {}, 'modes': {}, 'conflicts': []}))
        journal.chmod(0o644)
        self.assertNotEqual(self.run_action('apply').returncode, 0)
        self.assertEqual(self.kernel.read_bytes(), before)
        journal.unlink()
        journal.symlink_to(self.kernel)
        self.assertNotEqual(self.run_action('apply').returncode, 0)
        self.assertEqual(self.kernel.read_bytes(), before)

    def test_removed_entry_restores_only_owned_neighbor_and_changed_desired_mac_keeps_original_snapshot(self):
        self.seed()
        before = self.kernel_state()
        self.assertEqual(self.run_action('apply').returncode, 0)
        self.seed(entries='192.0.2.7 aa:bb:cc:dd:ee:08\n')
        self.assertEqual(self.run_action('apply').returncode, 0)
        self.assertEqual(self.kernel_state()['bindings']['vtnet1|192.0.2.7']['mac'], 'aa:bb:cc:dd:ee:08')
        self.seed(entries='')
        self.assertEqual(self.run_action('apply').returncode, 0)
        self.assertEqual(self.kernel_state()['bindings'], before['bindings'])
        self.assertEqual(self.run_action('reset').returncode, 0)
        self.assertEqual(self.kernel_state(), before)

    def test_no_old_journal_does_not_infer_ownership_and_unavailable_or_wan_bindings_fail_before_mutation(self):
        self.seed(enabled='NO')
        before = self.kernel.read_bytes()
        self.assertEqual(self.run_action('reset').returncode, 0)
        self.assertEqual(self.kernel.read_bytes(), before)
        self.seed(entries='198.51.100.10 aa:bb:cc:dd:ee:10\n')
        self.assertNotEqual(self.run_action('apply').returncode, 0)
        self.assertEqual(self.kernel.read_bytes(), before)
        self.seed()
        (self.configuration / '.staticarp-recovery-old').write_text('not recovered')
        self.assertNotEqual(self.run_action('apply').returncode, 0)
        self.assertEqual(self.kernel.read_bytes(), before)

    def test_new_kernel_boot_reapplies_explicit_settings_to_a_new_baseline_without_old_ownership(self):
        self.seed()
        self.assertEqual(self.run_action('apply').returncode, 0)
        self.modify_kernel(lambda state: (state['bindings'].pop('vtnet1|192.0.2.7'),
                                         state['modes'].update({'vtnet1': {'noarp': False, 'staticarp': False}})))
        result = self.run_action('apply', {'STATICARP_TEST_BOOT': '200:0'})
        self.assertEqual(result.returncode, 0, result.stderr)
        journal = json.loads((self.root / 'state/runtime.json').read_text())
        self.assertEqual(journal['boot'], '200:0')
        self.assertEqual(journal['modes']['vtnet1']['before'], {'noarp': False, 'staticarp': False})
        self.assertEqual(self.run_action('reset', {'STATICARP_TEST_BOOT': '200:0'}).returncode, 0)
        self.assertEqual(self.kernel_state()['modes']['vtnet1'], {'noarp': False, 'staticarp': False})

    def test_interface_replaced_with_same_name_and_state_is_not_touched_by_old_ownership(self):
        self.seed()
        self.assertEqual(self.run_action('apply').returncode, 0)
        before = self.kernel.read_bytes()
        self.assertNotEqual(self.run_action('apply', {'STATICARP_TEST_INDEX': '11'}).returncode, 0)
        self.assertEqual(self.kernel.read_bytes(), before)
        self.assertEqual(self.run_action('reset', {'STATICARP_TEST_INDEX': '11'}).returncode, 0)
        self.assertEqual(self.kernel.read_bytes(), before)

    def test_status_and_unknown_actions_do_not_call_kernel_commands(self):
        self.seed(entries='# comment\n\n192.0.2.7 aa:bb:cc:dd:ee:07\n192.0.2.8 aa:bb:cc:dd:ee:08\n')
        self.assertEqual(self.run_action('status').stdout, 'enabled=YES\nentries=2\n')
        self.assertEqual(self.calls(), [])
        self.assertEqual(self.run_action('unknown').returncode, 64)
        self.assertEqual(self.calls(), [])


if __name__ == '__main__':
    unittest.main()
