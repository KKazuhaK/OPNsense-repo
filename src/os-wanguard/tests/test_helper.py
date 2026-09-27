"""Run the real helper.php against stand-ins for core's functions and private paths.

The copy differs from the shipped script only in its paths and wait timings;
core's interface functions are replaced by recording stubs, so every refusal,
the bounded stop, the lease discard and the restart attempts can be exercised
without a router.
"""
import fcntl
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

PACKAGE = Path(__file__).resolve().parents[1]
HELPER = PACKAGE / 'src/usr/local/opnsense/scripts/wanguard/helper.php'
sys.path.insert(0, str(HELPER.parent))
import guard  # noqa: E402
import wanguard  # noqa: E402

STUB = r'''<?php
$GLOBALS['scenario'] = json_decode(file_get_contents(getenv('WANGUARD_SCENARIO')), true);

function scenario_event(array $entry)
{
    file_put_contents(getenv('WANGUARD_EVENTS'), json_encode($entry) . "\n", FILE_APPEND);
}

function scenario_state()
{
    $path = getenv('WANGUARD_STATE');
    return is_file($path) ? json_decode(file_get_contents($path), true) : ['running' => $GLOBALS['scenario']['running'], 'configured' => 0];
}

function scenario_save(array $state)
{
    file_put_contents(getenv('WANGUARD_STATE'), json_encode($state));
}

function scenario_device($pidfile)
{
    return preg_replace('/^.*dhclient\.(.*)\.pid$/', '$1', $pidfile);
}

final class product
{
    public static function getInstance()
    {
        return new self();
    }

    public function booting()
    {
        return $GLOBALS['scenario']['booting'] ? true : null;
    }
}

function &config_read_array()
{
    $keys = func_get_args();
    if (is_bool(end($keys))) {
        array_pop($keys);
    }
    $node = $GLOBALS['scenario']['config'];
    foreach ($keys as $key) {
        if (!isset($node[$key]) || !is_array($node[$key])) {
            $empty = [];
            return $empty;
        }
        $node = $node[$key];
    }
    return $node;
}

function legacy_interfaces_details($intf = null)
{
    scenario_event(['details', $intf]);
    $all = $GLOBALS['scenario']['details'];
    if ($intf === null) {
        return $all;
    }
    return isset($all[$intf]) ? [$intf => $all[$intf]] : [];
}

function interfaces_primary_address($interface, $ifconfig_details = null)
{
    return [$GLOBALS['scenario']['addresses'][$interface] ?? null, null, null, null];
}

function isvalidpid($pidfile)
{
    return !empty(scenario_state()['running'][scenario_device($pidfile)]);
}

function killbypid($pidfile, $sig = 'TERM', $waitforit = true)
{
    scenario_event(['kill', scenario_device($pidfile), $sig, $waitforit]);
    if (empty($GLOBALS['scenario']['stuck'])) {
        $state = scenario_state();
        $state['running'][scenario_device($pidfile)] = false;
        scenario_save($state);
    }
}

function interface_dhcp_configure($interface = 'wan')
{
    $state = scenario_state();
    $state['configured']++;
    $device = $GLOBALS['scenario']['config']['interfaces'][$interface]['if'];
    scenario_event(['configure', $interface, file_exists(getenv('WANGUARD_LEASES') . "/dhclient.leases.$device")]);
    if ($state['configured'] >= $GLOBALS['scenario']['starts_on']) {
        $state['running'][$device] = true;
    }
    scenario_save($state);
}
'''


class HelperTests(unittest.TestCase):
    def setUp(self):
        if not shutil.which('php'):
            self.skipTest('PHP is not installed')
        self.temporary = tempfile.TemporaryDirectory(prefix='wanguard-helper-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.run_dir = self.root / 'run'
        self.db = self.root / 'db'
        self.leases = self.root / 'leases'
        self.leases.mkdir()
        includes = self.root / 'inc'
        includes.mkdir()
        (includes / 'config.inc').write_text(STUB)
        (includes / 'util.inc').write_text('<?php\n')
        (includes / 'interfaces.inc').write_text('<?php\n')
        self.includes = includes
        source = HELPER.read_text()
        replacements = [
            ("const WANGUARD_RUN = '/var/run/wanguard';", "const WANGUARD_RUN = '%s';" % self.run_dir),
            ("const WANGUARD_DB = '/var/db/os-wanguard';", "const WANGUARD_DB = '%s';" % self.db),
            ('"/var/run/dhclient.{$device}.pid"', '"%s/dhclient.{$device}.pid"' % (self.root / 'pids')),
            ('"/var/db/dhclient.leases.{$device}"', '"%s/dhclient.leases.{$device}"' % self.leases),
            ('const WANGUARD_WAIT = 50;', 'const WANGUARD_WAIT = 3;'),
            ('usleep(200 * 1000);', 'usleep(1000);'),
            ("    openlog('wanguard', LOG_ODELAY, LOG_DAEMON);\n    syslog($priority, $message);",
             "    scenario_event(['log', $priority, $message]);"),
        ]
        for old, new in replacements:
            self.assertIn(old, source)
            source = source.replace(old, new)
        self.helper = self.root / 'helper.php'
        self.helper.write_text(source)
        self.events = self.root / 'events'
        self.scenario_file = self.root / 'scenario.json'

    def scenario(self, **changes):
        value = {
            'config': {'OPNsense': {'wanguard': {'general': {
                'enabled': '1', 'interfaces': 'wan,opt2,opt1,opt3,opt9,opt4', 'networks': '10.0.3.0/24, 172.31.254.0/24',
                'private_ranges': '0'}}},
                'interfaces': {
                    'wan': {'if': 'vtnet1', 'enable': '1', 'ipaddr': 'dhcp', 'descr': 'WAN'},
                    'opt2': {'if': 'vtnet3', 'enable': '1', 'ipaddr': 'dhcp', 'descr': 'WAN2'},
                    'opt1': {'if': 'vtnet2', 'enable': '1', 'ipaddr': '192.168.2.1', 'descr': 'LAN2'},
                    'opt3': {'if': 'vtnet4', 'ipaddr': 'dhcp'},
                    'opt4': {'if': 'bad dev', 'enable': '1', 'ipaddr': 'dhcp'},
                    'lan': {'if': 'vtnet0', 'enable': '1', 'ipaddr': '192.168.1.1'}}},
            'details': {'vtnet1': {'status': 'active'}, 'vtnet3': {'status': 'active'}, 'vtnet2': {'status': 'active'},
                        'vtnet4': {'status': 'no carrier'}},
            'addresses': {'wan': '198.51.100.7', 'opt2': '10.0.3.15', 'opt1': '192.168.2.1', 'opt3': '10.0.3.16'},
            'running': {'vtnet1': True, 'vtnet3': True},
            'booting': False, 'stuck': False, 'starts_on': 1,
        }
        for key, change in changes.items():
            if callable(change):
                change(value)
            else:
                value[key] = change
        self.scenario_file.write_text(json.dumps(value))

    def call(self, *arguments):
        result = subprocess.run(['php', '-d', 'include_path=' + str(self.includes), str(self.helper), *arguments],
                                capture_output=True, text=True, timeout=30,
                                env={**os.environ, 'WANGUARD_SCENARIO': str(self.scenario_file),
                                     'WANGUARD_EVENTS': str(self.events), 'WANGUARD_STATE': str(self.root / 'state.json'),
                                     'WANGUARD_LEASES': str(self.leases)})
        lines = result.stdout.strip().splitlines()
        self.assertEqual(len(lines), 1, result.stdout + result.stderr)
        return json.loads(lines[0]), result.returncode

    def recorded(self, kind=None):
        if not self.events.exists():
            return []
        entries = [json.loads(line) for line in self.events.read_text().splitlines()]
        return [entry for entry in entries if kind is None or entry[0] == kind]

    def test_observe_reports_only_what_the_daemon_decides_on(self):
        self.scenario()
        answer, code = self.call('observe')
        self.assertEqual(code, 0)
        self.assertEqual({key: answer[key] for key in ['enabled', 'booting', 'watched', 'networks', 'private_ranges']},
                         {'enabled': True, 'booting': False, 'watched': ['wan', 'opt2', 'opt1', 'opt3', 'opt9', 'opt4'],
                          'networks': ['10.0.3.0/24', '172.31.254.0/24'], 'private_ranges': False})
        rows = {row['name']: row for row in answer['interfaces']}
        self.assertEqual(rows['wan'], {'name': 'wan', 'descr': 'WAN', 'exists': True, 'device': 'vtnet1', 'enabled': True,
                                       'ipaddr': 'dhcp', 'eligible': True, 'address': '198.51.100.7', 'carrier': True,
                                       'dhclient_running': True})
        self.assertEqual((rows['opt2']['address'], rows['opt2']['eligible']), ('10.0.3.15', True))
        # Static, disabled, missing or oddly named interfaces are never looked at.
        for name in ['opt1', 'opt3', 'opt9', 'opt4']:
            self.assertFalse(rows[name]['eligible'], name)
            self.assertIsNone(rows[name]['address'], name)
        self.assertFalse(rows['opt9']['exists'])
        self.assertEqual(rows['opt9']['descr'], 'OPT9')
        self.assertEqual(self.recorded('details'), [['details', None]])

    def test_a_disabled_or_unconfigured_plugin_observes_nothing(self):
        for change in [lambda value: value['config']['OPNsense']['wanguard']['general'].update(enabled='0'),
                       lambda value: value['config'].pop('OPNsense')]:
            self.events.unlink(missing_ok=True)
            self.scenario(config=change)
            answer, _ = self.call('observe')
            self.assertFalse(answer['enabled'])
            self.assertEqual(answer['interfaces'], [])
            self.assertEqual(self.recorded('details'), [])

    def test_a_dhcp_lan_is_never_eligible(self):
        def lan_watched(value):
            value['config']['OPNsense']['wanguard']['general']['interfaces'] = 'lan,opt2'
            value['config']['interfaces']['lan']['ipaddr'] = 'dhcp'
        self.scenario(config=lan_watched, addresses={'lan': '10.0.3.20', 'opt2': '10.0.3.15'},
                      running={'vtnet0': True, 'vtnet3': True})
        answer, _ = self.call('observe')
        rows = {row['name']: row for row in answer['interfaces']}
        self.assertEqual((rows['lan']['eligible'], rows['lan']['address']), (False, None))
        self.assertTrue(rows['opt2']['eligible'])

    def test_a_carrier_loss_is_reported(self):
        self.scenario(details={'vtnet3': {'status': 'no carrier'}, 'vtnet1': {}})
        answer, _ = self.call('observe')
        rows = {row['name']: row for row in answer['interfaces']}
        self.assertFalse(rows['opt2']['carrier'])
        self.assertTrue(rows['wan']['carrier'])

    def test_redhcp_restarts_the_client_without_its_lease_memory(self):
        self.scenario()
        lease = self.leases / 'dhclient.leases.vtnet3'
        lease.write_text('lease { fixed-address 10.0.3.15; }\n')
        other = self.leases / 'dhclient.leases.vtnet1'
        other.write_text('untouched')
        answer, code = self.call('redhcp', 'opt2', '10.0.3.15', 'address 10.0.3.15 is in 10.0.3.0/24')
        self.assertEqual((answer, code), ({'result': 'requested', 'lease': 'discarded'}, 0))
        self.assertEqual(self.recorded('kill'), [['kill', 'vtnet3', 'TERM', False]])
        # The new client starts only after the memory is gone.
        self.assertEqual(self.recorded('configure'), [['configure', 'opt2', False]])
        copy = self.db / 'dhclient.leases.vtnet3.discarded'
        self.assertEqual(copy.read_text(), 'lease { fixed-address 10.0.3.15; }\n')
        self.assertEqual(copy.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.db.stat().st_mode & 0o777, 0o700)
        self.assertEqual(other.read_text(), 'untouched')
        messages = [entry[2] for entry in self.recorded('log')]
        self.assertEqual(len(messages), 2)
        self.assertIn('stopping the IPv4 DHCP client on opt2 (vtnet3) to discard its lease: address 10.0.3.15', messages[0])
        self.assertIn('started a new IPv4 DHCP client on opt2 (vtnet3); lease memory discarded', messages[1])
        self.assertEqual(self.recorded('details'), [['details', 'vtnet3']])

    def test_redhcp_never_starts_a_client_that_was_not_running(self):
        # The interface may still wait for an interface apply, or core stopped
        # its client on purpose: nothing is touched and nothing is counted.
        self.scenario(running={'vtnet3': False})
        lease = self.leases / 'dhclient.leases.vtnet3'
        lease.write_text('kept')
        answer, code = self.call('redhcp', 'opt2', '10.0.3.15', 'test')
        self.assertEqual((answer, code), ({'result': 'refused:no-client'}, 0))
        self.assertEqual(self.recorded('kill') + self.recorded('configure') + self.recorded('log'), [])
        self.assertEqual(lease.read_text(), 'kept')

    def test_redhcp_without_a_lease_file(self):
        self.scenario()
        answer, _ = self.call('redhcp', 'opt2', '10.0.3.15', 'test')
        self.assertEqual(answer, {'result': 'requested', 'lease': 'none'})
        self.assertEqual(self.recorded('kill'), [['kill', 'vtnet3', 'TERM', False]])
        self.assertEqual(self.recorded('configure'), [['configure', 'opt2', False]])

    def test_every_guard_refuses_before_anything_is_touched(self):
        general = lambda **fields: (lambda value: value['config']['OPNsense']['wanguard']['general'].update(fields))

        def lan_watched(value):
            value['config']['OPNsense']['wanguard']['general']['interfaces'] = 'wan,lan'
            value['config']['interfaces']['lan']['ipaddr'] = 'dhcp'
        cases = [
            ({'config': general(enabled='0')}, ('opt2', '10.0.3.15'), 'refused:disabled'),
            ({'config': general(interfaces='wan')}, ('opt2', '10.0.3.15'), 'refused:not-watched'),
            ({}, ('lan', '192.168.1.1'), 'refused:not-watched'),
            ({'config': lan_watched}, ('lan', '192.168.1.1'), 'refused:lan'),
            ({}, ('opt1', '192.168.2.1'), 'refused:not-dhcp'),
            ({}, ('opt3', '10.0.3.16'), 'refused:not-dhcp'),
            ({}, ('opt4', '10.0.3.15'), 'refused:not-dhcp'),
            ({}, ('opt9', '10.0.3.15'), 'refused:not-dhcp'),
            ({'booting': True}, ('opt2', '10.0.3.15'), 'refused:booting'),
            ({}, ('opt2', '10.0.3.99'), 'refused:address-changed'),
            ({'addresses': {'opt2': None}}, ('opt2', '10.0.3.15'), 'refused:address-changed'),
            ({'details': {'vtnet3': {'status': 'no carrier'}}}, ('opt2', '10.0.3.15'), 'refused:no-carrier'),
            ({'details': {}}, ('opt2', '10.0.3.15'), 'refused:no-carrier'),
        ]
        lease = self.leases / 'dhclient.leases.vtnet3'
        for changes, (name, address), expected in cases:
            with self.subTest(name=name, expected=expected, changes=sorted(changes)):
                self.events.unlink(missing_ok=True)
                (self.root / 'state.json').unlink(missing_ok=True)
                lease.write_text('kept')
                self.scenario(**changes)
                answer, code = self.call('redhcp', name, address, 'test')
                self.assertEqual((answer, code), ({'result': expected}, 0))
                self.assertEqual(self.recorded('kill') + self.recorded('configure'), [])
                self.assertEqual(lease.read_text(), 'kept')

    def test_malformed_requests_are_refused(self):
        self.scenario()
        for arguments in [('redhcp', 'OPT2', '10.0.3.15', 'x'), ('redhcp', 'opt2', 'fe80::1', 'x'),
                          ('redhcp', 'opt2', '10.0.3.15'), ('redhcp', 'opt2', 'garbage', 'x'),
                          ('restore', 'opt2', 'extra'), ('restore', '../x'), ('explode', 'opt2'), ()]:
            with self.subTest(arguments=arguments):
                answer, code = self.call(*arguments)
                self.assertEqual((answer, code), ({'result': 'refused:invalid'}, 2))
        self.assertEqual(self.recorded('kill') + self.recorded('configure'), [])

    def test_a_second_action_is_busy(self):
        self.scenario()
        self.run_dir.mkdir(mode=0o700)
        with open(self.run_dir / 'action.lock', 'w') as holder:
            fcntl.flock(holder, fcntl.LOCK_EX)
            self.assertEqual(self.call('redhcp', 'opt2', '10.0.3.15', 'x')[0], {'result': 'busy'})
            self.assertEqual(self.call('restore', 'opt2')[0], {'result': 'busy'})
        self.assertEqual(self.recorded('kill') + self.recorded('configure'), [])

    def test_an_old_client_that_will_not_stop_changes_nothing(self):
        self.scenario(stuck=True)
        lease = self.leases / 'dhclient.leases.vtnet3'
        lease.write_text('kept')
        answer, code = self.call('redhcp', 'opt2', '10.0.3.15', 'x')
        self.assertEqual((answer, code), ({'result': 'failed:old-client'}, 0))
        self.assertEqual(self.recorded('configure'), [])
        self.assertEqual(lease.read_text(), 'kept')
        self.assertEqual(self.recorded('log')[-1][1], 3)

    def test_a_client_that_does_not_start_is_tried_once_more(self):
        self.scenario(starts_on=2)
        self.assertEqual(self.call('redhcp', 'opt2', '10.0.3.15', 'x'),
                         ({'result': 'requested', 'lease': 'none'}, 0))
        self.assertEqual(len(self.recorded('configure')), 2)
        self.events.unlink()
        (self.root / 'state.json').unlink()
        self.scenario(starts_on=99)
        self.assertEqual(self.call('redhcp', 'opt2', '10.0.3.15', 'x'),
                         ({'result': 'failed:no-client', 'lease': 'none'}, 3))
        self.assertEqual(len(self.recorded('configure')), 2)
        self.assertIn('did not start again', self.recorded('log')[-1][2])

    @unittest.skipIf(os.geteuid() == 0, 'root can always remove the lease')
    def test_a_lease_that_cannot_be_moved_is_kept_and_the_request_still_happens(self):
        self.scenario()
        (self.leases / 'dhclient.leases.vtnet3').write_text('kept')
        self.leases.chmod(0o500)
        self.addCleanup(self.leases.chmod, 0o700)
        answer, _ = self.call('redhcp', 'opt2', '10.0.3.15', 'x')
        self.assertEqual(answer, {'result': 'requested', 'lease': 'kept'})
        self.assertEqual(self.recorded('configure'), [['configure', 'opt2', True]])
        self.assertTrue(any('could not be discarded' in entry[2] for entry in self.recorded('log')))

    def test_the_daemon_understands_the_helper(self):
        # The JSON contract end to end: the daemon's own helper wrapper, the
        # real helper script, and the decisions taken on what it reports.
        self.scenario()
        environment = {'WANGUARD_SCENARIO': str(self.scenario_file), 'WANGUARD_EVENTS': str(self.events),
                       'WANGUARD_STATE': str(self.root / 'state.json'), 'WANGUARD_LEASES': str(self.leases)}
        helper = wanguard.Helper([shutil.which('php'), '-d', 'include_path=' + str(self.includes), str(self.helper)])
        with mock.patch.dict(os.environ, environment):
            original = subprocess.run

            def run(*args, **kwargs):
                kwargs['env'] = {**kwargs.get('env', {}), **environment}
                return original(*args, **kwargs)
            with mock.patch.object(wanguard.subprocess, 'run', run):
                snapshot = helper.observe()
                self.assertEqual([name for name in snapshot['watched'] if guard.eligibility(snapshot['interfaces'][name]) is None],
                                 ['wan', 'opt2'])
                log = []
                state = guard.new_state('1:1')
                clock = [100.0]
                core = guard.Guard(state, helper, lambda level, message: log.append(message), lambda: clock[0], lambda: 0)
                core.apply(snapshot)
                clock[0] += 30
                core.apply(helper.observe())
        self.assertEqual(state['interfaces']['opt2']['last_action']['result'], 'requested')
        self.assertEqual(state['interfaces']['wan']['stage'], 0)
        self.assertEqual(self.recorded('configure'), [['configure', 'opt2', False]])

    def test_restore_starts_only_a_stopped_client(self):
        self.scenario()
        self.assertEqual(self.call('restore', 'opt2'), ({'result': 'running'}, 0))
        self.assertEqual(self.recorded('configure'), [])
        self.scenario(running={'vtnet3': False})
        (self.root / 'state.json').unlink(missing_ok=True)
        (self.leases / 'dhclient.leases.vtnet3').write_text('kept')
        self.assertEqual(self.call('restore', 'opt2'), ({'result': 'restored'}, 0))
        self.assertEqual(self.recorded('configure'), [['configure', 'opt2', True]])
        self.assertEqual(self.recorded('kill'), [])
        (self.root / 'state.json').unlink()
        self.scenario(running={'vtnet3': False}, starts_on=99)
        self.assertEqual(self.call('restore', 'opt2'), ({'result': 'failed:no-client'}, 3))
        # A client our action stopped is restarted without carrier as well:
        # a running client simply waits for the link.
        (self.root / 'state.json').unlink()
        self.scenario(running={'vtnet3': False}, details={'vtnet3': {'status': 'no carrier'}})
        self.assertEqual(self.call('restore', 'opt2'), ({'result': 'restored'}, 0))
        for changes, expected in [({'booting': True}, 'refused:booting'),
                                  ({'config': lambda value: value['config']['OPNsense']['wanguard']['general'].update(
                                      enabled='0')}, 'refused:disabled')]:
            (self.root / 'state.json').unlink(missing_ok=True)
            self.scenario(running={'vtnet3': False}, **changes)
            self.assertEqual(self.call('restore', 'opt2'), ({'result': expected}, 0))


if __name__ == '__main__':
    unittest.main()
