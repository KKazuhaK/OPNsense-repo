"""Exercise production rc and process ownership with actual private files/commands."""
import copy
import errno
import importlib.util
import json
import os
from pathlib import Path
import signal
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

PACKAGE = Path(__file__).resolve().parents[1]
SCRIPT = PACKAGE / 'src/usr/local/opnsense/scripts/ddclient/process_owner.py'
spec = importlib.util.spec_from_file_location('ddclient_process_owner', SCRIPT)
owner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(owner)


class OwnershipCommandTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='ddclient-owner-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.pidfile = self.root / 'service.pid'
        self.pidfile.write_text('12345\n')
        self.script = self.root / 'ddclient_opn.py'
        self.script.write_text('placeholder')
        self.table = self.root / 'processes.json'
        identity = {'pid': 12345, 'ppid': 100, 'uid': os.geteuid(), 'birth': '1000:123456',
                    'executable': str(Path(sys.executable).resolve()),
                    'argv': [sys.executable, str(self.script), '-p', str(self.pidfile),
                             '-c', '/private/literal $HOME `date` "quotes".json']}
        self.table.write_text(json.dumps({'processes': {'12345': identity,
            '12346': {**identity, 'pid': 12346, 'birth': '1000:123457',
                      'argv': [sys.executable, str(self.script), '-p', '/private/another.pid']},
            '12347': {**identity, 'pid': 12347, 'argv': ['/bin/sleep', 'ddclient_opn.py']}},
            'signals': [], 'identity': identity}))
        self.driver = self.root / 'driver.py'
        self.driver.write_text('''import importlib.util,json,os,sys
from pathlib import Path
spec=importlib.util.spec_from_file_location('production',sys.argv[1]); module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
if os.environ.get('OWNER_TEST_BOOT'): module.boot_token=lambda: os.environ['OWNER_TEST_BOOT']
path=Path(os.environ['OWNER_TEST_TABLE'])
class FixtureTable:
    def read(self,pid):
        state=json.loads(path.read_text()); return state['processes'].get(str(pid))
    def signal(self,pid,number):
        state=json.loads(path.read_text());state['signals'].append([pid,number])
        if number==15 and os.environ.get('OWNER_TEST_REPLACE'):
            state['processes'][str(pid)]['birth']='2000:0'
        elif number==15 and os.environ.get('OWNER_TEST_REWRITE_PID'):
            Path(os.environ['OWNER_TEST_PID']).write_text('12346\\n')
        elif number==15 and os.environ.get('OWNER_TEST_IGNORE_TERM'):pass
        else:state['processes'].pop(str(pid),None)
        path.write_text(json.dumps(state))
instance=module.Owner(sys.argv[3],sys.argv[4],sys.argv[5],table=FixtureTable())
try:
    if sys.argv[2]=='record':
        if os.environ.get('OWNER_TEST_FAIL_RECORD'):raise RuntimeError('simulated record failure')
        instance.record(timeout=.2)
    else:instance.stop(timeout=.1)
except Exception as error:
    print(str(error),file=sys.stderr);raise SystemExit(1)
''')
        self.environment = {**os.environ, 'OWNER_TEST_TABLE': str(self.table), 'OWNER_TEST_PID': str(self.pidfile)}

    def run_action(self, action, **environment):
        return subprocess.run([sys.executable, str(self.driver), str(SCRIPT), action,
                               str(self.pidfile), str(self.script), sys.executable],
                              env={**self.environment, **environment}, capture_output=True, text=True, timeout=3)

    def state(self):
        return json.loads(self.table.read_text())

    def edit(self, callback):
        state = self.state()
        callback(state)
        self.table.write_text(json.dumps(state))

    def test_record_and_stop_only_exact_instance_with_literal_argv_and_other_instances_preserved(self):
        before = copy.deepcopy(self.state()['processes'])
        self.assertEqual(self.run_action('record').returncode, 0)
        journal = Path(str(self.pidfile) + '.identity.json')
        self.assertEqual(journal.stat().st_mode & 0o777, 0o600)
        self.assertEqual(json.loads(journal.read_text())['identity']['argv'], before['12345']['argv'])
        self.assertEqual(self.run_action('stop').returncode, 0)
        after = self.state()
        self.assertEqual(after['signals'], [[12345, signal.SIGTERM]])
        self.assertEqual(after['processes'], {key: value for key, value in before.items() if key != '12345'})
        self.assertFalse(self.pidfile.exists())
        self.assertFalse(journal.exists())

    def test_legacy_adoption_is_exact_script_interpreter_and_pid_path(self):
        self.assertEqual(self.run_action('stop').returncode, 0)
        self.assertEqual(self.state()['signals'], [[12345, signal.SIGTERM]])

    def test_invalid_group_pid_symlink_wrong_interpreter_and_foreign_script_are_never_signalled(self):
        for value in ('0\n', '-1\n', '-123\n', '+12345\n', '12345 extra\n', ' 12345\n', '1\n'):
            with self.subTest(value=value):
                self.pidfile.write_text(value)
                self.assertNotEqual(self.run_action('stop').returncode, 0)
                self.assertEqual(self.state()['signals'], [])
        self.pidfile.write_text('12345\n')
        for field, value in (('executable', '/bin/sleep'), ('argv', [sys.executable, '/private/foreign.py']),
                             ('argv', [sys.executable, str(self.script), '-p', '/private/other.pid'])):
            with self.subTest(field=field, value=value):
                original = copy.deepcopy(self.state()['processes']['12345'])
                self.edit(lambda state: state['processes']['12345'].update({field: value}))
                self.assertNotEqual(self.run_action('stop').returncode, 0)
                self.assertEqual(self.state()['signals'], [])
                self.edit(lambda state: state['processes'].update({'12345': original}))
        alternate = self.root / 'alternate.pid'
        self.pidfile.rename(alternate)
        self.pidfile.symlink_to(alternate)
        self.assertNotEqual(self.run_action('stop').returncode, 0)
        self.assertEqual(self.state()['signals'], [])

    def test_owner_journal_rebases_and_stops_the_same_process_after_a_clock_step(self):
        self.assertEqual(self.run_action('record', OWNER_TEST_BOOT='1000:0').returncode, 0)
        journal = Path(str(self.pidfile) + '.identity.json')
        self.assertEqual(json.loads(journal.read_text())['boot'], '1000:0')
        # The kernel moves kern.boottime and the live birth by the same +300s.
        self.edit(lambda state: state['processes']['12345'].update({'birth': '1300:123456'}))
        self.assertEqual(self.run_action('stop', OWNER_TEST_BOOT='1300:0').returncode, 0)
        self.assertEqual(self.state()['signals'], [[12345, signal.SIGTERM]])
        self.assertFalse(self.pidfile.exists())
        self.assertFalse(journal.exists())

    def test_legacy_owner_journal_without_boot_keeps_exact_comparisons(self):
        self.assertEqual(self.run_action('record', OWNER_TEST_BOOT='1000:0').returncode, 0)
        journal = Path(str(self.pidfile) + '.identity.json')
        document = json.loads(journal.read_text())
        document.pop('boot')
        journal.write_text(json.dumps(document))
        # The shifted boot reader must not move a legacy birth; exact text matches.
        self.assertEqual(self.run_action('stop', OWNER_TEST_BOOT='1300:0').returncode, 0)
        self.assertEqual(self.state()['signals'], [[12345, signal.SIGTERM]])

    def test_saved_birth_and_pid_inode_mismatch_refuses_stop(self):
        self.assertEqual(self.run_action('record').returncode, 0)
        self.edit(lambda state: state['processes']['12345'].update({'birth': '1000:123457'}))
        self.assertNotEqual(self.run_action('stop').returncode, 0)
        self.assertEqual(self.state()['signals'], [])
        self.edit(lambda state: state['processes']['12345'].update({'birth': '1000:123456'}))
        alternate = self.root / 'replacement.pid'
        alternate.write_bytes(self.pidfile.read_bytes())
        os.replace(alternate, self.pidfile)
        self.assertNotEqual(self.run_action('stop').returncode, 0)
        self.assertEqual(self.state()['signals'], [])

    def test_sigkill_is_limited_to_same_verified_process_and_replacement_pid_blocks_it(self):
        self.assertEqual(self.run_action('record').returncode, 0)
        self.assertEqual(self.run_action('stop', OWNER_TEST_IGNORE_TERM='1').returncode, 0)
        self.assertEqual(self.state()['signals'], [[12345, signal.SIGTERM], [12345, signal.SIGKILL]])

    def test_pidfile_change_or_reused_process_after_term_preserves_replacement_and_sends_no_kill(self):
        for fault in ('OWNER_TEST_REWRITE_PID', 'OWNER_TEST_REPLACE'):
            with self.subTest(fault=fault):
                state = self.state()
                state['processes']['12345'] = copy.deepcopy(state['identity'])
                state['signals'] = []
                self.table.write_text(json.dumps(state))
                self.pidfile.write_text('12345\n')
                self.assertEqual(self.run_action('record').returncode, 0)
                self.assertNotEqual(self.run_action('stop', **{fault: '1'}).returncode, 0)
                self.assertEqual(self.state()['signals'], [[12345, signal.SIGTERM]])
                self.assertTrue(self.pidfile.exists())
                self.assertTrue(Path(str(self.pidfile) + '.identity.json').exists())

    def test_missing_pidfile_stops_only_the_exact_journalled_process(self):
        self.assertEqual(self.run_action('record').returncode, 0)
        journal = Path(str(self.pidfile) + '.identity.json')
        self.pidfile.unlink()
        self.assertEqual(self.run_action('stop').returncode, 0)
        self.assertEqual(self.state()['signals'], [[12345, signal.SIGTERM]])
        self.assertFalse(journal.exists())
        state = self.state()
        state['processes']['12345'] = copy.deepcopy(state['identity'])
        state['signals'] = []
        self.table.write_text(json.dumps(state))
        self.pidfile.write_text('12345\n')
        self.assertEqual(self.run_action('record').returncode, 0)
        self.edit(lambda value: value['processes']['12345'].update({'birth': '2000:0'}))
        self.pidfile.unlink()
        self.assertNotEqual(self.run_action('stop').returncode, 0)
        self.assertEqual(self.state()['signals'], [])
        self.assertTrue(journal.exists())

    def test_unchanged_stale_pidfile_and_journal_are_retired_after_owned_exit(self):
        self.assertEqual(self.run_action('record').returncode, 0)
        self.edit(lambda state: state['processes'].pop('12345'))
        self.assertEqual(self.run_action('stop').returncode, 0)
        self.assertEqual(self.state()['signals'], [])
        self.assertFalse(self.pidfile.exists())
        self.assertFalse(Path(str(self.pidfile) + '.identity.json').exists())

    def test_rc_poststart_and_stop_pass_real_pidfile_and_never_scan_ps(self):
        rc = self.root / 'rc.subr'
        rc.write_text('''load_rc_config() { :; }
run_rc_command() { case "$1" in start) "$start_postcmd";; stop) "$stop_cmd";; esac; }
''')
        source = (PACKAGE / 'src/etc/rc.d/ddclient_opn').read_text()
        source = source.replace('. /etc/rc.subr', '. "' + str(rc) + '"')
        source = source.replace('command=/usr/local/opnsense/scripts/ddclient/ddclient_opn.py', 'command="' + str(self.script) + '"')
        source = source.replace('command_interpreter=/usr/local/bin/python3', 'command_interpreter="' + sys.executable + '"')
        source = source.replace('pidfile="/var/run/${name}.pid"', 'pidfile="' + str(self.pidfile) + '"')
        source = source.replace('/usr/local/bin/python3 /usr/local/opnsense/scripts/ddclient/process_owner.py',
            '"' + sys.executable + '" "' + str(self.driver) + '" "' + str(SCRIPT) + '"')
        candidate = self.root / 'rc-ddclient'
        candidate.write_text(source)
        for action in ('start', 'stop'):
            process = subprocess.run(['sh', str(candidate), action], env=self.environment,
                                     capture_output=True, text=True, timeout=3)
            self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(self.state()['signals'], [[12345, signal.SIGTERM]])

    def test_rc_poststart_failure_cleans_up_the_exact_spawned_python_backend(self):
        rc = self.root / 'rc.subr'
        rc.write_text('''load_rc_config() { :; }
run_rc_command() { case "$1" in start) "$start_postcmd";; esac; }
''')
        source = (PACKAGE / 'src/etc/rc.d/ddclient_opn').read_text()
        source = source.replace('. /etc/rc.subr', '. "' + str(rc) + '"')
        source = source.replace('command=/usr/local/opnsense/scripts/ddclient/ddclient_opn.py', 'command="' + str(self.script) + '"')
        source = source.replace('command_interpreter=/usr/local/bin/python3', 'command_interpreter="' + sys.executable + '"')
        source = source.replace('pidfile="/var/run/${name}.pid"', 'pidfile="' + str(self.pidfile) + '"')
        source = source.replace('/usr/local/bin/python3 /usr/local/opnsense/scripts/ddclient/process_owner.py',
            '"' + sys.executable + '" "' + str(self.driver) + '" "' + str(SCRIPT) + '"')
        candidate = self.root / 'rc-ddclient-failed-start'
        candidate.write_text(source)
        process = subprocess.run(['sh', str(candidate), 'start'],
            env={**self.environment, 'OWNER_TEST_FAIL_RECORD': '1'}, capture_output=True, text=True, timeout=3)
        self.assertNotEqual(process.returncode, 0)
        self.assertEqual(self.state()['signals'], [[12345, signal.SIGTERM]])
        self.assertFalse(self.pidfile.exists())


class PreciseMetadataTests(unittest.TestCase):
    def raw(self, pid=12345, sec=1000, usec=123456, state=2):
        raw = bytearray(1088)
        struct.pack_into('=i', raw, 0, 1088)
        struct.pack_into('=ii', raw, 72, pid, 100)
        struct.pack_into('=I', raw, 168, os.geteuid())
        struct.pack_into('=qq', raw, 336, sec, usec)
        raw[388] = state
        return bytes(raw)

    def test_microsecond_birth_is_distinct_and_invalid_or_zombie_metadata_is_rejected(self):
        with mock.patch.object(owner.os, 'uname', return_value=mock.Mock(machine='amd64')):
            with mock.patch.object(owner, 'kernel_value', return_value=self.raw()):
                first = owner.precise_metadata(12345)
            with mock.patch.object(owner, 'kernel_value', return_value=self.raw(usec=123457)):
                self.assertNotEqual(first['birth'], owner.precise_metadata(12345)['birth'])
            for raw in (self.raw(pid=12346), self.raw(usec=1000000), self.raw(sec=0), b'wrong layout'):
                with self.subTest(raw_length=len(raw)), mock.patch.object(owner, 'kernel_value', return_value=raw):
                    with self.assertRaises(RuntimeError): owner.precise_metadata(12345)
            with mock.patch.object(owner, 'kernel_value', return_value=self.raw(state=5)):
                self.assertIsNone(owner.precise_metadata(12345))

    def test_only_absent_process_errors_are_empty_and_other_kernel_failures_preserve_pidfile(self):
        table = owner.ProcessTable()
        for number in (errno.ENOENT, errno.ESRCH):
            with self.subTest(number=number), mock.patch.object(
                    owner, 'precise_metadata', side_effect=OSError(number, 'absent')):
                self.assertIsNone(table.read(12345))

        with tempfile.TemporaryDirectory(prefix='ddclient-owner-error-') as directory:
            pidfile = Path(directory) / 'service.pid'
            script = Path(directory) / 'ddclient_opn.py'
            pidfile.write_text('12345\n')
            script.write_text('placeholder')
            control = owner.Owner(pidfile, script, sys.executable, table=table)
            for number in (errno.EPERM, errno.EIO):
                with self.subTest(number=number), mock.patch.object(
                        owner, 'precise_metadata', side_effect=OSError(number, 'metadata failure')):
                    with self.assertRaisesRegex(RuntimeError, 'Cannot establish DDClient process ownership'):
                        control.stop()
                self.assertEqual(pidfile.read_text(), '12345\n')
            identity = {'pid': 12345, 'ppid': 100, 'uid': os.geteuid(), 'birth': '1000:123456'}
            with (mock.patch.object(owner, 'precise_metadata', return_value=identity),
                  mock.patch.object(owner, 'kernel_value', return_value=b'')):
                with self.assertRaisesRegex(RuntimeError, 'identity changed or is incomplete'):
                    control.stop()
            self.assertEqual(pidfile.read_text(), '12345\n')

    def test_replaced_executable_of_a_live_process_fails_closed_and_exit_stays_empty(self):
        table = owner.ProcessTable()
        identity = {'pid': 12345, 'ppid': 100, 'uid': os.geteuid(), 'birth': '1000:123456'}
        for number in (errno.ENOENT, errno.ESRCH):
            with (self.subTest(number=number),
                  mock.patch.object(owner, 'precise_metadata', return_value=identity),
                  mock.patch.object(owner, 'kernel_value', side_effect=OSError(number, 'replaced'))):
                with self.assertRaisesRegex(RuntimeError, 'live DDClient process 12345 is unavailable'):
                    table.read(12345)
        with (mock.patch.object(owner, 'precise_metadata', side_effect=[identity, None]),
              mock.patch.object(owner, 'kernel_value', side_effect=OSError(errno.ENOENT, 'exited'))):
            self.assertIsNone(table.read(12345))


if __name__ == '__main__':
    unittest.main()
