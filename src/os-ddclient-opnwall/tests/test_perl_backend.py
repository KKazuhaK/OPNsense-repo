"""Run actual configd command bodies and test launch-owned mutable-title children."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

PACKAGE = Path(__file__).resolve().parents[1]
DIRECTORY = PACKAGE / 'src/usr/local/opnsense/scripts/ddclient'
sys.path.insert(0, str(DIRECTORY))
spec = importlib.util.spec_from_file_location('perl_backend', DIRECTORY / 'perl_backend.py')
backend = importlib.util.module_from_spec(spec)
spec.loader.exec_module(backend)


class Table:
    def __init__(self):
        self.identities = {}
        self.signals = []
    def read(self, pid):
        return copy.deepcopy(self.identities.get(pid))
    def signal(self, pid, number):
        self.signals.append((pid, number))
        self.identities.pop(pid, None)


class ChildOwnershipTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='ddclient-perl-child-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.table = Table()
        self.child = backend.Child(self.root / 'service.pid', self.table)
        self.identity = {'pid': 12345, 'ppid': 100, 'uid': os.geteuid(), 'birth': '1000:123456',
                         'executable': str(Path(backend.PERL).resolve()),
                         'argv': ['perl: ddclient - sleeping for 300 seconds']}
        self.table.identities[12345] = self.identity
        self.table.identities[12346] = {**self.identity, 'pid': 12346, 'birth': '1000:123457'}
        self.process = mock.Mock(pid=12345)
        self.process.poll.return_value = None

    def gated_launch(self, launches=None):
        launches = [] if launches is None else launches
        def launch(arguments, **options):
            self.assertEqual(len(options['pass_fds']), 1)
            launches.append(arguments)
            self.table.identities[12345] = {
                'pid': 12345, 'ppid': 100, 'uid': os.geteuid(), 'birth': '1000:123456',
                'executable': str(Path(sys.executable).resolve()), 'argv': arguments}
            return self.process
        with mock.patch.object(backend.os, 'write', return_value=1):
            result = self.child.launch(120, launch)
        return result

    def test_explicit_launch_owns_child_after_perl_rewrites_title_and_preserves_other_instance(self):
        launches = []
        self.gated_launch(launches)
        record = self.child.load()
        self.assertEqual(record['launch'][:5], [backend.PERL, backend.PROGRAM, '-foreground', '-daemon', '120'])
        self.assertNotEqual(record['launch'][-1], str(self.child.pidfile))
        self.assertEqual(self.child.journal.stat().st_mode & 0o777, 0o600)
        self.table.identities[12345] = {**self.identity,
            'argv': ['perl: ddclient - updating router.example.invalid']}
        self.child.cleanup(timeout=.1)
        self.assertEqual(self.table.signals, [(12345, signal.SIGTERM)])
        self.assertIn(12346, self.table.identities)
        self.assertFalse(self.child.journal.exists())

    def test_birth_reuse_and_wrong_executable_refuse_all_signals(self):
        self.gated_launch()
        self.table.identities[12345] = copy.deepcopy(self.identity)
        for field, value in (('birth', '1000:123457'), ('executable', '/bin/sleep'), ('uid', os.geteuid() + 1)):
            with self.subTest(field=field):
                original = self.table.identities[12345][field]
                self.table.identities[12345][field] = value
                with self.assertRaises(RuntimeError): self.child.cleanup(timeout=.1)
                self.assertEqual(self.table.signals, [])
                self.table.identities[12345][field] = original

    def test_missing_parent_pidfile_can_recover_proven_child_and_no_journal_does_not_adopt_title(self):
        self.child.cleanup(timeout=.1)
        self.assertEqual(self.table.signals, [])
        self.gated_launch()
        self.assertFalse(self.child.pidfile.exists())
        self.child.cleanup(timeout=.1)
        self.assertEqual(self.table.signals, [(12345, signal.SIGTERM)])
        self.child.cleanup(timeout=.1)
        self.assertEqual(self.table.signals, [(12345, signal.SIGTERM)])

    def test_journal_write_failure_terminates_only_explicit_unreaped_popen_child(self):
        def launch(arguments, **options):
            self.table.identities[12345] = {
                'pid': 12345, 'ppid': 100, 'uid': os.geteuid(), 'birth': '1000:123456',
                'executable': str(Path(sys.executable).resolve()), 'argv': arguments}
            return self.process
        with mock.patch.object(backend, 'persist', side_effect=OSError('simulated disk failure')), \
                mock.patch.object(backend.os, 'write') as release:
            with self.assertRaises(OSError): self.child.launch(120, launch)
        release.assert_not_called()
        self.process.terminate.assert_called_once()
        self.process.wait.assert_called_once_with(timeout=2)
        self.assertEqual(self.table.signals, [])
        self.assertIn(12346, self.table.identities)

    def test_durable_launcher_receipt_can_stop_before_exec_after_parent_crash(self):
        self.gated_launch()
        record = self.child.load()
        self.assertEqual(record['version'], 2)
        self.assertTrue(self.child.owns(record, self.table.identities[12345]))
        self.child.cleanup(timeout=.1)
        self.assertEqual(self.table.signals, [(12345, signal.SIGTERM)])
        self.assertFalse(self.child.journal.exists())


class ConfigdActionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='ddclient-actions-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.events = self.root / 'events'
        self.status = self.root / 'ddclient_opn.status'
        self.command = self.root / 'command.py'
        self.command.write_text('''import json,os,sys
from pathlib import Path
args=sys.argv[1:]
with Path(os.environ['DDCLIENT_ACTION_EVENTS']).open('a') as output:output.write(json.dumps(args)+'\\n')
if args[-1]=='enabled':sys.exit(0 if os.environ.get('DDCLIENT_PERL_ENABLED')=='1' else 1)
if os.environ.get('DDCLIENT_ACTION_FAIL')==' '.join(args):sys.exit(1)
''')

    def body(self, action):
        text = (PACKAGE / 'src/usr/local/opnsense/service/conf/actions.d/actions_ddclient.conf').read_text()
        section = text.split('[' + action + ']\n', 1)[1].split('\n[', 1)[0]
        lines = section.splitlines()
        offset = next(index for index, line in enumerate(lines) if line.startswith('command:'))
        result = [lines[offset][len('command:'):]]
        for line in lines[offset + 1:]:
            if line and not line[0].isspace():break
            result.append(line)
        return '\n'.join(result).strip()

    def run_action(self, action, **environment):
        body = self.body(action)
        invoke = '"' + sys.executable + '" "' + str(self.command) + '" '
        body = body.replace('/usr/local/etc/rc.d/ddclient_opnwall_perl', invoke + 'perl')
        body = body.replace('/usr/local/etc/rc.d/ddclient_opn', invoke + 'python')
        body = body.replace('/usr/local/bin/python3 /usr/local/opnsense/scripts/ddclient/perl_backend.py', invoke + 'force')
        body = body.replace('/var/tmp/ddclient_opn.status', shlex.quote(str(self.status)))
        return subprocess.run(['sh', '-c', body], capture_output=True, text=True,
            env={**os.environ, 'DDCLIENT_ACTION_EVENTS': str(self.events), **environment}, timeout=3)

    def calls(self):
        return [json.loads(line) for line in self.events.read_text().splitlines()] if self.events.exists() else []

    def test_stop_already_stopped_and_restart_use_validated_owned_rc_entrypoints(self):
        self.assertEqual(self.run_action('stop').returncode, 0)
        self.assertEqual(self.calls(), [['perl', 'onestop'], ['python', 'onestop']])
        self.events.unlink()
        self.status.write_text('preserve normal restart')
        self.assertEqual(self.run_action('restart').returncode, 0)
        self.assertEqual(self.calls(), [['perl', 'onestop'], ['python', 'onestop'], ['perl', 'start'], ['python', 'start']])
        self.assertTrue(self.status.exists())
        self.assertNotIn('pkill', self.body('stop') + self.body('restart'))

    def test_foreign_pid_stop_failure_never_starts_another_backend(self):
        for failure, expected in (('perl onestop', [['perl', 'onestop']]),
                                  ('python onestop', [['perl', 'onestop'], ['python', 'onestop']])):
            for action in ('stop', 'restart'):
                with self.subTest(failure=failure, action=action):
                    self.events.unlink(missing_ok=True)
                    self.assertNotEqual(self.run_action(action, DDCLIENT_ACTION_FAIL=failure).returncode, 0)
                    self.assertEqual(self.calls(), expected)

    def test_force_one_shot_runs_only_for_selected_perl_backend_after_successful_restart(self):
        self.status.write_text('force fresh state')
        self.assertEqual(self.run_action('force', DDCLIENT_PERL_ENABLED='1').returncode, 0)
        self.assertFalse(self.status.exists())
        self.assertEqual(self.calls(), [['perl', 'onestop'], ['python', 'onestop'], ['perl', 'enabled'],
                                       ['force', 'force'], ['perl', 'start'], ['python', 'start']])
        self.events.unlink()
        self.status.write_text('force fresh state')
        self.assertEqual(self.run_action('force', DDCLIENT_PERL_ENABLED='0').returncode, 0)
        self.assertFalse(self.status.exists())
        self.assertEqual(self.calls(), [['perl', 'onestop'], ['python', 'onestop'], ['perl', 'enabled'],
                                       ['perl', 'start'], ['python', 'start']])
        self.assertNotIn(['force', 'force'], self.calls())
        self.events.unlink()
        self.assertNotEqual(self.run_action('force', DDCLIENT_ACTION_FAIL='perl onestop', DDCLIENT_PERL_ENABLED='1').returncode, 0)
        self.assertEqual(self.calls(), [['perl', 'onestop']])
        self.events.unlink()
        self.assertNotEqual(self.run_action('force', DDCLIENT_ACTION_FAIL='force force', DDCLIENT_PERL_ENABLED='1').returncode, 0)
        self.assertEqual(self.calls()[-2:], [['perl', 'start'], ['python', 'start']])


class PerlRcTests(unittest.TestCase):
    def test_failed_parent_record_or_child_ready_cleans_up_the_scoped_backend(self):
        with tempfile.TemporaryDirectory(prefix='ddclient-perl-rc-') as temporary:
            root = Path(temporary)
            events = root / 'events'
            framework = root / 'rc.subr'
            framework.write_text('''load_rc_config() { :; }
run_rc_command() { case "$1" in start) "$start_postcmd";; esac; }
''')
            command = root / 'command.py'
            command.write_text('''import json,os,sys
from pathlib import Path
with Path(os.environ["PERL_RC_EVENTS"]).open("a") as output:
    output.write(json.dumps(sys.argv[1:]) + "\\n")
if os.environ.get("PERL_RC_FAIL") in sys.argv[1:]: raise SystemExit(7)
''')
            source = (PACKAGE / 'src/etc/rc.d/ddclient_opnwall_perl').read_text()
            source = source.replace('. /etc/rc.subr', '. "' + str(framework) + '"')
            source = source.replace('command=/usr/local/opnsense/scripts/ddclient/perl_backend.py',
                                    'command="' + str(command) + '"')
            source = source.replace('command_interpreter=/usr/local/bin/python3',
                                    'command_interpreter="' + sys.executable + '"')
            source = source.replace('/usr/local/bin/python3 /usr/local/opnsense/scripts/ddclient/process_owner.py',
                                    '"' + sys.executable + '" "' + str(command) + '" owner')
            source = source.replace('/usr/local/bin/python3 "$command"',
                                    '"' + sys.executable + '" "$command"')
            candidate = root / 'rc-perl'
            candidate.write_text(source)
            for failure, expected in (
                    ('record', [['owner', 'record', '/var/run/ddclient.pid', str(command), sys.executable],
                                 ['stop', '-p', '/var/run/ddclient.pid']]),
                    ('ready', [['owner', 'record', '/var/run/ddclient.pid', str(command), sys.executable],
                                ['ready', '-p', '/var/run/ddclient.pid'],
                                ['stop', '-p', '/var/run/ddclient.pid']])):
                with self.subTest(failure=failure):
                    events.unlink(missing_ok=True)
                    result = subprocess.run(['sh', str(candidate), 'start'], capture_output=True, text=True,
                        env={**os.environ, 'PERL_RC_EVENTS': str(events), 'PERL_RC_FAIL': failure}, timeout=3)
                    self.assertNotEqual(result.returncode, 0)
                    calls = [json.loads(line) for line in events.read_text().splitlines()]
                    self.assertEqual(calls, expected)


if __name__ == '__main__':
    unittest.main()
