#!/usr/local/bin/python3
"""Exercise unchanged service actions with native rc.subr in a private jail."""
import importlib.util
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import unittest

PACKAGE = Path(__file__).resolve().parents[2]
SOURCE = PACKAGE / 'src'
SCRIPTS = Path('/usr/local/opnsense/scripts/ddclient')
RCS = Path('/usr/local/etc/rc.d')
PIDFILES = (Path('/var/run/ddclient.pid'), Path('/var/run/ddclient_opn.pid'))
NATIVE = (sys.platform.startswith('freebsd') and os.geteuid() == 0 and
          os.environ.get('DDCLIENT_NATIVE_FIXTURE') == '1')
if NATIVE:
    NATIVE = subprocess.run(['/sbin/sysctl', '-n', 'security.jail.jailed'],
                            check=True, capture_output=True, text=True).stdout.strip() == '1'


@unittest.skipUnless(NATIVE, 'Requires a private designated jail; additional coverage only')
class NativeServiceActionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for path in (*PIDFILES, *[SCRIPTS / name for name in ('ddclient_opn.py', 'perl_backend.py')]):
            if path.exists():
                raise RuntimeError('This fixture requires its own empty jail service namespace.')
        SCRIPTS.mkdir(parents=True, exist_ok=True)
        RCS.mkdir(parents=True, exist_ok=True)
        Path('/etc/rc.conf.d').mkdir(parents=True, exist_ok=True)
        Path('/etc/rc.conf').touch()
        for name in ('process_owner.py', 'perl_backend.py'):
            shutil.copy2(SOURCE / 'usr/local/opnsense/scripts/ddclient' / name, SCRIPTS / name)
        for name in ('ddclient_opn', 'ddclient_opnwall_perl'):
            shutil.copy2(SOURCE / 'etc/rc.d' / name, RCS / name)
        # Synthetic backend work keeps the real launcher, PID, ownership and
        # mutable-title lifecycle without performing DNS-provider requests.
        (SCRIPTS / 'ddclient_opn.py').write_text('''#!/usr/local/bin/python3
import argparse,sys,time
sys.path.insert(0,'/usr/local/opnsense/site-python')
from daemonize import Daemonize
parser=argparse.ArgumentParser()
parser.add_argument('-p', '--pid', default='/var/run/ddclient_opn.pid')
args=parser.parse_args()
def run():
    while True:time.sleep(.1)
Daemonize(app='ddclient',pid=args.pid,action=run).start()
''')
        (SCRIPTS / 'ddclient_opn.py').chmod(0o755)
        Path('/usr/local/sbin').mkdir(parents=True, exist_ok=True)
        Path('/usr/local/sbin/ddclient').write_text('''#!/usr/local/bin/perl
use strict;
use warnings;
for my $i (0 .. $#ARGV-1) {
    if ($ARGV[$i] eq '-daemon' && $ARGV[$i+1] eq '0') {
        open(my $output, '>>', '/var/run/native-perl-force.log') or die $!;
        print $output join("\\n", @ARGV), "\\n";
        close($output);
        exit 0;
    }
}
$0='ddclient - sleeping for 120 seconds';
$SIG{TERM}=sub { exit 0; };
while (1) {sleep 1;}
''')
        Path('/usr/local/sbin/ddclient').chmod(0o755)
        Path('/usr/local/etc/ddclient.conf').touch()
        sys.path.insert(0, str(SCRIPTS))
        spec = importlib.util.spec_from_file_location('native_action_owner', SCRIPTS / 'process_owner.py')
        cls.owner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.owner)

    def setUp(self):
        self.captured = {}
        self.configure(None)
        self.addCleanup(self.cleanup)

    def configure(self, backend):
        for name, selected in (('ddclient_opn', backend == 'python'), ('ddclient_opnwall_perl', backend == 'perl')):
            Path('/etc/rc.conf.d/' + name).write_text(name + '_enable="' + ('YES' if selected else 'NO') + '"\n')

    def action(self, action):
        text = (SOURCE / 'usr/local/opnsense/service/conf/actions.d/actions_ddclient.conf').read_text()
        lines = text.split('[' + action + ']\n', 1)[1].split('\n[', 1)[0].splitlines()
        index = next(i for i, line in enumerate(lines) if line.startswith('command:'))
        body = [lines[index][len('command:'):]]
        for line in lines[index + 1:]:
            if line and not line[0].isspace():
                break
            body.append(line)
        return subprocess.run(['/bin/sh', '-c', '\n'.join(body)], capture_output=True, text=True, timeout=20)

    def capture(self):
        table = self.owner.ProcessTable()
        result = []
        for pidfile in PIDFILES:
            if not pidfile.exists():
                result.append(None)
                continue
            pid = int(pidfile.read_text().strip())
            identity = table.read(pid)
            self.assertIsNotNone(identity)
            self.captured[pid] = identity
            result.append(pid)
        return result

    def status(self, backend):
        pidfile = PIDFILES[backend == 'python']
        # OPNsense util.inc isvalidpid, used by pluginctl service_message, runs
        # exactly this PID-file query and does not require the process basename.
        return subprocess.run(['/bin/pgrep', '-nF', str(pidfile)], capture_output=True).returncode == 0

    def cleanup(self):
        self.action('stop')
        table = self.owner.ProcessTable()
        for pid, expected in self.captured.items():
            if table.read(pid) == expected:
                os.kill(pid, signal.SIGKILL)
        for pidfile in PIDFILES:
            for suffix in ('', '.identity.json', '.child.identity.json', '.control.lock'):
                Path(str(pidfile) + suffix).unlink(missing_ok=True)

    def success(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_python_actions_start_restart_stop_and_disabled_intent(self):
        self.configure('python')
        self.success(self.action('start'))
        perl, first = self.capture()
        self.assertIsNone(perl)
        self.assertTrue(self.status('python'))
        self.success(self.action('restart'))
        perl, second = self.capture()
        self.assertIsNone(perl)
        self.assertNotEqual(first, second)
        self.assertIsNone(self.owner.ProcessTable().read(first))
        self.configure(None)
        self.success(self.action('restart'))
        self.assertFalse(self.status('python'))
        self.assertFalse(self.status('perl'))
        self.success(self.action('stop'))

    def test_perl_actions_restart_and_both_backend_switch_directions(self):
        self.configure('perl')
        self.success(self.action('start'))
        first, python = self.capture()
        self.assertIsNone(python)
        self.assertTrue(self.status('perl'))
        self.success(self.action('restart'))
        second, python = self.capture()
        self.assertNotEqual(first, second)
        self.assertIsNone(python)
        self.configure('python')
        self.success(self.action('restart'))
        perl, python = self.capture()
        self.assertIsNone(perl)
        self.assertTrue(self.status('python'))
        self.configure('perl')
        self.success(self.action('restart'))
        perl, python = self.capture()
        self.assertIsNone(python)
        self.assertTrue(self.status('perl'))
        self.success(self.action('stop'))
        self.assertFalse(self.status('perl'))

    def test_foreign_pid_blocks_both_stop_and_restart_without_backend_launch(self):
        foreign = subprocess.Popen(['/bin/sleep', '120'])
        self.addCleanup(foreign.wait, timeout=3)
        self.addCleanup(foreign.kill)
        for pidfile, selected in zip(PIDFILES, ('python', 'perl')):
            with self.subTest(pidfile=pidfile):
                pidfile.write_text(str(foreign.pid))
                self.configure(selected)
                for action in ('stop', 'restart'):
                    self.assertNotEqual(self.action(action).returncode, 0)
                    self.assertIsNone(foreign.poll())
                    self.assertEqual(pidfile.read_text(), str(foreign.pid))
                    self.assertFalse(PIDFILES[1 - PIDFILES.index(pidfile)].exists())
                pidfile.unlink()

    def test_native_force_one_shot_has_its_own_pid_path_and_only_selected_perl_runs(self):
        log = Path('/var/run/native-perl-force.log')
        log.unlink(missing_ok=True)
        self.addCleanup(log.unlink, missing_ok=True)
        self.configure('perl')
        self.success(self.action('force'))
        perl, python = self.capture()
        self.assertIsNone(python)
        self.assertTrue(self.status('perl'))
        arguments = log.read_text().splitlines()
        self.assertEqual(arguments[arguments.index('-daemon') + 1], '0')
        self.assertEqual(arguments[arguments.index('-pid') + 1], '/var/run/ddclient.pid.force.pid')
        self.configure('python')
        self.success(self.action('force'))
        perl, python = self.capture()
        self.assertIsNone(perl)
        self.assertTrue(self.status('python'))
        self.assertEqual(log.read_text().splitlines(), arguments)


if __name__ == '__main__':
    unittest.main(verbosity=2)
