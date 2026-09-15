"""Exercise exact Mihomo daemon ownership without signalling host processes."""
import json
import importlib.util
import os
from pathlib import Path
import signal
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / 'src/usr/local/opnsense/scripts/mihomo'
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'common'))
sys.path.insert(0, str(SCRIPT))
import process_owner as owner

ROUTING_SCRIPT = SCRIPT / 'routing.py'
ROUTING_SPEC = importlib.util.spec_from_file_location('mihomo_identity_routing', ROUTING_SCRIPT)
routing = importlib.util.module_from_spec(ROUTING_SPEC)
ROUTING_SPEC.loader.exec_module(routing)


def identity(pid, executable, argv, *, parent=1, birth=None, uid=None):
    return {'pid': pid, 'ppid': parent, 'uid': os.geteuid() if uid is None else uid,
            'birth': birth or '%d:1' % pid, 'executable': executable,
            'argv': list(argv), 'stopped': False}


class ProcessOwnershipTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.parent_pid = self.root / 'mihomo.pid'
        self.child_pid = self.root / 'mihomo-child.pid'
        self.journal = self.root / 'state/process-identity.json'
        self.child_argv = [owner.CORE, '-d', owner.HOME, '-f', owner.CONFIG]
        self.live = {}
        self.signals = []

    def reader(self, pid):
        value = self.live.get(pid)
        return dict(value) if value is not None else None

    def signaler(self, pid, number):
        self.signals.append((pid, number))
        if number in (signal.SIGTERM, signal.SIGKILL):
            self.live.pop(pid, None)

    def group(self, tag='mihomo', executable=owner.CORE, argv=None):
        return owner.ProcessGroup(tag, self.parent_pid, self.child_pid, self.journal,
                                  executable, argv or self.child_argv,
                                  process_reader=self.reader, signaler=self.signaler,
                                  sleeper=lambda unused: None)

    def install_pid_files(self, parent=101, child=102):
        self.parent_pid.write_text(str(parent) + '\n')
        self.child_pid.write_text(str(child) + '\n')
        self.parent_pid.chmod(0o644)
        self.child_pid.chmod(0o644)
        self.live[parent] = identity(parent, owner.DAEMON,
                                     ['daemon: mihomo[%d]' % child])
        self.live[child] = identity(child, owner.CORE, self.child_argv, parent=parent)

    def test_exact_legacy_pid_pair_is_adopted_into_private_durable_journal(self):
        self.install_pid_files()
        group = self.group()

        self.assertTrue(group.running())

        record = json.loads(self.journal.read_text())
        self.assertEqual({'version', 'tag', 'parent', 'child'}, set(record))
        self.assertEqual(0o600, self.journal.stat().st_mode & 0o777)
        self.assertEqual(self.live[101]['birth'], record['parent']['birth'])
        self.assertEqual(self.child_argv, record['child']['argv'])

    def test_adoption_rejects_wrong_uid_executable_argv_and_parent_relationship(self):
        cases = {
            'uid': lambda: self.live[102].update(uid=os.geteuid() + 1),
            'executable': lambda: self.live[102].update(executable='/usr/local/bin/other'),
            'argv': lambda: self.live[102].update(argv=[owner.CORE, '-f', '/tmp/foreign.yaml']),
            'parent': lambda: self.live[102].update(ppid=999),
            'tag': lambda: self.live[101].update(argv=['daemon: another[102]']),
        }
        for name, mutate in cases.items():
            with self.subTest(name=name):
                self.live.clear()
                self.journal.unlink(missing_ok=True)
                self.install_pid_files()
                mutate()
                with self.assertRaises(owner.OwnershipError):
                    self.group().running()
                self.assertFalse(self.signals)
                self.assertTrue(self.parent_pid.exists())
                self.assertTrue(self.child_pid.exists())

    def test_reused_recorded_pids_are_never_signalled(self):
        self.install_pid_files()
        group = self.group()
        group.adopt()
        self.live[101] = identity(101, '/usr/bin/vim', ['/usr/bin/vim'], birth='999:1')
        self.live[102] = identity(102, '/bin/sleep', ['/bin/sleep', '99'], birth='999:2')

        with self.assertRaises(owner.OwnershipError):
            group.stop()

        self.assertEqual([], self.signals)
        self.assertTrue(self.journal.exists())
        self.assertTrue(self.parent_pid.exists())
        self.assertTrue(self.child_pid.exists())

    def test_a_later_live_mismatch_preserves_every_stale_pid_file(self):
        self.install_pid_files()
        group = self.group()
        group.adopt()
        self.live.pop(101)
        self.live[102] = identity(102, '/bin/sleep', ['/bin/sleep', '99'], birth='999:2')

        with self.assertRaises(owner.OwnershipError):
            group.discover()

        self.assertTrue(self.parent_pid.exists())
        self.assertTrue(self.child_pid.exists())
        self.assertTrue(self.journal.exists())
        self.assertEqual([], self.signals)

    def test_same_child_remains_owned_after_supervisor_exit_and_reparenting(self):
        self.install_pid_files()
        group = self.group()
        group.adopt()
        self.live.pop(101)
        self.live[102]['ppid'] = 1
        self.live[102]['stopped'] = True

        self.assertTrue(group.running(adopt=False))
        group.stop()

        self.assertIn((102, signal.SIGTERM), self.signals)
        self.assertFalse(self.journal.exists())

    def test_replaced_foreign_pid_file_is_preserved(self):
        self.install_pid_files()
        group = self.group()
        group.adopt()
        self.live.clear()
        self.child_pid.write_text('999\n')

        with self.assertRaises(owner.OwnershipError):
            group.discover()

        self.assertEqual('999', self.child_pid.read_text().strip())
        self.assertEqual([], self.signals)

    def test_identity_is_rechecked_immediately_before_each_signal(self):
        self.install_pid_files()
        group = self.group()
        group.adopt()
        calls = {101: 0, 102: 0}

        def changing(pid):
            calls[pid] += 1
            current = self.live.get(pid)
            if current is None:
                return None
            if pid == 101 and calls[pid] >= 2:
                return identity(pid, '/usr/bin/vim', ['/usr/bin/vim'], birth='999:1')
            return dict(current)

        group.process_reader = changing
        with self.assertRaises(owner.OwnershipError):
            group.stop()

        self.assertFalse(any(pid == 101 for pid, unused in self.signals))
        self.assertIn((102, signal.SIGTERM), self.signals)
        self.assertTrue(self.parent_pid.exists())

    def test_watcher_adoption_requires_its_exact_python_action(self):
        watcher_argv = [owner.PYTHON, owner.SCRIPT, 'watch']
        self.child_argv = watcher_argv
        self.install_pid_files(parent=201, child=202)
        self.live[201]['argv'] = ['daemon: mihomo-watch[202]']
        self.live[202] = identity(202, owner.PYTHON, watcher_argv, parent=201)
        group = self.group('mihomo-watch', owner.PYTHON, watcher_argv)

        self.assertTrue(group.running())
        self.live[202]['argv'][-1] = 'sub-update'
        self.assertFalse(group.running(adopt=False))
        self.assertEqual([], self.signals)

    def test_routing_core_check_uses_the_same_exact_process_journal(self):
        root = self.root / 'router'
        group = owner.core_group(root=root, process_reader=self.reader,
                                 signaler=self.signaler, sleeper=lambda unused: None)
        group.parent_pid.parent.mkdir(parents=True)
        group.parent_pid.write_text('301\n')
        group.child_pid.write_text('302\n')
        self.live[301] = identity(301, owner.DAEMON, ['daemon: mihomo[302]'])
        self.live[302] = identity(302, owner.CORE, group.child_argv, parent=301)
        group.adopt()
        checker = routing.Routing(root, lambda *unused, **options: None,
                                  lambda unused: None)
        checker.process_reader = self.reader

        self.assertTrue(checker.core_alive())
        self.live[302]['birth'] = '9000:4'
        self.assertFalse(checker.core_alive())


if __name__ == '__main__':
    unittest.main()
