"""Exercise actual shared process control with bounded native syscall fixtures."""
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import struct
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

COMMON = Path(__file__).resolve().parents[2] / 'common'
sys.path.insert(0, str(COMMON))
spec = importlib.util.spec_from_file_location('shared_owned_control', COMMON / 'process_control.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
spec = importlib.util.spec_from_file_location('shared_native_identity', COMMON / 'process_identity.py')
i = importlib.util.module_from_spec(spec); spec.loader.exec_module(i)


class IdentityTests(unittest.TestCase):
    def raw(self, state=3, pid=42):
        raw = bytearray(1088)
        struct.pack_into('=i', raw, 0, 1088)
        struct.pack_into('=ii', raw, 72, pid, 1)
        struct.pack_into('=I', raw, 168, os.geteuid())
        struct.pack_into('=qq', raw, 336, 1780000000, 12345)
        raw[388] = state
        return bytes(raw)

    def test_nonpositive_overflow_and_boolean_pids_never_query_kernel(self):
        with patch.object(i, 'kernel_value') as query:
            for pid in (0, -1, 2147483648, True, '42'):
                with self.subTest(pid=pid):
                    with self.assertRaises(RuntimeError): i.process(pid)
            query.assert_not_called()

    def test_stable_metadata_exact_nul_argv_and_stopped_state(self):
        for state in (3, 4):
            raw = self.raw(state)
            def query(name, pid):
                return {'kern.proc.pid': raw, 'kern.proc.pathname': b'/tmp/binary\0',
                        'kern.proc.args': b'/tmp/binary\0-c\0literal $path `text`\0'}[name]
            with patch.object(i.os, 'uname', return_value=types.SimpleNamespace(machine='amd64')), patch.object(i, 'kernel_value', side_effect=query):
                identity = i.process(42)
                self.assertEqual(identity['argv'], ['/tmp/binary', '-c', 'literal $path `text`'])
                self.assertEqual(identity['birth'], '1780000000:12345')
                self.assertEqual(identity['stopped'], state == 4)

    def test_pid_reuse_zombie_and_unknown_layout_fail_closed(self):
        with patch.object(i.os, 'uname', return_value=types.SimpleNamespace(machine='amd64')):
            with patch.object(i, 'kernel_value', return_value=self.raw(5)): self.assertIsNone(i.metadata(42))
            with patch.object(i, 'kernel_value', return_value=bytes(100)):
                with self.assertRaises(RuntimeError): i.metadata(42)
            with patch.object(i, 'kernel_value', side_effect=[self.raw(), b'/tmp/binary\0', b'/tmp/binary\0', self.raw(pid=43)]):
                with self.assertRaises(RuntimeError): i.process(42)

    def test_live_process_with_a_replaced_executable_is_not_reported_gone(self):
        with patch.object(i.os, 'uname', return_value=types.SimpleNamespace(machine='amd64')):
            with patch.object(i, 'metadata', side_effect=[{'pid': 42}, {'pid': 42}]), \
                    patch.object(i, 'kernel_value', side_effect=OSError(2, 'gone')):
                with self.assertRaises(RuntimeError): i.process(42)
            with patch.object(i, 'metadata', side_effect=[{'pid': 42}, None]), \
                    patch.object(i, 'kernel_value', side_effect=OSError(3, 'ended')):
                self.assertIsNone(i.process(42))


class ControlTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.pidfile = self.root / 'service.pid'
        self.binary = self.root / 'binary'; self.binary.touch()
        self.argv = [str(self.binary), '-c', 'path $literal `literal`']
        self.c = m.Control(self.pidfile, 'fixture:daemon', str(self.binary), self.argv[1:])
        self.kernel = {}; self.signals = []; self.stuck = False; self.respawn = False; self.foreign_respawn = False
        self.clock = 0
        for name, value in [('process', lambda pid: copy.deepcopy(self.kernel.get(pid))),
                            ('children', lambda parent: [pid for pid,value in self.kernel.items() if value['ppid'] == parent]),
                            ('boot', lambda: 'fixture-boot')]:
            p = patch.object(m, name, side_effect=value); p.start(); self.addCleanup(p.stop)
        p = patch.object(m.os, 'kill', side_effect=self.send); p.start(); self.addCleanup(p.stop)
        p = patch.object(m.time, 'sleep', return_value=None); p.start(); self.addCleanup(p.stop)
        def clock(): self.clock += .25; return self.clock
        p = patch.object(m.time, 'monotonic', side_effect=clock); p.start(); self.addCleanup(p.stop)

    def app(self, pid=22, ppid=11, birth='1780000000:22'):
        return {'pid':pid,'ppid':ppid,'uid':os.geteuid(),'birth':birth,'stopped':False,
                'executable':self.c.binary,'argv':self.argv}

    def running(self):
        self.pidfile.write_text('11\n')
        self.kernel = {11:{'pid':11,'ppid':1,'uid':os.geteuid(),'birth':'1780000000:11','stopped':False,
                           'executable':'/usr/sbin/daemon','argv':['daemon: fixture:daemon[22]']},22:self.app()}

    def send(self, pid, sig):
        self.assertGreater(pid, 0); self.signals.append((pid, sig))
        value = self.kernel.get(pid)
        if value is None: raise ProcessLookupError
        if sig == signal.SIGSTOP:
            value['stopped'] = True
            if self.respawn:
                self.kernel.pop(22, None); self.kernel[23] = self.app(23, birth='1780000000:23')
                value['argv'] = ['daemon: fixture:daemon[23]']
                if self.foreign_respawn:self.kernel[23]['executable']='/usr/sbin/sshd'
        elif sig == signal.SIGCONT:
            value['stopped'] = False
            if value.pop('term', False):
                self.kernel.pop(pid, None)
                for child in self.kernel.values():
                    if child['ppid'] == pid:child['ppid'] = 1
                if self.pidfile.exists() and self.pidfile.read_text().strip() == str(pid):self.pidfile.unlink()
        elif sig == signal.SIGTERM:
            if value['executable'] == '/usr/sbin/daemon':value['term'] = True
            elif not self.stuck:self.kernel.pop(pid, None)

    def test_zero_negative_overflow_pid_files_preserve_everything_without_signals(self):
        for pid in ('0', '-1', '2147483648', 'bad', ''):
            self.pidfile.write_text(pid)
            with self.assertRaises(RuntimeError): self.c.stop()
            self.assertEqual(self.pidfile.read_text(), pid)
            self.assertFalse(self.signals)

    def test_foreign_supervisor_and_unexpected_child_are_never_signaled(self):
        self.running(); self.kernel[11]['argv']=['daemon: foreign[22]']
        with self.assertRaises(RuntimeError):self.c.stop()
        self.assertFalse(self.signals); self.assertTrue(self.pidfile.exists())
        self.running(); self.kernel[22]['executable']='/usr/sbin/sshd'
        with self.assertRaises(RuntimeError):self.c.stop()
        self.assertFalse(self.signals)

    def test_recorded_birth_reuse_preserves_foreign_pid_file(self):
        self.running(); self.c.record()
        self.kernel[11]['birth'] = '1780000001:11'
        with self.assertRaises(RuntimeError): self.c.stop()
        self.assertTrue(self.pidfile.exists()); self.assertFalse(self.signals)

    def test_clock_step_keeps_a_live_writer_owned(self):
        boot = '{ sec = 1780000000, usec = 100 }'
        with patch.object(m, 'boot', return_value=boot):
            self.running(); self.c.record()
            self.assertTrue(self.c.status())
            shifted = '{ sec = 1780000300, usec = 100 }'
            for value in self.kernel.values():
                sec, usec = value['birth'].split(':')
                value['birth'] = '%d:%s' % (int(sec) + 300, usec)
            with patch.object(m, 'boot', return_value=shifted):
                self.assertTrue(self.c.status())
                self.c.stop()
        self.assertFalse(self.kernel); self.assertFalse(self.c.journal.exists())
        self.assertIn((11, signal.SIGTERM), self.signals)
        self.assertIn((22, signal.SIGTERM), self.signals)

    def test_previous_boot_receipt_without_pidfile_is_retired_without_signals(self):
        self.running(); self.c.record()
        record = json.loads(self.c.journal.read_text()); record['boot'] = 'different-boot'
        m.persist(self.c.journal, record)
        self.pidfile.unlink(); self.kernel = {}
        self.c.stop()
        self.assertFalse(self.c.journal.exists()); self.assertFalse(self.signals)

    def test_missing_pidfile_keeps_exact_journalled_supervisor_recoverable(self):
        self.running(); self.c.record(); self.pidfile.unlink()
        self.assertTrue(self.c.status())
        self.c.stop()
        self.assertFalse(self.kernel); self.assertFalse(self.c.journal.exists())
        self.assertIn((11, signal.SIGTERM), self.signals)
        self.assertIn((22, signal.SIGTERM), self.signals)

    def test_respawn_child_is_captured_after_freeze_and_old_child_is_not_signaled(self):
        self.running(); self.c.record(); self.respawn=True
        self.c.stop()
        self.assertIn((23,signal.SIGTERM),self.signals)
        self.assertNotIn((22,signal.SIGTERM),self.signals)
        self.assertFalse(self.kernel);self.assertFalse(self.c.journal.exists())

    def test_unexpected_child_after_freeze_is_preserved_and_parent_resumed(self):
        self.running();self.respawn=True;self.foreign_respawn=True
        with self.assertRaises(RuntimeError):self.c.stop()
        self.assertEqual(self.signals,[(11,signal.SIGSTOP),(11,signal.SIGCONT)])
        self.assertFalse(self.kernel[11]['stopped']);self.assertIn(23,self.kernel)

    def test_partial_stop_journal_retains_orphan_and_blocks_import_until_its_exit(self):
        self.running();self.c.record();self.stuck=True
        with self.assertRaises(RuntimeError):self.c.stop()
        self.assertFalse(self.pidfile.exists());self.assertTrue(self.c.journal.exists());self.assertIn(22,self.kernel)
        with self.assertRaises(RuntimeError):self.c.idle()
        self.stuck=False;self.c.stop()
        self.assertFalse(self.kernel);self.assertFalse(self.c.journal.exists())

    def test_persist_failure_stops_healthy_writer_before_terminating_supervisor(self):
        self.running()
        with patch.object(m,'persist',side_effect=OSError('fixture disk full')):self.c.stop()
        self.assertLess(self.signals.index((22,signal.SIGTERM)),self.signals.index((11,signal.SIGTERM)))
        self.assertFalse(self.kernel);self.assertFalse(self.pidfile.exists())

    def test_persist_failure_and_stuck_writer_keeps_supervisor_pid_for_recovery(self):
        self.running();self.stuck=True
        with patch.object(m,'persist',side_effect=OSError('fixture disk full')):
            with self.assertRaises(RuntimeError):self.c.stop()
        self.assertIn(11,self.kernel);self.assertIn(22,self.kernel);self.assertTrue(self.pidfile.exists())
        self.assertFalse(self.kernel[11]['stopped'])
        with self.assertRaises(RuntimeError):self.c.idle()

    def test_foreign_replacement_pid_is_not_deleted_after_owned_children_stop(self):
        self.running();self.c.record()
        original=self.send
        def signal_and_replace(pid,sig):
            original(pid,sig)
            if pid==22 and sig==signal.SIGTERM:
                self.kernel[99]=dict(self.app(99,1),executable='/usr/sbin/sshd',argv=['sshd'])
                self.pidfile.write_text('99\n')
        with patch.object(m.os,'kill',side_effect=signal_and_replace):
            with self.assertRaises(RuntimeError):self.c.stop()
        self.assertEqual(self.pidfile.read_text(),'99\n');self.assertIn(99,self.kernel)
        self.assertFalse(any(pid==99 for pid,sig in self.signals))

    def test_invalid_journal_and_pid_symlink_are_preserved(self):
        self.running();self.c.journal.write_text('{"children":[]}');self.c.journal.chmod(0o600)
        with self.assertRaises(RuntimeError):self.c.stop()
        self.assertFalse(self.signals)
        self.pidfile.unlink();target=self.root/'foreign';target.write_text('11');self.pidfile.symlink_to(target)
        with self.assertRaises(OSError):self.c.stop()
        self.assertTrue(self.pidfile.is_symlink());self.assertEqual(target.read_text(),'11')

    def test_native_child_inventory_ignores_legitimate_kernel_pid_zero(self):
        with patch.object(m.subprocess,'run',return_value=types.SimpleNamespace(returncode=0,stdout=b'0 0\n11 1\n22 11\n')):
            # Restore the actual inventory parser patched by the fixture.
            spec=importlib.util.spec_from_file_location('inventory_parser',COMMON/'process_control.py')
            actual=importlib.util.module_from_spec(spec);spec.loader.exec_module(actual)
            self.assertEqual(actual.children(11),[22])

    def test_real_busy_owned_lock_times_out_without_touching_processes_or_settings(self):
        self.running()
        lockpath=Path(str(self.pidfile)+'.control.lock')
        argv=['process_control.py','status',str(self.pidfile),'fixture:daemon',str(self.binary),*self.argv[1:]]
        with lockpath.open('w') as lock:
            m.fcntl.flock(lock.fileno(),m.fcntl.LOCK_EX | m.fcntl.LOCK_NB)
            with patch.object(m.sys,'argv',argv), patch.object(m.sys,'stderr',io.StringIO()):
                self.assertEqual(m.main(),1)
            self.assertEqual(self.pidfile.read_text(),'11\n')
            self.assertFalse(self.c.journal.exists());self.assertFalse(self.signals)
            self.assertEqual(set(self.kernel),{11,22})
        with patch.object(m.sys,'argv',argv):self.assertEqual(m.main(),0)


if __name__ == '__main__':unittest.main()
