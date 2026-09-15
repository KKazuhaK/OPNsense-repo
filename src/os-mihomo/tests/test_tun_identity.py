"""Verify that only the exact TUN created by the owned Mihomo core is removed."""
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
from unittest import mock

from test_mihomo import m


class TunKernel:
    def __init__(self):
        self.present = True
        self.index = 17
        self.driver = 'tun4'
        self.metric = 0
        self.mtu = 9000
        self.description = ''
        self.opened_by = 202
        self.up = True
        self.addresses = True
        self.calls = []
        self.fail_description = False
        self.fail_after_description = False

    def verbose(self):
        flags = '8051' if self.up else '8010'
        lines = ['tun_mihomo: flags=%s<TEST> metric %d mtu %d' %
                 (flags, self.metric, self.mtu)]
        if self.description:
            lines.append('\tdescription: ' + self.description)
        if self.opened_by is not None:
            lines.append('\tOpened by PID %d' % self.opened_by)
        if self.addresses:
            lines.append('\tinet 198.18.0.1 netmask 0xfffffffc')
        lines.append('\tdrivername: ' + self.driver)
        return ('\n'.join(lines) + '\n').encode()

    def run(self, args, **kwargs):
        self.calls.append(list(args))
        if args == ['/sbin/ifconfig', '-v', 'tun_mihomo']:
            return subprocess.CompletedProcess(args, 0 if self.present else 1,
                                               self.verbose() if self.present else b'', b'')
        if args == ['/sbin/ifconfig', 'tun_mihomo']:
            output = self.verbose() if self.present else b''
            return subprocess.CompletedProcess(args, 0 if self.present else 1, output, b'')
        if args[:3] == ['/sbin/ifconfig', 'tun_mihomo', 'description']:
            if self.fail_description:
                raise m.Error('injected description failure')
            self.description = args[3]
            if self.fail_after_description:
                raise m.Error('injected post-description crash')
            return subprocess.CompletedProcess(args, 0, b'', b'')
        if args == ['/sbin/ifconfig', 'tun_mihomo', 'destroy']:
            self.present = False
            return subprocess.CompletedProcess(args, 0, b'', b'')
        if args[:2] == ['/usr/local/bin/python3', m.ROUTING_HELPER]:
            return subprocess.CompletedProcess(args, 0, b'{}\n', b'')
        if args[0] == '/usr/sbin/daemon':
            raise AssertionError('A foreign TUN must be rejected before core startup.')
        raise AssertionError('Unexpected command: ' + repr(args))


class TunIdentityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.state = Path(self.temp.name)
        self.state.chmod(0o700)
        self.state_patch = mock.patch.object(m, 'STATE', str(self.state))
        self.state_patch.start()
        self.addCleanup(self.state_patch.stop)
        self.kernel = TunKernel()
        self.live = {}
        self.system = m.System(process_reader=lambda pid: self.live.get(pid))
        self.system.run = self.kernel.run
        group = self.system._core_group()
        self.core = {'pid': 202, 'ppid': 101, 'uid': os.geteuid(), 'birth': '1000:2',
                     'executable': '/usr/local/bin/mihomo',
                     'argv': list(group.child_argv)}
        self.live[202] = dict(self.core, stopped=False)
        self.record = {'child': dict(self.core)}
        self.index_patch = mock.patch.object(socket, 'if_nametoindex', return_value=self.kernel.index)
        self.index_patch.start()
        self.addCleanup(self.index_patch.stop)

    @property
    def receipt(self):
        return self.state / 'tun-runtime-identity.json'

    def claim(self):
        self.system.claim_tun(self.record)
        return json.loads(self.receipt.read_text())

    def close_core(self):
        self.live.clear()
        self.kernel.opened_by = None
        self.kernel.up = False
        self.kernel.addresses = False

    def test_claim_records_opener_and_kernel_identity_then_closed_cleanup_destroys_it(self):
        receipt = self.claim()
        self.assertEqual('owned', receipt['phase'])
        self.assertEqual(self.core, receipt['core'])
        self.assertEqual({'flags': 0x8051, 'addresses': ['inet:198.18.0.1'],
                          'opened_by': self.core['pid']}, receipt['opened'])
        self.assertEqual(self.kernel.description, receipt['description'])
        self.assertEqual(0o600, self.receipt.stat().st_mode & 0o777)
        self.close_core()

        destroyed, unused = self.system.destroy_owned_tun()

        self.assertTrue(destroyed)
        self.assertFalse(self.kernel.present)
        self.assertFalse(self.receipt.exists())

    def test_unjournalled_same_name_interface_is_preserved(self):
        self.close_core()
        with self.assertRaisesRegex(m.Error, 'unowned'):
            self.system.destroy_owned_tun()
        self.assertTrue(self.kernel.present)
        self.assertNotIn(['/sbin/ifconfig', 'tun_mihomo', 'destroy'], self.kernel.calls)

    def test_start_fails_before_launch_when_same_name_interface_is_foreign(self):
        self.close_core()
        config = self.state / 'config.yaml'
        config.write_text('tun: {enable: false}\ndns: {enable: false}\n')
        with mock.patch.object(self.system, 'running', return_value=False), \
                mock.patch.object(self.system, 'recover_reloads'):
            with self.assertRaisesRegex(m.Error, 'unowned'):
                self.system.start(config, False)
        self.assertTrue(self.kernel.present)

    def test_changed_description_driver_or_new_opener_is_never_destroyed(self):
        for field, value in (('description', 'Operator TUN'), ('driver', 'tun9'),
                             ('opened_by', 999)):
            with self.subTest(field=field):
                self.receipt.unlink(missing_ok=True)
                self.kernel = TunKernel()
                self.system.run = self.kernel.run
                self.live[202] = dict(self.core, stopped=False)
                self.claim()
                self.close_core()
                setattr(self.kernel, field, value)
                with self.assertRaises(m.Error):
                    self.system.destroy_owned_tun()
                self.assertTrue(self.kernel.present)

    def test_claiming_receipt_recovers_crash_before_description_write(self):
        self.kernel.fail_description = True
        with self.assertRaisesRegex(m.Error, 'description failure'):
            self.system.claim_tun(self.record)
        receipt = json.loads(self.receipt.read_text())
        self.assertEqual('claiming', receipt['phase'])
        self.assertEqual('', self.kernel.description)
        self.kernel.fail_description = False
        self.close_core()

        destroyed, unused = self.system.destroy_owned_tun()

        self.assertTrue(destroyed)
        self.assertFalse(self.kernel.present)

    def test_claiming_receipt_recovers_crash_after_unique_description_write(self):
        self.kernel.fail_after_description = True
        with self.assertRaisesRegex(m.Error, 'post-description crash'):
            self.system.claim_tun(self.record)
        receipt = json.loads(self.receipt.read_text())
        self.assertEqual('claiming', receipt['phase'])
        self.assertEqual(receipt['description'], self.kernel.description)
        self.close_core()

        destroyed, unused = self.system.destroy_owned_tun()

        self.assertTrue(destroyed)
        self.assertFalse(self.kernel.present)

    def test_live_reused_core_pid_cannot_resume_a_pending_claim(self):
        self.kernel.fail_description = True
        with self.assertRaises(m.Error):
            self.system.claim_tun(self.record)
        self.kernel.fail_description = False
        self.live[202] = dict(self.core, birth='2000:9', stopped=False)
        with self.assertRaises(m.Error):
            self.system.claim_tun(self.record)
        self.assertEqual('', self.kernel.description)


if __name__ == '__main__':
    unittest.main()
