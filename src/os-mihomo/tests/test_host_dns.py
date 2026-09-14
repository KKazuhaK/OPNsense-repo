"""Recover only host DNS written by a stopped FreeBSD Mihomo core."""
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from test_mihomo import m


class HostDNSRecoveryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='mihomo-host-dns-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.resolver = self.root / 'resolv.conf'
        self.config = self.root / 'config.xml'
        self.local = self.root / 'resolv.conf.local'
        self.pending = self.root / 'state/host-dns-reload-pending'
        self.pending.parent.mkdir(mode=0o700)
        self.resolver.write_bytes(b'search localdomain\nnameserver 198.18.0.2\n')
        self.config.write_text('<opnsense><system><dnsserver>1.1.1.1</dnsserver></system></opnsense>')
        self.interface = b'tun_mihomo: flags=8043\n\tinet 198.18.0.1 netmask 0xfffffffc broadcast 198.18.0.1\n'
        self.present, self.alive, self.foreign_core = True, False, False
        self.fail_reload, self.noop_reload, self.destroy_edit = False, False, None
        self.commands = []
        self.system = m.System()
        self.routing_patch = mock.patch.object(self.system, 'routing')
        self.routing_patch.start()
        self.addCleanup(self.routing_patch.stop)
        self.system.running = lambda: self.alive
        path_patch = mock.patch.object(m.System, '_host_dns_paths', return_value=
            (self.resolver, self.config, self.local, self.pending))
        path_patch.start()
        self.addCleanup(path_patch.stop)
        # Portable fixtures emulate the root owner used by native configd.
        original_fstat = os.fstat
        def root_fstat(descriptor):
            info = original_fstat(descriptor)
            return SimpleNamespace(**{name: 0 if name == 'st_uid' else getattr(info, name)
                for name in ('st_uid', 'st_mode', 'st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')})
        owner_patch = mock.patch.object(m.os, 'fstat', side_effect=root_fstat)
        owner_patch.start()
        self.addCleanup(owner_patch.stop)
        runner_patch = mock.patch.object(m.subprocess, 'run', side_effect=self.run_command)
        runner_patch.start()
        self.addCleanup(runner_patch.stop)

    def run_command(self, args, **options):
        self.commands.append(list(args))
        if args == ['/usr/bin/pgrep', '-x', 'mihomo']:
            return subprocess.CompletedProcess(args, 0 if self.foreign_core else 1, b'', b'')
        if args == ['/sbin/ifconfig', 'tun_mihomo']:
            return subprocess.CompletedProcess(args, 0 if self.present else 1, self.interface if self.present else b'', b'')
        if args == ['/sbin/ifconfig', 'tun_mihomo', 'destroy']:
            self.present = False
            if self.destroy_edit:
                self.destroy_edit()
            return subprocess.CompletedProcess(args, 0, b'', b'')
        if args == ['/usr/local/sbin/configctl', 'dns', 'reload']:
            if self.fail_reload:
                # Exercise System.run's real configctl bare-ERR detection.
                return subprocess.CompletedProcess(args, 0, b'ERR', b'')
            if not self.noop_reload:
                self.resolver.write_bytes(b'nameserver 127.0.0.1\nnameserver 1.1.1.1\n')
            return subprocess.CompletedProcess(args, 0, b'OK', b'')
        if args == ['/usr/sbin/service', 'sing-box', 'onestatus']:
            return subprocess.CompletedProcess(args, 1, b'', b'')
        if args[0] == '/usr/sbin/daemon':
            self.alive, self.present = True, True
            self.resolver.write_bytes(b'search localdomain\nnameserver 198.18.0.2\n')
            return subprocess.CompletedProcess(args, 0, b'', b'')
        if args == ['/sbin/route', '-n', 'get', '8.8.8.8']:
            return subprocess.CompletedProcess(args, 0, b'interface: tun_mihomo\n', b'')
        raise AssertionError('Unexpected system command: ' + repr(args))

    def reload_count(self):
        return self.commands.count(['/usr/local/sbin/configctl', 'dns', 'reload'])

    def test_crashed_core_recovers_host_dns_after_destroying_tun(self):
        self.system.destroy_tun()
        self.assertFalse(self.present)
        self.assertEqual(self.reload_count(), 1)
        self.assertLess(self.commands.index(['/sbin/ifconfig', 'tun_mihomo', 'destroy']),
                        self.commands.index(['/usr/local/sbin/configctl', 'dns', 'reload']))
        self.assertIn(b'127.0.0.1', self.resolver.read_bytes())
        self.assertFalse(self.pending.exists())
        self.system.destroy_tun()
        self.assertEqual(self.reload_count(), 1)

    def test_failed_reload_retries_without_tun_and_keeps_private_fingerprint(self):
        original = self.resolver.read_bytes()
        self.fail_reload = True
        with self.assertRaises(m.Error):
            self.system.destroy_tun()
        self.assertFalse(self.present)
        self.assertEqual(self.resolver.read_bytes(), original)
        self.assertEqual(stat.S_IMODE(self.pending.stat().st_mode), 0o600)
        record = json.loads(self.pending.read_bytes())
        self.assertEqual(record, {'servers': ['198.18.0.2'], 'checksum': hashlib.sha256(original).hexdigest()})
        self.fail_reload = False
        self.system.destroy_tun()
        self.assertEqual(self.reload_count(), 2)
        self.assertFalse(self.pending.exists())

    def test_operator_rewrite_after_failed_reload_cancels_retry(self):
        self.fail_reload = True
        with self.assertRaises(m.Error):
            self.system.destroy_tun()
        operator = b'nameserver 9.9.9.9\n'
        self.resolver.write_bytes(operator)
        self.fail_reload = False
        self.system.destroy_tun()
        self.assertEqual(self.reload_count(), 1)
        self.assertEqual(self.resolver.read_bytes(), operator)
        self.assertFalse(self.pending.exists())

    def test_noop_reload_keeps_retry_until_resolver_was_regenerated(self):
        self.noop_reload = True
        with self.assertRaises(m.Error):
            self.system.destroy_tun()
        self.assertFalse(self.present)
        self.assertTrue(self.pending.exists())
        self.noop_reload = False
        self.system.destroy_tun()
        self.assertEqual(self.reload_count(), 2)
        self.assertFalse(self.pending.exists())

    def test_later_core_with_new_tun_address_replaces_stale_recovery_proof(self):
        self.fail_reload = True
        with self.assertRaises(m.Error):
            self.system.destroy_tun()
        self.present, self.fail_reload = True, False
        self.interface = b'tun_mihomo: flags=8043\n\tinet 198.19.8.1 netmask 0xfffffffc\n'
        self.resolver.write_bytes(b'search localdomain\nnameserver 198.19.8.2\n')
        self.system.destroy_tun()
        self.assertEqual(self.reload_count(), 2)
        self.assertFalse(self.pending.exists())

    def test_operator_edit_during_tun_cleanup_is_rechecked(self):
        self.destroy_edit = lambda: self.resolver.write_bytes(b'nameserver 9.9.9.9\n')
        self.system.destroy_tun()
        self.assertFalse(self.present)
        self.assertEqual(self.reload_count(), 0)
        self.assertEqual(self.resolver.read_bytes(), b'nameserver 9.9.9.9\n')
        self.assertFalse(self.pending.exists())

    def test_native_xml_operator_dns_is_preserved(self):
        self.config.write_text('<opnsense><system><dnsserver>198.18.0.2</dnsserver></system></opnsense>')
        self.system.destroy_tun()
        self.assertFalse(self.present)
        self.assertEqual(self.reload_count(), 0)
        self.assertFalse(self.pending.exists())

    def test_local_operator_dns_is_preserved(self):
        self.local.write_text('nameserver 198.18.0.2 # deliberate operator resolver\n')
        self.system.destroy_tun()
        self.assertFalse(self.present)
        self.assertEqual(self.reload_count(), 0)
        self.assertFalse(self.pending.exists())

    def test_native_xml_operator_edit_during_cleanup_is_rechecked(self):
        self.destroy_edit = lambda: self.config.write_text(
            '<opnsense><system><dnsserver>198.18.0.2</dnsserver></system></opnsense>')
        self.system.destroy_tun()
        self.assertEqual(self.reload_count(), 0)
        self.assertFalse(self.pending.exists())

    def test_running_or_foreign_core_prevents_host_reset(self):
        for own, foreign in ((True, False), (False, True)):
            with self.subTest(own=own, foreign=foreign):
                self.present, self.alive, self.foreign_core = True, own, foreign
                self.system.destroy_tun()
                self.assertFalse(self.present)
                self.assertEqual(self.reload_count(), 0)
                self.assertEqual(self.pending.exists(), foreign)
                self.pending.unlink(missing_ok=True)

    def test_global_zombie_entry_retains_proof_until_child_is_reaped(self):
        self.foreign_core = True
        self.system.destroy_tun()
        self.assertFalse(self.present)
        self.assertTrue(self.pending.exists())
        self.assertEqual(self.reload_count(), 0)
        self.foreign_core = False
        self.system.destroy_tun()
        self.assertEqual(self.reload_count(), 1)
        self.assertFalse(self.pending.exists())

    def test_ready_start_captures_dns_before_crash_erases_tun_addresses(self):
        self.present = False
        self.resolver.write_bytes(b'nameserver 127.0.0.1\n')
        candidate = self.root / 'candidate.yaml'
        candidate.write_text('mixed-port: 7890\nbind-address: 127.0.0.1\n'
                             'tun: {enable: true, auto-route: true}\n'
                             "dns: {enable: true, listen: '127.0.0.1:1053'}\n")
        with mock.patch.object(m.socket, 'create_connection'):
            self.system.start(candidate, transparent=True)
        self.assertTrue(self.alive)
        self.assertTrue(self.pending.exists())
        self.assertEqual(stat.S_IMODE(self.pending.stat().st_mode), 0o600)
        self.assertEqual(self.reload_count(), 0)
        self.alive = False
        # Native FreeBSD retains the interface but erases inet addresses when
        # the dead core's last descriptor closes.
        self.interface = b'tun_mihomo: flags=8043\n'
        self.system.destroy_tun()
        self.assertFalse(self.present)
        self.assertEqual(self.reload_count(), 1)
        self.assertFalse(self.pending.exists())

    def test_core_start_during_cleanup_defers_recovery(self):
        self.destroy_edit = lambda: setattr(self, 'foreign_core', True)
        self.system.destroy_tun()
        self.assertEqual(self.reload_count(), 0)
        self.assertTrue(self.pending.exists())
        self.foreign_core, self.destroy_edit = False, None
        self.system.destroy_tun()
        self.assertEqual(self.reload_count(), 1)

    def test_custom_ipv4_and_ipv6_core_addresses_are_derived_from_tun(self):
        self.interface = b'tun_mihomo: flags=8043\n\tinet 198.19.8.1 netmask 0xfffffffc\n\tinet6 fd12:3456::1 prefixlen 126\n'
        self.resolver.write_bytes(b'search localdomain\nnameserver 198.19.8.2\nnameserver fd12:3456::2\n')
        self.system.destroy_tun()
        self.assertEqual(self.reload_count(), 1)
        self.assertFalse(self.pending.exists())

    def test_close_restored_dns_or_noncore_formats_are_not_reset(self):
        for content in (b'nameserver 127.0.0.1\n', b'nameserver 198.18.0.2\n',
                        b'search operator.example\nnameserver 198.18.0.2\n',
                        b'search localdomain\nnameserver 198.18.0.2\nnameserver 1.1.1.1\n',
                        b'search localdomain\nnameserver 198.18.0.22\n',
                        b'search localdomain\nnameserver 198.18.0.2\n# operator edit\n'):
            with self.subTest(content=content):
                self.present = True
                self.resolver.write_bytes(content)
                self.system.destroy_tun()
                self.assertFalse(self.present)
                self.assertEqual(self.reload_count(), 0)
                self.assertFalse(self.pending.exists())

    def test_absent_tun_without_local_recovery_proof_is_not_reset(self):
        self.present = False
        self.system.destroy_tun()
        self.assertEqual(self.reload_count(), 0)
        self.assertFalse(self.pending.exists())

    def test_unknown_native_xml_prevents_host_reset(self):
        self.config.write_text('<invalid')
        self.system.destroy_tun()
        self.assertFalse(self.present)
        self.assertEqual(self.reload_count(), 0)

    def test_insecure_or_corrupt_retry_marker_cannot_reset_host_dns(self):
        for content, mode in ((b'{}', 0o600), (b'{}', 0o644)):
            with self.subTest(mode=mode):
                self.present = True
                self.pending.write_bytes(content)
                self.pending.chmod(mode)
                with self.assertRaises(m.Error):
                    self.system.destroy_tun()
                self.assertFalse(self.present)
                self.assertEqual(self.reload_count(), 0)


if __name__ == '__main__':
    unittest.main()
