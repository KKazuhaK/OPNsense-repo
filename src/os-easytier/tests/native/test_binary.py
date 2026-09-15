"""Validate the rendered config and query a private, genuine EasyTier core."""
import importlib.util
import json
import re
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

PACKAGE = Path(__file__).resolve().parents[2]
BINARIES = PACKAGE / 'src/usr/local/sbin'
CORE = BINARIES / 'easytier-core'
CLI = BINARIES / 'easytier-cli'
SCRIPT = PACKAGE / 'src/usr/local/opnsense/scripts/easytier/manage.py'
sys.path.insert(0, str(PACKAGE.parent / 'common'))


class PortalTests(unittest.TestCase):
    def test_peers_use_configured_port_and_convert_wildcard_listeners_to_loopback(self):
        spec = importlib.util.spec_from_file_location('portal_manager', SCRIPT)
        manager = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(manager)
        for portal, expected in [(0, '127.0.0.1:15888'), (30123, '127.0.0.1:30123'),
                                 ('127.0.0.1:30124', '127.0.0.1:30124'),
                                 ('0.0.0.0:30125', '127.0.0.1:30125'),
                                 ('[::]:30126', '[::1]:30126')]:
            with self.subTest(portal=portal), patch.object(manager, 'stored', return_value={'rpc_portal': portal}), \
                    patch.object(manager, 'running', return_value=True), \
                    patch.object(manager, 'run', return_value=subprocess.CompletedProcess([], 0, '')) as run:
                self.assertEqual('ok', manager.dispatch('peers')['status'])
                self.assertEqual(['/usr/local/sbin/easytier-cli', '-p', expected, 'peer'], run.call_args.args[0])

    def test_invalid_portal_never_reaches_cli_or_exposes_config_in_cli_error(self):
        spec = importlib.util.spec_from_file_location('invalid_portal_manager', SCRIPT)
        manager = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(manager)
        for portal in [True, [], {}, 65536, -1, 'https://user:SENTINEL@127.0.0.1', '127.0.0.1:0']:
            with self.subTest(portal=portal), patch.object(manager, 'stored', return_value={'rpc_portal': portal}), \
                    patch.object(manager, 'running', return_value=True), patch.object(manager, 'run') as run:
                with self.assertRaisesRegex(ValueError, '^Invalid RPC portal.$'):
                    manager.dispatch('peers')
                run.assert_not_called()

    def test_startup_portal_cli_preserves_bind_address_and_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'config.toml'
            runner = Path(directory) / 'manage.py'
            runner.write_text(SCRIPT.read_text().replace(
                "CONFIG = Path('/usr/local/etc/easytier/config.toml')", f'CONFIG = Path({str(config)!r})'))
            runner.with_name('network.py').write_text((SCRIPT.with_name('network.py')).read_text())
            runner.with_name('process_identity.py').write_text(
                (PACKAGE.parent / 'common/process_identity.py').read_text())
            config.write_text('rpc_portal = "0.0.0.0:30125"\n')
            result = subprocess.run([sys.executable, str(runner), 'rpc-portal'], capture_output=True, text=True)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual('0.0.0.0:30125\n', result.stdout)
            config.write_text('rpc_portal = "SENTINEL_INVALID_PORTAL"\n')
            result = subprocess.run([sys.executable, str(runner), 'rpc-portal'], capture_output=True, text=True)
            self.assertEqual(1, result.returncode)
            self.assertEqual('', result.stdout)
            self.assertNotIn('SENTINEL', result.stderr)

    def test_rc_start_validates_before_launch_and_never_reloads_global_pf(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def remap(source):
                return re.sub(r'(?<![A-Za-z0-9_./-])/(usr/local|var)(?=/)',
                              lambda match: str(root / match[1]), source)
            for directory in ('usr/local/bin', 'usr/local/opnsense/scripts/easytier', 'var/run', 'var/log'):
                (root / directory).mkdir(parents=True, exist_ok=True)
            (root / 'usr/local/bin/python3').symlink_to(sys.executable)
            helper = root / 'usr/local/opnsense/scripts/easytier/network.py'
            marker, arguments, reject = root / 'running', root / 'arguments', root / 'reject'
            helper.write_text(f"import pathlib,sys\n"
                              f"reject=pathlib.Path({str(reject)!r})\n"
                              f"running=pathlib.Path({str(marker)!r})\n"
                              "action=sys.argv[1]\n"
                              "if action == 'check' and reject.exists(): raise SystemExit(1)\n"
                              "if action == 'status': raise SystemExit(0 if running.exists() else 1)\n")
            helper.with_name('config_mirror.py').write_text('raise SystemExit(0)\n')
            daemon = root / 'daemon'
            daemon.write_text(f'#!/bin/sh\nprintf "%s\\n" "$@" > "{arguments}"\ntouch "{marker}"\n')
            daemon.chmod(0o700)
            library = root / 'rc.subr'
            library.write_text('load_rc_config() { :; }\nrun_rc_command() { easytier_start; }\n')
            rc = root / 'rc'
            source = (PACKAGE / 'src/usr/local/etc/rc.d/easytier').read_text()
            rc.write_text(remap(source.replace('. /etc/rc.subr', 'PRIVATE_RC_LIBRARY'))
                          .replace('PRIVATE_RC_LIBRARY', f'. "{library}"').replace('/usr/sbin/daemon', str(daemon)))
            result = subprocess.run(['sh', str(rc), 'onestart'], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(str(helper) + '\nrun\n', arguments.read_text())
            self.assertEqual((root / 'var/log/easytier.log').stat().st_mode & 0o777, 0o600)
            arguments.unlink()
            marker.unlink()
            reject.touch()
            result = subprocess.run(['sh', str(rc), 'onestart'], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(arguments.exists())
            self.assertNotIn('configctl filter', source)
            self.assertNotIn('pfctl', source)


@unittest.skipUnless(sys.platform.startswith('freebsd') and CORE.is_file() and CLI.is_file(),
                     'Requires bundled native FreeBSD EasyTier binaries')
class BinaryTests(unittest.TestCase):
    def test_rendered_config_passes_core_validation_and_native_rpc_peers(self):
        spec = importlib.util.spec_from_file_location('binary_manager', SCRIPT)
        manager = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(manager)
        with tempfile.TemporaryDirectory(prefix='easytier-core-test-') as directory:
            root = Path(directory)
            with socket.socket() as reservation:
                reservation.bind(('127.0.0.1', 0))
                port = reservation.getsockname()[1]
            manager.CONFIG = root / 'config.toml'
            manager.RC = str(root / 'status')
            manager.CONFIG.write_text(manager.render({
                'hostname': 'native-fixture', 'rpc_portal': f'127.0.0.1:{port}',
                'listeners': [], 'peer': [], 'network_identity': {
                    'network_name': 'native-fixture', 'network_secret': 'SENTINEL_秘密'},
                'flags': {'no_tun': True, 'disable_upnp': True, 'disable_ipv6': True},
            }))
            checked = subprocess.run([str(CORE), '-c', str(manager.CONFIG), '--check-config'],
                                     capture_output=True, text=True, timeout=10, cwd=root)
            self.assertEqual(0, checked.returncode, checked.stderr)
            log = root / 'core.log'
            with log.open('w') as stream:
                core = subprocess.Popen([str(CORE), '-c', str(manager.CONFIG), '--no-listener',
                                         '--rpc-portal', manager.rpc_portal(for_connection=False),
                                         '--no-tun', '--disable-upnp', '--disable-ipv6',
                                         '--stun-servers', '--stun-servers-v6',
                                         '--console-log-level', 'error'],
                                        stdout=stream, stderr=subprocess.STDOUT, cwd=root)
                try:
                    Path(manager.RC).write_text(f'#!/bin/sh\nkill -0 {core.pid}\n')
                    Path(manager.RC).chmod(0o700)
                    deadline = time.monotonic() + 10
                    while time.monotonic() < deadline:
                        self.assertIsNone(core.poll(), log.read_text())
                        try:
                            with socket.create_connection(('127.0.0.1', port), timeout=0.2):
                                break
                        except OSError:
                            time.sleep(0.05)
                    else:
                        self.fail('The native core did not open the configured RPC portal: ' + log.read_text())
                    original = manager.run

                    def native(arguments, timeout=30):
                        if arguments[0] == '/usr/local/sbin/easytier-cli':
                            arguments = [str(CLI), *arguments[1:]]
                        return original(arguments, timeout)

                    with patch.object(manager, 'run', side_effect=native):
                        result = manager.dispatch('peers')
                    self.assertEqual('ok', result['status'], result)
                    self.assertTrue(result['running'])
                    self.assertTrue(any(row[1:3] == ['native-fixture', 'Local'] for row in result['rows']), result)
                    self.assertTrue(all(len(row) == 10 for row in result['rows']))
                    self.assertNotIn('SENTINEL', json.dumps(result))
                finally:
                    core.terminate()
                    core.wait(timeout=10)
            manager.CONFIG.write_text('hostname = [\n')
            rejected = subprocess.run([str(CORE), '-c', str(manager.CONFIG), '--check-config'],
                                      capture_output=True, text=True, timeout=10, cwd=root)
            self.assertNotEqual(0, rejected.returncode)
