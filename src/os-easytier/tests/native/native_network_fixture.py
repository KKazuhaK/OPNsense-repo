#!/usr/local/bin/python3
"""Run additional genuine-TUN coverage only in an explicitly owned VNET jail.

This is an isolated native fixture, not fresh OPNsense installation acceptance.
Core 1 uses a real TUN; Core 2 uses its supported userspace subnet proxy.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import tomllib


def command(arguments, timeout=10):
    return subprocess.run(arguments, capture_output=True, text=True, timeout=timeout, check=False)


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def wait(check, seconds=25):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        result = check()
        if result:
            return result
        time.sleep(.1)
    raise AssertionError('A native fixture condition did not complete before its deadline.')


def reserve_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


class Echo:
    def __init__(self, host='127.0.0.1'):
        self.tcp = socket.socket()
        self.tcp.bind((host, 0))
        self.tcp.listen(8)
        self.port = self.tcp.getsockname()[1]
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind((host, self.port))
        self.closed = False
        for sock, operation in ((self.tcp, self.tcp_loop), (self.udp, self.udp_loop)):
            sock.settimeout(.2)
            threading.Thread(target=operation, daemon=True).start()

    def tcp_loop(self):
        while not self.closed:
            try:
                client, _peer = self.tcp.accept()
            except (OSError, TimeoutError):
                continue
            with client:
                client.settimeout(3)
                try:
                    client.sendall(client.recv(4096))
                except OSError:
                    pass

    def udp_loop(self):
        while not self.closed:
            try:
                value, peer = self.udp.recvfrom(4096)
                self.udp.sendto(value, peer)
            except (OSError, TimeoutError):
                pass

    def request(self, host, protocol):
        nonce = ('easytier-native-' + secrets.token_hex(12)).encode()
        kind = socket.SOCK_STREAM if protocol == 'tcp' else socket.SOCK_DGRAM
        with socket.socket(socket.AF_INET, kind) as sock:
            sock.settimeout(4)
            sock.connect((host, self.port))
            sock.sendall(nonce)
            assert sock.recv(4096) == nonce, 'The peer proxy did not return the exact fresh nonce.'

    def close(self):
        self.closed = True
        self.tcp.close()
        self.udp.close()


def run_fixture(payload, report_path):
    assert sys.platform.startswith('freebsd'), 'The native fixture requires FreeBSD.'
    assert command(['/sbin/sysctl', '-n', 'security.jail.jailed']).stdout.strip() == '1', 'Refusing host-level native mutations.'
    assert socket.gethostname().startswith('easytier-isolation-'), 'The fixture requires an explicitly owned VNET jail hostname.'
    assert os.geteuid() == 0, 'The fixture requires root inside its own jail.'
    scripts = payload / 'usr/local/opnsense/scripts/easytier'
    core, cli = payload / 'usr/local/sbin/easytier-core', payload / 'usr/local/sbin/easytier-cli'
    assert core.is_file() and cli.is_file() and (scripts / 'network.py').is_file()
    initial_pf = command(['/sbin/pfctl', '-sr'])
    assert initial_pf.returncode == 0 and not initial_pf.stdout.strip(), 'Refusing an existing jail firewall ruleset.'
    pf_enabled = 'Status: Enabled' in command(['/sbin/pfctl', '-s', 'info']).stdout
    root = Path(tempfile.mkdtemp(prefix='easytier-native-', dir='/tmp'))
    root.chmod(0o700)
    processes, echoes = [], []
    report = {'scope': 'isolated owned VNET jail; Core 1 real TUN, Core 2 userspace proxy',
              'fresh_opnsense_acceptance': False, 'core_sha256': hashlib.sha256(core.read_bytes()).hexdigest(),
              'network_payload_sha256': hashlib.sha256((scripts / 'network.py').read_bytes()).hexdigest(),
              'native_route_payload_sha256': hashlib.sha256((scripts / 'native_route.py').read_bytes()).hexdigest(),
              'route_control_payload_sha256': hashlib.sha256((scripts / 'route_control.py').read_bytes()).hexdigest(),
              'process_identity_payload_sha256': hashlib.sha256((scripts / 'process_identity.py').read_bytes()).hexdigest(),
              'manage_payload_sha256': hashlib.sha256((scripts / 'manage.py').read_bytes()).hexdigest(),
              'checks': {}, 'ok': False}
    network_root, config, rc, pid = root / 'network', root / 'config.toml', root / 'rc.conf', root / 'core.pid'
    replacements = {'/var/run/easytier-network': str(network_root), '/usr/local/etc/easytier/config.toml': str(config),
                    '/etc/rc.conf.d/easytier': str(rc), '/var/run/easytier.pid': str(pid),
                    '/usr/local/sbin/easytier-core': str(core), '/usr/local/sbin/easytier-cli': str(cli)}
    for filename in ('network.py', 'native_route.py', 'route_control.py', 'process_identity.py', 'manage.py'):
        source = (scripts / filename).read_text()
        for original, replacement in replacements.items():
            source = source.replace(original, replacement)
        (root / filename).write_text(source)
    sys.path.insert(0, str(root))
    network = load(root / 'network.py', 'easytier_native_fixture_network')
    native = load(root / 'native_route.py', 'easytier_native_fixture_routing')
    manager = load(root / 'manage.py', 'easytier_native_fixture_manager')
    for family in ('inet', 'inet6'):
        probe = command(['/usr/bin/netstat', '-rnW', '-f', family])
        assert probe.returncode == 0, 'Native numeric routing table probe failed: ' + probe.stderr
    before_routes = network.routing_table()
    before_interfaces = set(socket.if_nameindex())
    original_routes = dict(before_routes)
    real_echo = '10.253.123.1'
    assert command(['/sbin/ifconfig', 'lo1', 'create', 'inet', real_echo + '/32', 'up']).returncode == 0
    before_routes = network.routing_table()
    interface = 'et_fixture'
    mapped = '192.168.241.1'
    remote_route = mapped + '/32'
    rc.write_text('easytier_enable="YES"\n')
    rc.chmod(0o600)
    secret = secrets.token_hex(16)
    listener, rpc1, rpc2 = reserve_port(), reserve_port(), reserve_port()
    identity = {'network_name': 'native-' + secrets.token_hex(6), 'network_secret': secret}
    peer = {'hostname': 'userspace-peer', 'ipv4': '10.253.122.2/24', 'listeners': [f'tcp://127.0.0.1:{listener}'],
            'rpc_portal': f'127.0.0.1:{rpc2}', 'network_identity': identity,
            'proxy_network': [{'cidr': real_echo + '/32', 'mapped_cidr': remote_route}], 'routes': [],
            'flags': {'no_tun': True, 'use_smoltcp': True, 'proxy_forward_by_system': False,
                      'disable_upnp': True, 'enable_ipv6': False, 'disable_p2p': True,
                      'disable_udp_hole_punching': True, 'disable_tcp_hole_punching': True}}
    local = {'hostname': 'real-tun-router', 'ipv4': '10.253.122.1/24', 'listeners': [],
             'rpc_portal': f'127.0.0.1:{rpc1}', 'network_identity': identity, 'peer': [{'uri': f'tcp://127.0.0.1:{listener}'}],
             'flags': {'dev_name': interface, 'no_tun': False, 'disable_upnp': True, 'enable_ipv6': False,
                       'disable_p2p': True, 'disable_udp_hole_punching': True, 'disable_tcp_hole_punching': True},
             'fixture_future_field': {'nested': [1, 2, 3]}}
    peer_config = root / 'peer.toml'
    peer_config.write_text(manager.render(peer))
    peer_config.chmod(0o600)
    config.write_text(manager.render(local))
    config.chmod(0o600)
    original_config = config.read_bytes()
    captures = []
    try:
        peer_log = (root / 'peer.log').open('w')
        remote = subprocess.Popen([str(core), '--config-file', str(peer_config), '--rpc-portal', f'127.0.0.1:{rpc2}'],
                                  stdout=peer_log, stderr=subprocess.STDOUT)
        processes.append(remote)
        wait(lambda: command([str(cli), '-p', f'127.0.0.1:{rpc2}', '-o', 'json', 'route'], 3).returncode == 0)
        def start_local():
            log = (root / ('local-' + secrets.token_hex(3) + '.log')).open('w')
            process = subprocess.Popen([sys.executable, str(root / 'network.py'), 'run'], stdout=log, stderr=subprocess.STDOUT)
            processes.append(process)
            wait(lambda: network.JOURNAL.exists() and network.load_record().get('active') and network.owns_interface(network.load_record()))
            wait(lambda: network.routing_table().get(remote_route, {}).get('interface') == interface)
            return process, network.load_record()
        local_process, owner = start_local()
        assert config.read_bytes() == original_config
        runtime = tomllib.loads(network.RUNTIME.read_text())
        assert runtime == {**local, 'routes': []}
        assert network.RUNTIME.stat().st_mode & 0o777 == 0o600
        assert owner['interface']['name'] == interface and owner['interface']['opened_by'] == owner['core']['pid']
        report['checks']['real_tun_custom_name_runtime_copy_learned_route'] = True
        # An exact existing route belongs to the fixture's native loopback,
        # and EXCL plus the DELETE OIF selector must preserve it.
        foreign = '192.168.243.1/32'
        native.mutate('add', foreign, 'lo0')
        foreign_snapshot = network.routing_table()[foreign]
        for action in ('add', 'delete'):
            try:
                native.mutate(action, foreign, interface)
            except OSError:
                pass
            else:
                raise AssertionError('A VPN request modified a foreign exact-prefix route.')
            assert network.routing_table()[foreign] == foreign_snapshot
        native.mutate('delete', foreign, 'lo0')
        report['checks']['exclusive_add_and_oif_delete_preserve_foreign_route'] = True
        rules = root / 'pf.conf'
        def pf(block=False):
            lines = ['set skip on { lo0 lo1 }', 'pass out all flags any no state']
            if block:
                lines.append(f'block in quick on {interface} inet from {mapped} to 10.253.122.1')
            # This is an administrator rule, not a plugin anchor. Interface any
            # reproduces the floating-rule workflow for an unassigned TUN.
            lines.append(f'pass in inet from {mapped} to 10.253.122.1 flags any no state')
            rules.write_text('\n'.join(lines) + '\n')
            result = command(['/sbin/pfctl', '-f', str(rules)])
            assert result.returncode == 0, 'The native administrator fixture rules were rejected.'
        if not pf_enabled:
            assert command(['/sbin/pfctl', '-e']).returncode == 0
        echo = Echo(real_echo)
        echoes.append(echo)
        pf()
        capture_file = root / 'real-tun.pcap'
        capture = subprocess.Popen(['/usr/sbin/tcpdump', '-n', '-i', interface, '-U', '-w', str(capture_file), 'host', mapped],
                                   stdout=subprocess.DEVNULL, stderr=(root / 'capture.log').open('w'))
        captures.append(capture)
        time.sleep(.2)
        echo.request(mapped, 'tcp')
        echo.request(mapped, 'udp')
        report['checks']['genuine_tun_tcp_udp_peer_proxy_exact_nonce'] = True
        pf(block=True)
        for protocol in ('tcp', 'udp'):
            try:
                echo.request(mapped, protocol)
            except (OSError, TimeoutError):
                pass
            else:
                raise AssertionError('A later pass bypassed the earlier administrator TUN block.')
        pf()
        echo.request(mapped, 'tcp')
        echo.request(mapped, 'udp')
        capture.send_signal(signal.SIGINT)
        capture.wait(timeout=5)
        captures.remove(capture)
        decoded = command(['/usr/sbin/tcpdump', '-nr', str(capture_file)])
        assert decoded.returncode == 0 and mapped in decoded.stdout
        report['checks']['administrator_floating_pass_and_earlier_block_on_real_tun'] = True
        os.kill(owner['core']['pid'], signal.SIGKILL)
        wait(lambda: local_process.poll() is not None and network.interface_identity(interface) is None)
        assert remote_route not in network.routing_table() and not pid.exists()
        assert network.routing_table() == before_routes
        echo.request(real_echo, 'tcp')
        echo.request(real_echo, 'udp')
        report['checks']['core_sigkill_restores_native_routes_interface_and_loopback_echo'] = True
        local_process, owner = start_local()
        os.kill(owner['core']['pid'], signal.SIGSTOP)
        wait(lambda: local_process.poll() is not None and network.interface_identity(interface) is None, 35)
        assert remote_route not in network.routing_table()
        assert network.routing_table() == before_routes
        assert 'Core RPC stopped responding' in network.load_record().get('error', '')
        echo.request(real_echo, 'tcp')
        report['checks']['core_sigstop_rpc_hang_withdrawal_and_owned_child_cleanup'] = True
        local_process, owner = start_local()
        rc.write_text('easytier_enable="NO"\n')
        wait(lambda: local_process.poll() is not None and network.interface_identity(interface) is None)
        assert network.routing_table() == before_routes
        assert 'NO' in rc.read_text()
        report['checks']['administrative_stop_intent_preserved'] = True
        rc.write_text('easytier_enable="YES"\n')
        # Foreign same-name kernel interfaces must survive a rejected start.
        assert command(['/sbin/ifconfig', 'tun', 'create', 'name', interface]).returncode == 0
        foreign_interface = network.interface_identity(interface)
        rejection = command([sys.executable, str(root / 'network.py'), 'run'], 10)
        assert rejection.returncode != 0 and 'already belongs' in rejection.stderr
        assert network.interface_identity(interface) == foreign_interface
        assert network.routing_table() == before_routes
        assert command(['/sbin/ifconfig', interface, 'destroy']).returncode == 0
        report['checks']['foreign_same_name_interface_preserved'] = True
        assert config.read_bytes() == original_config
        report['ok'] = True
    finally:
        for capture in captures:
            if capture.poll() is None:
                capture.send_signal(signal.SIGINT)
                capture.wait(timeout=5)
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=25)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
        for echo in echoes:
            echo.close()
        empty = root / 'original-pf.conf'
        empty.write_text(initial_pf.stdout)
        command(['/sbin/pfctl', '-f', str(empty)])
        if not pf_enabled:
            command(['/sbin/pfctl', '-d'])
        command(['/sbin/ifconfig', 'lo1', 'destroy'])
        report['runtime_artifacts'] = str(root)
        report['cleanup_route_table_matches_baseline'] = network.routing_table() == original_routes
        report['cleanup_interfaces_match_baseline'] = set(socket.if_nameindex()) == before_interfaces
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, indent=2) + '\n')
        report_path.chmod(0o600)
    assert report['ok'] and report['cleanup_route_table_matches_baseline'] and report['cleanup_interfaces_match_baseline']
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--payload-root', type=Path, default=Path('/'))
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    run_fixture(args.payload_root, args.report)
