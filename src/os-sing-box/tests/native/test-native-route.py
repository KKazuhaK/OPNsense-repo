#!/usr/local/bin/python3
"""Exercise native route transport inside an explicitly selected disposable VNET."""

import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import socket


def command(args, check=True):
    value = subprocess.run(args, capture_output=True, timeout=15)
    if check and value.returncode:
        raise RuntimeError(value.stderr.decode(errors='replace'))
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true', help='Run only inside a disposable VNET jail')
    parser.add_argument('--helper', default='/usr/local/opnsense/scripts/singbox/native_route.py')
    parser.add_argument('--routing', default='/usr/local/opnsense/scripts/singbox/routing.py')
    args = parser.parse_args(argv)
    if not args.run:
        print('SKIP: select --run inside a disposable FreeBSD VNET jail.')
        return 0
    if not sys.platform.startswith('freebsd') or os.geteuid() != 0:
        raise RuntimeError('This fixture requires root inside a disposable FreeBSD VNET jail.')
    os.environ['LC_ALL'] = 'C'
    if command(['/sbin/sysctl', '-n', 'security.jail.jailed']).stdout.strip() != b'1':
        raise RuntimeError('This fixture must not run on the host.')
    if not socket.gethostname().startswith('singbox-isolation-'):
        raise RuntimeError('This fixture requires an explicitly owned Sing-box isolation jail.')
    spec = importlib.util.spec_from_file_location('native_route_fixture_routing', Path(args.routing))
    routing = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(routing)

    def routes(fib, family=4):
        # Exercise the actual guarded single-FIB reader before allocation too.
        return {key: value for key, value in routing.Routing().routes(fib).items()
                if value['family'] == family}

    def add(fib, wanted, check=True):
        return command([sys.executable, args.helper, 'add', '--fib', str(fib),
                        '--route', json.dumps(wanted)], check)

    def cli(action, fib, destination, gateway=None, interface=None, family=4, discard=''):
        args = ['/sbin/route', '-n', action, '-fib', str(fib), '-inet' if family == 4 else '-inet6',
                '-host' if '/' not in destination else '-net', destination]
        if gateway is not None:
            args.append(gateway)
        if interface is not None:
            args.extend(['-iface' if gateway is None else '-ifp', interface])
        if discard:
            args.append('-' + discard)
        return command(args)

    baseline = {family: routes(0, family) for family in (4, 6)}
    reserved = ['10.253.0.0/24', '10.255.255.254/32', '203.0.113.0/25', '203.0.113.128/25']
    if any(route['destination'] in reserved for route in baseline[4].values()):
        raise RuntimeError('A fixture destination is already occupied.')
    interfaces, owned = [], {}
    checks = []
    try:
        for address in ('192.0.3.10/32', '192.0.4.10/32'):
            name = command(['/sbin/ifconfig', 'lo', 'create']).stdout.decode().strip()
            if not routing.IFNAME.fullmatch(name) or not name.startswith('lo'):
                raise RuntimeError('The fixture interface could not be identified.')
            interfaces.append(name)
            command(['/sbin/ifconfig', name, 'inet', address, 'up'])
        first, second = interfaces
        count = int(command(['/sbin/sysctl', '-n', 'net.fibs']).stdout)
        if not 1 <= count <= 65531:
            raise RuntimeError('No fixture routing tables are available.')
        command(['/sbin/sysctl', 'net.fibs=' + str(count + 3)])
        cold, ambiguous, occupied = range(count, count + 3)

        def remember(family, destination):
            wanted = next(route for route in routes(0, family).values() if route['destination'] == destination)
            owned[(family, routing.route_key(wanted))] = wanted
            return wanted

        cli('add', 0, '10.255.255.254', interface=first)
        remember(4, '10.255.255.254/32')
        cli('add', 0, '10.253.0.0/24', '10.255.255.254', first)
        selected = remember(4, '10.253.0.0/24')
        cli('delete', 0, '10.255.255.254')
        owned.pop((4, '4:10.255.255.254/32%'))
        cli('add', 0, '10.255.255.254', '10.253.0.1', first)
        peer = remember(4, '10.255.255.254/32')
        old = command(['/sbin/route', '-n', 'add', '-fib', str(cold), '-net',
                       '10.253.0.0/24', '10.255.255.254', '-ifp', first], False)
        assert old.returncode, 'The old CLI must reproduce the cold-gateway failure.'
        for wanted in (selected, peer):
            add(cold, wanted)
            assert routing.route_semantic(routes(cold)[routing.route_key(wanted)]) == routing.route_semantic(wanted)
        checks.append('cold cyclic gateway clone')

        cli('add', ambiguous, '10.255.255.254', interface=second)
        add(ambiguous, selected)
        assert routing.route_semantic(routes(ambiguous)[routing.route_key(selected)]) == routing.route_semantic(selected)
        checks.append('ambiguous gateway keeps explicit source interface')
        cli('add', occupied, '10.253.0.0/24', interface=second)
        before = routes(occupied)
        rejected = add(occupied, selected, False)
        assert rejected.returncode and routes(occupied) == before
        assert b'File exists' in rejected.stderr
        checks.append('exclusive add preserves existing destination without ECMP')

        for destination, discard in [('203.0.113.0/25', 'blackhole'), ('203.0.113.128/25', 'reject')]:
            cli('add', 0, destination, '127.0.0.1', discard=discard)
            wanted = remember(4, destination)
            # FreeBSD normalizes these discard gateways to an interface route.
            # Exercise the real dispatcher instead of inventing a numeric path.
            routing.Routing().route_command('add', cold, wanted)
            assert routing.route_semantic(routes(cold)[routing.route_key(wanted)]) == routing.route_semantic(wanted)
        checks.append('blackhole and reject route clones')

        command(['/sbin/ifconfig', first, 'inet6', '2001:db8:3::10/64', '-ifdisabled'])
        command(['/sbin/ifconfig', second, 'inet6', '2001:db8:4::10/64', '-ifdisabled'])
        cli('add', 0, '2001:db8:40::/64', '2001:db8:3::1', first, family=6)
        wanted6 = remember(6, '2001:db8:40::/64')
        add(cold, wanted6)
        assert routing.route_semantic(routes(cold, 6)[routing.route_key(wanted6)]) == routing.route_semantic(wanted6)
        cli('add', ambiguous, '2001:db8:3::1', interface=second, family=6)
        add(ambiguous, wanted6)
        assert routing.route_semantic(routes(ambiguous, 6)[routing.route_key(wanted6)]) == routing.route_semantic(wanted6)
        checks.append('IPv6 numeric gateway clone and ambiguous interface')

        cli('add', 0, '2001:db8:41::/64', 'fe80::1%' + first, first, family=6)
        scoped = remember(6, '2001:db8:41::/64')
        add(cold, scoped)
        assert routing.route_semantic(routes(cold, 6)[routing.route_key(scoped)]) == routing.route_semantic(scoped)
        checks.append('IPv6 scoped gateway clone')
    finally:
        for (family, key), wanted in reversed(list(owned.items())):
            live = routes(0, family).get(key)
            if live is None:
                continue
            if routing.route_identity(live) != routing.route_identity(wanted):
                raise RuntimeError('A fixture source route changed ownership; cleanup stopped.')
            routing.Routing().route_command('delete', 0, live)
        for name in reversed(interfaces):
            command(['/sbin/ifconfig', name, 'destroy'])
        assert {family: routes(0, family) for family in (4, 6)} == baseline
    print(json.dumps({'checks': checks, 'source_routes_and_interfaces_restored': True}))
    return 0


if __name__ == '__main__':
    sys.exit(main())
