#!/usr/local/bin/python3
"""Apply sing-box configuration to the shared TUN routing state machine."""

import argparse
import json
import os
from pathlib import Path
import sys

from process_identity import process
from tun_policy_routing import (
    DETAIL, DEVICE_LIMIT, IFNAME, LIMIT, MAX_CONFIG, MAX_STATES,
    RESERVE_ATTEMPTS, RESERVE_BACKOFF, ROUTE_LIMIT, RouteControlError,
    RoutingError, TunPolicyRouting, capture_states as shared_capture_states,
    failure, network, normalize_context as shared_normalize_context,
    parse_routes, route_identity, route_key, route_semantic, source_networks,
    state_tuple,
)


STATE = '/var/db/os-sing-box'
TUN = 'tun_singbox'
ANCHOR = 'singbox'
LABEL = 'singbox-routing'


def normalize_context(context):
    return shared_normalize_context(context, TUN)


def capture_states(text, fib):
    return shared_capture_states(text, fib, TUN)


class Routing(TunPolicyRouting):
    STATE = STATE
    TUN = TUN
    ANCHOR = ANCHOR
    LABEL = LABEL
    PF_PREFIX = 'singbox'
    NATIVE_PYTHON = '/usr/local/bin/python3'
    NATIVE_HELPER = '/usr/local/opnsense/scripts/singbox/native_route.py'
    ROUTING_LOCK = '/var/run/sing-box-routing.lock'
    SINGLE_FIB_FALLBACK = True

    def core_alive(self):
        try:
            record = json.loads(
                self.read(self.state / 'service-state.json', b'{}', private=True))
            child = record.get('core') or {}
            pid = child.get('pid', 0)
            expected = ['/usr/local/bin/sing-box', 'run', '-c',
                        str(self.state / 'runtime.json')]
            if (type(pid) is not int or not 1 < pid < 2147483648
                    or child.get('arguments') != expected
                    or child.get('uid') != os.geteuid()
                    or child.get('executable') != os.path.realpath(expected[0])):
                return False
            value = process(pid)
            return (value is not None and value['birth'] == child.get('birth')
                    and value['uid'] == os.geteuid()
                    and value['executable'] == os.path.realpath(expected[0])
                    and value['argv'] == expected and not value['stopped'])
        except (ValueError, UnicodeError, AttributeError, RuntimeError):
            return False

    def routing_inputs(self):
        try:
            settings = json.loads(self.read(
                self.path('/usr/local/etc/sing-box/integration.json'),
                b'{}', private=True))
            config = json.loads(self.read(
                self.state / 'runtime.json', b'{}', private=True,
                limit=MAX_CONFIG))
            context = json.loads(self.read(
                self.state / 'routing-context.json', b'{}', private=True))
        except ValueError:
            raise RoutingError('The routing configuration is invalid.') from None
        if not isinstance(settings, dict) or not isinstance(config, dict):
            raise RoutingError('The routing configuration is invalid.')
        inbounds = config.get('inbounds', [])
        dns = config.get('dns', {})
        if not isinstance(inbounds, list) or not isinstance(dns, dict):
            raise RoutingError('The routing configuration is invalid.')
        tun = [item for item in inbounds
               if isinstance(item, dict) and item.get('type') == 'tun']
        if (not all(settings.get(key) is True
                    for key in ('transparent', 'transparent_consent')) or not tun):
            return None
        if (len(tun) != 1 or tun[0].get('auto_route') is not False
                or tun[0].get('interface_name') != TUN):
            raise RoutingError(
                'Disable core automatic routing before selecting LAN flows.')
        servers = dns.get('servers', [])
        if not isinstance(servers, list):
            raise RoutingError('The routing DNS configuration is invalid.')
        if any(isinstance(item, dict) and item.get('type') == 'fakeip'
               for item in servers):
            raise RoutingError('Device routing requires real-address DNS responses.')
        return settings, context, settings.get('ipv6') is True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('enable', 'disable', 'refresh', 'status'))
    args = parser.parse_args()
    if not sys.platform.startswith('freebsd') or os.geteuid() != 0:
        raise RoutingError('Native routing requires FreeBSD root.')
    print(json.dumps(Routing(Path('/')).execute(args.action), sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (RoutingError, OSError, UnicodeError) as error:
        print('Sing-box routing could not be applied safely; owned recovery will be retried. '
              + str(error), file=sys.stderr)
        raise SystemExit(1)
