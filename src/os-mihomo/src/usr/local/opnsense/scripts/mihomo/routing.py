#!/usr/local/bin/python3
"""Apply Mihomo configuration to the shared TUN routing state machine."""

import argparse
import json
import os
from pathlib import Path
import re
import sys

import yaml
from tun_policy_routing import (
    DETAIL, DEVICE_LIMIT, IFNAME, LIMIT, MAX_CONFIG, MAX_STATES,
    RESERVE_ATTEMPTS, RESERVE_BACKOFF, ROUTE_LIMIT, RouteControlError,
    RoutingError, TunPolicyRouting, capture_states as shared_capture_states,
    failure, network, normalize_context as shared_normalize_context,
    parse_routes, route_identity, route_key, route_semantic, source_networks,
    state_tuple,
)
from process_owner import OwnershipError, REDIRECT_LISTENER, REDIRECT_PORT, core_group


STATE = '/var/db/os-mihomo'
TUN = 'tun_mihomo'
ANCHOR = 'mihomo'
LABEL = 'mihomo-routing'
# OPNsense interface identifiers such as lan, wan and optN.
INTERFACE_ID = re.compile(r'[A-Za-z][A-Za-z0-9_]{0,31}')


def capture_scope(settings, context):
    """Keep only the interfaces the operator chose to capture from.

    An empty selection keeps today's behaviour: every interface that is not
    WAN-like. A selection narrows the candidates before the shared policy sees
    them, so WAN-like interfaces, the TUN and loopback stay excluded whatever
    is listed, and a listed interface that is missing or disabled simply
    contributes nothing. Router addresses and native routes, which keep traffic
    to every local network off the TUN, are not part of what is narrowed.
    """
    selected = settings.get('capture_interfaces') or []
    if (not isinstance(selected, list) or len(selected) > DEVICE_LIMIT
            or not all(isinstance(name, str) and INTERFACE_ID.fullmatch(name) for name in selected)):
        raise RoutingError('The capture interface selection is invalid.')
    if not selected or not isinstance(context, dict) or not isinstance(context.get('interfaces'), list):
        return context
    return dict(context, interfaces=[item for item in context['interfaces']
                                     if isinstance(item, dict) and item.get('name') in selected])


def normalize_context(context):
    return shared_normalize_context(context, TUN)


def capture_states(text, fib):
    return shared_capture_states(text, fib, TUN)


class Routing(TunPolicyRouting):
    STATE = STATE
    TUN = TUN
    ANCHOR = ANCHOR
    LABEL = LABEL
    PF_PREFIX = 'mihomo'
    NATIVE_PYTHON = '/usr/local/bin/python3'
    NATIVE_HELPER = '/usr/local/opnsense/scripts/mihomo/native_route.py'
    ROUTING_LOCK = '/var/run/mihomo-routing.lock'
    TCP_REDIRECT = True

    def core_alive(self):
        try:
            return core_group(root=self.root,
                              process_reader=getattr(self, 'process_reader', None),
                              sleeper=self.delay).running()
        except OwnershipError:
            return False

    def routing_inputs(self):
        try:
            settings = json.loads(self.read(self.state / 'settings.json', b'{}'))
            config = yaml.safe_load(
                self.read(self.state / 'config.yaml', b'{}', limit=MAX_CONFIG)) or {}
            context = json.loads(
                self.read(self.state / 'routing-context.json', b'{}'))
        except (ValueError, yaml.YAMLError):
            raise RoutingError('The routing configuration is invalid.') from None
        if (not isinstance(settings, dict) or not isinstance(config, dict)
                or not isinstance(config.get('tun'), dict)):
            raise RoutingError('The routing configuration is invalid.')
        if (not all(settings.get(key) is True for key in (
                'service_enabled', 'transparent', 'transparent_consent'))
                or config['tun'].get('enable') is not True):
            return None
        if config['tun'].get('auto-route') is not False:
            raise RoutingError(
                'Disable core automatic routing before selecting LAN flows.')
        dns = config.get('dns', {})
        if not isinstance(dns, dict):
            raise RoutingError('The routing DNS configuration is invalid.')
        if dns.get('enable') and dns.get('enhanced-mode') == 'fake-ip':
            raise RoutingError('Device routing requires real-address DNS responses.')
        self.config = config
        return settings, capture_scope(settings, context), config.get('ipv6') is True

    def redirect_port(self, settings):
        """Offer the TCP redirect only to the core's own, actually bound listener.

        The rendered config alone is not proof: an upgrade rewrites it without a
        restart, and another process could hold the port. Redirected TCP would
        then fail, so every listener on the port must be the running core.
        """
        if settings.get('tcp_redirect') is not True:
            return None
        listeners = (getattr(self, 'config', None) or {}).get('listeners')
        owned = [item for item in listeners if isinstance(item, dict)
                 and item.get('name') == REDIRECT_LISTENER] if isinstance(listeners, list) else []
        if owned != [{'name': REDIRECT_LISTENER, 'type': 'redir',
                      'port': REDIRECT_PORT, 'listen': '127.0.0.1'}]:
            return None
        try:
            group = core_group(root=self.root,
                               process_reader=getattr(self, 'process_reader', None),
                               sleeper=self.delay)
            record = group.discover(adopt=False)
            if record is None or not group.same(record['child']):
                return None
        except OwnershipError:
            return None
        value = self.command(['/usr/bin/sockstat', '-4', '-l', '-q', '-P', 'tcp',
                              '-p', str(REDIRECT_PORT)], check=False)
        rows = [line.split() for line in value.stdout.decode(errors='replace').splitlines()
                if line.strip()]
        expected = (str(record['child']['pid']), '127.0.0.1:%d' % REDIRECT_PORT)
        if value.returncode or not rows or any(
                len(row) < 6 or (row[2], row[5]) != expected for row in rows):
            return None
        return REDIRECT_PORT


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
        print('Mihomo routing could not be applied safely; owned recovery will be retried. '
              + str(error), file=sys.stderr)
        raise SystemExit(1)
