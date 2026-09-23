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
from process_owner import OwnershipError, core_group


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

    def enable(self, record, refresh=False):
        """Arm capture, and keep watching when there is nothing to capture yet.

        The shared state machine withdraws capture when no selected interface
        has an address, and a refresh of that inactive record returns without
        looking again. A selected interface that gains its address later, such
        as a VPN server assigned as an interface that starts after the core at
        boot, raises no WAN event either, so capture would stay off until a
        restart. Record the wait, re-evaluate on every refresh, and arm as soon
        as a source exists.
        """
        if (refresh and not record['active'] and not record['pending']
                and record.get('resume') is not True and record.get('awaiting_sources') is True):
            if self.capturable(record) is False:
                return self.status(record)
            record.pop('awaiting_sources', None)
            self.save(record)
            return super().enable(record)
        result = super().enable(record, refresh)
        waiting = (not record['active'] and not record['pending']
                   and self.capturable(record) is False)
        if waiting != (record.get('awaiting_sources') is True):
            if waiting:
                record['awaiting_sources'] = True
            else:
                record.pop('awaiting_sources', None)
            self.save(record)
        return result

    def capturable(self, record):
        """None when capture is not wanted, else whether any source exists now."""
        if not self.core_alive():
            return None
        inputs = self.routing_inputs()
        if inputs is None:
            return None
        settings, context, ipv6_enabled = inputs
        native = {key: route for key, route in self.routes(0).items()
                  if route['interface'] != self.TUN}
        families = {4, 6} if ipv6_enabled else {4}
        _, interface_count, _ = self.policy(settings, context, native, families, record.get('fib') or 1)
        return interface_count > 0

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
        return settings, capture_scope(settings, context), config.get('ipv6') is True


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
