"""Own private-FIB routes and PF flow selection for TUN plugins."""

import contextlib
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import time

from route_control import (IFNAME, RESERVE_ATTEMPTS, RESERVE_BACKOFF,
                           RouteError as RouteControlError,
                           format_command_failure, parse_network,
                           parse_route_table, private_fib_occupied,
                           reserve_private_fib, route_identity, route_key,
                           route_semantic)


LIMIT = 4 * 1024 * 1024
MAX_CONFIG = 16 * 1024 * 1024
MAX_STATES = 64 * 1024 * 1024
ROUTE_LIMIT = 8192
DEVICE_LIMIT = 128
DETAIL = 512
ROUTE_FIELDS = frozenset((
    'family', 'destination', 'scope', 'gateway', 'interface', 'flags', 'discard'))

__all__ = [
    'DETAIL', 'DEVICE_LIMIT', 'IFNAME', 'LIMIT', 'MAX_CONFIG', 'MAX_STATES',
    'RESERVE_ATTEMPTS', 'RESERVE_BACKOFF', 'ROUTE_LIMIT', 'RouteControlError',
    'RoutingError', 'RoutingMutationAmbiguous', 'TunPolicyRouting', 'capture_states', 'failure', 'network',
    'foreign_rtable_rules', 'normalize_context', 'parse_routes', 'redirect_states', 'route_identity',
    'route_key', 'route_semantic', 'source_networks', 'state_tuple', 'valid_redirect_port',
]


class RoutingError(Exception):
    pass


class RoutingMutationAmbiguous(RoutingError):
    """A launched mutation may have reached the kernel before transport failed."""


def failure(args, value):
    return format_command_failure(args, value, DETAIL)


def network(value, family=None):
    try:
        return parse_network(value, family)
    except RouteControlError as error:
        raise RoutingError(str(error)) from None


def parse_routes(text, family):
    try:
        return parse_route_table(text, family, LIMIT, ROUTE_LIMIT)
    except RouteControlError as error:
        raise RoutingError(str(error)) from None


def normalize_context(context, tun):
    if (not isinstance(context, dict)
            or not isinstance(context.get('interfaces'), list)
            or not isinstance(context.get('local_addresses'), list)):
        raise RoutingError('The firewall routing context is unavailable.')
    if len(context['interfaces']) > 256 or len(context['local_addresses']) > 4096:
        raise RoutingError('The firewall routing context exceeds its supported limit.')
    interfaces, local = {}, set()
    for item in context['interfaces']:
        if (not isinstance(item, dict)
                or not IFNAME.fullmatch(item.get('device', ''))
                or not isinstance(item.get('wan'), bool)
                or not isinstance(item.get('networks'), list)):
            raise RoutingError('The firewall interface context is invalid.')
        nets = []
        for value in item['networks']:
            try:
                nets.append(ipaddress.ip_network(value, strict=False))
            except (TypeError, ValueError):
                raise RoutingError('An interface network is invalid.') from None
        if len(nets) > 256:
            raise RoutingError('An interface has too many networks.')
        if not item['wan'] and item['device'] != tun and item['device'] != 'lo0':
            interfaces.setdefault(item['device'], []).extend(nets)
    for value in context['local_addresses']:
        try:
            local.add(ipaddress.ip_address(value.split('%')[0]))
        except (AttributeError, ValueError):
            raise RoutingError('A local interface address is invalid.') from None
    return interfaces, local


def source_networks(lan, settings):
    mode, entries = settings.get('device_mode', 'off'), settings.get('device_list', [])
    if (mode not in ('off', 'blacklist', 'whitelist')
            or not isinstance(entries, list) or len(entries) > DEVICE_LIMIT):
        raise RoutingError('The device routing policy is invalid.')
    try:
        devices = [ipaddress.ip_network(value, strict=False) for value in entries]
    except (TypeError, ValueError):
        raise RoutingError('A device network is invalid.') from None
    selected = []
    for original in lan:
        if original.prefixlen == 0:
            raise RoutingError('A LAN interface must have a specific network.')
        applicable = [net for net in devices
                      if net.version == original.version and net.overlaps(original)]
        if mode == 'whitelist' and entries:
            selected.extend(net if net.subnet_of(original) else original for net in applicable)
        else:
            remaining = [original]
            if mode == 'blacklist':
                for excluded in applicable:
                    next_ranges = []
                    for net in remaining:
                        if net.subnet_of(excluded):
                            continue
                        next_ranges.extend(net.address_exclude(excluded)
                                           if excluded.subnet_of(net) else [net])
                    remaining = next_ranges
            selected.extend(remaining)
    result = []
    for family in (4, 6):
        result.extend(ipaddress.collapse_addresses(net for net in selected
                                                   if net.version == family))
    if len(result) > ROUTE_LIMIT:
        raise RoutingError('The device policy exceeds its supported prefix count.')
    return result


def state_tuple(block):
    """Normalize an untranslated PF transport tuple across either arrow."""
    headline = block.splitlines()[0] if block else ''
    found = re.fullmatch(r'\S+\s+(tcp|udp)\s+(\S+)\s+(?:<-|->)\s+(\S+)\s+\S+\s*', headline)
    if not found:
        return None
    endpoints = []
    for value in found.group(2, 3):
        endpoint = re.fullmatch(r'(.+)\[([0-9]+)\]', value)
        if endpoint is None:
            endpoint = re.fullmatch(r'([0-9.]+):([0-9]+)', value)
        if endpoint is None:
            return None
        try:
            address = ipaddress.ip_address(endpoint.group(1))
            port = int(endpoint.group(2))
            if not 0 <= port <= 65535:
                return None
        except ValueError:
            return None
        endpoints.append((address.version, str(address), port))
    if endpoints[0][0] != endpoints[1][0]:
        return None
    return found.group(1), tuple(sorted(endpoints))


def capture_states(text, fib, tun):
    """Select captured flows after the caller excludes foreign FIB rules."""
    if len(text.encode()) > MAX_STATES:
        raise RoutingError('The firewall state table exceeds its supported limit.')
    result, tuples, partners = [], set(), []
    for block in re.split(r'(?m)(?=^\S)', text):
        owned = bool(re.search(r'\brtable:\s+' + str(fib) + r'\b', block))
        origin = re.search(r'(?m)^\s+origif:\s+(\S+)\s*$', block)
        header = block.splitlines()[0].split() if block else []
        tun_origin = (origin is not None and origin.group(1) == tun) or (
            bool(header) and header[0] == tun)
        if not owned and not tun_origin:
            continue
        targets = re.findall(r'\b(?:route-to|reply-to|dup-to|gateway):\s+(\S+)', block)
        if any(not target.endswith('@' + tun) for target in targets):
            continue
        found = re.search(
            r'\bid:\s+([0-9a-fA-F]{16})\s+creatorid:\s+([0-9a-fA-F]{8})\b', block)
        if not found:
            if owned:
                raise RoutingError('An owned firewall state has no valid identifier.')
            continue
        identifier = found.group(1).lower() + '/' + found.group(2).lower()
        transport = state_tuple(block)
        if owned:
            result.append(identifier)
            if transport is not None:
                # Creator ID avoids associating a synchronized foreign state
                # with an otherwise equal transport tuple.
                tuples.add((found.group(2).lower(), transport))
        elif tun_origin and transport is not None:
            partners.append((identifier, found.group(2).lower(), transport))
    result.extend(identifier for identifier, creator, transport in partners
                  if (creator, transport) in tuples)
    return list(dict.fromkeys(result))


def valid_redirect_port(value):
    """A loopback TCP redirect port: an integer listener port other than DNS."""
    return type(value) is int and 1 <= value <= 65535 and value != 53


def redirect_states(text, port):
    """Select states PF translated to the core's loopback redirect listener."""
    if len(text.encode()) > MAX_STATES:
        raise RoutingError('The firewall state table exceeds its supported limit.')
    result = []
    headline = re.compile(r'\S+\s+tcp\s+127\.0\.0\.1:' + str(port)
                          + r'\s+\(\S+\)\s+<-\s+\S+\s+\S+\s*')
    for block in re.split(r'(?m)(?=^\S)', text):
        # The parenthesized original destination marks a translated state; an
        # untranslated connection to the listener is not one of ours.
        if not block or not headline.fullmatch(block.splitlines()[0]):
            continue
        found = re.search(
            r'\bid:\s+([0-9a-fA-F]{16})\s+creatorid:\s+([0-9a-fA-F]{8})\b', block)
        if not found:
            raise RoutingError('A redirected firewall state has no valid identifier.')
        result.append(found.group(1).lower() + '/' + found.group(2).lower())
    return list(dict.fromkeys(result))


def foreign_rtable_rules(text, fib, anchor, label):
    """Find recursive PF rules that reuse a plugin's private routing table."""
    if len(text.encode()) > MAX_CONFIG:
        raise RoutingError('The firewall ruleset exceeds its supported limit.')
    if (type(fib) is not int or fib < 1 or not isinstance(anchor, str)
            or not isinstance(label, str)):
        raise RoutingError('The firewall routing ownership is invalid.')
    stack = []
    for line in text.splitlines():
        opened = re.fullmatch(r'\s*anchor\s+"([^"\\]+)"(?:\s+.*?)?\s*\{\s*', line)
        if opened is not None:
            stack.append(opened.group(1))
            continue
        if re.fullmatch(r'\s*}\s*', line):
            if not stack:
                raise RoutingError('The recursive firewall ruleset is malformed.')
            stack.pop()
            continue
        if re.search(r'(?<!\S)rtable\s+' + str(fib) + r'(?!\S)', line):
            labels = re.findall(r'(?<!\S)label\s+"([^"\\]*)"', line)
            if stack != [anchor] or labels != [label]:
                return True
    if stack:
        raise RoutingError('The recursive firewall ruleset is malformed.')
    return False


def fib_states_present(text, fib):
    """Return whether any state still has an ambiguous private-FIB binding."""
    if len(text.encode()) > MAX_STATES:
        raise RoutingError('The firewall state table exceeds its supported limit.')
    return bool(re.search(r'(?<!\S)rtable:\s+' + str(fib) + r'(?!\S)', text))


class TunPolicyRouting:
    """Shared ownership state machine configured by a product adapter."""

    STATE = None
    TUN = None
    ANCHOR = None
    LABEL = None
    PF_PREFIX = None
    NATIVE_PYTHON = None
    NATIVE_HELPER = None
    ROUTING_LOCK = None
    SINGLE_FIB_FALLBACK = False
    # Adapters whose core listens for PF-redirected TCP opt in; every other
    # adapter keeps exactly the TUN-only anchor, commands and status.
    TCP_REDIRECT = False

    def __init__(self, root=Path('/'), run=None, delay=None):
        required = (self.STATE, self.TUN, self.ANCHOR, self.LABEL,
                    self.PF_PREFIX, self.NATIVE_PYTHON, self.NATIVE_HELPER,
                    self.ROUTING_LOCK)
        if any(not value for value in required):
            raise RoutingError('The routing adapter is incomplete.')
        self.root = Path(root)
        self.state = self.path(self.STATE)
        self.marker = self.state / 'routing-state.json'
        self.runner = run or subprocess.run
        self.delay = delay or time.sleep

    def path(self, value):
        return self.root / value.lstrip('/')

    def command(self, args, check=True, limit=LIMIT):
        try:
            value = self.runner(args, capture_output=True, timeout=15)
        except subprocess.TimeoutExpired:
            raise RoutingMutationAmbiguous('A routing operation timed out after it was launched.') from None
        except OSError:
            raise RoutingError('A routing operation failed or timed out.') from None
        if len(value.stdout) + len(value.stderr) > limit:
            raise RoutingMutationAmbiguous('A completed routing operation produced too much output.')
        if check and value.returncode:
            raise RoutingError(failure(args, value))
        return value

    def read(self, path, default=None, private=False, limit=LIMIT):
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            return default
        except OSError:
            raise RoutingError('A routing state file is unavailable.') from None
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or info.st_size > limit
                    or (private and stat.S_IMODE(info.st_mode) != 0o600)):
                raise RoutingError('A routing state file has invalid ownership or size.')
            raw = stream.read(limit + 1)
        if len(raw) > limit:
            raise RoutingError('A routing state file exceeds its supported limit.')
        return raw

    def load(self):
        raw = self.read(self.marker, private=True)
        if raw is None:
            return {'schema': 1, 'fib': None, 'active': False,
                    'routes': {}, 'pending': False}
        try:
            record = json.loads(raw)
            if (record['schema'] != 1 or not isinstance(record['active'], bool)
                    or not isinstance(record['pending'], bool)
                    or not isinstance(record['routes'], dict)
                    or not isinstance(record.get('resume', False), bool)
                    or not isinstance(record.get('pf_collision', False), bool)
                    or not isinstance(record.get('route_recovery_ambiguous', False), bool)
                    or not isinstance(record.get('awaiting_sources', False), bool)):
                raise ValueError
            if record.get('pf_collision') and (
                    record['active'] or not record['pending']):
                raise ValueError
            # A failed inspection keeps its paid-for reservation so a status
            # poll cannot allocate another FIB before the next retry.
            for value in (record['fib'], record.get('reserved')):
                if value is not None and (
                        type(value) is not int or not 1 <= value <= 65534):
                    raise ValueError
            for key, route in record['routes'].items():
                self.validate_record_route(key, route)
            if len(record['routes']) > ROUTE_LIMIT:
                raise ValueError
            if 'tcp_redirect_port' in record and not valid_redirect_port(record['tcp_redirect_port']):
                raise ValueError
            pending_route = record.get('pending_route')
            if pending_route is not None:
                if (not isinstance(pending_route, dict)
                        or set(pending_route) != {'key', 'route'}
                        or record['fib'] is None
                        or record['active'] or not record['pending']
                        or pending_route['key'] in record['routes']):
                    raise ValueError
                self.validate_record_route(
                    pending_route['key'], pending_route['route'])
                if len(record['routes']) == ROUTE_LIMIT:
                    raise ValueError
            elif record.get('route_recovery_ambiguous'):
                raise ValueError
            return record
        except (KeyError, TypeError, ValueError):
            raise RoutingError('The routing ownership record is invalid.') from None

    def save(self, record):
        name, directory = None, None
        try:
            self.state.mkdir(parents=True, exist_ok=True)
            flags = os.O_RDONLY | os.O_NOFOLLOW
            if hasattr(os, 'O_DIRECTORY'):
                flags |= os.O_DIRECTORY
            directory = os.open(self.state, flags)
            info = os.fstat(directory)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
                raise RoutingError('The routing state directory has invalid ownership.')
            fd, name = tempfile.mkstemp(prefix='.routing-', dir=self.state)
            with os.fdopen(fd, 'wb') as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write(json.dumps(record, sort_keys=True).encode() + b'\n')
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(name, self.marker)
            name = None
            # The rename is not a durable journal entry until its directory is
            # synchronized as well. Recovery decisions must survive a crash.
            os.fsync(directory)
        except OSError:
            raise RoutingError('The routing ownership record could not be saved.') from None
        finally:
            if name is not None:
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(name)
            if directory is not None:
                os.close(directory)

    @staticmethod
    def validate_record_route(key, route):
        if (not isinstance(key, str) or not isinstance(route, dict)
                or set(route) != ROUTE_FIELDS
                or key != route_key(route)
                or not IFNAME.fullmatch(route['interface'])
                or route['family'] not in (4, 6)):
            raise ValueError
        network(route['destination'], route['family'])
        if route['scope'] and not IFNAME.fullmatch(route['scope']):
            raise ValueError
        if route['gateway'] != 'interface':
            address, _, zone = route['gateway'].partition('%')
            if ipaddress.ip_address(address).version != route['family']:
                raise ValueError
            if zone and not IFNAME.fullmatch(zone):
                raise ValueError
        if route['discard'] not in ('', 'blackhole', 'reject'):
            raise ValueError
        if (not isinstance(route['flags'], str)
                or not re.fullmatch(r'[A-Za-z0-9!]*', route['flags'])):
            raise ValueError

    def routes(self, fib):
        result = {}
        for family, flag in ((4, 'inet'), (6, 'inet6')):
            value = self.command(
                ['/usr/bin/netstat', '-rn', '-F', str(fib), '-f', flag],
                check=not self.SINGLE_FIB_FALLBACK)
            if value.returncode:
                # Some FreeBSD single-FIB kernels reject even explicit FIB 0.
                # Unqualified netstat is safe only for confirmed FIB 0.
                count = self.command(['/sbin/sysctl', '-n', 'net.fibs'], check=False)
                current = self.command(['/sbin/sysctl', '-n', 'net.my_fibnum'], check=False)
                if (not self.SINGLE_FIB_FALLBACK or fib != 0
                        or count.returncode or current.returncode
                        or count.stdout.strip() != b'1'
                        or current.stdout.strip() != b'0'):
                    raise RoutingError('The requested routing table could not be read.')
                value = self.command(['/usr/bin/netstat', '-rn', '-f', flag])
            result.update(parse_routes(value.stdout.decode(errors='strict'), family))
            if len(result) > ROUTE_LIMIT:
                raise RoutingError('The routing table exceeds the supported route count.')
        return result

    def core_alive(self):
        raise NotImplementedError

    def routing_inputs(self):
        """Return settings, routing context and whether IPv6 is enabled."""
        raise NotImplementedError

    def redirect_port(self, settings):
        """Return the loopback TCP redirect port the running core verifiably owns, or None."""
        return None

    def redirect_target(self, settings):
        """Redirect TCP only to a listener the core owns, through a hooked anchor.

        Without either, captured TCP stays on the TUN, so a missing listener
        or an unhooked anchor slows flows down but never lets them bypass.
        """
        if not self.TCP_REDIRECT:
            return None
        port = self.redirect_port(settings)
        if port is None:
            return None
        if not valid_redirect_port(port):
            raise RoutingError('The TCP redirect port is invalid.')
        return port if self.rdr_anchor_hooked() else None

    def rdr_anchor_hooked(self):
        """Whether the loaded main ruleset evaluates this anchor's translation rules."""
        value = self.command(['/sbin/pfctl', '-sn'], check=False, limit=MAX_CONFIG)
        if value.returncode:
            return False
        hook = 'rdr-anchor "%s" all' % self.ANCHOR
        return any(line.strip() == hook
                   for line in value.stdout.decode(errors='replace').splitlines())

    def anchor(self, content):
        self.check_anchor()
        fd, name = tempfile.mkstemp(prefix='.routing-pf-', dir=self.state)
        try:
            with os.fdopen(fd, 'wb') as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write(content.encode())
            self.command(['/sbin/pfctl', '-a', self.ANCHOR, '-nf', name])
            self.command(['/sbin/pfctl', '-a', self.ANCHOR, '-f', name])
        finally:
            os.unlink(name)

    def check_anchor(self):
        return self.anchor_rules()[0]

    def anchor_rules(self):
        """Return the anchor's filter and translation rules once both are owned."""
        current = self.command(
            ['/sbin/pfctl', '-a', self.ANCHOR, '-sr']).stdout.decode(errors='strict')
        if any(line.strip() and not self.owned_anchor_line(line)
               for line in current.splitlines()):
            raise RoutingError('The routing anchor contains rules owned elsewhere.')
        translation = ''
        if self.TCP_REDIRECT:
            # A load replaces the anchor's translation rules too, so a foreign
            # one must stop it instead of being flushed without notice.
            translation = self.command(
                ['/sbin/pfctl', '-a', self.ANCHOR, '-sn']).stdout.decode(errors='strict')
            if any(line.strip() and not self.owned_translation_line(line)
                   for line in translation.splitlines()):
                raise RoutingError('The routing anchor contains translation rules owned elsewhere.')
        return current, translation

    def owned_translation_line(self, line):
        """Recognize only the TCP redirect rules this adapter can generate."""
        line = re.sub(r'\s+', ' ', line.strip()).replace('to !<', 'to ! <')
        prefix = re.escape(self.PF_PREFIX)
        head = (r'on ' + IFNAME.pattern.rstrip('\\Z') + r' inet proto tcp from <'
                + prefix + r'_sources_[0-9]+> ')
        if re.fullmatch(r'no rdr ' + head + r'to any port = (?:53|domain)', line):
            return True
        found = re.fullmatch(r'rdr ' + head + r'to ! <' + prefix
                             + r'_local> -> 127\.0\.0\.1 port ([0-9]{1,5})', line)
        return found is not None and valid_redirect_port(int(found.group(1)))

    def kill_redirect_states(self, port, text=None):
        if text is None:
            text = self.command(
                ['/sbin/pfctl', '-ss', '-vv'], limit=MAX_STATES
            ).stdout.decode(errors='strict')
        for identifier in redirect_states(text, port):
            self.command(['/sbin/pfctl', '-k', 'id', '-k', identifier])

    def neutralize_sources(self):
        """Empty the anchor's source tables when a foreign rule blocks clearing it.

        Restoring the private FIB neutralizes the TUN match rules, but a
        redirect keeps working without it; empty sources stop both without
        touching the foreign rule.
        """
        with contextlib.suppress(RoutingError, OSError, UnicodeError):
            tables = self.command(
                ['/sbin/pfctl', '-a', self.ANCHOR, '-sT']).stdout.decode(errors='strict')
            pattern = re.escape(self.PF_PREFIX) + r'_sources_[0-9]+'
            for name in tables.split():
                if re.fullmatch(pattern, name):
                    self.command(['/sbin/pfctl', '-a', self.ANCHOR, '-t', name, '-T', 'flush'])

    def owned_anchor_line(self, line):
        """Recognize only rules this adapter can generate, not a shared label."""
        line = re.sub(r'\s+', ' ', line.strip()).replace('to !<', 'to ! <')
        prefix = re.escape(self.PF_PREFIX)
        table = re.fullmatch(
            r'table <(' + prefix + r'_(?:local|sources_[0-9]+))> \{ (.+) \}',
            line)
        if table is not None:
            try:
                values = [value.strip() for value in table.group(2).split(',')]
                return bool(values) and all(values) and all(
                    str(ipaddress.ip_network(value, strict=True)) == value
                    for value in values)
            except ValueError:
                return False
        match = re.fullmatch(
            r'match in on (' + IFNAME.pattern.rstrip('\\Z') + r') '
            r'(inet|inet6) proto (tcp|udp) from <(' + prefix
            + r'_sources_[0-9]+)> to ! <(' + prefix + r'_local)> (.+)',
            line)
        if match is None:
            return False
        family, protocol, tail = match.group(2), match.group(3), match.group(6)
        label = re.escape(self.LABEL)
        fib = r'(?:[1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-4])'
        actions = (
            r'label "' + label + r'" rtable ' + fib,
            r'rtable ' + fib + r' label "' + label + r'"',
        )
        if protocol == 'tcp':
            actions = tuple('flags S/SA ' + action for action in actions)
        return (family in ('inet', 'inet6')
                and any(re.fullmatch(action, tail) for action in actions))

    def check_firewall_ownership(self, record):
        """Fail closed until foreign FIB rules and their states have drained."""
        try:
            rules = self.command(
                ['/sbin/pfctl', '-a', '*', '-sr'], limit=MAX_CONFIG
            ).stdout.decode(errors='strict')
            collision = foreign_rtable_rules(
                rules, record['fib'], self.ANCHOR, self.LABEL)
            if not collision and record.get('pf_collision'):
                states = self.command(
                    ['/sbin/pfctl', '-ss', '-vv'], limit=MAX_STATES
                ).stdout.decode(errors='strict')
                collision = fib_states_present(states, record['fib'])
        except (RoutingError, OSError, UnicodeError):
            record.update(active=False, pending=True, pf_collision=True)
            self.save(record)
            raise RoutingError(
                'The recursive firewall routing ownership could not be verified.') from None
        if collision:
            record.update(active=False, pending=True, pf_collision=True)
            self.save(record)
            raise RoutingError(
                'Another firewall rule or surviving state uses this private routing table.')
        if record.pop('pf_collision', None) is not None:
            self.save(record)

    def occupied(self, fib):
        """Allow only unchanged interface routes cloned from the main FIB."""
        return private_fib_occupied(self.routes(0), self.routes(fib))

    def fib_count(self):
        """Return the kernel's current routing-table count, if readable."""
        value = self.command(['/sbin/sysctl', '-n', 'net.fibs'], check=False)
        if value.returncode:
            return None
        try:
            count = int(value.stdout.strip())
        except ValueError:
            return None
        return count if count >= 1 else None

    def allocate(self, record):
        def count():
            try:
                return int(self.command(
                    ['/sbin/sysctl', '-n', 'net.fibs']).stdout.strip())
            except ValueError:
                raise RouteControlError(
                    'No supported private routing table is available.') from None

        try:
            reserve_private_fib(
                record, count,
                lambda value: self.command(['/sbin/sysctl', 'net.fibs=' + str(value)]),
                self.occupied, self.save, self.delay,
                lock_path=self.path('/var/run/opnsense-route-fib.lock'))
        except RouteControlError as error:
            raise RoutingError(str(error)) from None

    def route_command(self, action, fib, route):
        if action == 'add' and route['gateway'] != 'interface':
            # route(8)'s netlink backend ignores -ifp for numeric gateways.
            # The native helper sends OIF and creates the prefix exclusively.
            self.command([self.NATIVE_PYTHON, str(self.path(self.NATIVE_HELPER)),
                          'add', '--fib', str(fib),
                          '--route', json.dumps(route, sort_keys=True)])
            return
        net = ipaddress.ip_network(route['destination'])
        destination = str(net.network_address)
        if route['scope']:
            destination += '%' + route['scope']
        host = net.prefixlen == net.max_prefixlen
        if not host:
            destination += '/' + str(net.prefixlen)
        args = ['/sbin/route', '-n', action, '-fib', str(fib),
                '-inet' if route['family'] == 4 else '-inet6',
                '-host' if host else '-net', destination]
        if route['gateway'] == 'interface':
            args.extend(['-iface', route['interface']])
        else:
            args.extend([route['gateway'], '-ifp', route['interface']])
        if route['discard']:
            args.append('-' + route['discard'])
        self.command(args)

    @staticmethod
    def foreign_routes(record, desired, snapshot, native):
        """Return entries that are neither owned nor exact native interface clones."""
        foreign = {}
        pending = record.get('pending_route') or {}
        for key, route in snapshot.items():
            previous = record['routes'].get(key)
            if (previous is not None
                    and route_identity(route) == route_identity(previous)):
                continue
            if (pending.get('key') == key
                    and route_semantic(route) == route_semantic(pending['route'])):
                continue
            source = native.get(key)
            borrowed = (source is not None
                        and ipaddress.ip_network(route['destination']).prefixlen != 0
                        and route.get('gateway') == 'interface'
                        and not route.get('discard')
                        and 'G' not in str(route.get('flags', ''))
                        and route_identity(route) == route_identity(source))
            if not borrowed:
                foreign[key] = route
        return foreign

    def recover_pending_route(self, record, desired, snapshot, strict):
        """Settle one write-ahead add without claiming a different live route."""
        pending = record.get('pending_route')
        if pending is None:
            return snapshot
        fib, key, intended = record['fib'], pending['key'], pending['route']
        existing = snapshot.get(key)
        wanted = desired.get(key)
        if existing is None:
            record.pop('pending_route', None)
            record.pop('route_recovery_ambiguous', None)
            self.save(record)
            return snapshot
        if route_semantic(existing) != route_semantic(intended):
            record.pop('pending_route', None)
            record.pop('route_recovery_ambiguous', None)
            self.save(record)
            if strict:
                raise RoutingError(
                    'A pending private routing destination is owned elsewhere.')
            return snapshot
        # The receipt was durable before the add was launched. After a crash,
        # an equal live route may therefore be either our result or a concurrent
        # administrator route. Equality cannot prove provenance, so never adopt
        # or delete it automatically.
        record['route_recovery_ambiguous'] = True
        self.save(record)
        raise RoutingError(
            'A pending private route has ambiguous ownership and was preserved.')

    def sync(self, record, desired, strict=True, native=None):
        """Never change a destination whose live identity differs from our journal."""
        fib = record['fib']
        snapshot = self.routes(fib)
        snapshot = self.recover_pending_route(
            record, desired, snapshot, strict)
        keys = set(record['routes']) | set(desired)
        if len(keys) > ROUTE_LIMIT:
            raise RoutingError('The routing update exceeds the supported route count.')
        foreign = self.foreign_routes(record, desired, snapshot, native or {})
        if strict and foreign:
            raise RoutingError('The private routing table contains a destination owned elsewhere.')
        # Restore ordinary defaults first so surviving gateway states retain a
        # complete fallback even when a later route fails during stop.
        ordered = sorted(
            keys,
            key=lambda value: (
                ipaddress.ip_network(
                    (desired.get(value) or record['routes'][value])['destination']
                ).prefixlen != 0,
                value))
        for key in ordered:
            previous = record['routes'].get(key)
            existing = snapshot.get(key)
            wanted = desired.get(key)
            if (previous is not None and existing is not None
                    and route_identity(existing) != route_identity(previous)):
                # Operator changes are foreign even when the destination is ours.
                del record['routes'][key]
                self.save(record)
                if strict:
                    raise RoutingError(
                        'A private routing destination was changed externally.')
                continue
            if existing is not None and previous is None:
                # Exact interface clones are borrowed. Every other unjournalled
                # destination remains foreign, even if its forwarding semantics
                # happen to match the requested route.
                source = (native or {}).get(key)
                if (source is not None
                        and ipaddress.ip_network(existing['destination']).prefixlen
                        and existing['gateway'] == 'interface'
                        and not existing['discard'] and 'G' not in existing['flags']
                        and route_identity(existing) == route_identity(source)):
                    continue
                if strict:
                    raise RoutingError('A private routing destination is owned elsewhere.')
                continue
            if (previous is not None and wanted is not None and existing is not None
                    and route_semantic(existing) == route_semantic(wanted)):
                continue
            # A full snapshot suffices for unchanged entries. Immediately
            # recheck only destinations about to be mutated.
            if existing is not None:
                latest = self.routes(fib).get(key)
                if latest is not None and route_identity(latest) != route_identity(existing):
                    raise RoutingError(
                        'A private routing destination changed concurrently.')
                existing = latest
            if existing is not None:
                try:
                    self.route_command('delete', fib, existing)
                except RoutingMutationAmbiguous:
                    latest = self.routes(fib).get(key)
                    if latest is not None:
                        if route_identity(latest) != route_identity(existing):
                            raise RoutingError(
                                'A private routing destination changed during deletion.')
                        raise
            record['routes'].pop(key, None)
            snapshot.pop(key, None)
            self.save(record)
            if wanted is not None:
                # Numeric adds use kernel EXCL; direct interface adds cannot
                # append a gateway path. Neither replaces a concurrent owner.
                record['pending_route'] = {'key': key, 'route': dict(wanted)}
                record.pop('route_recovery_ambiguous', None)
                self.save(record)
                ambiguous = False
                try:
                    self.route_command('add', fib, wanted)
                except RoutingMutationAmbiguous:
                    ambiguous = True
                except RoutingError:
                    inserted = self.routes(fib).get(key)
                    if (inserted is not None
                            and route_semantic(inserted) == route_semantic(wanted)):
                        record['route_recovery_ambiguous'] = True
                        self.save(record)
                        raise RoutingError(
                            'A failed private route add left an equal route with ambiguous ownership; it was preserved.') from None
                    record.pop('pending_route', None)
                    record.pop('route_recovery_ambiguous', None)
                    self.save(record)
                    raise
                inserted = self.routes(fib).get(key)
                if inserted is None or route_semantic(inserted) != route_semantic(wanted):
                    record.pop('pending_route', None)
                    record.pop('route_recovery_ambiguous', None)
                    self.save(record)
                    if ambiguous and inserted is None:
                        raise RoutingMutationAmbiguous(
                            'The private route result remained unknown after exact readback.')
                    raise RoutingError('The private route could not be verified.')
                if ambiguous:
                    record['route_recovery_ambiguous'] = True
                    self.save(record)
                    raise RoutingMutationAmbiguous(
                        'The private route exists after an ambiguous add and was preserved without claiming ownership.')
                record['routes'][key] = inserted
                record.pop('pending_route', None)
                record.pop('route_recovery_ambiguous', None)
                snapshot[key] = inserted
                self.save(record)

    def policy(self, settings, context, native, families, fib, redirect=None):
        interfaces, addresses = normalize_context(context, self.TUN)
        bypass = {
            str(ipaddress.ip_network(str(address) + (
                '/32' if address.version == 4 else '/128')))
            for address in addresses
        }
        for route in native.values():
            net = ipaddress.ip_network(route['destination'])
            if route['interface'] != self.TUN and net.prefixlen:
                bypass.add(route['destination'])
            # Include devices behind known LAN static/VPN routes as well as
            # directly connected devices, without trusting arbitrary sources.
            if (route['interface'] in interfaces and net.prefixlen
                    and not (net.is_loopback or net.is_link_local or net.is_multicast)):
                interfaces[route['interface']].append(net)
        # Local and control traffic must never enter a proxy stack.
        bypass.update(('127.0.0.0/8', '169.254.0.0/16', '224.0.0.0/4',
                       '255.255.255.255/32', '::1/128', 'fe80::/10', 'ff00::/8'))
        local_table = self.PF_PREFIX + '_local'
        lines = ['table <%s> { %s }' % (local_table, ', '.join(sorted(bypass)))]
        tables, translation, matches = [], [], []
        source_count, interface_count = 0, 0
        for index, (interface, lan) in enumerate(sorted(interfaces.items())):
            selected = [net for net in source_networks(lan, settings)
                        if net.version in families]
            if not selected:
                continue
            interface_count += 1
            source_count += len(selected)
            table = self.PF_PREFIX + '_sources_' + str(index)
            tables.append('table <%s> { %s }' % (table, ', '.join(map(str, selected))))
            rules = []
            if redirect is not None and 4 in families and any(net.version == 4 for net in selected):
                # New IPv4 TCP reaches the core's loopback listener through the
                # kernel stack. DNS stays on the TUN for its hijack, and the
                # TUN match below still carries TCP whenever this is absent.
                translation.append('no rdr on %s inet proto tcp from <%s> to any port 53'
                                   % (interface, table))
                translation.append('rdr on %s inet proto tcp from <%s> to !<%s> -> 127.0.0.1 port %d'
                                   % (interface, table, local_table, redirect))
            for family in sorted(families):
                if any(net.version == family for net in selected):
                    prefix = 'match in on %s %s ' % (
                        interface, 'inet' if family == 4 else 'inet6')
                    suffix = 'from <%s> to !<%s> ' % (table, local_table)
                    action = 'rtable %d label "%s"' % (fib, self.LABEL)
                    # An unmatched DNAT reply must not become a new captured
                    # LAN flow under an interface-bound state policy.
                    rules.append(prefix + 'proto tcp ' + suffix
                                 + 'flags S/SA ' + action)
                    # ICMP forwarding in these cores is direct. Keep it on the
                    # native path, including diagnostics and PMTUD.
                    rules.append(prefix + 'proto udp ' + suffix + action)
            if redirect is None:
                lines.extend(tables[-1:] + rules)
            else:
                matches.extend(rules)
        if redirect is not None:
            # PF parses translation rules only before any filter rule.
            lines.extend(tables + translation + matches)
        return '\n'.join(lines) + '\n', interface_count, source_count

    def disable(self, record):
        # Clearing the anchor and restoring routes are externally visible
        # mutations. Persist the recovery state before either can occur.
        record.update(active=False, pending=True, resume=False,
                      interface_count=0, source_count=0)
        self.save(record)
        port = record.get('tcp_redirect_port')
        anchor_error = None
        try:
            self.anchor('')
        except (RoutingError, OSError, UnicodeError) as error:
            # Foreign anchor contents must remain intact. Restoring our FIB
            # default still removes capture without rewriting their rules.
            anchor_error = error
            if port is not None:
                # A redirect needs no private FIB, so restoring the FIB alone
                # would leave it sending TCP to a listener about to stop.
                self.neutralize_sources()
        if record['fib'] is None:
            if anchor_error is not None:
                raise RoutingError('The routing anchor could not be cleared safely.') from None
            if port is not None:
                try:
                    self.kill_redirect_states(port)
                except (RoutingError, UnicodeError):
                    raise RoutingError('Owned firewall state cleanup will be retried.') from None
            record.pop('tcp_redirect_port', None)
            record.update(pending=False, fingerprint='')
            self.save(record)
            return self.status(record)
        state_error, collision_error = None, None
        try:
            self.check_firewall_ownership(record)
        except RoutingError as error:
            collision_error = error
        if collision_error is None:
            try:
                states = self.command(
                    ['/sbin/pfctl', '-ss', '-vv'], limit=MAX_STATES
                ).stdout.decode(errors='strict')
                owned = capture_states(states, record['fib'], self.TUN)
                if port is not None:
                    owned += redirect_states(states, port)
                for identifier in dict.fromkeys(owned):
                    self.command(['/sbin/pfctl', '-k', 'id', '-k', identifier])
            except (RoutingError, UnicodeError) as error:
                state_error = error
        count = self.fib_count()
        if count is not None and record['fib'] >= count:
            # net.fibs does not survive a reboot, so a journaled table number
            # can fall outside the kernel's current range. A table the kernel
            # never created cannot hold routes: never query or rewrite it, and
            # release the number so the next start reserves a valid one.
            record['routes'].clear()
            record.pop('pending_route', None)
            record.pop('route_recovery_ambiguous', None)
            record['fib'] = None
        else:
            # Preserve ordinary routes, including the system default, for
            # surviving explicit gateway states. This private table can be
            # reused next start.
            system = self.routes(0)
            native = {key: route for key, route in system.items()
                      if route['interface'] != self.TUN}
            self.sync(record, native, strict=False, native=system)
        if (anchor_error is not None or state_error is not None
                or collision_error is not None):
            raise RoutingError('Owned firewall state cleanup will be retried.') from None
        record.pop('tcp_redirect_port', None)
        record.update(pending=False, fingerprint='')
        self.save(record)
        return self.status(record)

    def sources_available(self, record):
        """Whether capture withdrawn for lack of sources could select one now.

        None means capture is no longer wanted at all: the core is down or the
        routing inputs are off. This only evaluates the policy; it changes no
        route, anchor or state.
        """
        if not self.core_alive():
            return None
        inputs = self.routing_inputs()
        if inputs is None:
            return None
        settings, context, ipv6_enabled = inputs
        native = {key: route for key, route in self.routes(0).items()
                  if route['interface'] != self.TUN}
        _, interface_count, _ = self.policy(
            settings, context, native, {4, 6} if ipv6_enabled else {4},
            record['fib'] or 1)
        return interface_count > 0

    def enable(self, record, refresh=False):
        resume = refresh or record.get('resume') is True
        if refresh and not record['active']:
            if record.get('resume') is True:
                return self.enable(record)
            if record['pending']:
                return self.disable(record)
            # An interface can gain its address after the core started, with
            # no WAN event to restart it, so a capture withdrawn for lack of
            # sources keeps looking instead of staying off until a restart.
            if record.get('awaiting_sources') is True:
                available = self.sources_available(record)
                if available is not False:
                    record.pop('awaiting_sources', None)
                    self.save(record)
                if available:
                    return self.enable(record)
            return self.status(record)
        record.pop('awaiting_sources', None)
        if not self.core_alive():
            return self.disable(record)
        inputs = self.routing_inputs()
        if inputs is None:
            return self.disable(record)
        settings, context, ipv6_enabled = inputs
        interface = self.command(['/sbin/ifconfig', self.TUN]).stdout.decode(errors='strict')
        families = {4} if re.search(r'\binet\s+', interface) else set()
        if ipv6_enabled and re.search(r'\binet6\s+', interface):
            families.add(6)
        if not families:
            raise RoutingError('The proxy interface has no usable address family.')
        system = self.routes(0)
        native = {key: route for key, route in system.items()
                  if route['interface'] != self.TUN}
        self.allocate(record)
        redirect = self.redirect_target(settings) if 4 in families else None
        content, interface_count, source_count = self.policy(
            settings, context, native, families, record['fib'], redirect)
        if not any(line.startswith('rdr on ') for line in content.splitlines()):
            redirect = None
        fingerprint = hashlib.sha256(
            json.dumps([content, native], sort_keys=True).encode()).hexdigest()
        desired = dict(native)
        for family in families:
            default = {
                'family': family,
                'destination': '0.0.0.0/0' if family == 4 else '::/0',
                'scope': '', 'gateway': 'interface', 'interface': self.TUN,
                'flags': '', 'discard': '',
            }
            desired[route_key(default)] = default
        if not interface_count:
            result = self.disable(record)
            record['awaiting_sources'] = True
            self.save(record)
            return result
        try:
            current_anchor, current_translation = self.anchor_rules()
            self.check_firewall_ownership(record)
        except RoutingError:
            # Do not trust a no-op refresh after another owner changed rules.
            try:
                self.disable(record)
            finally:
                record['resume'] = resume
                self.save(record)
            raise
        live = self.routes(record['fib'])
        intact = not self.foreign_routes(record, desired, live, system) and all(
            key in live and route_identity(route) == route_identity(live[key])
            for key, route in record['routes'].items())
        if (not refresh or fingerprint != record.get('fingerprint')
                or not current_anchor.strip() or not intact
                or bool(current_translation.strip()) != (redirect is not None)):
            # A crash at any later instruction must leave enough durable state
            # for refresh to finish or withdraw capture safely.
            previous = record.get('tcp_redirect_port')
            record.update(active=False, pending=True, resume=resume,
                          interface_count=0, source_count=0)
            if redirect is not None:
                # Journal the port first so recovery can find its states.
                record['tcp_redirect_port'] = redirect
            self.save(record)
            try:
                self.sync(record, desired, native=system)
                self.check_firewall_ownership(record)
                self.anchor(content)
                self.check_firewall_ownership(record)
                if record.get('pending_route') is not None:
                    raise RoutingError('A private route mutation remains unsettled.')
                if previous is not None and previous != redirect:
                    # A translated state outlives its rule; drop connections
                    # still bound to a listener this policy no longer uses.
                    self.kill_redirect_states(previous)
                if redirect is None:
                    record.pop('tcp_redirect_port', None)
                record.update(active=True, pending=False, resume=False,
                              fingerprint=fingerprint,
                              interface_count=interface_count,
                              source_count=source_count)
                self.save(record)
            except (RoutingError, OSError, UnicodeError):
                with contextlib.suppress(RoutingError, OSError, UnicodeError):
                    self.disable(record)
                record['resume'] = resume
                with contextlib.suppress(RoutingError, OSError, UnicodeError):
                    self.save(record)
                raise
        return self.status(record)

    @staticmethod
    def status(record):
        result = {key: record.get(key, 0)
                  for key in ('active', 'pending', 'fib',
                              'interface_count', 'source_count',
                              'route_recovery_ambiguous')}
        if 'tcp_redirect_port' in record:
            result['tcp_redirect_port'] = record['tcp_redirect_port']
        return result

    def execute(self, action):
        self.state.mkdir(parents=True, exist_ok=True)
        lockpath = self.path(self.ROUTING_LOCK)
        lockpath.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(lockpath, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'a') as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) != 0o600):
                raise RoutingError('The routing lock has invalid ownership.')
            try:
                fcntl.flock(
                    stream,
                    fcntl.LOCK_EX | (fcntl.LOCK_NB if action == 'refresh' else 0))
            except BlockingIOError:
                return {'busy': True}
            record = self.load()
            if action == 'status':
                return self.status(record)
            if action == 'disable':
                return self.disable(record)
            return self.enable(record, refresh=action == 'refresh')
