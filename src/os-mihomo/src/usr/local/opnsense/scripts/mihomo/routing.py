#!/usr/local/bin/python3
"""Select new LAN flows with PF match rules without changing the main FIB."""

import argparse
import contextlib
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import sys
import tempfile

import yaml


STATE = '/var/db/os-mihomo'
TUN = 'tun_mihomo'
ANCHOR = 'mihomo'
LABEL = 'mihomo-routing'
LIMIT = 4 * 1024 * 1024
MAX_CONFIG = 16 * 1024 * 1024
MAX_STATES = 64 * 1024 * 1024
ROUTE_LIMIT = 8192
DEVICE_LIMIT = 128
IFNAME = re.compile(r'[A-Za-z0-9_.-]{1,15}\Z')


class RoutingError(Exception):
    pass


def network(value, family=None):
    """Decode netstat's shortened IPv4 destinations and scoped IPv6 prefixes."""
    if value == 'default':
        return ipaddress.ip_network('0.0.0.0/0' if family == 4 else '::/0'), ''
    address, slash, length = value.partition('/')
    address, scoped, scope = address.partition('%')
    if scoped and not IFNAME.fullmatch(scope):
        raise RoutingError('An interface scope is invalid.')
    if ':' not in address:
        parts = address.split('.')
        if not all(p.isdecimal() for p in parts) or not 1 <= len(parts) <= 4:
            raise RoutingError('A routing destination is invalid.')
        if not slash:
            length = str(32 if len(parts) == 4 else len(parts) * 8)
        address = '.'.join(parts + ['0'] * (4 - len(parts)))
    elif not slash:
        length = '128'
    try:
        result = ipaddress.ip_network(address + '/' + length, strict=False)
    except ValueError:
        raise RoutingError('A routing destination is invalid.') from None
    if family and result.version != family:
        raise RoutingError('A routing address family is inconsistent.')
    return result, scope


def route_key(route):
    return '%d:%s%%%s' % (route['family'], route['destination'], route['scope'])


def route_identity(route):
    return {key: route[key] for key in ('family', 'destination', 'scope', 'gateway', 'interface', 'flags')}


def route_semantic(route):
    return {key: route[key] for key in ('family', 'destination', 'scope', 'gateway', 'interface', 'discard')}


def parse_routes(text, family):
    """Read only numeric route entries, retaining an exact ownership identity."""
    if len(text.encode()) > LIMIT:
        raise RoutingError('The routing table exceeds the supported limit.')
    columns, routes = None, {}
    for line in text.splitlines():
        words = line.split()
        if not words:
            continue
        if words[0] == 'Destination':
            if 'Gateway' not in words or 'Flags' not in words or 'Netif' not in words:
                raise RoutingError('The routing table format is unsupported.')
            columns = {name: words.index(name) for name in ('Destination', 'Gateway', 'Flags', 'Netif')}
            continue
        if columns is None:
            continue
        if len(words) <= max(columns.values()):
            raise RoutingError('A routing table entry is incomplete.')
        destination, scope = network(words[columns['Destination']], family)
        gateway = words[columns['Gateway']]
        interface, flags = words[columns['Netif']], words[columns['Flags']]
        if not IFNAME.fullmatch(interface) or not re.fullmatch(r'[A-Za-z0-9!]+', flags):
            raise RoutingError('A routing table entry is invalid.')
        if gateway.startswith('link#'):
            if not re.fullmatch(r'link#[0-9]+', gateway):
                raise RoutingError('A link gateway is invalid.')
            gateway = 'interface'
        else:
            addr, _, zone = gateway.partition('%')
            try:
                if ipaddress.ip_address(addr).version != family:
                    raise ValueError
            except ValueError:
                # Link-layer neighbour entries are not routes to reproduce.
                if 'L' in flags or re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', gateway):
                    continue
                raise RoutingError('A numeric gateway is required.') from None
            if zone and not IFNAME.fullmatch(zone):
                raise RoutingError('A gateway scope is invalid.')
        if 'L' in flags:
            continue
        route = {'family': family, 'destination': str(destination), 'scope': scope,
                 'gateway': gateway, 'interface': interface, 'flags': flags,
                 'discard': 'blackhole' if 'B' in flags else 'reject' if 'R' in flags else ''}
        key = route_key(route)
        if key in routes and route_identity(routes[key]) != route_identity(route):
            raise RoutingError('Multiple routes to one destination are unsupported.')
        routes[key] = route
        if len(routes) > ROUTE_LIMIT:
            raise RoutingError('The routing table exceeds the supported route count.')
    if columns is None:
        # netstat omits the column header for a genuinely empty FIB.
        empty = [line.strip() for line in text.splitlines() if line.strip()]
        if not 1 <= len(empty) <= 2 or not re.fullmatch(r'Routing tables(?:\s*\(fib:\s*[0-9]+\))?', empty[0]) or (len(empty) == 2 and empty[1] != ('Internet:' if family == 4 else 'Internet6:')):
            raise RoutingError('The routing table has no recognized header.')
    return routes


def normalize_context(context):
    if not isinstance(context, dict) or not isinstance(context.get('interfaces'), list) or not isinstance(context.get('local_addresses'), list):
        raise RoutingError('The firewall routing context is unavailable.')
    if len(context['interfaces']) > 256 or len(context['local_addresses']) > 4096:
        raise RoutingError('The firewall routing context exceeds its supported limit.')
    interfaces, local = {}, set()
    for item in context['interfaces']:
        if not isinstance(item, dict) or not IFNAME.fullmatch(item.get('device', '')) or not isinstance(item.get('wan'), bool) or not isinstance(item.get('networks'), list):
            raise RoutingError('The firewall interface context is invalid.')
        nets = []
        for value in item['networks']:
            try:
                nets.append(ipaddress.ip_network(value, strict=False))
            except (TypeError, ValueError):
                raise RoutingError('An interface network is invalid.') from None
        if len(nets) > 256:
            raise RoutingError('An interface has too many networks.')
        if not item['wan'] and item['device'] != TUN and item['device'] != 'lo0':
            interfaces.setdefault(item['device'], []).extend(nets)
    for value in context['local_addresses']:
        try:
            local.add(ipaddress.ip_address(value.split('%')[0]))
        except (AttributeError, ValueError):
            raise RoutingError('A local interface address is invalid.') from None
    return interfaces, local


def source_networks(lan, settings):
    mode, entries = settings.get('device_mode', 'off'), settings.get('device_list', [])
    if mode not in ('off', 'blacklist', 'whitelist') or not isinstance(entries, list) or len(entries) > DEVICE_LIMIT:
        raise RoutingError('The device routing policy is invalid.')
    try:
        devices = [ipaddress.ip_network(value, strict=False) for value in entries]
    except (TypeError, ValueError):
        raise RoutingError('A device network is invalid.') from None
    selected = []
    for original in lan:
        if original.prefixlen == 0:
            raise RoutingError('A LAN interface must have a specific network.')
        applicable = [net for net in devices if net.version == original.version and net.overlaps(original)]
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
                        next_ranges.extend(net.address_exclude(excluded) if excluded.subnet_of(net) else [net])
                    remaining = next_ranges
            selected.extend(remaining)
    result = []
    for family in (4, 6):
        result.extend(ipaddress.collapse_addresses(net for net in selected if net.version == family))
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


def capture_states(text, fib):
    """Remove captured flows and their exact TUN return-state counterparts."""
    if len(text.encode()) > MAX_STATES:
        raise RoutingError('The firewall state table exceeds its supported limit.')
    result, tuples, partners = [], set(), []
    for block in re.split(r'(?m)(?=^\S)', text):
        owned = bool(re.search(r'\brtable:\s+' + str(fib) + r'\b', block))
        origin = re.search(r'(?m)^\s+origif:\s+(\S+)\s*$', block)
        header = block.splitlines()[0].split() if block else []
        tun_origin = (origin is not None and origin.group(1) == TUN) or (bool(header) and header[0] == TUN)
        if not owned and not tun_origin:
            continue
        targets = re.findall(r'\b(?:route-to|reply-to|dup-to|gateway):\s+(\S+)', block)
        if any(not target.endswith('@' + TUN) for target in targets):
            continue
        found = re.search(r'\bid:\s+([0-9a-fA-F]{16})\s+creatorid:\s+([0-9a-fA-F]{8})\b', block)
        if not found:
            if owned:
                raise RoutingError('An owned firewall state has no valid identifier.')
            continue
        identifier = found.group(1).lower() + '/' + found.group(2).lower()
        transport = state_tuple(block)
        if owned:
            result.append(identifier)
            if transport is not None:
                # Creator ID prevents associating a synchronized foreign state
                # with an otherwise equal transport tuple.
                tuples.add((found.group(2).lower(), transport))
        elif tun_origin and transport is not None:
            partners.append((identifier, found.group(2).lower(), transport))
    result.extend(identifier for identifier, creator, transport in partners if (creator, transport) in tuples)
    result = list(dict.fromkeys(result))
    return result


class Routing:
    def __init__(self, root=Path('/'), run=None):
        self.root = Path(root)
        self.state = self.path(STATE)
        self.marker = self.state / 'routing-state.json'
        self.runner = run or subprocess.run

    def path(self, value):
        return self.root / value.lstrip('/')

    def command(self, args, check=True, limit=LIMIT):
        try:
            value = self.runner(args, capture_output=True, timeout=15)
        except (OSError, subprocess.TimeoutExpired):
            raise RoutingError('A routing operation failed or timed out.') from None
        if len(value.stdout) + len(value.stderr) > limit or (check and value.returncode):
            raise RoutingError('A routing operation failed.')
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
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_size > limit or (private and stat.S_IMODE(info.st_mode) != 0o600):
                raise RoutingError('A routing state file has invalid ownership or size.')
            raw = stream.read(limit + 1)
        if len(raw) > limit:
            raise RoutingError('A routing state file exceeds its supported limit.')
        return raw

    def load(self):
        raw = self.read(self.marker, private=True)
        if raw is None:
            return {'schema': 1, 'fib': None, 'active': False, 'routes': {}, 'pending': False}
        try:
            record = json.loads(raw)
            if record['schema'] != 1 or not isinstance(record['active'], bool) or not isinstance(record['pending'], bool) or not isinstance(record['routes'], dict):
                raise ValueError
            if not isinstance(record.get('resume', False), bool):
                raise ValueError
            if not isinstance(record['fib'], int) or not 1 <= record['fib'] <= 65534:
                raise ValueError
            for key, route in record['routes'].items():
                if key != route_key(route) or not IFNAME.fullmatch(route['interface']) or route['family'] not in (4, 6):
                    raise ValueError
                network(route['destination'], route['family'])
                if route['scope'] and not IFNAME.fullmatch(route['scope']):
                    raise ValueError
                if route['gateway'] != 'interface':
                    address, _, zone = route['gateway'].partition('%')
                    ipaddress.ip_address(address)
                    if zone and not IFNAME.fullmatch(zone):
                        raise ValueError
                if route['discard'] not in ('', 'blackhole', 'reject'):
                    raise ValueError
                if not isinstance(route['flags'], str) or not re.fullmatch(r'[A-Za-z0-9!]*', route['flags']):
                    raise ValueError
            if len(record['routes']) > ROUTE_LIMIT:
                raise ValueError
            return record
        except (KeyError, TypeError, ValueError):
            raise RoutingError('The routing ownership record is invalid.') from None

    def save(self, record):
        self.state.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(prefix='.routing-', dir=self.state)
        try:
            with os.fdopen(fd, 'wb') as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write(json.dumps(record, sort_keys=True).encode() + b'\n')
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(name, self.marker)
        finally:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(name)

    def routes(self, fib):
        result = {}
        for family, flag in ((4, 'inet'), (6, 'inet6')):
            value = self.command(['/usr/bin/netstat', '-rn', '-F', str(fib), '-f', flag])
            result.update(parse_routes(value.stdout.decode(errors='strict'), family))
        return result

    def core_alive(self):
        try:
            pid = int(self.read(self.path('/var/run/mihomo-child.pid'), b'0').strip())
            if pid <= 1:
                return False
            value = self.command(['/bin/ps', '-p', str(pid), '-o', 'command='], check=False)
            arguments = shlex.split(value.stdout.decode())
            return value.returncode == 0 and bool(arguments) and arguments[0] == '/usr/local/bin/mihomo'
        except (ValueError, UnicodeError):
            return False

    def anchor(self, content):
        self.check_anchor()
        fd, name = tempfile.mkstemp(prefix='.routing-pf-', dir=self.state)
        try:
            with os.fdopen(fd, 'wb') as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write(content.encode())
            self.command(['/sbin/pfctl', '-a', ANCHOR, '-nf', name])
            self.command(['/sbin/pfctl', '-a', ANCHOR, '-f', name])
        finally:
            os.unlink(name)

    def check_anchor(self):
        current = self.command(['/sbin/pfctl', '-a', ANCHOR, '-sr']).stdout.decode(errors='strict')
        if any(line.strip() and ('label "' + LABEL + '"') not in line for line in current.splitlines()):
            raise RoutingError('The routing anchor contains rules owned elsewhere.')
        return current

    def allocate(self, record):
        count = int(self.command(['/sbin/sysctl', '-n', 'net.fibs']).stdout.strip())
        if record['fib'] is not None and record['fib'] < count:
            return
        if not 1 <= count < 65535:
            raise RoutingError('No supported private routing table is available.')
        self.command(['/sbin/sysctl', 'net.fibs=' + str(count + 1)])
        if int(self.command(['/sbin/sysctl', '-n', 'net.fibs']).stdout.strip()) != count + 1:
            raise RoutingError('The private routing table allocation could not be verified.')
        # FreeBSD clones kernel interface routes into newly allocated FIBs.
        # Borrow identical nondefault system routes, but never claim ownership.
        native = self.routes(0)
        for key, route in self.routes(count).items():
            if not ipaddress.ip_network(route['destination']).prefixlen or key not in native or route_identity(route) != route_identity(native[key]):
                raise RoutingError('The new routing table is already occupied.')
        record.update(fib=count, routes={}, active=False)
        self.save(record)

    def route_command(self, action, fib, route):
        net = ipaddress.ip_network(route['destination'])
        destination = str(net.network_address)
        if route['scope']:
            destination += '%' + route['scope']
        host = net.prefixlen == net.max_prefixlen
        if not host:
            destination += '/' + str(net.prefixlen)
        args = ['/sbin/route', '-n', action, '-fib', str(fib),
                '-inet' if route['family'] == 4 else '-inet6', '-host' if host else '-net', destination]
        if route['gateway'] == 'interface':
            args.extend(['-iface', route['interface']])
        else:
            args.extend([route['gateway'], '-ifp', route['interface']])
        if route['discard']:
            args.append('-' + route['discard'])
        self.command(args)

    def sync(self, record, desired, strict=True):
        """Never change a destination whose live identity differs from our journal."""
        fib = record['fib']
        snapshot = self.routes(fib)
        keys = set(record['routes']) | set(desired)
        # Restore both ordinary defaults before a less important route can
        # fail during stop; surviving gateway states need a complete fallback.
        for key in sorted(keys, key=lambda value: (ipaddress.ip_network((desired.get(value) or record['routes'][value])['destination']).prefixlen != 0, value)):
            previous, existing, wanted = record['routes'].get(key), snapshot.get(key), desired.get(key)
            if previous is not None and existing is not None and route_identity(existing) != route_identity(previous):
                # Operator changes are foreign even when the destination is ours.
                del record['routes'][key]
                self.save(record)
                if strict:
                    raise RoutingError('A private routing destination was changed externally.')
                continue
            if existing is not None and previous is None:
                if wanted is not None and ipaddress.ip_network(wanted['destination']).prefixlen and route_identity(existing) == route_identity(wanted):
                    continue
                if strict:
                    raise RoutingError('A private routing destination is owned elsewhere.')
                continue
            if previous is not None and wanted is not None and existing is not None and route_semantic(existing) == route_semantic(wanted):
                continue
            # A full snapshot suffices for unchanged entries. Immediately
            # recheck only destinations we are about to mutate.
            if existing is not None:
                latest = self.routes(fib).get(key)
                if latest is not None and route_identity(latest) != route_identity(existing):
                    raise RoutingError('A private routing destination changed concurrently.')
                existing = latest
            if existing is not None:
                self.route_command('delete', fib, existing)
            record['routes'].pop(key, None)
            self.save(record)
            if wanted is not None:
                # RTM_ADD fails if a concurrent owner inserted this key. It
                # never overwrites a route, so absent keys need no extra dump.
                self.route_command('add', fib, wanted)
                inserted = self.routes(fib).get(key)
                if inserted is None or route_semantic(inserted) != route_semantic(wanted):
                    raise RoutingError('The private route could not be verified.')
                record['routes'][key] = inserted
                snapshot[key] = inserted
                self.save(record)

    def policy(self, settings, context, native, families, fib):
        interfaces, addresses = normalize_context(context)
        bypass = {str(ipaddress.ip_network(str(addr) + ('/32' if addr.version == 4 else '/128'))) for addr in addresses}
        for route in native.values():
            net = ipaddress.ip_network(route['destination'])
            if route['interface'] != TUN and net.prefixlen:
                bypass.add(route['destination'])
            # Include devices behind a known LAN static/VPN route, as well as
            # directly connected devices, without trusting arbitrary sources.
            if route['interface'] in interfaces and net.prefixlen and not (net.is_loopback or net.is_link_local or net.is_multicast):
                interfaces[route['interface']].append(net)
        # Local/control traffic must never be put through a proxy stack.
        bypass.update(('127.0.0.0/8', '169.254.0.0/16', '224.0.0.0/4', '255.255.255.255/32',
                       '::1/128', 'fe80::/10', 'ff00::/8'))
        lines = ['table <mihomo_local> { ' + ', '.join(sorted(bypass)) + ' }']
        source_count, interface_count = 0, 0
        for index, (interface, lan) in enumerate(sorted(interfaces.items())):
            selected = [net for net in source_networks(lan, settings) if net.version in families]
            if not selected:
                continue
            interface_count += 1
            source_count += len(selected)
            table = 'mihomo_sources_' + str(index)
            lines.append('table <%s> { %s }' % (table, ', '.join(map(str, selected))))
            for family in sorted(families):
                if any(net.version == family for net in selected):
                    prefix = 'match in on %s %s ' % (interface, 'inet' if family == 4 else 'inet6')
                    suffix = 'from <%s> to !<mihomo_local> ' % table
                    action = 'rtable %d label "%s"' % (fib, LABEL)
                    # An unmatched DNAT reply must not become a new captured
                    # LAN flow under an interface-bound state policy.
                    lines.append(prefix + 'proto tcp ' + suffix + 'flags S/SA ' + action)
                    # ICMP forwarding in this core is always direct. Keep it
                    # on the native path, including diagnostics and PMTUD.
                    lines.append(prefix + 'proto udp ' + suffix + action)
        return '\n'.join(lines) + '\n', interface_count, source_count

    def disable(self, record):
        anchor_error = None
        try:
            self.anchor('')
        except (RoutingError, UnicodeError) as error:
            # Foreign anchor contents must remain intact. Restoring our FIB
            # default still removes capture without rewriting their rules.
            anchor_error = error
        record.update(active=False, pending=record['fib'] is not None, resume=False, interface_count=0, source_count=0)
        if record['fib'] is None:
            if anchor_error is not None:
                raise RoutingError('The routing anchor could not be cleared safely.') from None
            return self.status(record)
        self.save(record)
        state_error = None
        try:
            states = self.command(['/sbin/pfctl', '-ss', '-vv'], limit=MAX_STATES).stdout.decode(errors='strict')
            for identifier in capture_states(states, record['fib']):
                self.command(['/sbin/pfctl', '-k', 'id', '-k', identifier])
        except (RoutingError, UnicodeError) as error:
            state_error = error
        # Preserve ordinary routes, including the system default, for surviving
        # explicit gateway states. This private table can be reused next start.
        native = {key: route for key, route in self.routes(0).items() if route['interface'] != TUN}
        self.sync(record, native, strict=False)
        if anchor_error is not None or state_error is not None:
            raise RoutingError('Owned firewall state cleanup will be retried.') from None
        record.update(pending=False, fingerprint='')
        self.save(record)
        return self.status(record)

    def enable(self, record, refresh=False):
        resume = refresh or record.get('resume') is True
        if refresh and not record['active']:
            if record.get('resume') is True:
                return self.enable(record)
            return self.disable(record) if record['pending'] else self.status(record)
        if not self.core_alive():
            return self.disable(record)
        try:
            settings = json.loads(self.read(self.state / 'settings.json', b'{}'))
            config = yaml.safe_load(self.read(self.state / 'config.yaml', b'{}', limit=MAX_CONFIG)) or {}
            context = json.loads(self.read(self.state / 'routing-context.json', b'{}'))
        except (ValueError, yaml.YAMLError):
            raise RoutingError('The routing configuration is invalid.') from None
        if not isinstance(settings, dict) or not isinstance(config, dict) or not isinstance(config.get('tun'), dict):
            raise RoutingError('The routing configuration is invalid.')
        if not all(settings.get(key) is True for key in ('service_enabled', 'transparent', 'transparent_consent')) or config['tun'].get('enable') is not True:
            return self.disable(record)
        if config['tun'].get('auto-route') is not False:
            raise RoutingError('Disable core automatic routing before selecting LAN flows.')
        dns = config.get('dns', {})
        if not isinstance(dns, dict):
            raise RoutingError('The routing DNS configuration is invalid.')
        if dns.get('enable') and dns.get('enhanced-mode') == 'fake-ip':
            raise RoutingError('Device routing requires real-address DNS responses.')
        interface = self.command(['/sbin/ifconfig', TUN]).stdout.decode(errors='strict')
        families = {4} if re.search(r'\binet\s+', interface) else set()
        if config.get('ipv6') is True and re.search(r'\binet6\s+', interface):
            families.add(6)
        if not families:
            raise RoutingError('The proxy interface has no usable address family.')
        native = {key: route for key, route in self.routes(0).items() if route['interface'] != TUN}
        self.allocate(record)
        content, interface_count, source_count = self.policy(settings, context, native, families, record['fib'])
        fingerprint = hashlib.sha256(json.dumps([content, native], sort_keys=True).encode()).hexdigest()
        desired = dict(native)
        for family in families:
            default = {'family': family, 'destination': '0.0.0.0/0' if family == 4 else '::/0', 'scope': '',
                       'gateway': 'interface', 'interface': TUN, 'flags': '', 'discard': ''}
            desired[route_key(default)] = default
        if not interface_count:
            return self.disable(record)
        try:
            current_anchor = self.check_anchor()
        except RoutingError:
            # Do not trust a no-op refresh after another owner changed rules.
            try:
                self.disable(record)
            finally:
                record['resume'] = resume
                self.save(record)
            raise
        live = self.routes(record['fib'])
        intact = all(key in live and route_identity(route) == route_identity(live[key]) for key, route in record['routes'].items())
        if not refresh or fingerprint != record.get('fingerprint') or not current_anchor.strip() or not intact:
            try:
                self.sync(record, desired)
                self.anchor(content)
            except RoutingError:
                record.update(active=False, pending=True)
                self.save(record)
                with contextlib.suppress(RoutingError):
                    self.disable(record)
                record['resume'] = resume
                self.save(record)
                raise
            record.update(active=True, pending=False, resume=False, fingerprint=fingerprint,
                          interface_count=interface_count, source_count=source_count)
            self.save(record)
        return self.status(record)

    @staticmethod
    def status(record):
        return {key: record.get(key, 0) for key in ('active', 'pending', 'fib', 'interface_count', 'source_count')}

    def execute(self, action):
        self.state.mkdir(parents=True, exist_ok=True)
        lockpath = self.path('/var/run/mihomo-routing.lock')
        lockpath.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(lockpath, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'a') as stream:
            if os.fstat(stream.fileno()).st_uid != os.geteuid():
                raise RoutingError('The routing lock has invalid ownership.')
            try:
                fcntl.flock(stream, fcntl.LOCK_EX | (fcntl.LOCK_NB if action == 'refresh' else 0))
            except BlockingIOError:
                return {'busy': True}
            record = self.load()
            if action == 'status':
                return self.status(record)
            return self.disable(record) if action == 'disable' else self.enable(record, refresh=action == 'refresh')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('enable', 'disable', 'refresh', 'status'))
    args = parser.parse_args()
    if not sys.platform.startswith('freebsd') or os.geteuid() != 0:
        raise RoutingError('Native routing requires FreeBSD root.')
    print(json.dumps(Routing().execute(args.action), sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (RoutingError, OSError, UnicodeError):
        print('Mihomo routing could not be applied safely; owned recovery will be retried.', file=sys.stderr)
        raise SystemExit(1)
