#!/usr/local/bin/python3
"""Manage Mihomo configuration, service state, and transparent DNS as one unit."""
import argparse
import base64
import contextlib
import copy
import fcntl
import gzip
import hashlib
import io
import ipaddress
import json
import os
import pwd
from pathlib import Path
import re
import secrets
import shlex
import socket
import stat
import subprocess
import sys
import tempfile
from xml.etree import ElementTree
import time
import zlib
from urllib import parse as urlparse, request as urlrequest

import yaml
from process_owner import OwnershipError, core_group, valid_identity, watch_group

MAX_CONFIG = 16 * 1024 * 1024
MAX_BACKUP = 24 * 1024 * 1024
BACKUP_KEYS = ('subscription_url', 'secret', 'device', 'service_enabled', 'transparent',
               'transparent_consent', 'mixed_port', 'socks_port', 'bind_address', 'allow_lan',
               'tun_stack', 'tun_mtu', 'dns_mode', 'dns_hijack', 'dns_fallback', 'router_dns',
               'dns_override', 'ipv6', 'geo_source', 'dns_default', 'dns_nameserver',
               'dns_proxy_nameserver',
               'device_mode', 'device_list', 'controller')
BACKUP_WARNING = 'The operation completed, but the Mihomo configuration backup could not be updated.'
BACKUP_INTEGRITY_WARNING = ('The saved Mihomo backup checksum does not match. The current local configuration is retained. '
                            'Stop the service and use Repair saved backup to validate and import the edited backup.')
UNBOUND_GENERATED = '/var/unbound/etc/zz-mihomo.conf'
UNBOUND_CONFIG_ROOT = '/var/unbound'
UNBOUND_TEMPLATE_ROOT = '/usr/local/opnsense/service/templates/OPNsense/Unbound'
FORWARDER = '127.0.0.1@1053'
ROOT_ANCHOR = '/var/unbound/root.key'
STATE_SCHEMA = 1
SCRIPT = "/usr/local/opnsense/scripts/mihomo/mihomo.py"
HELPER = "/usr/local/opnsense/scripts/mihomo/setup_unbound.php"
ROUTING_HELPER = "/usr/local/opnsense/scripts/mihomo/routing.py"
MIRROR_HELPER = "/usr/local/opnsense/scripts/mihomo/config_mirror.php"
STATE = "/var/db/os-mihomo"
HOME = STATE + "/home"
SHARE = "/usr/local/share/mihomo"
PID = "/var/run/mihomo-child.pid"
DAEMON_PID = "/var/run/mihomo.pid"
WATCH_PID = "/var/run/mihomo-watch.pid"
WATCH_CHILD_PID = "/var/run/mihomo-watch-child.pid"
DEFAULT_UI_URL = "https://github.com/Zephyruso/zashboard/releases/latest/download/dist.zip"
ROUTING_DIAGNOSTIC_LIMIT = 512
INTEGRATION_PREFIX = b'Mihomo integration state: '
INTEGRATION_FIELDS = frozenset(('effective_forwarding', 'dns_changed',
                                'integration_changed', 'filter_changed', 'cron_changed'))


class Error(Exception):
    pass


class BackupIntegrityError(Error):
    pass


def bounded_routing_diagnostic(value):
    """Keep a native routing diagnosis single-line and safe for public status."""
    text = ' '.join(''.join(character if character.isprintable() else ' '
                            for character in str(value)).split())
    return text.encode('utf-8', errors='replace')[:ROUTING_DIAGNOSTIC_LIMIT].decode('utf-8', errors='ignore')


def routing_status_error(message, error):
    detail = bounded_routing_diagnostic(error)
    return message + (' ' + detail if detail else '')


def integration_state(output):
    """Accept exactly one complete, boolean decision from the bundled helper."""
    lines = [line for line in output.splitlines() if line.startswith(INTEGRATION_PREFIX)]
    if len(lines) != 1 or len(lines[0]) > 4096:
        raise Error('The Mihomo integration helper returned no unique reload decision.')

    def unique_object(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError('duplicate key')
            value[key] = item
        return value

    try:
        value = json.loads(lines[0][len(INTEGRATION_PREFIX):].decode('utf-8', errors='strict'),
                           object_pairs_hook=unique_object)
    except (UnicodeError, ValueError, TypeError):
        raise Error('The Mihomo integration helper returned an invalid reload decision.') from None
    if (not isinstance(value, dict) or set(value) != INTEGRATION_FIELDS
            or any(type(value[field]) is not bool for field in INTEGRATION_FIELDS)):
        raise Error('The Mihomo integration helper returned an invalid reload decision.')
    return value


def reload_receipt(path, actions):
    """Read a private reload receipt without following a replaced path."""
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                or stat.S_IMODE(before.st_mode) != 0o600 or before.st_size > 4096):
            raise Error('A Mihomo integration reload receipt is invalid.')
        content = stream.read(4097)
        after = os.fstat(stream.fileno())
    if len(content) > 4096 or any(getattr(before, field) != getattr(after, field) for field in
            ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')):
        raise Error('A Mihomo integration reload receipt changed while it was read.')
    try:
        value = json.loads(content)
    except (UnicodeError, ValueError, TypeError):
        raise Error('A Mihomo integration reload receipt is invalid.') from None
    if (not isinstance(value, dict) or set(value) != {'action', 'version'}
            or value.get('version') != 1 or value.get('action') not in actions):
        raise Error('A Mihomo integration reload receipt is invalid.')
    return value['action']


class LocalAPIHandler(urlrequest.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, url):
        # The controller secret belongs only to the local core.
        return None


class Loader(yaml.SafeLoader):
    """Use YAML 1.2 booleans and reject ambiguous duplicate explicit keys."""
    yaml_implicit_resolvers = {
        key: [(tag, pattern) for tag, pattern in values
              if tag not in {"tag:yaml.org,2002:bool", "tag:yaml.org,2002:timestamp"}]
        for key, values in yaml.SafeLoader.yaml_implicit_resolvers.items()
    }

    def construct_mapping(self, node, deep=False):
        seen = set()
        for key, _ in node.value:
            if key.tag == "tag:yaml.org,2002:merge":
                continue
            value = self.construct_object(key, deep=deep)
            try:
                if value in seen:
                    raise Error("The YAML contains duplicate mapping keys.")
                seen.add(value)
            except TypeError:
                raise Error("YAML mapping keys must be scalars.") from None
        self.flatten_mapping(node)
        return super().construct_mapping(node, deep=deep)


Loader.add_implicit_resolver("tag:yaml.org,2002:bool", re.compile(r"^(?:true|false|True|False|TRUE|FALSE)$"), list("tTfF"))


def parse_yaml(content):
    if len(content) > MAX_CONFIG:
        raise Error("The subscription exceeds the configuration size limit.")
    try:
        data = yaml.load(content, Loader=Loader)
    except (yaml.YAMLError, UnicodeError, RecursionError, ValueError):
        raise Error("The subscription is not valid YAML.") from None
    if not isinstance(data, dict):
        raise Error("A complete YAML configuration mapping is required.")

    def inspect(value, parents=(), depth=0):
        if depth > 80 or id(value) in parents:
            raise Error("Recursive or excessively nested YAML is not supported.")
        if isinstance(value, dict):
            if any(not isinstance(key, str) for key in value):
                raise Error("Configuration mapping keys must be strings.")
            for child in value.values():
                inspect(child, parents + (id(value),), depth + 1)
        elif isinstance(value, list):
            for child in value:
                inspect(child, parents + (id(value),), depth + 1)
    inspect(data)
    return data


def check_subscription(data):
    proxies = data.get("proxies")
    providers = data.get("proxy-providers")
    if not ((isinstance(proxies, list) and proxies) or (isinstance(providers, dict) and providers)):
        raise Error("The subscription must contain top-level proxies or proxy-providers.")
    if not isinstance(data.get("proxy-groups"), list) or not isinstance(data.get("rules"), list) or not data["rules"]:
        raise Error("The subscription must include proxy-groups and a nonempty rules list.")


def merge_yaml(base, overlay):
    """Deep-merge mappings and apply the six explicit list extensions."""
    result = copy.deepcopy(base)
    for key, value in overlay.items():
        if key.startswith(('prepend-', 'append-')):
            target = key.split('-', 1)[1]
            if target not in {'rules', 'proxy-groups', 'proxies'} or not isinstance(value, list):
                raise Error("Unsupported list extension in merge YAML.")
            continue
        if isinstance(value, dict) and value and isinstance(result.get(key), dict):
            result[key] = merge_yaml(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    for target in ('rules', 'proxy-groups', 'proxies'):
        if any(prefix + target in overlay for prefix in ('prepend-', 'append-')):
            current = result.get(target, [])
            if not isinstance(current, list):
                raise Error("List extensions require a list value.")
            result[target] = copy.deepcopy(overlay.get('prepend-' + target, [])) + current + copy.deepcopy(overlay.get('append-' + target, []))
    return result


def dns_transport_rules(content):
    """Read literal upstream IPs without resolving their verification names."""
    addresses = set()
    for value in re.findall(r'^\s*forward-addr:\s*([^\s#]+)', content, re.MULTILINE):
        address = value.strip('"').split('@', 1)[0].strip('[]')
        try:
            addresses.add(ipaddress.ip_address(address))
        except ValueError:
            raise Error("The router DNS upstream must use literal IP addresses.") from None
    if not addresses:
        raise Error("No router DNS upstream addresses were found. Configure explicit forwarding upstreams first.")
    return [('IP-CIDR' if ip.version == 4 else 'IP-CIDR6') + ',' + str(ip) + ('/32' if ip.version == 4 else '/128') + ',DIRECT,no-resolve'
            for ip in sorted(addresses, key=lambda ip: (ip.version, int(ip)))] + ['DST-PORT,853,DIRECT']


def advertises_ipv6(content):
    """Detect enabled router-advertisement or DHCPv6 server configuration."""
    import xml.etree.ElementTree as ET
    try:
        root = ET.fromstring(content)
    except ET.ParseError:
        raise Error("Unable to inspect the router IPv6 configuration.") from None
    for group in ('radvd', 'dhcpdv6'):
        for entry in root.findall('./' + group + '/*'):
            enabled = entry.find('enable')
            if enabled is not None and (enabled.text or '').strip().lower() not in {'0', 'false', 'no'}:
                return True
            if group == 'radvd' and entry.findtext('mode', '').lower() not in {'', 'disabled'}:
                return True
    for service in ('Kea/dhcp6', 'Dhcprelay/dhcp6', 'RouterAdvertisements'):
        for entry in root.findall('./OPNsense/' + service + '//enabled'):
            if (entry.text or '').strip() == '1':
                return True
    return False


DNS_MODES = ('fake-ip', 'redir-host', 'normal')
DNS_MODE_DEFAULT = 'redir-host'
HIJACK_TARGETS = ['any:53', 'tcp://any:53']
# Rule databases, as verified reachable sets. A category that one source does not
# publish makes every rule naming it fail, so the sets are never mixed.
GEO_SOURCES = {
    'metacubex': {
        'geoip': 'https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.dat',
        'geosite': 'https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat',
        'mmdb': 'https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/country.mmdb',
        'asn': 'https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/GeoLite2-ASN.mmdb',
    },
    'loyalsoldier-cdn': {
        'geoip': 'https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geoip.dat',
        'geosite': 'https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geosite.dat',
        'mmdb': 'https://cdn.jsdelivr.net/gh/Loyalsoldier/geoip@release/Country.mmdb',
    },
    'loyalsoldier': {
        'geoip': 'https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat',
        'geosite': 'https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat',
        'mmdb': 'https://github.com/Loyalsoldier/geoip/releases/latest/download/Country.mmdb',
    },
}
# jsDelivr refuses MetaCubeX/meta-rules-dat: the repository is past its 50 MB
# package limit, and it never serves release assets. Loyalsoldier is the mirrored set.
GEO_SOURCE_DEFAULT = 'metacubex'
GEO_UPDATE_HOURS = 24


DEVICE_MODES = ('off', 'whitelist', 'blacklist')
DEVICE_LIMIT = 64


def device_networks(entries):
    """Normalise each entry to a network, rejecting anything ambiguous."""
    networks = []
    for entry in entries or []:
        if not isinstance(entry, str) or entry.strip() != entry or not entry:
            raise Error('A device entry must be a single address or network.')
        try:
            networks.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            raise Error('Not an address or network: ' + entry) from None
    if len(networks) > DEVICE_LIMIT:
        raise Error('At most %d device entries may be listed.' % DEVICE_LIMIT)
    return networks


# Where each DHCP backend OPNsense can run keeps its reservations. A device
# with one holds its address across leases, which is what makes an address
# worth writing into a rule at all.
RESERVATIONS = (('./dnsmasq/hosts', 'hwaddr', 'ip'),
                ('./dhcpd/*/staticmap', 'mac', 'ipaddr'),
                ('./OPNsense/Kea/dhcp4/reservations/reservation', 'hw_address', 'ip_address'))
DHCP_LEASES = ('/var/db/dnsmasq.leases',)


def randomised_mac(mac):
    """Whether the address is locally administered rather than a real one.

    Phones and laptops present a different address per network by default, and
    rotate it. Such an address identifies nothing for long, so a reservation
    made against it stops matching without warning.
    """
    try:
        return bool(int(mac.split(':')[0], 16) & 0x02)
    except (ValueError, AttributeError, IndexError):
        return False


def read_leases(root=Path('/')):
    """Hostnames the DHCP server has handed out, keyed by address."""
    found = {}
    for name in DHCP_LEASES:
        path = root / name.lstrip('/')
        try:
            text = path.read_text(errors='replace')
        except OSError:
            continue
        for line in text.splitlines():
            fields = line.split()
            # <expiry> <mac> <address> <hostname> <client-id>; the file also
            # carries a DUID line that parses as none of that.
            if len(fields) < 4 or fields[1].count(':') != 5:
                continue
            try:
                ipaddress.ip_address(fields[2])
            except ValueError:
                continue
            found[fields[2]] = {'mac': fields[1].lower(),
                                'hostname': '' if fields[3] == '*' else fields[3]}
    return found


def read_reservations(root=Path('/')):
    """Addresses pinned to a device, whichever DHCP server is in use."""
    pinned = set()
    try:
        tree = ElementTree.parse(str(root / 'conf/config.xml'))
    except (OSError, ElementTree.ParseError):
        return pinned
    for path, _, address in RESERVATIONS:
        for node in tree.getroot().findall(path):
            value = (node.findtext(address) or '').strip()
            if value:
                pinned.add(value)
    return pinned


def uplink_interface(run):
    """The interface the default route leaves by, whose neighbours are not ours."""
    result = run(['/sbin/route', '-n', 'get', 'default'], check=False)
    if result.returncode != 0:
        return ''
    found = re.search(r'interface:\s*(\S+)', result.stdout.decode(errors='replace'))
    return found.group(1) if found else ''


def local_addresses(run):
    """The router's own addresses, which are never a device to steer."""
    result = run(['/sbin/ifconfig', '-a'], check=False)
    if result.returncode != 0:
        return set()
    text = result.stdout.decode(errors='replace')
    return set(re.findall(r'\binet6?\s+([0-9a-fA-F.:]+)', text))


def read_neighbours(run):
    """Devices the router has spoken to on a link of its own.

    Neighbours on the uplink are the ISP's, not the household's, and a
    link-local address names an interface rather than a device: neither can
    stand in a rule, and offering them would only invite a policy that matches
    nothing or the wrong thing.
    """
    skip = uplink_interface(run)
    found = {}
    for args, pattern in ((['/usr/sbin/arp', '-an'],
                           r'\((\S+?)\) at ([0-9a-fA-F:]{17}) on (\S+)'),
                          (['/usr/sbin/ndp', '-an'],
                           r'^(\S+?)\s+([0-9a-fA-F:]{17})\s+(\S+)')):
        result = run(args, check=False)
        if result.returncode != 0:
            continue
        for address, mac, interface in re.findall(pattern, result.stdout.decode(errors='replace'), re.M):
            if interface == skip or '%' in address:
                continue
            try:
                parsed = ipaddress.ip_address(address)
            except ValueError:
                continue
            if parsed.is_link_local or parsed.is_loopback or parsed.is_multicast:
                continue
            found.setdefault(address, mac.lower())
    return found


def known_devices(run, root=Path('/')):
    """What the router knows about the devices on it, for the policy picker.

    Only the address ever reaches a rule: Mihomo matches source addresses, and
    by the time a packet reaches it the link-layer address is long gone. The
    hardware address is carried here so a device can be recognised, and so the
    two ways an address stops identifying it can be pointed out.
    """
    leases = read_leases(root)
    reserved = read_reservations(root)
    neighbours = read_neighbours(run)
    ours = local_addresses(run)
    devices = []
    for address in (set(leases) | set(neighbours)) - ours:
        lease = leases.get(address, {})
        mac = lease.get('mac') or neighbours.get(address, '')
        devices.append({'address': address, 'mac': mac,
                        'hostname': lease.get('hostname', ''),
                        'reserved': address in reserved,
                        'randomised_mac': randomised_mac(mac)})
    devices.sort(key=lambda d: (ipaddress.ip_address(d['address']).version,
                                ipaddress.ip_address(d['address'])))
    return devices


def routing_settings(settings):
    """Bypassed clients need DNS answers usable on their ordinary route."""
    result = dict(settings)
    if result.get('transparent') and result.get('dns_mode') == 'fake-ip':
        result['dns_mode'] = 'redir-host'
    for field in ('dns_default', 'dns_nameserver', 'dns_proxy_nameserver'):
        values = result.get(field)
        if isinstance(values, list):
            result[field] = [normalize_dns_server(field, value)
                             if isinstance(value, str) else value for value in values]
    return result


def device_routing_policy(settings):
    """Describe source selection without exposing firewall implementation."""
    if not settings.get('transparent'):
        return []
    mode = settings.get('device_mode', 'off')
    networks = device_networks(settings.get('device_list'))
    if mode == 'off' or not networks:
        return ['Internal devices may enter TUN.',
                'Router traffic and WAN connections bypass TUN.']
    action = 'Enter TUN' if mode == 'whitelist' else 'Bypass TUN'
    other = 'Other devices bypass TUN.' if mode == 'whitelist' else 'Other internal devices may enter TUN.'
    return [action + ': ' + str(net) for net in networks] + [other,
            'Router traffic and WAN connections bypass TUN.']


# What a subscription that ships no DNS policy gets instead of nothing. It sits
# UNDER the subscription, so a provider that states its own dns block keeps it in
# full: the two are never blended, because half of one policy and half of another
# resolves neither correctly.
BASELINE_DNS = {
    'enable': True,
    'prefer-h3': False,
    'use-hosts': True,
    'use-system-hosts': True,
    # respect-rules needs the proxy path up before the first lookup resolves,
    # which is a bootstrap loop on a router that has just started.
    'respect-rules': False,
    # Bootstrap servers must be IP-hosted, or there is nothing to resolve them with.
    'default-nameserver': ['223.5.5.5', '119.29.29.29'],
    'proxy-server-nameserver': ['https://dns.alidns.com/dns-query', 'https://doh.pub/dns-query'],
    'nameserver': ['https://dns.alidns.com/dns-query', 'https://doh.pub/dns-query'],
    'nameserver-policy': {
        # Private names must go to the system resolver. A public DoH cannot answer
        # .lan, .local or a NAS hostname, so sending them there breaks the LAN.
        'geosite:private': ['system'],
        'geosite:cn': ['https://dns.alidns.com/dns-query', 'https://doh.pub/dns-query'],
        # Cloudflare by literal IP: its certificate carries IP SANs, so this
        # validates without skip-cert-verify. Google by IP would not.
        'geosite:geolocation-!cn': ['https://1.1.1.1/dns-query', 'https://1.0.0.1/dns-query'],
    },
    'fake-ip-range': '198.18.0.0/15',
    'fake-ip-filter-mode': 'blacklist',
    'fake-ip-filter': ['geosite:private', '*.lan', '*.local', '*.arpa', 'localhost',
                       'localhost.*', '+.msftconnecttest.com', '+.msftncsi.com',
                       '+.pool.ntp.org', 'time.*.com', 'time.*.gov', 'time.*.apple.com',
                       '+.push.apple.com', '+.market.xiaomi.com'],
}


def baseline(data):
    """Fill in what the subscription leaves out, and nothing it states itself."""
    result = {}
    if not (isinstance(data.get('dns'), dict) and data['dns']):
        result['dns'] = copy.deepcopy(BASELINE_DNS)
    if not isinstance(data.get('profile'), dict) or 'store-selected' not in data['profile']:
        # Without this the core forgets which proxy each group is set to every
        # time it restarts, and a group falls back to whatever its provider
        # listed first. Restarting happens on a subscription update, a reboot
        # and every transparent routing change, and the first entry is usually
        # DIRECT -- so the node the operator picked in the panel silently stops
        # being used and everything goes out unproxied.
        result.setdefault('profile', {})['store-selected'] = True
    return result


# DNS upstreams the user may state instead of the ones the subscription ships.
# An empty list means "whatever the subscription provides", never "none".
DNS_SERVER_FIELDS = {'dns_default': 'default-nameserver', 'dns_nameserver': 'nameserver',
                     'dns_proxy_nameserver': 'proxy-server-nameserver'}
DNS_SERVER_LIMIT = 8
# Accepted beside an address: mihomo resolves these through the host itself.
DNS_SERVER_ALIASES = ('system', 'dhcp')


def dot_tls_name_compat(value):
    """Translate an Unbound-style IP plus TLS name into Mihomo's hostname form."""
    try:
        parsed = urlparse.urlsplit(value)
        host, port = parsed.hostname, parsed.port
        literal = str(ipaddress.ip_address(host))
    except (AttributeError, TypeError, ValueError):
        return None
    if (parsed.scheme != 'tls' or parsed.username is not None or parsed.password is not None
            or parsed.path or parsed.query or not parsed.fragment):
        return None
    server_name, separator, parameters = parsed.fragment.partition('&')
    labels = server_name.split('.')
    if (len(server_name) <= 15 or len(server_name) > 253 or len(labels) < 2
            or any(not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', label)
                   for label in labels)):
        return None
    normalized = 'tls://' + server_name + (':' + str(port) if port is not None else '')
    return literal, normalized + ('#' + parameters if separator else '')


def normalize_dns_server(field, value):
    """Keep interface selectors while repairing a copied Unbound DoT endpoint."""
    compatible = dot_tls_name_compat(value)
    if compatible is None:
        return value
    # Bootstrap must stay addressable before DNS works. The copied TLS name is
    # used by the encrypted upstream fields; its literal endpoint bootstraps it.
    return compatible[0] if field == 'dns_default' else compatible[1]


def dns_server_host(value):
    """The host a DNS upstream points at, whatever syntax states it."""
    text = value.split('#', 1)[0]
    if '://' in text:
        text = text.split('://', 1)[1].split('/', 1)[0]
    if text.startswith('['):
        return text[1:].split(']', 1)[0]
    # A single colon is a port; several mean the address itself is IPv6.
    return text.rsplit(':', 1)[0] if text.count(':') == 1 else text


def check_dns_servers(field, values):
    if not isinstance(values, list) or len(values) > DNS_SERVER_LIMIT:
        raise Error("At most %d DNS servers may be listed per field." % DNS_SERVER_LIMIT)
    for value in values:
        if (not isinstance(value, str) or not value.strip() or value != value.strip()
                or any(char in value for char in " \t\r\n\x00")):
            raise Error("A DNS server must be a single address without spaces.")
        normalize_dns_server(field, value)
        if value in DNS_SERVER_ALIASES and field != 'dns_default':
            continue
        if field != 'dns_default':
            continue
        # Bootstrap servers resolve the other servers, so nothing can resolve them,
        # and mihomo itself rejects anything here that is not a bare address.
        try:
            ipaddress.ip_address(dns_server_host(value))
        except ValueError:
            raise Error("Default nameservers must be addressed by literal IP, because "
                        "they are what resolves every other server: " + value) from None


# Simple switches for the settings a user changes most often. They are applied
# UNDER the merge YAML, so a hand-written override always wins. When an overlay
# states one of these keys in its canonical form, absorb_switches() lifts it into
# the switch instead, so the UI never shows a value the config contradicts.
SWITCH_DEFAULTS = {'router_dns': False, 'dns_override': False, 'ipv6': False, 'dns_hijack': True,
                   'dns_mode': DNS_MODE_DEFAULT, 'geo_source': GEO_SOURCE_DEFAULT,
                   'mixed_port': 7890, 'socks_port': 7891, 'allow_lan': False,
                   'bind_address': '127.0.0.1', 'tun_stack': 'gvisor', 'tun_mtu': 1420}
# Bumped only to re-seed the switches from an installation that predates them.
SWITCH_SCHEMA = 4
# gVisor needs no kernel support and is what the presets ship; system is faster
# where the host can carry it; mixed uses system for TCP and gVisor for UDP.
TUN_STACKS = ('gvisor', 'system', 'mixed')
PORT_LIMIT = 65535
DNS_LISTEN_PORT = 1053
MTU_RANGE = (576, 9000)
CONTROLLER_PORT = 9090
LOOPBACK_CONTROLLER = '127.0.0.1:%d' % CONTROLLER_PORT
ANY_CONTROLLER = '0.0.0.0:%d' % CONTROLLER_PORT


def switch_overlay(settings):
    """Base overlay produced by the simple switches."""
    ipv6 = bool(settings.get('ipv6', False))
    overlay = {
        'ipv6': ipv6,
        'mixed-port': int(settings.get('mixed_port', SWITCH_DEFAULTS['mixed_port'])),
        'socks-port': int(settings.get('socks_port', SWITCH_DEFAULTS['socks_port'])),
        'allow-lan': bool(settings.get('allow_lan', False)),
        'bind-address': str(settings.get('bind_address') or SWITCH_DEFAULTS['bind_address']),
        'dns': {'ipv6': ipv6,
                'enhanced-mode': settings.get('dns_mode', DNS_MODE_DEFAULT)},
        'tun': {'dns-hijack': list(HIJACK_TARGETS) if settings.get('dns_hijack', True) else [],
                'stack': settings.get('tun_stack') or SWITCH_DEFAULTS['tun_stack'],
                'mtu': int(settings.get('tun_mtu', SWITCH_DEFAULTS['tun_mtu']))},
        'geox-url': dict(GEO_SOURCES[settings.get('geo_source') or GEO_SOURCE_DEFAULT]),
        'geodata-mode': True, 'geo-auto-update': True, 'geo-update-interval': GEO_UPDATE_HOURS,
    }
    # Router DNS owns every upstream, so a stated server would contradict it.
    if not settings.get('router_dns') and settings.get('dns_override'):
        for field, key in DNS_SERVER_FIELDS.items():
            stated = settings.get(field)
            if stated:
                overlay['dns'][key] = [normalize_dns_server(field, value) for value in stated]
    return overlay


def switch_conflicts(rendered, settings):
    """Switches whose effective value the merge YAML overrode."""
    dns = rendered.get('dns') or {}
    tun = rendered.get('tun') or {}
    wanted = switch_overlay(settings)
    out = []
    if dns.get('ipv6') is not wanted['dns']['ipv6']:
        out.append('ipv6')
    if dns.get('enhanced-mode') != wanted['dns']['enhanced-mode']:
        out.append('dns_mode')
    if bool(tun.get('dns-hijack')) is not bool(wanted['tun']['dns-hijack']):
        out.append('dns_hijack')
    for field, key in (('mixed_port', 'mixed-port'), ('socks_port', 'socks-port'),
                       ('allow_lan', 'allow-lan'), ('bind_address', 'bind-address')):
        if key in rendered and rendered[key] != wanted[key]:
            out.append(field)
    # A stopped TUN carries the inert values render() forces, not a conflict.
    if tun.get('enable'):
        for field, key in (('tun_stack', 'stack'), ('tun_mtu', 'mtu')):
            if key in tun and tun[key] != wanted['tun'][key]:
                out.append(field)
    return out


def absorb_switches(overlay, settings):
    """Lift canonical switch values out of an overlay into the settings.

    A value the switches cannot express (a custom dns-hijack target list, an
    unknown DNS mode) is deliberately left in the overlay, where it keeps
    winning; switch_conflicts() then reports it to the user.
    """
    if not isinstance(overlay, dict):
        return settings
    settings = dict(settings)
    dns = overlay.get('dns') if isinstance(overlay.get('dns'), dict) else {}
    tun = overlay.get('tun') if isinstance(overlay.get('tun'), dict) else {}

    top6, dns6 = overlay.get('ipv6'), dns.get('ipv6')
    stated = [v for v in (top6, dns6) if v is not None]
    if stated and all(isinstance(v, bool) for v in stated) and len(set(stated)) == 1:
        settings['ipv6'] = stated[0]
        overlay.pop('ipv6', None)
        dns.pop('ipv6', None)

    if dns.get('enhanced-mode') in DNS_MODES:
        settings['dns_mode'] = dns.pop('enhanced-mode')

    for field, key in (('mixed_port', 'mixed-port'), ('socks_port', 'socks-port')):
        port = overlay.get(key)
        # bool is an int, and "allow-lan: true" next door makes that a live risk.
        if isinstance(port, int) and not isinstance(port, bool) and 1 <= port <= PORT_LIMIT:
            settings[field] = port
            overlay.pop(key)
    if isinstance(overlay.get('allow-lan'), bool):
        settings['allow_lan'] = overlay.pop('allow-lan')
    if isinstance(overlay.get('bind-address'), str) and overlay['bind-address']:
        settings['bind_address'] = overlay.pop('bind-address')
    if tun.get('stack') in TUN_STACKS:
        settings['tun_stack'] = tun.pop('stack')
    mtu = tun.get('mtu')
    if isinstance(mtu, int) and not isinstance(mtu, bool) and MTU_RANGE[0] <= mtu <= MTU_RANGE[1]:
        settings['tun_mtu'] = tun.pop('mtu')

    # The controller is settings policy now, so leaving it here would display a
    # value the rendered configuration ignores.
    controller = overlay.get('external-controller')
    if isinstance(controller, str) and ':' in controller:
        host, _, port = controller.rpartition(':')
        if host in ('127.0.0.1', '0.0.0.0') and port.isdigit():
            settings['controller'] = controller
            overlay.pop('external-controller')

    lifted_dns = False
    for field, key in DNS_SERVER_FIELDS.items():
        stated = dns.get(key)
        if isinstance(stated, list) and all(isinstance(v, str) for v in stated):
            settings[field] = list(stated)
            dns.pop(key)
            lifted_dns = True
    if lifted_dns:
        settings['dns_override'] = True

    urls = overlay.get('geox-url')
    if isinstance(urls, dict):
        for name, known in GEO_SOURCES.items():
            if urls == known:
                settings['geo_source'] = name
                overlay.pop('geox-url')
                break

    hijack = tun.get('dns-hijack')
    if isinstance(hijack, list) and (not hijack or hijack == HIJACK_TARGETS):
        settings['dns_hijack'] = bool(hijack)
        tun.pop('dns-hijack')

    for key, section in (('dns', dns), ('tun', tun)):
        if overlay.get(key) is section and not section:
            overlay.pop(key)
    return settings


def adopt_switches(rendered, settings):
    """Seed the switches from a configuration rendered before they existed.

    Upgrades must not change behaviour, so the effective values win over the
    defaults. The stored overlay is absorbed afterwards and overrides this,
    because it states intent while a rendered file only states the outcome.
    """
    settings = dict(settings)
    dns = rendered.get('dns') if isinstance(rendered.get('dns'), dict) else {}
    tun = rendered.get('tun') if isinstance(rendered.get('tun'), dict) else {}
    for value in (rendered.get('ipv6'), dns.get('ipv6')):
        if isinstance(value, bool):
            settings['ipv6'] = value
            break
    # A disabled section carries the inert state render() forces, not an intent.
    if dns.get('enable') is True and dns.get('enhanced-mode') in DNS_MODES:
        settings['dns_mode'] = dns['enhanced-mode']
    if tun.get('enable') is True and isinstance(tun.get('dns-hijack'), list):
        settings['dns_hijack'] = bool(tun['dns-hijack'])
    for field, key in (('mixed_port', 'mixed-port'), ('socks_port', 'socks-port')):
        if isinstance(rendered.get(key), int) and not isinstance(rendered.get(key), bool):
            settings[field] = rendered[key]
    if isinstance(rendered.get('allow-lan'), bool):
        settings['allow_lan'] = rendered['allow-lan']
    if isinstance(rendered.get('bind-address'), str) and rendered['bind-address']:
        settings['bind_address'] = rendered['bind-address']
    # An inert section carries what render() forces, not what was intended.
    if tun.get('enable') is True:
        if tun.get('stack') in TUN_STACKS:
            settings['tun_stack'] = tun['stack']
        if isinstance(tun.get('mtu'), int) and not isinstance(tun.get('mtu'), bool):
            settings['tun_mtu'] = tun['mtu']
    for name, known in GEO_SOURCES.items():
        if rendered.get('geox-url') == known:
            settings['geo_source'] = name
            break
    return settings


def orphan_policy_keys(base, overlay):
    """Merge YAML policy keys that match nothing the subscription states.

    nameserver-policy is a mapping, so an overlay entry replaces a provider one
    only when the key matches character for character. A provider that renames
    its key, or a typo in ours, turns the override into a new entry beside the
    one it was meant to replace: both stay in force, and nothing reports it.
    """
    def policy(mapping):
        dns = mapping.get('dns') if isinstance(mapping.get('dns'), dict) else {}
        value = dns.get('nameserver-policy') if isinstance(dns, dict) else None
        return value if isinstance(value, dict) else {}
    existing = policy(base)
    return [key for key in policy(overlay) if key not in existing]


def switch_overrides(overlay):
    """Switch keys a hand-written overlay still dictates after absorption."""
    probe = copy.deepcopy(overlay) if isinstance(overlay, dict) else {}
    absorb_switches(probe, {})
    dns = probe.get('dns') if isinstance(probe.get('dns'), dict) else {}
    tun = probe.get('tun') if isinstance(probe.get('tun'), dict) else {}
    out = []
    if 'ipv6' in probe or 'ipv6' in dns:
        out.append('ipv6')
    if 'enhanced-mode' in dns:
        out.append('dns_mode')
    if 'dns-hijack' in tun:
        out.append('dns_hijack')
    if 'geox-url' in probe:
        out.append('geo_source')
    for field, key in (('mixed_port', 'mixed-port'), ('socks_port', 'socks-port'),
                       ('allow_lan', 'allow-lan'), ('bind_address', 'bind-address')):
        if key in probe:
            out.append(field)
    for field, key in (('tun_stack', 'stack'), ('tun_mtu', 'mtu')):
        if key in tun:
            out.append(field)
    out.extend(field for field, key in DNS_SERVER_FIELDS.items() if key in dns)
    return out


def render(data, settings, transparent=None, overlay=None, upstreams='', ipv6_advertised=False):
    result = merge_yaml(baseline(data), data)
    router_dns = settings.get('router_dns', False)
    if router_dns:
        result = merge_yaml(result, {'dns': {
            'nameserver': ['127.0.0.1'], 'proxy-server-nameserver': ['127.0.0.1'],
            'default-nameserver': ['127.0.0.1'], 'nameserver-policy': {}}})
        # An empty policy replaces the provider policy rather than deep-merging it.
        result['dns']['nameserver-policy'] = {}
    result = merge_yaml(result, switch_overlay(settings))
    if overlay is None:
        overlay = parse_yaml((Path(__file__).resolve().parents[3] / 'share/mihomo/presets/full.yaml').read_bytes())
        if settings.get('controller'):
            overlay['external-controller'] = settings['controller']
    result = merge_yaml(result, overlay)
    enabled = settings["transparent"] if transparent is None else transparent
    dns = result.get("dns", {})
    if not isinstance(dns, dict):
        raise Error("The dns section must be a mapping.")
    tun = result.get('tun', {})
    if not isinstance(tun, dict):
        raise Error("The tun section must be a mapping.")
    for section in (tun, dns):
        if 'enable' in section and not isinstance(section['enable'], bool):
            raise Error("TUN and DNS enablement must be boolean values.")
    if not enabled:
        tun.update(enable=False, **{'auto-route': False, 'strict-route': False, 'dns-hijack': []})
        dns.update(enable=False, listen='')
    tun['device'] = 'tun_mihomo'
    # Transparent routing belongs to the plugin's source policy, never FIB0.
    # Enforce this after merging so subscription/merge YAML cannot re-enable
    # the global routes that also capture unrelated DNAT replies.
    tun.update(**{'auto-route': False, 'strict-route': False, 'auto-redirect': False})
    if tun.get('enable') and dns.get('enable') and dns.get('enhanced-mode') == 'fake-ip':
        dns['enhanced-mode'] = 'redir-host'
    result["dns"] = dns
    result['tun'] = tun
    result.update({
        "external-ui": result.get('external-ui', HOME + "/ui"),
        "external-ui-url": result.get('external-ui-url', DEFAULT_UI_URL), "secret": settings["secret"],
        "external-controller": settings.get('controller') or LOOPBACK_CONTROLLER,
    })
    for key in ('port', 'socks-port', 'mixed-port', 'redir-port', 'tproxy-port'):
        value = result.get(key, 0)
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 65535 or value == 53:
            raise Error("Proxy listener ports must be valid and cannot use port 53.")
    for value in (dns.get('listen', ''), result.get('external-controller', ''), result.get('external-controller-tls', '')):
        if value:
            if not isinstance(value, str) or ':' not in value:
                raise Error('Listeners require a numeric port other than 53.')
            port = value.rsplit(':', 1)[-1]
            if not re.fullmatch('[0-9]{1,5}', port) or not 0 <= int(port) <= 65535 or int(port) == 53:
                raise Error('Listeners require a numeric port other than 53.')
    for listener in result.get('listeners', []):
        if not isinstance(listener, dict):
            raise Error('Additional listeners must be mappings.')
        port = listener.get('port', 0)
        if isinstance(port, bool) or not isinstance(port, int) or not 0 <= port <= 65535 or port == 53:
            raise Error("Additional listeners cannot bind port 53.")
    # Device selection belongs to native source routing before the TUN. It must
    # never rewrite provider rules or restrict clients using an explicit proxy.
    result['rules'] = result.get('rules', [])
    if router_dns:
        if ipv6_advertised and not (result.get('ipv6') is True and dns.get('ipv6') is True):
            raise Error("Clients are being offered IPv6 while Mihomo IPv6 is disabled. Validate IPv6 before enabling router DNS.")
        if dns.get('fallback'):
            raise Error("Remove DNS fallback upstreams from merge YAML before enabling router DNS.")
        result['rules'] = dns_transport_rules(upstreams) + result.get('rules', [])
    return yaml.safe_dump(result, allow_unicode=True, sort_keys=False).encode()


def atomic_write(path, content, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(prefix="." + path.name + ".", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temporary)


class System:
    def __init__(self, process_reader=None):
        self.process_reader = process_reader

    def _core_group(self, config=None):
        return core_group(process_reader=self.process_reader, signaler=os.kill,
                          sleeper=time.sleep, config=str(config or Path(STATE) / 'config.yaml'))

    def _watch_group(self):
        return watch_group(process_reader=self.process_reader, signaler=os.kill,
                           sleeper=time.sleep)

    @staticmethod
    def _ownership(operation):
        try:
            return operation()
        except OwnershipError as error:
            raise Error('Exact Mihomo process ownership could not be established; no process was signalled.') from error

    def routing(self, action):
        result = self.run(['/usr/local/bin/python3', ROUTING_HELPER, action], timeout=90, check=False)
        if result.returncode:
            detail = bounded_routing_diagnostic(result.stderr.decode(errors='replace'))
            raise Error(detail or 'Transparent routing failed without a native diagnostic.')
        return result

    def run(self, args, timeout=45, check=True, cwd=None, input=None):
        try:
            options = {'input': input} if input is not None else {}
            result = subprocess.run(args, capture_output=True, timeout=timeout, cwd=cwd, **options)
        except (subprocess.TimeoutExpired, OSError):
            raise Error("A system operation failed or timed out.") from None
        output = result.stdout + result.stderr
        # configctl reports failure as a bare ERR, which carries no other marker.
        failed_action = args[0] == "/usr/local/sbin/configctl" and (
            b"Execute error" in output or b"Error (" in output or output.strip() == b"ERR")
        if check and (result.returncode or failed_action):
            raise Error("A system operation failed; the previous configuration was retained.")
        return result

    def running(self):
        return self._ownership(self._core_group().running)

    def process_running(self, path, executable, arguments):
        """Check a non-signalled worker by exact kernel argv and executable."""
        try:
            text = Path(path).read_text().strip()
            if not re.fullmatch(r'[1-9][0-9]{0,9}', text):
                return False
            identity = self._core_group().identity(int(text))
            return bool(identity and identity['uid'] == os.geteuid()
                        and identity['executable'] == executable
                        and identity['argv'] == arguments)
        except (OSError, OwnershipError):
            return False

    def validate(self, candidate):
        data = parse_yaml(Path(candidate).read_bytes())
        tun = data.get('tun', {})
        if tun.get('enable') and tun.get('stack', 'gvisor') != 'gvisor':
            raise Error('This FreeBSD core supports only the gVisor TUN stack. Select gVisor before enabling transparent routing.')
        result = self.run(["/usr/local/bin/mihomo", "-t", "-d", HOME, "-f", str(candidate)], timeout=90, check=False)
        if result.returncode:
            raise Error("Mihomo rejected the configuration. No configuration was applied.")

    def recover_reloads(self):
        """Finish reloads whose configuration write was already made durable."""
        cron_pending = Path(STATE) / 'cron-reload-pending.json'
        if reload_receipt(cron_pending, {'remove', 'restore-cron'}) is not None:
            self.restore_cron()
        filter_pending = Path(STATE) / 'filter-reload-pending.json'
        if reload_receipt(filter_pending, {'enable-tun', 'remove'}) is not None:
            self.run(['/usr/local/sbin/configctl', 'filter', 'reload'], timeout=90)
            filter_pending.unlink(missing_ok=True)

    @staticmethod
    @contextlib.contextmanager
    def _tun_lock():
        state = Path(STATE)
        if state.is_symlink():
            raise Error('The Mihomo TUN ownership directory is unsafe.')
        state.mkdir(mode=0o700, parents=True, exist_ok=True)
        directory = state.stat()
        if (not stat.S_ISDIR(directory.st_mode) or directory.st_uid != os.geteuid()
                or stat.S_IMODE(directory.st_mode) != 0o700):
            raise Error('The Mihomo TUN ownership directory is not private.')
        path = state / 'tun-runtime-identity.lock'
        descriptor = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'a') as lock:
            info = os.fstat(lock.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) != 0o600):
                raise Error('The Mihomo TUN ownership lock is invalid.')
            deadline = time.monotonic() + 2
            while True:
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError as error:
                    if time.monotonic() >= deadline:
                        raise Error('Mihomo TUN ownership is busy and will be retried.') from error
                    time.sleep(0.02)
            yield

    def tun_snapshot(self):
        result = self.run(['/sbin/ifconfig', '-v', 'tun_mihomo'], check=False)
        if result.returncode:
            return None
        try:
            text = result.stdout.decode('utf-8', errors='strict')
            header = re.match(r'tun_mihomo: flags=([0-9a-fA-F]+)\b.*\bmetric ([0-9]+) mtu ([0-9]+)', text)
            driver = re.search(r'^\s*drivername: (tun[0-9]+)\s*$', text, re.M)
            description = re.search(r'^\s*description: (.*)$', text, re.M)
            opener = re.search(r'^\s*Opened by PID ([0-9]+)\s*$', text, re.M)
            if header is None or driver is None:
                raise ValueError
            flags, metric, mtu = int(header.group(1), 16), int(header.group(2)), int(header.group(3))
            opened_by = int(opener.group(1)) if opener else None
            addresses = []
            for family, raw in re.findall(r'^\s*(inet6?)\s+(\S+)', text, re.M):
                address = ipaddress.ip_address(raw.split('%', 1)[0])
                if (family == 'inet') != (address.version == 4):
                    raise ValueError
                addresses.append(family + ':' + str(address))
            addresses = sorted(set(addresses))
            if (not 0 <= flags <= 0xffffffffffffffff
                    or not 0 <= metric < 2147483648 or not 0 < mtu <= 1048576
                    or len(addresses) > 16
                    or opened_by is not None and not 1 < opened_by < 2147483648):
                raise ValueError
            index = socket.if_nametoindex('tun_mihomo')
            value = {'name': 'tun_mihomo', 'index': index, 'driver': driver.group(1),
                     'metric': metric, 'mtu': mtu,
                     'description': description.group(1) if description else '',
                     'opened_by': opened_by, 'flags': flags, 'addresses': addresses}
            value['closed'] = not (flags & 0x41) and opened_by is None \
                and not addresses
            return value
        except (OSError, UnicodeError, ValueError):
            raise Error('The exact Mihomo TUN interface identity could not be read.') from None

    def _tun_receipt(self):
        path = Path(STATE) / 'tun-runtime-identity.json'
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            return None
        with os.fdopen(descriptor, 'rb') as stream:
            before = os.fstat(stream.fileno())
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                    or stat.S_IMODE(before.st_mode) != 0o600 or before.st_size > 65536):
                raise Error('The Mihomo TUN ownership receipt is invalid; the interface was preserved.')
            raw = stream.read(65537)
            after = os.fstat(stream.fileno())
        if len(raw) > 65536 or any(getattr(before, field) != getattr(after, field) for field in
                ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')):
            raise Error('The Mihomo TUN ownership receipt changed while it was read.')
        try:
            receipt = json.loads(raw)
        except (UnicodeError, ValueError, TypeError):
            raise Error('The Mihomo TUN ownership receipt is invalid; the interface was preserved.') from None
        stable = ('name', 'index', 'driver', 'metric', 'mtu')
        common = {'version', 'phase', *stable, 'description', 'core', 'opened'}
        phase = receipt.get('phase') if isinstance(receipt, dict) else None
        expected = common | ({'preclaim'} if phase == 'claiming' else set())
        core = receipt.get('core') if isinstance(receipt, dict) else None
        opened = receipt.get('opened') if isinstance(receipt, dict) else None
        if (not isinstance(receipt, dict) or set(receipt) != expected or receipt.get('version') != 1
                or phase not in ('claiming', 'owned') or receipt.get('name') != 'tun_mihomo'
                or type(receipt.get('index')) is not int or receipt['index'] <= 0
                or not re.fullmatch(r'tun[0-9]+', str(receipt.get('driver', '')))
                or type(receipt.get('metric')) is not int or not 0 <= receipt['metric'] < 2147483648
                or type(receipt.get('mtu')) is not int or not 0 < receipt['mtu'] <= 1048576
                or not re.fullmatch(r'Mihomo owner [0-9a-f]{32}', str(receipt.get('description', '')))
                or not valid_identity(core) or not self._core_group().child_matches(core)
                or not isinstance(opened, dict) or set(opened) != {'flags', 'addresses', 'opened_by'}
                or type(opened.get('flags')) is not int or not 0 <= opened['flags'] <= 0xffffffffffffffff
                or opened['flags'] & 0x41 != 0x41 or opened.get('opened_by') != core['pid']
                or not isinstance(opened.get('addresses'), list)
                or not 1 <= len(opened['addresses']) <= 16
                or any(not isinstance(value, str) for value in opened['addresses'])):
            raise Error('The Mihomo TUN ownership receipt is invalid; the interface was preserved.')
        try:
            canonical = []
            for value in opened['addresses']:
                family, separator, raw = value.partition(':')
                address = ipaddress.ip_address(raw)
                if not separator or family not in ('inet', 'inet6') \
                        or (family == 'inet') != (address.version == 4):
                    raise ValueError
                canonical.append(family + ':' + str(address))
            if opened['addresses'] != sorted(set(canonical)):
                raise ValueError
        except ValueError:
            raise Error('The Mihomo TUN ownership receipt is invalid; the interface was preserved.') from None
        if phase == 'claiming':
            preclaim = receipt['preclaim']
            if (not isinstance(preclaim, dict)
                    or set(preclaim) != {*stable, 'description', 'opened_by'}
                    or any(preclaim.get(key) != receipt[key] for key in stable)
                    or not isinstance(preclaim.get('description'), str)
                    or len(preclaim['description'].encode('utf-8')) > 255
                    or preclaim.get('opened_by') != core['pid']):
                raise Error('The pending Mihomo TUN ownership receipt is invalid; the interface was preserved.')
        return receipt

    @staticmethod
    def _write_tun_receipt(receipt):
        atomic_write(Path(STATE) / 'tun-runtime-identity.json',
                     (json.dumps(receipt, sort_keys=True) + '\n').encode())

    @staticmethod
    def _clear_tun_receipt():
        path = Path(STATE) / 'tun-runtime-identity.json'
        path.unlink(missing_ok=True)
        try:
            descriptor = os.open(path.parent, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            return
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def claim_tun(self, process_record):
        with self._tun_lock():
            core = process_record.get('child') if isinstance(process_record, dict) else None
            owner = self._core_group()
            if (not valid_identity(core) or not owner.child_matches(core) or not owner.same(core)):
                raise Error('The Mihomo TUN was not opened by the verified core.')
            current = self.tun_snapshot()
            if current is None or current['opened_by'] != core['pid']:
                raise Error('The Mihomo TUN was not opened by the verified core.')
            stable = ('name', 'index', 'driver', 'metric', 'mtu')
            receipt = self._tun_receipt()
            if receipt is None:
                receipt = {key: current[key] for key in stable}
                receipt.update(version=1, phase='claiming',
                               description='Mihomo owner ' + secrets.token_hex(16), core=core,
                               opened={key: current[key] for key in ('flags', 'addresses', 'opened_by')},
                               preclaim={key: current[key] for key in (*stable, 'description', 'opened_by')})
                self._write_tun_receipt(receipt)
            elif receipt['core'] != core:
                raise Error('The Mihomo TUN ownership belongs to another core identity.')
            exact = all(current.get(key) == receipt[key] for key in stable)
            opened = all(current.get(key) == receipt['opened'][key]
                         for key in ('flags', 'addresses', 'opened_by'))
            if receipt['phase'] == 'owned':
                if not exact or not opened or current['description'] != receipt['description']:
                    raise Error('The Mihomo TUN ownership marker changed externally.')
                return
            preclaim = receipt['preclaim']
            if (not exact or not opened
                    or current['description'] not in (preclaim['description'], receipt['description'])
                    or not owner.same(core)):
                raise Error('The Mihomo TUN changed during ownership claim.')
            if current['description'] == preclaim['description']:
                if self.tun_snapshot() != current or not owner.same(core):
                    raise Error('The Mihomo TUN changed before ownership could be marked.')
                self.run(['/sbin/ifconfig', 'tun_mihomo', 'description', receipt['description']])
            verified = self.tun_snapshot()
            if (verified is None or any(verified.get(key) != receipt[key] for key in (*stable, 'description'))
                    or verified['opened_by'] != core['pid'] or not owner.same(core)):
                raise Error('The Mihomo TUN ownership marker could not be verified.')
            receipt['phase'] = 'owned'
            receipt.pop('preclaim')
            self._write_tun_receipt(receipt)

    def destroy_owned_tun(self, prepare=None):
        with self._tun_lock():
            receipt = self._tun_receipt()
            current = self.tun_snapshot()
            if current is None:
                if receipt is not None:
                    self._clear_tun_receipt()
                return False, None
            if receipt is None:
                raise Error('An unowned interface named tun_mihomo was preserved.')
            stable = ('name', 'index', 'driver', 'metric', 'mtu')
            exact = all(current.get(key) == receipt[key] for key in stable)
            preclaim = receipt.get('preclaim', {})
            marked = current.get('description') == receipt['description']
            unmarked = receipt['phase'] == 'claiming' and current.get('description') == preclaim.get('description')
            if not exact or not (marked or unmarked) or not current['closed']:
                raise Error('The Mihomo TUN is open or its ownership changed; the interface was preserved.')
            if self.tun_snapshot() != current:
                raise Error('The Mihomo TUN changed during cleanup; the interface was preserved.')
            prepared, preparation_error = None, None
            if prepare is not None:
                try:
                    prepared = prepare()
                except (Error, OSError) as error:
                    # DNS proof and TUN ownership are independent. Once the
                    # exact closed interface is known, a damaged DNS receipt
                    # must not retain routes or a stale plugin TUN.
                    preparation_error = error
            if self.tun_snapshot() != current:
                raise Error('The Mihomo TUN changed while cleanup was prepared; the interface was preserved.')
            result = self.run(['/sbin/ifconfig', 'tun_mihomo', 'destroy'], check=False)
            if result.returncode and self.tun_snapshot() is not None:
                raise Error('Owned Mihomo TUN destruction failed and will be retried.')
            self._clear_tun_receipt()
            if preparation_error is not None:
                raise preparation_error
            return True, prepared

    def start(self, config, transparent):
        data = parse_yaml(Path(config).read_bytes())
        needs_dns = data.get('dns', {}).get('enable') and data.get('dns', {}).get('listen') == '127.0.0.1:1053'
        if transparent and self.run(["/usr/sbin/service", "sing-box", "onestatus"], check=False).returncode == 0:
            raise Error("Sing-box already owns transparent routing.")
        if self.running():
            raise Error("Mihomo is already running; an existing process must be stopped before starting another.")
        self.recover_reloads()
        self.destroy_tun()
        self.run(["/usr/sbin/daemon", "-P", DAEMON_PID, "-p", PID, "-f", "-o", "/var/log/mihomo.log",
                  "-t", "mihomo", "/usr/local/bin/mihomo", "-d", HOME, "-f", str(config)])
        owner = self._core_group(config)
        try:
            process_record = self._ownership(owner.record_started)
        except Error:
            with contextlib.suppress(Error):
                self._ownership(owner.stop)
            raise
        tun_claimed = False
        for _ in range(30):
            if self.running():
                port = data.get('mixed-port') or data.get('socks-port') or data.get('port')
                if port:
                    bind = data.get('bind-address', '127.0.0.1')
                    bind = '127.0.0.1' if bind in {'*', '0.0.0.0', '::'} else bind.strip('[]')
                    try:
                        with socket.create_connection((bind, port), timeout=0.5):
                            pass
                    except OSError:
                        time.sleep(0.5)
                        continue
                if transparent:
                    interface = self.run(['/sbin/ifconfig', 'tun_mihomo'], check=False)
                    present = interface.returncode == 0
                    if not present:
                        time.sleep(0.5)
                        continue
                    # FreeBSD clears TUN addresses as soon as the last core
                    # descriptor closes. Capture local ownership while the
                    # ready core still exposes its configured addresses.
                    try:
                        if not tun_claimed:
                            self.claim_tun(process_record)
                            tun_claimed = True
                        self._host_dns_prepare(interface.stdout)
                    except (Error, OSError):
                        self.stop()
                        raise
                if not needs_dns:
                    return
                try:
                    with socket.create_connection(("127.0.0.1", 1053), timeout=0.5):
                        return
                except OSError:
                    pass
            time.sleep(0.5)
        self.stop()
        raise Error("Mihomo did not become ready.")

    def stop(self):
        routing_error = None
        try:
            self.routing('disable')
        except (Error, OSError) as error:
            routing_error = error
        self._ownership(self._core_group().stop)
        self.destroy_tun()
        if routing_error is not None:
            raise routing_error

    def destroy_tun(self):
        routing_error = None
        try:
            self.routing('disable')
        except (Error, OSError) as error:
            routing_error = error
        interface = self.run(["/sbin/ifconfig", "tun_mihomo"], check=False)
        recovery = None
        stopped = not self.running()
        if interface.returncode == 0:
            # Ownership is checked before DNS proof is written and again before
            # destruction. An operator's same-name TUN is left untouched.
            _, recovery = self.destroy_owned_tun(
                lambda: self._host_dns_prepare(interface.stdout)) if stopped \
                else self.destroy_owned_tun()
        else:
            self.destroy_owned_tun()
            if stopped:
                recovery = self._host_dns_prepare(b'')
        if recovery is not None:
            self._host_dns_recover(recovery)
        if routing_error is not None:
            raise routing_error

    @staticmethod
    def _host_dns_paths():
        return (Path('/etc/resolv.conf'), Path('/conf/config.xml'),
                Path('/etc/resolv.conf.local'), Path(STATE) / 'host-dns-reload-pending')

    @staticmethod
    def _host_dns_read(path, private=False, limit=65536):
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            return None
        with os.fdopen(descriptor, 'rb') as stream:
            before = os.fstat(stream.fileno())
            if (not stat.S_ISREG(before.st_mode) or before.st_size > limit or
                    (private and (before.st_uid != 0 or stat.S_IMODE(before.st_mode) != 0o600))):
                raise Error('The pending host DNS recovery file is invalid.')
            content = stream.read(limit + 1)
            after = os.fstat(stream.fileno())
        if len(content) > limit or any(getattr(before, field) != getattr(after, field) for field in
                ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')):
            raise Error('The host DNS configuration changed while it was read.')
        return content

    @staticmethod
    def _host_dns_servers(content):
        # This exact format is written by the bundled sing-tun FreeBSD core.
        try:
            lines = content.decode('ascii').splitlines()
            if not 2 <= len(lines) <= 3 or lines[0] != 'search localdomain':
                return None
            servers = [str(ipaddress.ip_address(line.removeprefix('nameserver '))) for line in lines[1:]]
            canonical = ('search localdomain\n' + ''.join('nameserver ' + server + '\n' for server in servers)).encode()
            if content != canonical or len({ipaddress.ip_address(server).version for server in servers}) != len(servers):
                return None
            return servers
        except (UnicodeError, ValueError, AttributeError):
            return None

    def _host_dns_core_stopped(self):
        return not self.running()

    def _host_dns_operator_owned(self, servers):
        _, config, local, _ = self._host_dns_paths()
        try:
            root = ElementTree.fromstring(self._host_dns_read(config, limit=MAX_CONFIG) or b'')
            explicit = [node.text or '' for node in root.findall('./system/dnsserver')]
            for line in (self._host_dns_read(local) or b'').decode().splitlines():
                tokens = line.partition('#')[0].split()
                if len(tokens) >= 2 and tokens[0] == 'nameserver':
                    explicit.append(tokens[1])
            for value in explicit:
                with contextlib.suppress(ValueError):
                    if str(ipaddress.ip_address(value.strip())) in servers:
                        return True
            return False
        except (OSError, Error, ElementTree.ParseError, UnicodeError):
            # Without the native configuration, ownership cannot be established.
            return True

    def _host_dns_forget(self, record):
        pending = self._host_dns_paths()[3]
        if self._host_dns_read(pending, private=True, limit=4096) == record:
            pending.unlink(missing_ok=True)

    def _host_dns_prepare(self, interface):
        resolver, _, _, pending = self._host_dns_paths()
        content = self._host_dns_read(resolver)
        servers = self._host_dns_servers(content)
        record = self._host_dns_read(pending, private=True, limit=4096)
        if record is not None:
            try:
                saved = json.loads(record)
                if (not isinstance(saved, dict) or set(saved) != {'servers', 'checksum'} or
                        not isinstance(saved['servers'], list) or
                        not isinstance(saved['checksum'], str) or not re.fullmatch('[a-f0-9]{64}', saved['checksum'])):
                    raise ValueError()
                expected = ('search localdomain\n' + ''.join('nameserver ' + value + '\n' for value in saved['servers'])).encode()
                if self._host_dns_servers(expected) != saved['servers']:
                    raise ValueError()
            except (ValueError, TypeError, KeyError):
                raise Error('The pending host DNS recovery file is invalid.') from None
            if (servers != saved['servers'] or content is None or
                    hashlib.sha256(content).hexdigest() != saved['checksum'] or self._host_dns_operator_owned(servers)):
                self._host_dns_forget(record)
                # A later core can have used a different TUN address. A live
                # interface supplies fresh ownership; an absent one does not.
            else:
                return record
        expected = set()
        for value in re.findall(rb'^\s+inet6?\s+([0-9a-fA-F:.]+)(?:%\S+)?\s', interface, re.MULTILINE):
            with contextlib.suppress(ValueError):
                expected.add(str(ipaddress.ip_address(value.decode()) + 1))
        if not servers or not set(servers).issubset(expected) or self._host_dns_operator_owned(servers):
            return None
        record = json.dumps({'servers': servers, 'checksum': hashlib.sha256(content).hexdigest()}, sort_keys=True).encode() + b'\n'
        # This local retry marker is never part of the XML configuration archive.
        atomic_write(pending, record)
        return record

    def _host_dns_recover(self, record):
        if not self._host_dns_core_stopped():
            return
        # Destroying the interface or a concurrent operator edit can change DNS.
        # Recheck both native ownership and the fingerprint before regenerating.
        if self._host_dns_prepare(b'') != record:
            return
        self.run(['/usr/local/sbin/configctl', 'dns', 'reload'], timeout=90)
        if hashlib.sha256(self._host_dns_read(self._host_dns_paths()[0]) or b'').hexdigest() == json.loads(record)['checksum']:
            raise Error('Host DNS recovery did not regenerate the resolver configuration and will be retried.')
        self._host_dns_forget(record)

    def resolver_running(self):
        return self.run(["/usr/bin/pgrep", "-q", "-x", "unbound"], check=False).returncode == 0

    @staticmethod
    def anchor_snapshot():
        """The DNSSEC root anchor as it stands, if it is one we could put back.

        Only the managed format is worth keeping: a file Unbound wrote itself,
        carrying the key states it maintains. Anything else is already the
        damaged shape described in restore_anchor(), and restoring it would
        only reinstate the damage.
        """
        try:
            content = Path(ROOT_ANCHOR).read_bytes()
        except OSError:
            return None
        return content if content.startswith(b"; autotrust") else None

    @staticmethod
    def restore_anchor(anchor):
        """Put the operator's DNSSEC root anchor back after a failed restart.

        OPNsense's Unbound start script treats a configuration it cannot check
        as a damaged anchor: it deletes root.key and has unbound-anchor fetch a
        new one. That fetch needs a working resolver, which during a DNS change
        is the one thing missing, so unbound-anchor falls back to writing the
        two root DS records in its plain format. auto-trust-anchor-file cannot
        read that -- it reports the anchor for '.' presented twice, the
        validator fails to initialise, and the resolver never starts again, so
        a restart that merely failed becomes a router with no DNS at all.
        Writing the original file back makes the failure a transient one.
        """
        atomic_write(Path(ROOT_ANCHOR), anchor, mode=0o644)
        with contextlib.suppress(OSError, KeyError):
            entry = pwd.getpwnam("unbound")
            os.chown(ROOT_ANCHOR, entry.pw_uid, entry.pw_gid)

    def repair_resolver(self, anchor):
        """Bring the resolver back if it refused to start, and say why it did."""
        if self.resolver_running():
            return
        if anchor is not None:
            self.restore_anchor(anchor)
        self.run(["/usr/local/sbin/configctl", "unbound", "restart"], timeout=90)
        if not self.resolver_running():
            raise Error("The resolver did not come back. No DNS change was left in place.")

    def forwarded(self):
        """Whether the file Unbound actually reads sends queries to Mihomo."""
        try:
            return FORWARDER in Path(UNBOUND_GENERATED).read_text()
        except OSError:
            return False

    def unbound_template_targets(self):
        """Every file a reload of the Unbound templates is able to write.

        Only two of them land in the chroot. The rest are written outside it and
        reach the resolver when the restart copies them in, so the chroot on its
        own cannot say whether the reload changed the policy Unbound is about to
        serve -- an operator who replaces the DNS over TLS upstreams and saves
        without applying changes dot.conf and nothing else. The engine keeps the
        mapping in +TARGETS beside the templates; read it rather than repeating
        a list here, because a firmware update extends it without asking us.
        """
        containers = sorted(Path(UNBOUND_TEMPLATE_ROOT).glob('*/+TARGETS'))
        if not containers:
            return None
        targets = []
        for container in containers:
            for line in container.read_text().splitlines():
                entry = line.strip()
                if not entry or entry.startswith('#'):
                    continue
                target = entry.partition(':')[2].strip()
                # A '[...]' placeholder expands once per model node, so the set
                # of files behind such a mapping is not knowable from it alone.
                if (not target or not Path(target).is_absolute()
                        or any(char in target for char in '[]*?')):
                    return None
                targets.append(Path(target))
        return targets

    def unbound_render_snapshot(self):
        """Compare everything a template reload can write before avoiding a restart."""
        root = Path(UNBOUND_CONFIG_ROOT)
        try:
            main = root / 'unbound.conf'
            if not main.is_file():
                return None
            targets = self.unbound_template_targets()
            if targets is None:
                return None
            files = sorted(root.rglob('*.conf'))
            if len(files) + len(targets) > 4096:
                return None
            # The chroot is walked by the path Unbound reads and every remaining
            # target by the path the engine writes to, so the two never collide.
            inside = {os.path.realpath(filename) for filename in files}
            entries = [(filename.relative_to(root).as_posix(), filename, True) for filename in files]
            entries += [(target.as_posix(), target, False) for target in targets
                        if os.path.realpath(target) not in inside]
            digest = hashlib.sha256()
            total = 0
            for name, filename, chrooted in entries:
                try:
                    with filename.open('rb') as handle:
                        data = handle.read(MAX_CONFIG - total + 1)
                except FileNotFoundError:
                    # A target the configuration does not need yet is simply
                    # absent; its appearance is itself a change worth a restart.
                    if chrooted:
                        return None
                    data = None
                if data is not None:
                    total += len(data)
                    if total > MAX_CONFIG:
                        return None
                if chrooted:
                    for line in data.decode('utf-8').splitlines():
                        if re.match(r'^\s*include(?:-toplevel)?\s*:', line):
                            parts = shlex.split(line, comments=True)
                            if len(parts) != 2 or parts[0] not in ('include:', 'include-toplevel:'):
                                return None
                            include = Path(parts[1])
                            if (not include.is_absolute() or include.suffix != '.conf'
                                    or not include.parent.resolve().is_relative_to(root.resolve())
                                    or (include.name != '*.conf' and not include.is_file())):
                                return None
                name = name.encode()
                digest.update(len(name).to_bytes(4, 'big'))
                digest.update(name)
                digest.update(b'\x00' if data is None else b'\x01')
                if data is not None:
                    digest.update(len(data).to_bytes(8, 'big'))
                    digest.update(data)
            return digest.digest()
        except (OSError, ValueError, UnicodeError):
            return None

    def dns(self, enabled, settings, recovery_only=False):
        pending = Path(STATE) / "dns-reload-pending"
        was_pending = pending.exists()
        atomic_write(pending, b"pending\n")
        mode = 'rescue' if recovery_only else 'enable' if enabled else 'disable'
        result = self.run(["/usr/local/bin/php", HELPER, mode,
                  "1" if settings["dns_fallback"] else "0"], timeout=90)
        integration = integration_state(result.stdout)
        expected_forwarding = integration['effective_forwarding']
        # "unchanged" reports that the configuration already said this. It says
        # nothing about the file Unbound reads, which is generated from that
        # configuration separately and can still describe the previous state --
        # a stale one pointing at a stopped core leaves the network without DNS.
        # DNSSEC can leave the effective forwarder disabled even when transparent
        # DNS was requested. Older helpers keep the conservative intent check.
        if (not integration['integration_changed'] and not was_pending
                and self.forwarded() == expected_forwarding):
            pending.unlink(missing_ok=True)
            return
        integration_only = bool(not integration['dns_changed']
            and integration['integration_changed'] and not was_pending
            and self.forwarded() == expected_forwarding)
        previous_render = self.unbound_render_snapshot() if integration_only else None
        # The Unbound templates live in sub-containers, so the bare name matches
        # nothing: it generates no file and answers ERR. Without the wildcard the
        # configuration Unbound is about to be checked against is never rewritten.
        self.run(["/usr/local/sbin/configctl", "template", "reload", "OPNsense/Unbound/*"], timeout=90)
        if (integration_only and previous_render is not None
                and previous_render == self.unbound_render_snapshot() and self.resolver_running()):
            if integration['filter_changed']:
                self.run(["/usr/local/sbin/configctl", "filter", "reload"], timeout=90)
            pending.unlink(missing_ok=True)
            return
        # Taken before the restart, because the restart is what can destroy it:
        # OPNsense's start script re-fetches the root anchor whenever
        # unbound-checkconf is unhappy, and a fetch made while DNS is being
        # changed has nothing to ask. See restore_anchor().
        anchor = self.anchor_snapshot()
        actions = [["unbound", "restart"], ["unbound", "cache", "flush"]]
        # Interface/rule XML is independent of resolver XML. Avoid disrupting
        # all firewall states when this operation changed only DNS; a retry
        # remains conservative because the older pending marker predates the
        # helper's exact decision.
        if integration['filter_changed'] or was_pending:
            actions.append(["filter", "reload"])
        for args in actions:
            self.run(["/usr/local/sbin/configctl", *args], timeout=90)
        self.repair_resolver(anchor)
        pending.unlink(missing_ok=True)

    def remove(self):
        filter_pending = Path(STATE) / 'filter-reload-pending.json'
        cron_pending = Path(STATE) / 'cron-reload-pending.json'
        retry_filter = reload_receipt(filter_pending, {'enable-tun', 'remove'}) is not None
        retry_cron = reload_receipt(cron_pending, {'remove', 'restore-cron'}) is not None
        atomic_write(filter_pending, b'{"action":"remove","version":1}\n')
        atomic_write(cron_pending, b'{"action":"remove","version":1}\n')
        result = self.run(["/usr/local/bin/php", HELPER, "remove"], timeout=90)
        integration = integration_state(result.stdout)
        if retry_filter or integration['filter_changed']:
            self.run(["/usr/local/sbin/configctl", "filter", "reload"], timeout=90)
        filter_pending.unlink(missing_ok=True)
        if retry_cron or integration['cron_changed']:
            self.run(["/usr/local/sbin/configctl", "cron", "restart"], timeout=90)
        cron_pending.unlink(missing_ok=True)

    def restore_cron(self):
        pending = Path(STATE) / 'cron-reload-pending.json'
        retry = reload_receipt(pending, {'remove', 'restore-cron'}) is not None
        atomic_write(pending, b'{"action":"restore-cron","version":1}\n')
        result = self.run(['/usr/local/bin/php', HELPER, 'restore-cron'], timeout=90)
        integration = integration_state(result.stdout)
        if retry or integration['cron_changed']:
            self.run(['/usr/local/sbin/configctl', 'cron', 'restart'], timeout=90)
        pending.unlink(missing_ok=True)

    def tun(self):
        pending = Path(STATE) / 'filter-reload-pending.json'
        retry = reload_receipt(pending, {'enable-tun', 'remove'}) is not None
        atomic_write(pending, b'{"action":"enable-tun","version":1}\n')
        result = self.run(['/usr/local/bin/php', HELPER, 'enable-tun'], timeout=90)
        integration = integration_state(result.stdout)
        context = Path(STATE) / 'routing-context.json'
        missing_context = context.is_symlink() or not context.is_file()
        if retry or integration['filter_changed'] or missing_context:
            self.run(['/usr/local/sbin/configctl', 'filter', 'reload'], timeout=90)
        pending.unlink(missing_ok=True)
        self.routing('enable')

    def restore_integration(self, settings, payload):
        # Early boot restores only configuration; normal boot starts services.
        atomic_write(Path(STATE) / 'dns-reload-pending', b'pending\n')
        self.run(['/usr/local/bin/php', HELPER, 'restore-backup',
                  '1' if settings['dns_fallback'] else '0'],
                 input=json.dumps(payload, ensure_ascii=True).encode(), timeout=90)

    def rescue(self, settings):
        # Pending XML cannot be paired with the older local ownership journals.
        self.dns(False, settings, recovery_only=True)

    def check_router_dns(self):
        import struct
        query = struct.pack('!HHHHHH', 0x4d48, 0x100, 1, 0, 0, 0) + b'\x09localhost\x00\x00\x01\x00\x01'
        try:
            with socket.create_connection(('127.0.0.1', 53), timeout=3) as client:
                client.sendall(struct.pack('!H', len(query)) + query)
                length = client.recv(2)
                if len(length) != 2:
                    raise ValueError
                response = b''
                size = struct.unpack('!H', length)[0]
                while len(response) < size:
                    part = client.recv(size - len(response))
                    if not part:
                        raise ValueError
                    response += part
                if len(response) < 12 or response[:2] != query[:2] or response[3] & 15:
                    raise ValueError
        except (OSError, ValueError):
            raise Error('The router DNS resolver did not answer successfully. No provider DNS fallback is used.') from None

    def watch(self):
        owner = self._watch_group()
        if not self._ownership(owner.running):
            self.run(["/usr/sbin/daemon", "-P", WATCH_PID, "-p", WATCH_CHILD_PID, "-f", "-o", "/var/log/mihomo.log",
                      "-t", "mihomo-watch", "/usr/local/bin/python3", SCRIPT, "watch"])
            try:
                self._ownership(owner.record_started)
            except Error:
                with contextlib.suppress(Error):
                    self._ownership(owner.stop)
                raise

    def stop_watch(self):
        self._ownership(self._watch_group().stop)


def fetch_subscription(url, user_agent, proxy="127.0.0.1:7891", run=subprocess.run, sleep=time.sleep):
    try:
        from urllib.parse import urlsplit
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError
    except ValueError:
        raise Error("A valid HTTP or HTTPS subscription URL is required.") from None
    if any(char in url + user_agent for char in "\r\n\x00"):
        raise Error("The URL and User-Agent must not contain control characters.")
    with tempfile.TemporaryDirectory(prefix="mihomo-fetch-") as directory:
        output = Path(directory) / "subscription.yaml"
        curl_config = Path(directory) / "curl.conf"
        escaped = url.replace("\\", "\\\\").replace('"', '\\"')
        atomic_write(curl_config, ('url = "' + escaped + '"\n').encode())
        routes = [None] + ([proxy] if proxy else [])
        for route in routes:
            for attempt in range(2):
                args = ["/usr/local/bin/curl", "--disable", "--config", str(curl_config), "--silent",
                        "--location", "--max-redirs", "3", "--proto", "=http,https", "--proto-redir", "=https",
                        "--connect-timeout", "10", "--max-time", "30", "--max-filesize", str(MAX_CONFIG),
                        "--user-agent", user_agent, "--output", str(output), "--write-out", "%{http_code}"]
                if route:
                    args += ["--socks5-hostname", route]
                else:
                    args += ["--noproxy", "*"]
                try:
                    response = run(args, capture_output=True, timeout=35)
                except subprocess.TimeoutExpired:
                    response = subprocess.CompletedProcess(args, 28, b"000", b"")
                except OSError:
                    raise Error("Curl is unavailable.") from None
                status = response.stdout.decode(errors="replace").strip()
                if status.isdigit() and 400 <= int(status) < 500:
                    raise Error("The subscription returned HTTP " + status + ". No retry or proxy fallback was attempted.")
                if response.returncode == 0 and status == "200":
                    content = output.read_bytes()
                    if not content:
                        raise Error("The subscription response is empty.")
                    return content
                retryable = response.returncode == 28 or (status.isdigit() and 500 <= int(status) <= 599)
                if not retryable:
                    raise Error("The subscription request failed. Check its URL, TLS certificate, and network.")
                if attempt == 0:
                    sleep(1)
    raise Error("The subscription could not be fetched after bounded timeout/server-error retries.")


class Manager:
    def __init__(self, root=Path("/"), system=None, backup_transport=None, proxy_api=None):
        self.root = Path(root)
        self.system = system or System()
        self.state = self.path(STATE)
        self.settings_file = self.state / "settings.json"
        self.source_file = self.state / "subscription.yaml"
        self.config_file = self.state / "config.yaml"
        self.merge_file = self.state / 'merge.yaml'
        self.warnings_file = self.state / 'warnings.json'
        self.status_file = self.path("/var/run/mihomo-status.json")
        self.backup_marker = self.state / 'backup-applied.sha256'
        self.backup_warning_file = self.state / 'backup-warning'
        self.selections_file = self.state / 'proxy-selections.json'
        self.replay_file = self.state / 'proxy-replay-pending'
        self.proxy_warning_file = self.state / 'proxy-backup-warning'
        self.backup_transport = backup_transport or self._backup_transport
        self.proxy_api = proxy_api or self._proxy_api
        self._lock_depth = 0

    def path(self, path):
        return self.root / path.lstrip("/")

    @contextlib.contextmanager
    def lock(self, blocking=True):
        if self._lock_depth:
            yield
            return
        path = self.path("/var/run/os-mihomo.lock")
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a") as stream:
            os.chmod(path, 0o600)
            try:
                fcntl.flock(stream, fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB))
            except BlockingIOError:
                raise Error("Another Mihomo operation is in progress.") from None
            self._lock_depth += 1
            try:
                yield
            finally:
                self._lock_depth -= 1

    def _backup_read(self, path):
        for parent in [path, *path.parents]:
            if parent == self.root.parent:
                break
            if parent.is_symlink():
                raise Error('A Mihomo backup path traverses a symbolic link.')
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            return None
        with os.fdopen(descriptor, 'rb') as handle:
            before = os.fstat(handle.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_CONFIG:
                raise Error('A Mihomo backup file exceeds its supported size or type.')
            content = handle.read(MAX_CONFIG + 1)
            after = os.fstat(handle.fileno())
        if len(content) > MAX_CONFIG or (before.st_dev, before.st_ino, before.st_size,
                before.st_mtime_ns, before.st_ctime_ns) != (after.st_dev, after.st_ino,
                after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise Error('The Mihomo configuration changed while its backup was read.')
        return content

    def _backup_transport(self, action, payload=None):
        helper = self.path(MIRROR_HELPER)
        # Existing isolated backend fixtures never bootstrap the host's XML.
        if self.root != Path('/') and not helper.exists():
            return {} if action == 'import' else {'changed': False}
        try:
            answer = subprocess.run(['/usr/local/bin/php', str(helper), action],
                input=json.dumps(payload, ensure_ascii=True).encode() if payload is not None else None,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=60, check=False)
            if answer.returncode or len(answer.stdout) > MAX_BACKUP:
                raise ValueError()
            decoded = json.loads(answer.stdout)
            if not isinstance(decoded, dict):
                raise ValueError()
            return decoded
        except (OSError, ValueError, subprocess.SubprocessError):
            raise Error('The native Mihomo configuration backup operation failed.') from None

    @staticmethod
    def _backup_checksum(payload):
        fields = {key: value for key, value in payload.items() if key != 'checksum'}
        if any(not isinstance(key, str) or not isinstance(value, str) for key, value in fields.items()):
            raise Error('The stored Mihomo configuration backup is invalid.')
        content = json.dumps(fields, ensure_ascii=True, sort_keys=True, separators=(',', ':')).encode()
        if len(content) > MAX_BACKUP:
            raise Error('The stored Mihomo configuration backup exceeds its size limit.')
        return hashlib.sha256(content).hexdigest()

    def _stored_backup(self, verify=True):
        stored = self.backup_transport('import')
        if not isinstance(stored, dict):
            raise Error('The stored Mihomo configuration backup is invalid.')
        checksum = self._backup_checksum(stored)
        if 'checksum' in stored and not isinstance(stored['checksum'], str):
            raise Error('The stored Mihomo configuration backup is invalid.')
        if verify and stored.get('checksum') and stored['checksum'] != checksum:
            raise BackupIntegrityError(BACKUP_INTEGRITY_WARNING)
        return stored, checksum

    @staticmethod
    def _backup_revision(stored):
        return hashlib.sha256(json.dumps(stored, ensure_ascii=True, sort_keys=True,
                              separators=(',', ':')).encode()).hexdigest()

    def _guard_backup(self):
        stored, checksum = self._stored_backup()
        marker = self._backup_read(self.backup_marker)
        if stored and (marker or b'').strip() != checksum.encode():
            raise Error('A restored Mihomo configuration is pending. Stop the service and restore it or reboot before saving.')
        return stored

    def _preset_path(self, name):
        if name not in ('full.yaml', 'tun-only.yaml', 'proxy-only.yaml'):
            raise Error('The stored Mihomo merge preset is invalid.')
        path = self.path(SHARE + '/presets/' + name)
        return path if path.exists() else Path(__file__).resolve().parents[3] / 'share/mihomo/presets' / name

    def _consent_scope(self):
        xml = self._backup_read(self.path('/conf/config.xml'))
        if xml:
            with contextlib.suppress(ElementTree.ParseError):
                doc = ElementTree.fromstring(xml)
                identity = [doc.findtext('./system/' + name, '') for name in ('uuid', 'hostname', 'domain')]
                if any(identity):
                    return hashlib.sha256('|'.join(identity).encode()).hexdigest()
        return ''

    def _mirror_payload(self):
        settings = self.settings()
        payload = {key: json.dumps(settings[key], ensure_ascii=True, separators=(',', ':'))
                   for key in BACKUP_KEYS if key in settings}
        merge = self._backup_read(self.merge_file) or b'{}\n'
        payload['merge_yaml'] = json.dumps(merge.decode('utf-8'), ensure_ascii=True)
        payload['merge_preset'] = ''
        actual = parse_yaml(merge)
        for name in ('full.yaml', 'tun-only.yaml', 'proxy-only.yaml'):
            preset = parse_yaml(self._preset_path(name).read_bytes())
            absorb_switches(preset, settings)
            if actual == preset:
                payload['merge_preset'] = name
                break
        source = self._backup_read(self.source_file)
        payload['subscription_snapshot'] = base64.b64encode(gzip.compress(source, mtime=0)).decode() if source is not None else ''
        data = parse_yaml(source) if source is not None else {}
        local = []
        for path in self._reference_paths(data, actual):
            value = self._backup_read(self.path(path))
            local.append({'path': path, 'data': base64.b64encode(value).decode() if value is not None else None,
                          'mode': stat.S_IMODE(self.path(path).stat().st_mode) if value is not None else 0o600})
        raw = json.dumps({'version': 1, 'files': local}, sort_keys=True, separators=(',', ':')).encode()
        if len(raw) > MAX_CONFIG:
            raise Error('Referenced Mihomo configuration exceeds its backup size limit.')
        payload['local_files'] = base64.b64encode(gzip.compress(raw, mtime=0)).decode()
        payload['proxy_selections'] = (self._backup_read(self.selections_file) or b'{}').decode('utf-8')
        for field, filename in [('dns_state', 'dns-state.json'), ('tun_state', 'tun-state.json')]:
            value = self._backup_read(self.state / filename)
            payload[field] = json.dumps(value.decode('utf-8'), ensure_ascii=True) if value is not None else ''
        payload['consent_scope'] = self._consent_scope()
        payload['checksum'] = self._backup_checksum(payload)
        return payload

    def mirror_backup(self):
        with self.lock():
            try:
                stored = self._guard_backup()
                payload = {**stored, **self._mirror_payload()}
                payload['checksum'] = self._backup_checksum(payload)
                answer = self.backup_transport('export', {**payload, '_expected': self._backup_revision(stored)})
                if not isinstance(answer, dict):
                    raise ValueError()
                atomic_write(self.backup_marker, (payload['checksum'] + '\n').encode())
                self.backup_warning_file.unlink(missing_ok=True)
                if self.proxy_warning_file.exists():
                    raise Error(BACKUP_WARNING)
                return {'ok': True, 'changed': bool(answer.get('changed'))}
            except (Error, OSError, ValueError, TypeError, UnicodeError) as error:
                warning = BACKUP_INTEGRITY_WARNING if isinstance(error, BackupIntegrityError) else BACKUP_WARNING
                with contextlib.suppress(OSError):
                    atomic_write(self.backup_warning_file, warning.encode())
                return {'ok': False, 'warning': warning}

    def _mirrored_result(self, result):
        report = self.mirror_backup()
        if not report['ok']:
            result['warning'] = report['warning']
        with contextlib.suppress(Error, OSError, ValueError):
            status = json.loads(self.status_file.read_bytes()) if self.status_file.exists() else {}
            self.publish_status(dns_active=bool(status.get('dns_active')), error=status.get('error', ''))
        return result

    @staticmethod
    def _backup_text(value):
        try:
            decoded = json.loads(value)
            return decoded if isinstance(decoded, str) else value
        except ValueError:
            return value

    @staticmethod
    def _selection_map(value):
        mapping = json.loads(value)
        if (not isinstance(mapping, dict) or len(mapping) > 512 or any(
                not isinstance(key, str) or not isinstance(choice, str) or not key or
                len(key) > 4096 or len(choice) > 4096 for key, choice in mapping.items())):
            raise Error('The stored Mihomo proxy selections are invalid.')
        return mapping

    @staticmethod
    def _journal(field, raw):
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise Error('The stored Mihomo ownership journal is invalid.')
        if field == 'dns_state':
            if (str(value.get('forwarding')) not in ('0', '1') or
                    type(value.get('had_fake_ip_private_address')) is not bool or
                    ('removed_fake_ip_private_address' in value and
                     type(value['removed_fake_ip_private_address']) is not bool) or
                    not isinstance(value.get('roots'), dict) or len(value['roots']) > 512 or any(
                        not re.fullmatch(r'[A-Za-z0-9-]{1,128}', key) or str(enabled) not in ('0', '1')
                        for key, enabled in value['roots'].items())):
                raise Error('The stored Mihomo ownership journal is invalid.')
        elif (not re.fullmatch(r'opt[0-9]{1,8}', value.get('interface', '')) or
              type(value.get('created_interface')) is not bool or type(value.get('created_rule')) is not bool):
            raise Error('The stored Mihomo ownership journal is invalid.')
        return raw

    def _reference_paths(self, data, overlay):
        merged = merge_yaml(data, overlay)
        paths = set()
        for field in ('proxy-providers', 'rule-providers'):
            providers = merged.get(field, {})
            if not isinstance(providers, dict):
                raise Error('The Mihomo provider configuration is invalid.')
            for provider in providers.values():
                if not isinstance(provider, dict) or provider.get('type') != 'file':
                    continue
                value = provider.get('path')
                if not isinstance(value, str) or not value or any(ord(c) < 32 for c in value):
                    raise Error('A local Mihomo provider has an unsupported configuration path.')
                path = os.path.normpath(value if value.startswith('/') else HOME + '/' + value)
                forbidden = ('/conf', '/dev', '/proc', '/boot', '/bin', '/sbin', '/usr/bin',
                    '/usr/sbin', '/usr/lib', '/usr/local/bin', '/usr/local/sbin', '/usr/local/lib',
                    '/usr/local/opnsense', '/etc/ssh', '/usr/local/etc/pkg', '/root/.ssh')
                critical = {'/', '/etc', '/usr', '/usr/local', '/usr/local/etc', '/var', '/var/db',
                    '/var/run', '/var/log', '/root', '/home', '/tmp', '/etc/passwd',
                    '/etc/master.passwd', '/etc/group', '/etc/rc', '/etc/rc.conf', '/etc/fstab'}
                if (path.startswith('//') or path in critical or path in (STATE, HOME, HOME + '/cache.db') or
                        any(path == root or path.startswith(root + '/') for root in forbidden) or
                        (path.startswith(STATE + '/') and not path.startswith(HOME + '/'))):
                    raise Error('A local Mihomo provider references a protected configuration path.')
                paths.add(path)
        if len(paths) > 512:
            raise Error('There are too many local Mihomo provider files to back up.')
        return sorted(paths)

    def _reference_restore(self, stored, data, overlay):
        paths = self._reference_paths(data, overlay)
        if 'local_files' not in stored:
            if paths:
                raise Error('The saved Mihomo backup is missing local provider files.')
            return {}
        compressed = base64.b64decode(stored['local_files'], validate=True)
        with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as handle:
            raw = handle.read(MAX_CONFIG + 1)
        if len(raw) > MAX_CONFIG:
            raise ValueError()
        document = json.loads(raw)
        if (not isinstance(document, dict) or document.get('version') != 1 or
                not isinstance(document.get('files'), list) or len(document['files']) > 512 or
                any(not isinstance(entry, dict) or set(entry) != {'path', 'data', 'mode'}
                    or not isinstance(entry['path'], str) or
                    (entry['data'] is not None and not isinstance(entry['data'], str))
                    for entry in document['files']) or [e['path'] for e in document['files']] != paths):
            raise ValueError()
        restored = {}
        for entry in document['files']:
            if type(entry['mode']) is not int or not 0 <= entry['mode'] <= 0o777:
                raise ValueError()
            content = base64.b64decode(entry['data'], validate=True) if entry['data'] is not None else None
            if content is not None and len(content) > MAX_CONFIG:
                raise ValueError()
            restored[self.path(entry['path'])] = (content, entry['mode'])
        return restored

    def restore_backup(self, force=False, repair=False):
        with self.lock():
            stored, checksum = self._stored_backup(verify=not repair)
            if not stored:
                return {'restored': False, 'snapshot': False}
            if not force and (self._backup_read(self.backup_marker) or b'').strip() == checksum.encode():
                return {'restored': False, 'snapshot': True}
            if self.system.running():
                raise Error('Stop Mihomo before restoring its configuration backup.')
            try:
                settings = {
                    'subscription_url': '', 'secret': secrets.token_hex(32), 'device': 'router',
                    'transparent': False, 'transparent_consent': False, 'service_enabled': True,
                    'dns_fallback': True, **SWITCH_DEFAULTS}
                with contextlib.suppress(Error):
                    if self.settings_file.exists():
                        settings = self.settings()
                for field in BACKUP_KEYS:
                    if field not in stored or stored[field] == '':
                        continue
                    fallback = settings.get(field, [] if field in (*DNS_SERVER_FIELDS, 'device_list') else
                                            'off' if field == 'device_mode' else LOOPBACK_CONTROLLER)
                    decoded = json.loads(stored[field]) if not isinstance(fallback, str) else self._backup_text(stored[field])
                    if isinstance(fallback, bool) and type(decoded) is int and decoded in (0, 1):
                        decoded = bool(decoded)
                    if type(decoded) is not type(fallback):
                        raise ValueError()
                    settings[field] = decoded
                settings.update(transparent=False, transparent_consent=False,
                                state_schema=STATE_SCHEMA, switch_schema=SWITCH_SCHEMA)
                self.check_settings(settings)
                pending = {self.settings_file: (json.dumps(settings, indent=2) + '\n').encode()}
                merge = self._backup_read(self.merge_file)
                if stored.get('merge_preset'):
                    preset = parse_yaml(self._preset_path(self._backup_text(stored['merge_preset'])).read_bytes())
                    absorb_switches(preset, settings)
                    merge = yaml.safe_dump(preset, allow_unicode=True, sort_keys=False).encode()
                elif 'merge_yaml' in stored:
                    merge = self._backup_text(stored['merge_yaml']).encode('utf-8') or b'{}\n'
                if merge is None:
                    merge = self._preset_path('full.yaml').read_bytes()
                overlay = parse_yaml(merge)
                pending[self.merge_file] = merge
                source = self._backup_read(self.source_file)
                if 'subscription_snapshot' in stored:
                    if stored['subscription_snapshot']:
                        encoded = base64.b64decode(stored['subscription_snapshot'], validate=True)
                        with gzip.GzipFile(fileobj=io.BytesIO(encoded)) as handle:
                            source = handle.read(MAX_CONFIG + 1)
                        if len(source) > MAX_CONFIG:
                            raise ValueError()
                    else:
                        source = None
                    pending[self.source_file] = source
                data = parse_yaml(source) if source is not None else {'proxies': [], 'proxy-groups': [], 'rules': ['MATCH,DIRECT']}
                if source is not None:
                    check_subscription(data)
                journals = {}
                scope = stored.get('consent_scope', '')
                if scope and not re.fullmatch('[a-f0-9]{64}', scope):
                    raise ValueError()
                current_scope = self._consent_scope()
                owned = bool(scope and scope == current_scope)
                for field, filename in [('dns_state', 'dns-state.json'), ('tun_state', 'tun-state.json')]:
                    if field in stored:
                        raw = self._backup_text(stored[field]) if stored[field] else ''
                        # Validate even untrusted journals, but never install them
                        # over local journals before their XML pairing is checked.
                        validated = self._journal(field, raw) if raw else None
                        journals[field] = json.loads(validated) if owned and validated else None
                    pending[self.state / filename] = None
                if 'proxy_selections' in stored:
                    selections = self._selection_map(stored['proxy_selections'] or '{}')
                    pending[self.selections_file] = json.dumps(selections, ensure_ascii=True, sort_keys=True).encode()
                    pending[self.replay_file] = b'pending\n' if selections else None
                references = self._reference_restore(stored, data, overlay)
                pending.update({path: content for path, (content, mode) in references.items()})
                upstreams, ipv6 = self.router_context(settings)
                config = render(data, settings, overlay=overlay, upstreams=upstreams, ipv6_advertised=ipv6)
                pending[self.config_file] = config
                pending[self.backup_marker] = (checksum + '\n').encode()
                self.state.mkdir(parents=True, mode=0o700, exist_ok=True)
                staged, originals, recovery, applied, created = {}, {}, {}, [], []
                committed = False
                try:
                    for path, content in pending.items():
                        originals[path] = self._backup_read(path)
                        parent = path.parent
                        while not parent.exists():
                            parent = parent.parent
                        if originals[path] is not None:
                            fd, name = tempfile.mkstemp(prefix='.backup-original-', dir=parent)
                            os.close(fd)
                            recovery[path] = Path(name)
                            atomic_write(recovery[path], originals[path], stat.S_IMODE(path.stat().st_mode))
                        if content is not None:
                            fd, name = tempfile.mkstemp(prefix='.backup-restore-', dir=parent)
                            os.close(fd)
                            staged[path] = Path(name)
                            atomic_write(staged[path], content, references.get(path, (None, 0o600))[1])
                    self.system.validate(staged[self.config_file])
                    for path in pending:
                        if path in (self.state / 'dns-state.json', self.state / 'tun-state.json'):
                            continue
                        missing = []
                        parent = path.parent
                        while not parent.exists():
                            missing.append(parent)
                            parent = parent.parent
                        for parent in reversed(missing):
                            parent.mkdir(mode=0o700)
                            created.append(parent)
                        if pending[path] is None:
                            path.unlink(missing_ok=True)
                        else:
                            os.replace(staged[path], path)
                        applied.append(path)
                    restore = getattr(self.system, 'restore_integration', self.system.dns)
                    payload = {'expected': self._backup_revision(stored), 'scope': scope, 'current_scope': current_scope,
                               'journals': journals, 'repair_checksum': checksum if repair else ''}
                    restore(settings, payload) if hasattr(self.system, 'restore_integration') else restore(False, settings)
                    committed = True
                except Exception:
                    for path in reversed(applied):
                        try:
                            if originals[path] is None:
                                path.unlink(missing_ok=True)
                            else:
                                os.replace(recovery[path], path)
                        except OSError:
                            pass
                    for parent in reversed(created):
                        with contextlib.suppress(OSError):
                            parent.rmdir()
                    raise
                finally:
                    for path in staged.values():
                        path.unlink(missing_ok=True)
                    for destination, path in recovery.items():
                        if committed or destination not in applied:
                            path.unlink(missing_ok=True)
                # Core caches are derived; proxy choices are replayed through API.
                result = {'restored': True, 'snapshot': True}
                if not owned and any(stored.get(field) for field in ('dns_state', 'tun_state')):
                    result['warning'] = 'The saved ownership journals do not match this system configuration and were not applied.'
                try:
                    (self.path(HOME) / 'cache.db').unlink(missing_ok=True)
                    self.backup_warning_file.unlink(missing_ok=True)
                    self.proxy_warning_file.unlink(missing_ok=True)
                    self.record_warnings(data, overlay)
                    self.publish_status(settings)
                except (Error, OSError, ValueError):
                    result['warning'] = 'The Mihomo configuration was restored, but its derived status could not be refreshed.'
                return result
            except (Error, OSError, ValueError, TypeError, UnicodeError, EOFError, zlib.error):
                raise Error('The Mihomo configuration backup could not be restored; its saved copy was retained.') from None

    def _proxy_api(self, method, path, payload=None):
        if self.root != Path('/'):
            return {'proxies': {}} if method == 'GET' else {}
        settings = self.settings()
        host, port = settings.get('controller', LOOPBACK_CONTROLLER).rsplit(':', 1)
        host = '127.0.0.1'
        request = urlrequest.Request('http://' + host + ':' + port + path,
            data=json.dumps(payload).encode() if payload is not None else None, method=method,
            headers={'Authorization': 'Bearer ' + settings['secret'], 'Content-Type': 'application/json'})
        opener = urlrequest.build_opener(urlrequest.ProxyHandler({}), LocalAPIHandler())
        with opener.open(request, timeout=2) as response:
            value = response.read(2 * 1024 * 1024 + 1)
        if len(value) > 2 * 1024 * 1024:
            raise ValueError()
        return json.loads(value) if value else {}

    def proxy_tick(self):
        if not self.system.running():
            return False
        try:
            proxies = self.proxy_api('GET', '/proxies').get('proxies', {})
            if not isinstance(proxies, dict) or len(proxies) > 4096:
                raise ValueError()
            if self.replay_file.exists():
                saved = self._selection_map((self._backup_read(self.selections_file) or b'{}').decode())
                deadline, mutations, complete = time.monotonic() + 3, 0, True
                for name, choice in saved.items():
                    group = proxies.get(name, {})
                    if group.get('type', '').lower() != 'selector' or choice not in group.get('all', []):
                        continue
                    if group.get('now') != choice:
                        if mutations >= 32 or time.monotonic() >= deadline:
                            complete = False
                            break
                        self.proxy_api('PUT', '/proxies/' + urlparse.quote(name, safe=''), {'name': choice})
                        mutations += 1
                        group['now'] = choice
                if not complete:
                    return False
                self.replay_file.unlink(missing_ok=True)
            choices = {name: group['now'] for name, group in proxies.items() if isinstance(group, dict)
                       and group.get('type', '').lower() == 'selector' and group.get('all')
                       and isinstance(group.get('now'), str) and group['now'] != group['all'][0]}
            self._selection_map(json.dumps(choices))
            self.proxy_warning_file.unlink(missing_ok=True)
            content = json.dumps(choices, ensure_ascii=True, sort_keys=True).encode()
            if content != (self._backup_read(self.selections_file) or b'{}'):
                atomic_write(self.selections_file, content)
                return True
        except (OSError, ValueError, Error, TypeError, AttributeError):
            with contextlib.suppress(OSError):
                atomic_write(self.proxy_warning_file, BACKUP_WARNING.encode())
        return False

    def settings(self):
        try:
            value = json.loads(self.settings_file.read_bytes())
            for key, fallback in SWITCH_DEFAULTS.items():
                value.setdefault(key, fallback)
            self.check_settings(value)
            return value
        except (OSError, ValueError, TypeError, KeyError):
            raise Error("Mihomo settings are missing or invalid; run initialization first.") from None

    def check_settings(self, settings):
        for key in ("transparent", "dns_fallback", "service_enabled", 'router_dns',
                    'dns_override', 'ipv6', 'dns_hijack', 'allow_lan'):
            if key not in settings and key in SWITCH_DEFAULTS:
                continue
            if not isinstance(settings.get(key), bool):
                raise Error("Service policies must be boolean values.")
        if settings.get('dns_mode', DNS_MODE_DEFAULT) not in DNS_MODES:
            raise Error("The DNS mode must be one of: " + ", ".join(DNS_MODES) + ".")
        if settings.get('geo_source', GEO_SOURCE_DEFAULT) not in GEO_SOURCES:
            raise Error("The rule database must be one of: " + ", ".join(GEO_SOURCES) + ".")
        for field in DNS_SERVER_FIELDS:
            check_dns_servers(field, settings.get(field) or [])
        ports = {}
        for field, label in (('mixed_port', 'mixed'), ('socks_port', 'SOCKS')):
            value = settings.get(field, SWITCH_DEFAULTS[field])
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= PORT_LIMIT:
                raise Error('The %s port must be a number between 1 and %d.' % (label, PORT_LIMIT))
            # 53 belongs to the resolver, 1053 to Mihomo's own, 9090 to the
            # dashboard. Taking one of them stops the core starting, and the
            # reason is buried in its log rather than shown here.
            if value in (53, DNS_LISTEN_PORT, CONTROLLER_PORT):
                raise Error('Port %d is already used by the router, so the %s port cannot take it.'
                            % (value, label))
            if value in ports:
                raise Error('The mixed and SOCKS ports cannot both be %d.' % value)
            ports[value] = field
        stack = settings.get('tun_stack', SWITCH_DEFAULTS['tun_stack'])
        if stack not in TUN_STACKS:
            raise Error('The TUN stack must be one of: ' + ', '.join(TUN_STACKS) + '.')
        mtu = settings.get('tun_mtu', SWITCH_DEFAULTS['tun_mtu'])
        if isinstance(mtu, bool) or not isinstance(mtu, int) or not MTU_RANGE[0] <= mtu <= MTU_RANGE[1]:
            raise Error('The TUN MTU must be a number between %d and %d.' % MTU_RANGE)
        bind = settings.get('bind_address', SWITCH_DEFAULTS['bind_address'])
        if not isinstance(bind, str) or not bind:
            raise Error('The bind address is required; use * to accept every address.')
        if bind != '*':
            try:
                ipaddress.ip_address(bind.strip('[]'))
            except ValueError:
                raise Error('The bind address must be an IP address, or * for every address.') from None
        if settings.get('device_mode', 'off') not in DEVICE_MODES:
            raise Error('The device policy must be one of: ' + ', '.join(DEVICE_MODES) + '.')
        device_networks(settings.get('device_list'))
        if not isinstance(settings.get("secret"), str) or not settings["secret"]:
            raise Error("A nonempty dashboard secret is required.")
        controller = settings.get("controller", "127.0.0.1:9090")
        try:
            host, port = controller.rsplit(":", 1)
            ipaddress.IPv4Address(host)
            if not 1 <= int(port) <= 65535 or int(port) == 53:
                raise ValueError
        except (AttributeError, ValueError):
            raise Error("The controller must bind to an IPv4 address and port.") from None
        for key in ("subscription_url", "device"):
            if not isinstance(settings.get(key), str) or any(char in settings[key] for char in "\r\n\x00"):
                raise Error("Invalid subscription settings.")
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", settings["device"]):
            raise Error("The device label must contain only letters, digits, dots, underscores, or hyphens.")

    def write_settings(self, settings):
        self.check_settings(settings)
        atomic_write(self.settings_file, (json.dumps(settings, indent=2) + "\n").encode())

    def publish_status(self, settings=None, dns_active=False, error=""):
        settings = settings or self.settings()
        running = self.system.running()
        routing_active = False
        with contextlib.suppress(OSError, ValueError, TypeError):
            routing = json.loads((self.state / 'routing-state.json').read_bytes())
            routing_active = running and settings['transparent'] and isinstance(routing, dict) and routing.get('active') is True
        overrides = []
        if self.merge_file.exists():
            with contextlib.suppress(Error, OSError):
                overrides = switch_overrides(parse_yaml(self.merge_file.read_bytes()))
        status = {"running": running, "transparent": settings["transparent"],
                  "routing_active": routing_active,
                  "dns_active": dns_active, "dns_fallback": settings["dns_fallback"],
                  "service_enabled": settings["service_enabled"], "overrides": overrides,
                  "error": bounded_routing_diagnostic(error), "backup_warning": self.backup_warning_file.read_text()
                      if self.backup_warning_file.exists() else BACKUP_WARNING
                      if self.proxy_warning_file.exists() else '', "updated": time.time()}
        atomic_write(self.status_file, json.dumps(status).encode(), 0o644)
        return status

    def log(self, message):
        message = time.strftime("[%Y-%m-%d %H:%M:%S] ") + message + "\n"
        path = self.path("/var/log/mihomo_sub.log")
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o640)
            with os.fdopen(fd, "a") as stream:
                os.chmod(path, 0o640)
                stream.write(message)
        except OSError:
            pass

    def initialize(self, upgrade=False):
        self._restore_for_start()
        self.state.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.state, 0o700)
        if self.settings_file.exists():
            settings = self.settings()
        else:
            legacy = self.state / "migrate"
            source = legacy / "config.yaml"
            existing = parse_yaml(source.read_bytes()) if source.exists() else {}
            env = {}
            if (legacy / "env").exists():
                for line in (legacy / "env").read_text().splitlines():
                    try:
                        tokens = shlex.split(line)
                        if tokens and "=" in tokens[-1]:
                            key, value = tokens[-1].split("=", 1)
                            env[key] = value
                    except ValueError:
                        raise Error("The legacy subscription settings could not be read.") from None
            settings = {"subscription_url": env.get("mihomo_URL", ""),
                        "secret": env.get("mihomo_secret") or existing.get("secret") or secrets.token_hex(32),
                        "device": re.sub(r"[^A-Za-z0-9._-]", "-", socket.gethostname())[:64] or "router",
                        "transparent": False, "dns_fallback": True, "service_enabled": True,
                        **SWITCH_DEFAULTS}
            if existing:
                atomic_write(self.source_file, source.read_bytes())
            self.write_settings(settings)
        recognized = (type(settings.get('state_schema')) is int
                      and settings['state_schema'] == STATE_SCHEMA
                      and isinstance(settings.get('transparent_consent'), bool))
        # Unmarked legacy policies are never evidence of explicit TUN consent.
        if not recognized:
            settings.update(transparent=False, service_enabled=True,
                            state_schema=STATE_SCHEMA, transparent_consent=False)
        elif settings['transparent'] and not settings['transparent_consent']:
            settings['transparent'] = False
        self.write_settings(settings)
        if not self.merge_file.exists():
            preset = self.path(SHARE + '/presets/full.yaml')
            if not preset.exists():
                preset = Path(__file__).resolve().parents[3] / 'share/mihomo/presets/full.yaml'
            overlay = parse_yaml(preset.read_bytes())
            if settings.get('controller'):
                overlay['external-controller'] = settings['controller']
            atomic_write(self.merge_file, yaml.safe_dump(overlay, sort_keys=False).encode())
        # The switches own these keys. Adopt whatever the installed configuration
        # already does, then lift any canonical value out of the stored overlay, so
        # a later toggle cannot be silently reverted by merge.yaml.
        migrating = settings.get('switch_schema') != SWITCH_SCHEMA
        rendered = {}
        if migrating and self.config_file.exists():
            with contextlib.suppress(Error, OSError):
                rendered = parse_yaml(self.config_file.read_bytes())
                settings = adopt_switches(rendered, settings)
        stored = parse_yaml(self.merge_file.read_bytes())
        cleaned = copy.deepcopy(stored)
        lifted = absorb_switches(cleaned, settings)
        if cleaned != stored:
            settings = lifted
            atomic_write(self.merge_file, yaml.safe_dump(cleaned, sort_keys=False, allow_unicode=True).encode())
        if migrating:
            # The stored overlay predates the address in use, so the running
            # configuration decides where the controller is bound, not the file.
            if isinstance(rendered.get('external-controller'), str):
                settings['controller'] = rendered['external-controller']
            settings.setdefault('controller', ANY_CONTROLLER)
            # Before this switch existed, any populated manual field always
            # replaced its subscription counterpart. Keep that effective intent.
            if any(settings.get(field) for field in DNS_SERVER_FIELDS):
                settings['dns_override'] = True
            settings['switch_schema'] = SWITCH_SCHEMA
        settings = routing_settings(settings)
        self.write_settings(settings)
        runtime_home = self.path(HOME)
        runtime_home.mkdir(parents=True, exist_ok=True, mode=0o700)
        for name in ('GeoIP.dat', 'GeoSite.dat'):
            target = runtime_home / name
            if not target.exists() and not target.is_symlink():
                target.symlink_to(SHARE + '/' + name)
        data = parse_yaml(self.source_file.read_bytes()) if self.source_file.exists() else {
            "proxies": [], "proxy-groups": [], "rules": ["MATCH,DIRECT"], "log-level": "info"}
        candidate = self.candidate(data, settings)
        try:
            self.system.validate(candidate)
            atomic_write(self.config_file, candidate.read_bytes())
        finally:
            candidate.unlink(missing_ok=True)
        # An upgrade replaces this file under a watchdog that already loaded the
        # previous one. Retire it here so the next start runs the installed code.
        self.system.stop_watch()
        self.publish_status(settings)
        return self._mirrored_result({"initialized": True, "transparent": settings["transparent"]})

    def router_context(self, settings):
        if not settings.get('router_dns'):
            return '', False
        config = self.path('/conf/config.xml').read_bytes()
        upstreams = self.path('/var/unbound/etc/dot.conf').read_text()
        if (self.state / 'dns-state.json').exists():
            import xml.etree.ElementTree as ET
            snapshot = json.loads((self.state / 'dns-state.json').read_bytes())
            entries = ET.fromstring(config).findall('./OPNsense/unboundplus/dots/dot')
            upstreams = '\n'.join('forward-addr: ' + node.findtext('server', '') + '@' + node.findtext('port', '853')
                for node in entries if node.get('uuid') != 'b126bf65-a985-49ca-a9d2-16f156aac198'
                and (node.findtext('enabled') == '1' or snapshot.get('roots', {}).get(node.get('uuid')) == '1'))
        return upstreams, advertises_ipv6(config)

    def record_warnings(self, data, overlay=None):
        """Publish what the applied configuration silently did not do."""
        if overlay is None:
            overlay = parse_yaml(self.merge_file.read_bytes()) if self.merge_file.exists() else {}
        orphans = orphan_policy_keys(merge_yaml(baseline(data), data), overlay)
        atomic_write(self.warnings_file, json.dumps({'policy_orphans': orphans}).encode(), 0o644)

    def candidate(self, data, settings, overlay=None):
        upstreams, ipv6 = self.router_context(settings)
        content = render(data, settings, overlay=overlay if overlay is not None else parse_yaml(self.merge_file.read_bytes()), upstreams=upstreams, ipv6_advertised=ipv6)
        fd, name = tempfile.mkstemp(prefix=".candidate-", suffix=".yaml", dir=self.state)
        os.close(fd)
        path = Path(name)
        atomic_write(path, content)
        return path

    def stop(self, settings=None, reason=None):
        settings = settings or self.settings()
        # Restore direct DNS before stopping the listener, even for fail-closed policy.
        failed = None
        try:
            self.system.dns(False, settings)
        except (Error, OSError) as error:
            failed = error
        try:
            self.system.stop()
        finally:
            # A cleanup that works leaves nothing behind to explain itself, so
            # the caller's failure is what the status has to name: without it a
            # start that could not arm reads as a service nobody ever asked for.
            self.publish_status(settings, dns_active=failed is not None,
                error='DNS restoration failed; the core and TUN were stopped. Recovery will be retried.' if failed
                      else str(reason) if reason is not None else '')
        if failed:
            raise Error('DNS restoration failed; the core and TUN were stopped. Recovery will be retried.') from None

    def start(self, settings=None):
        original = settings or self.settings()
        settings = routing_settings(original)
        if not settings["service_enabled"]:
            self.publish_status(settings)
            return {"running": False, "message": "The service is administratively stopped."}
        data = parse_yaml(self.source_file.read_bytes()) if self.source_file.exists() else {'proxies': [], 'proxy-groups': [], 'rules': ['MATCH,DIRECT']}
        overlay = parse_yaml(self.merge_file.read_bytes())
        cleaned = copy.deepcopy(overlay)
        dns = cleaned.get('dns')
        if settings.get('transparent') and isinstance(dns, dict) and dns.get('enhanced-mode') == 'fake-ip':
            dns.pop('enhanced-mode')
            settings = dict(settings, dns_mode='redir-host')
        candidate = self.candidate(data, settings, overlay=cleaned)
        try:
            self.system.validate(candidate)
            generated = parse_yaml(candidate.read_bytes())
            if settings != original:
                self.write_settings(settings)
            if cleaned != overlay:
                atomic_write(self.merge_file, yaml.safe_dump(cleaned, sort_keys=False, allow_unicode=True).encode())
            atomic_write(self.config_file, candidate.read_bytes())
        finally:
            candidate.unlink(missing_ok=True)
        self.record_warnings(data)
        tun = bool(generated.get('tun', {}).get('enable'))
        dns_active = bool(tun and generated.get('dns', {}).get('enable') and generated['dns'].get('listen') == '127.0.0.1:1053' and not settings.get('router_dns'))
        self.system.dns(False, settings)
        if settings.get('router_dns'):
            self.system.check_router_dns()
        try:
            self.system.start(self.config_file, tun)
            if tun:
                self.system.tun()
            if dns_active:
                self.system.dns(True, settings)
            if self.selections_file.exists():
                atomic_write(self.replay_file, b'pending\n')
            self.proxy_tick()
            # The watchdog starts only once arming has succeeded. Starting it
            # earlier would have it retry a failed arm every few seconds, which
            # is how one uptime consumed two thousand kernel routing tables, and
            # its first tick republishes ground truth anyway -- erasing the
            # reason Manager.stop just recorded. A failed arm stays failed and
            # stays explained.
            self.system.watch()
        except (Error, OSError) as error:
            self.stop(settings, reason=error)
            raise
        return self.publish_status(settings, dns_active)

    def apply(self, content, settings=None, subscription=True, overlay=None):
        self._guard_backup()
        settings = settings or self.settings()
        if overlay is not None:
            settings = absorb_switches(overlay, settings)
        settings = routing_settings(settings)
        self.check_settings(settings)
        data = parse_yaml(content)
        if subscription:
            check_subscription(data)
        candidate = self.candidate(data, settings, overlay)
        backup_dir = Path(tempfile.mkdtemp(prefix=".rollback-", dir=self.state))
        try:
            self.system.validate(candidate)
            before = {}
            for path in (self.config_file, self.source_file, self.settings_file, self.merge_file):
                backup = backup_dir / path.name
                if path.exists():
                    os.link(path, backup)
                    before[path] = backup
                else:
                    before[path] = None
            running = self.system.running()
            previous = self.settings()
            try:
                if running:
                    self.stop(previous)
                atomic_write(self.config_file, candidate.read_bytes())
                if subscription:
                    atomic_write(self.source_file, content)
                self.write_settings(settings)
                if overlay is not None:
                    atomic_write(self.merge_file, yaml.safe_dump(overlay, sort_keys=False, allow_unicode=True).encode())
                self.record_warnings(data, overlay)
                if running:
                    self.start(settings)
                else:
                    self.publish_status(settings)
            except (Error, OSError):
                # Recovery files must be restored even if a DNS cleanup fails.
                try:
                    self.stop(settings)
                except (Error, OSError):
                    with contextlib.suppress(Error, OSError):
                        self.system.stop()
                for path, original in before.items():
                    if original is None:
                        path.unlink(missing_ok=True)
                    else:
                        os.replace(original, path)
                if running:
                    try:
                        self.system.dns(False, previous)
                        self.start(previous)
                    except (Error, OSError):
                        direct = False
                        try:
                            self.system.dns(False, previous)
                            direct = True
                        except (Error, OSError):
                            pass
                        message = "Rollback restored the files; the service could not restart. " + (
                            "Direct DNS is active." if direct else "DNS restoration also failed; integration state is retained for recovery.")
                        self.publish_status(previous, error=message)
                        raise Error(message) from None
                raise Error("The change failed. The previous configuration and secret were restored.") from None
        finally:
            candidate.unlink(missing_ok=True)
            for path in backup_dir.iterdir():
                path.unlink(missing_ok=True)
            backup_dir.rmdir()
        return self._mirrored_result({"applied": True, "proxies": len(data.get("proxies", [])), "rules": len(data["rules"])})

    def set_policy(self, enabled):
        settings = self.settings()
        settings["transparent"] = enabled
        settings['state_schema'] = STATE_SCHEMA
        settings['transparent_consent'] = enabled
        if enabled and not self.source_file.exists():
            raise Error("Fetch and validate a subscription before enabling transparent routing.")
        if enabled and not self.system.running():
            raise Error("Start the proxy service before enabling transparent routing.")
        if enabled and not parse_yaml(self.merge_file.read_bytes()).get('tun', {}).get('enable'):
            raise Error('Choose a TUN preset or enable TUN in merge YAML before activation.')
        if self.source_file.exists():
            result = self.apply(self.source_file.read_bytes(), settings)
        else:
            data = {"proxies": [], "proxy-groups": [], "rules": ["MATCH,DIRECT"]}
            result = self.apply(yaml.safe_dump(data).encode(), settings, subscription=False)
        return result

    def update_status(self, status, error=""):
        atomic_write(self.path("/var/run/mihomo-update.json"),
                     json.dumps({"status": status, "error": error, "updated": time.time()}).encode(), 0o644)

    def update(self):
        # Network waits must not prevent the watchdog from restoring DNS.
        path = self.path("/var/run/os-mihomo-sub.lock")
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a") as stream:
            os.chmod(path, 0o600)
            try:
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise Error("A subscription update is already running.") from None
            with self.lock():
                self._guard_backup()
                settings = self.settings()
                proxy = ''
                if self.system.running():
                    current = parse_yaml(self.config_file.read_bytes())
                    port = current.get('socks-port') or current.get('mixed-port')
                    bind = current.get('bind-address', '127.0.0.1')
                    bind = '127.0.0.1' if bind in {'*', '0.0.0.0', '::'} else bind
                    if port:
                        proxy = ('[' + bind + ']' if ':' in bind else bind) + ':' + str(port)
            self.update_status("running")
            self.log("Fetching the subscription directly.")
            try:
                content = fetch_subscription(settings["subscription_url"], "OPNsense-Mihomo/1 (" + settings["device"] + ")", proxy)
                with self.lock():
                    latest = self.settings()
                    if (latest["subscription_url"], latest["device"]) != (settings["subscription_url"], settings["device"]):
                        raise Error("Subscription settings changed during download. The response was discarded.")
                    result = self.apply(content, latest)
                self.log("Subscription validated and applied.")
                self.update_status("completed")
                return result
            except (Error, OSError) as error:
                message = str(error) if isinstance(error, Error) else "Unable to read or persist the subscription configuration."
                self.log(message)
                self.update_status("failed", message)
                raise

    def queue_update(self):
        self.settings()
        path = self.path("/var/run/mihomo-update.pid")
        worker = ['/usr/local/bin/python3', SCRIPT, 'sub-update']
        if self.system.process_running(str(path), worker[0], worker):
            raise Error("A subscription update is already queued or running.")
        process = subprocess.Popen(worker,
                                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, start_new_session=True)
        atomic_write(path, str(process.pid).encode())
        return {"queued": True}

    def watchdog_tick(self):
        try:
            self._guard_backup()
        except Error as error:
            # Backup preservation must not disable the local crash rescue path.
            # Only the running-settings rewrite and mirror need the XML guard.
            settings = self.settings()
            active = False
            with contextlib.suppress(OSError, ValueError):
                active = bool(json.loads(self.status_file.read_bytes()).get('dns_active'))
            rescue_error = ''
            if not self.system.running():
                try:
                    self.system.destroy_tun()
                except (Error, OSError) as routing_failure:
                    rescue_error = routing_status_error(
                        'Routing cleanup failed and will be retried.', routing_failure) + ' '
                pending_dns = (self.state / 'dns-reload-pending').exists()
                if pending_dns or (active and (settings['dns_fallback'] or not settings['service_enabled'])):
                    try:
                        if hasattr(self.system, 'rescue'):
                            self.system.rescue(settings)
                        else:
                            self.system.dns(False, settings)
                        active = False
                    except (Error, OSError):
                        rescue_error += 'Direct DNS recovery failed and will be retried. '
            if isinstance(error, BackupIntegrityError):
                atomic_write(self.backup_warning_file, BACKUP_INTEGRITY_WARNING.encode())
            return self.publish_status(settings, active, error=rescue_error + str(error))
        result = self._watchdog_tick()
        self.proxy_tick()
        self.mirror_backup()
        result['backup_warning'] = BACKUP_WARNING if self.backup_warning_file.exists() or self.proxy_warning_file.exists() else ''
        atomic_write(self.status_file, json.dumps(result).encode(), 0o644)
        return result

    def _watchdog_tick(self):
        settings = self.settings()
        try:
            status = json.loads(self.status_file.read_bytes())
        except (OSError, ValueError):
            status = {}
        active = bool(status.get("dns_active"))
        if not self.system.running():
            routing_error = ''
            try:
                self.system.destroy_tun()
            except (Error, OSError) as error:
                routing_error = routing_status_error(
                    'Routing cleanup failed and will be retried.', error) + ' '
            if active and (settings['dns_fallback'] or not settings['service_enabled'] or (self.state / 'dns-reload-pending').exists()):
                try:
                    self.system.dns(False, settings)
                    active = False
                except (Error, OSError):
                    return self.publish_status(settings, active, error=routing_error + 'Direct DNS recovery failed and will be retried.')
                return self.publish_status(settings, error=routing_error or "Mihomo exited. Direct DNS and routing were restored automatically.")
            if routing_error:
                return self.publish_status(settings, active, error=routing_error)
        elif settings.get('transparent') and hasattr(self.system, 'routing'):
            try:
                self.system.routing('refresh')
            except (Error, OSError) as error:
                return self.publish_status(settings, active, error=routing_status_error(
                    'Transparent routing recovery failed and will be retried.', error))
        if settings.get('router_dns'):
            upstreams, ipv6 = self.router_context(settings)
            data = parse_yaml(self.config_file.read_bytes())
            if ipv6 and not (data.get('ipv6') is True and data.get('dns', {}).get('ipv6') is True):
                return self.publish_status(settings, active, error='IPv6 is now being advertised to clients while Mihomo IPv6 is disabled. Disable router DNS or validate IPv6 support.')
            pins = dns_transport_rules(upstreams)
            if self.system.running() and data.get('rules', [])[:len(pins)] != pins:
                self.apply(self.source_file.read_bytes(), settings)
            return self.publish_status(settings, active)
        return self.publish_status(settings, active)

    def _restore_for_start(self):
        try:
            return self.restore_backup()
        except BackupIntegrityError as error:
            atomic_write(self.backup_warning_file, BACKUP_INTEGRITY_WARNING.encode())
            # A damaged XML mirror must not retire a usable local installation.
            # Fresh installs still fail with the explicit repair instructions.
            try:
                self.settings()
                parse_yaml(self.config_file.read_bytes())
            except (Error, OSError):
                raise error from None
            return {'restored': False, 'snapshot': True, 'warning': BACKUP_INTEGRITY_WARNING}

    def dispatch(self, action, argument=None):
        if action == 'repair-backup':
            return self.restore_backup(force=True, repair=True)
        if action == 'import-config':
            return self.restore_backup(force=True)
        if action == 'reconcile-backup':
            return self._restore_for_start()
        if action == 'mirror-backup':
            result = self.mirror_backup()
            if not result['ok']:
                raise Error(BACKUP_WARNING)
            return result
        if action in {'start', 'restart', 'boot'}:
            if action == 'restart' and self.system.running():
                stored, checksum = self._stored_backup(verify=False)
                if stored and (self._backup_read(self.backup_marker) or b'').strip() != checksum.encode():
                    # Stop the old writer before applying newly restored intent.
                    self.system.stop_watch()
                    self.system.stop()
            self._restore_for_start()
        mutation = action not in {'status', 'devices', 'clear-log', 'clear-sub-log', 'queue-update'}
        if mutation and action not in {'init', 'restore-cron', 'stop', 'suspend', 'remove', 'start', 'restart', 'boot'}:
            self._guard_backup()
        if action in {'stop', 'suspend', 'remove'}:
            self.proxy_tick()
        result = self._dispatch(action, argument)
        if mutation and action not in {'init', 'restore-cron', 'sub-update', 'save-config', 'save-merge',
                'load-preset', 'set-settings', 'enable-transparent', 'disable-transparent'}:
            result = self._mirrored_result(result)
        return result

    def _dispatch(self, action, argument=None):
        if action in {"clear-log", "clear-sub-log"}:
            path = self.path("/var/log/mihomo.log" if action == "clear-log" else "/var/log/mihomo_sub.log")
            with path.open("w"):
                pass
            return {"cleared": True}
        if action == "init":
            return self.initialize(argument == "upgrade")
        if action == 'restore-cron':
            self.system.restore_cron()
            return {'restored': True}
        if action == 'devices':
            return {'devices': known_devices(self.system.run, self.root),
                    'rules': [],
                    'routing': device_routing_policy(self.settings())}
        if action == "queue-update":
            return self.queue_update()
        if action == "sub-update":
            return self.update()
        if action == "save-config":
            return self.apply(Path(argument).read_bytes())
        if action in {'save-merge', 'load-preset'}:
            path = Path(argument)
            if action == 'load-preset':
                name = argument if re.fullmatch(r'[a-z0-9-]+\.yaml', argument or '') else path.read_text().strip()
                if not re.fullmatch(r'[a-z0-9-]+\.yaml', name):
                    raise Error('Invalid preset name.')
                path = self.path(SHARE + '/presets/' + name)
            overlay = parse_yaml(path.read_bytes())
            content = self.source_file.read_bytes() if self.source_file.exists() else b'proxies: []\nproxy-groups: []\nrules: ["MATCH,DIRECT"]\n'
            return self.apply(content, subscription=self.source_file.exists(), overlay=overlay)
        if action == "set-settings":
            value = json.loads(Path(argument).read_bytes())
            settings = self.settings()
            for key in ("subscription_url", "secret", "device", "dns_fallback",
                        'router_dns', 'dns_override', 'ipv6', 'dns_hijack', 'dns_mode', 'geo_source',
                        'device_mode', 'device_list', 'mixed_port', 'socks_port',
                        'allow_lan', 'bind_address', 'tun_stack', 'tun_mtu', *DNS_SERVER_FIELDS):
                if key in value:
                    settings[key] = value[key]
            if 'dashboard_any' in value:
                current = settings.get('controller') or LOOPBACK_CONTROLLER
                port = current.rsplit(':', 1)[-1] if ':' in current else str(CONTROLLER_PORT)
                host = '0.0.0.0' if value['dashboard_any'] else '127.0.0.1'
                settings['controller'] = host + ':' + port
            if self.source_file.exists():
                return self.apply(self.source_file.read_bytes(), settings)
            base = {"proxies": [], "proxy-groups": [], "rules": ["MATCH,DIRECT"]}
            return self.apply(yaml.safe_dump(base).encode(), settings, subscription=False)
        if action in {"enable-transparent", "disable-transparent"}:
            return self.set_policy(action == "enable-transparent")
        settings = self.settings()
        if action in {"suspend", "stop", "remove"}:
            if action != 'suspend':
                settings['service_enabled'] = False
                self.write_settings(settings)
            self.stop(settings)
            self.system.stop_watch()
            if action != "suspend":
                settings["service_enabled"] = False
                if action == "remove":
                    settings["transparent"] = False
                    settings['transparent_consent'] = False
                    self.system.remove()
                self.write_settings(settings)
                self.publish_status(settings)
            return {"running": False}
        if action in {"start", "restart", "boot", "wan-restart"}:
            if action in {"start", "restart"}:
                settings["service_enabled"] = True
                self.write_settings(settings)
            if action == "wan-restart" and not self.system.running():
                return {"running": False}
            if action in {"restart", "wan-restart"} and self.system.running():
                self.stop(settings)
            if self.system.running():
                self.system.watch()
                generated = parse_yaml(self.config_file.read_bytes())
                dns = generated.get('dns', {})
                dns_active = bool(generated.get('tun', {}).get('enable') and dns.get('enable')
                                  and dns.get('listen') == '127.0.0.1:1053' and not settings.get('router_dns'))
                return self.publish_status(settings, dns_active)
            return self.start(settings)
        if action == "status":
            try:
                status = json.loads(self.status_file.read_bytes())
            except (OSError, ValueError):
                status = {}
            return self.publish_status(settings, bool(status.get("dns_active")), error=status.get('error', ''))
        raise Error("Unknown action.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Return structured action results for configd.")
    parser.add_argument("action")
    parser.add_argument("argument", nargs="?")
    args = parser.parse_args()
    if os.geteuid() != 0:
        print("Mihomo state changes require root privileges.", file=sys.stderr)
        return 1
    manager = Manager()
    if args.action == "watch":
        reported = None
        while True:
            try:
                with manager.lock(blocking=False):
                    manager.watchdog_tick()
                reported = None
            except (Error, OSError) as failure:
                message = str(failure)
                if message != reported:
                    reported = message
                    print('watchdog tick failed: ' + message, flush=True)
            time.sleep(5)
    try:
        if args.action == "sub-update":
            result = manager.update()
        else:
            with manager.lock():
                result = manager.dispatch(args.action, args.argument)
        if args.json:
            print(json.dumps({"ok": True, "result": result}))
        else:
            print("Mihomo operation completed.")
        return 0
    except (Error, OSError, ValueError, TypeError, KeyError) as error:
        message = str(error) if isinstance(error, Error) else "Unable to read or persist Mihomo configuration."
        if args.json:
            print(json.dumps({"ok": False, "error": message}))
            return 0
        print(message, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
