"""Execute actual pkg hooks and core/route recovery in an isolated VNET jail."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import shutil
import socket
import stat
import subprocess
import sys
import time
import urllib.request
import xml.etree.ElementTree as ET


def command(args, check=True):
    result = subprocess.run(args, capture_output=True, timeout=120)
    if check and result.returncode:
        raise RuntimeError('Command failed: ' + ' '.join(args) + '\n' + result.stdout.decode(errors='replace') + result.stderr.decode(errors='replace'))
    return result


def action(name, argument=None, ok=True):
    args = ['/usr/local/bin/python3', '/usr/local/opnsense/scripts/mihomo/mihomo.py', '--json', name]
    if argument is not None:
        args.append(str(argument))
    value = json.loads(command(args).stdout)
    assert value['ok'] is ok, value
    return value


def running():
    return action('status')['result']['running']


host_dns_marker = Path('/var/db/os-mihomo/host-dns-reload-pending')
host_dns_resolver = Path('/etc/resolv.conf')
gateway_cycle = {}


def native_routes(fib):
    """Parse genuine tables with the installed module's unchanged parser."""
    script_directory = '/usr/local/opnsense/scripts/mihomo'
    if script_directory not in sys.path:
        sys.path.insert(0, script_directory)
    spec = importlib.util.spec_from_file_location(
        'native_routing', '/usr/local/opnsense/scripts/mihomo/routing.py')
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    routes = {}
    for family, name in ((4, 'inet'), (6, 'inet6')):
        output = command(['/usr/bin/netstat', '-rn', '-F', str(fib), '-f', name]).stdout.decode()
        routes.update(helper.parse_routes(output, family))
    return helper, routes


def prepare_gateway_cycle():
    """Model a foreign interface's cyclic numeric gateways before cold copying."""
    command(['/sbin/ifconfig', 'lo2', 'create', 'inet', '192.0.3.10/32', 'up'])
    command(['/sbin/route', '-n', 'add', '-host', '10.255.255.254', '-iface', 'lo2'])
    command(['/sbin/route', '-n', 'add', '-net', '10.0.0.0/24', '10.255.255.254', '-ifp', 'lo2'])
    command(['/sbin/route', '-n', 'delete', '-host', '10.255.255.254'])
    command(['/sbin/route', '-n', 'add', '-host', '10.255.255.254', '10.0.0.1', '-ifp', 'lo2'])
    helper, routes = native_routes(0)
    for route in routes.values():
        if route['destination'] in ('10.0.0.0/24', '10.255.255.254/32'):
            assert route['interface'] == 'lo2' and route['gateway'] != 'interface'
            gateway_cycle[helper.route_key(route)] = helper.route_identity(route)
    assert len(gateway_cycle) == 2


def assert_core_host_dns_marker():
    """The no-auto-route core must leave the jail's native resolver alone."""
    assert running()
    assert host_dns_restored()
    assert host_dns_resolver.read_bytes() == native_dns_before_core


def assert_private_routing(active):
    """Exercise actual PF and kernel tables without claiming LAN packet flow."""
    assert b'tun_mihomo' not in command(['/sbin/route', '-n', 'get', '8.8.8.8']).stdout
    marker = Path('/var/db/os-mihomo/routing-state.json')
    anchor = command(['/sbin/pfctl', '-a', 'mihomo', '-sr']).stdout.decode()
    if not marker.exists():
        assert not active and not anchor.strip()
        return
    info = marker.lstat()
    assert stat.S_ISREG(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600
    saved = json.loads(marker.read_bytes())
    assert saved['active'] is active and saved['pending'] is False
    if saved['fib'] is None:
        assert not active and not anchor.strip()
        return
    assert isinstance(saved['fib'], int) and saved['fib'] > 0
    helper, routes = native_routes(saved['fib'])
    for key, expected in gateway_cycle.items():
        assert key in routes and helper.route_identity(routes[key]) == expected
    _, main_routes = native_routes(0)
    for key, expected in gateway_cycle.items():
        assert helper.route_identity(main_routes[key]) == expected
    route = command(['/sbin/route', '-n', 'get', '-fib', str(saved['fib']), '8.8.8.8']).stdout
    assert (b'tun_mihomo' in route) is active
    if active:
        root_rules = command(['/sbin/pfctl', '-sr']).stdout.decode().splitlines()
        assert root_rules[0].startswith('anchor "mihomo"')
        assert not any(word in anchor for word in ('pass ', 'quick ', 'proto icmp'))
        assert 'match in on lo1 inet proto tcp' in anchor and 'flags S/SA' in anchor
        assert 'match in on lo1 inet proto udp' in anchor
        assert 'rtable ' + str(saved['fib']) in anchor
        sources = command(['/sbin/pfctl', '-a', 'mihomo', '-t', 'mihomo_sources_0', '-T', 'show']).stdout
        assert b'192.0.2.0/24' in sources
        assert action('status')['result']['routing_active'] is True
    else:
        assert not anchor.strip()


def host_dns_restored():
    # Normal Core.Close can restore the original file without a search line;
    # the synthetic reload adapter adds the fixture's localdomain search line.
    lines = [line.split() for line in host_dns_resolver.read_text().splitlines() if line.strip()]
    if lines and lines[0] == ['search', 'localdomain']:
        lines = lines[1:]
    return not host_dns_marker.exists() and lines == [['nameserver', '127.0.0.1']]


def assert_host_dns_restored():
    # configd DNS generation is synthetic; the private Unbound query is real.
    assert host_dns_restored()
    assert socket.gethostbyname('policy.test') == '192.0.2.20'


checks = []
def passed(name):
    checks.append(name)
    print('PASS:', name, flush=True)


def erase_private_saved_backup(path):
    """Remove only the tested plugin's snapshot from generated private XML."""
    private_xml = ET.parse(path)
    private_mihomo = private_xml.find('./OPNsense/Mihomo')
    saved_backup = private_mihomo.find('backup') if private_mihomo is not None else None
    assert saved_backup is not None
    private_mihomo.remove(saved_backup)
    private_xml.write(path)


# run.sh sets this for a second round against a resolver that validates DNSSEC,
# which the integration has to leave exactly as the operator configured it.
dnssec = os.environ.get('MIHOMO_JAIL_DNSSEC', '0') == '1'
shutil.rmtree('/var/db/os-mihomo', ignore_errors=True)
previous = command(['/usr/local/sbin/pkg', '-o', 'RUN_SCRIPTS=false', 'add', '-f', '-M', '/root/old.pkg'])
print(previous.stdout.decode(errors='replace') + previous.stderr.decode(errors='replace'), flush=True)
config = ET.fromstring('''<opnsense><system><secret>MASTER_SECRET_DO_NOT_COPY</secret></system>
<interfaces><lan><if>lo1</if></lan></interfaces><filter/><radvd/><dhcpdv6/>
<OPNsense><unboundplus>''' + ('<general><dnssec>1</dnssec></general>' if dnssec else '') + '''<forwarding><enabled>1</enabled></forwarding>
<advanced><privateaddress>10.0.0.0/8,198.18.0.0/15</privateaddress></advanced>
<dots><dot uuid="owner-dot"><enabled>1</enabled><type>dot</type><domain/><server>192.0.2.53</server><port>853</port></dot></dots>
</unboundplus></OPNsense><cron><item><command>mihomo sub-update</command><minutes>30</minutes><hours>*/12</hours></item></cron></opnsense>''')
ET.indent(config)
ET.ElementTree(config).write('/conf/config.xml')
source = b'''proxies:
- {name: Test, type: socks5, server: 127.0.0.1, port: 18888}
proxy-groups: [{name: Proxy, type: select, proxies: [Test, DIRECT]}]
rules: ["MATCH,DIRECT"]
secret: legacy-secret
external-controller: 127.0.0.1:9090
tun: {enable: true, device: tun_mihomo}
dns: {enable: true, listen: '127.0.0.1:1053', ipv6: false, nameserver: [127.0.0.1], default-nameserver: [127.0.0.1]}
'''
Path('/usr/local/etc/mihomo/config.yaml').write_bytes(source)
Path('/usr/local/etc/mihomo/sub/env').write_text("mihomo_URL='https://example.invalid/private/SENTINEL_TOKEN'\nmihomo_secret='legacy-secret'\n")
Path('/var/unbound/etc/dot.conf').write_text('forward-zone:\n name: "."\n forward-addr: 192.0.2.53@853#gateway.test\n forward-addr: 2001:db8::53@853#gateway.test\n')
Path('/root/actions.log').write_text('')
# A cached prepared filesystem may retain DNS from an earlier failed core.
# Reset the generated private XML's resolver before any package starts a core.
command(['/usr/local/sbin/configctl', 'dns', 'reload'])
assert host_dns_restored()
native_dns_before_core = host_dns_resolver.read_bytes()
# Execute the real upgrade; the old published removal hooks remain unmodified.
# The repository solver sets PKG_UPGRADE and executes the old removal hooks.
new_manifest = json.loads(command(['/usr/bin/tar', '-xOf', '/root/new.pkg', '+MANIFEST']).stdout)
Path('/root/deps').mkdir(exist_ok=True)
Path('/root/empty').mkdir(exist_ok=True)
for name, value in dict(new_manifest['deps'], jq={'origin': 'textproc/jq', 'version': '1.8.1'}).items():
    manifest = dict(new_manifest, name=name, origin=value['origin'], version=value['version'], files={}, scripts={}, deps={}, flatsize=0)
    Path('/root/deps/+MANIFEST').write_text(json.dumps(manifest))
    command(['/usr/local/sbin/pkg', 'create', '-M', '/root/deps/+MANIFEST', '-r', '/root/empty', '-o', '/root/deps'])
    command(['/usr/local/sbin/pkg', 'add', '-f', '/root/deps/' + name + '-' + value['version'] + '.pkg'])
Path('/root/repo/All').mkdir(parents=True, exist_ok=True)
shutil.copyfile('/root/new.pkg', '/root/repo/All/os-mihomo-' + new_manifest['version'] + '.pkg')
command(['/usr/local/sbin/pkg', 'repo', '/root/repo'])
Path('/root/repos').mkdir(exist_ok=True)
Path('/root/repos/test.conf').write_text('test: {url: "file:///root/repo", signature_type: "none", enabled: yes}')
command(['/usr/local/sbin/pkg', '-o', 'REPOS_DIR=/root/repos', 'update', '-f'])
installed = command(['/usr/local/sbin/pkg', '-o', 'RUN_SCRIPTS=true', '-o', 'REPOS_DIR=/root/repos', 'upgrade', '-y', 'os-mihomo'])
print(installed.stdout.decode(errors='replace') + installed.stderr.decode(errors='replace'), flush=True)
settings = json.loads(Path('/var/db/os-mihomo/settings.json').read_text())
assert settings['transparent'] is False
assert settings['state_schema'] == 1
assert settings['transparent_consent'] is False
assert settings['secret'] == 'legacy-secret'
assert Path('/var/db/os-mihomo/subscription.yaml').read_bytes() == source
assert running()
assert command(['/sbin/ifconfig', 'tun_mihomo'], check=False).returncode != 0
assert not action('status')['result']['dns_active']
with socket.create_connection(('127.0.0.1', 7890), timeout=3):
    pass
passed('Actual 1.0.2 upgrade starts proxy ports without TUN or DNS takeover')
root = ET.parse('/conf/config.xml').getroot()
assert root.findtext('./OPNsense/unboundplus/dots/dot[@uuid="owner-dot"]/enabled') == '1'
assert root.findtext('./cron/item/command') == 'mihomo sub-update'
assert not Path('/var/db/os-mihomo/migrate/config.xml').exists()
assert not any(b'MASTER_SECRET_DO_NOT_COPY' in p.read_bytes() for p in Path('/var/db/os-mihomo/migrate').glob('*') if p.is_file())
passed('Upgrade retains subscription/secret/cron without retaining the master secret store')
# Reproduce the old cleanup explicitly even if this pkg version skips that phase.
manifest = command(['/usr/bin/tar', '-xOf', '/root/old.pkg', '+MANIFEST']).stdout.decode()
post = re.search(r'"post-deinstall": <<EOS\n(.*?)\nEOS', manifest, re.S)
assert post
Path('/root/old-post.sh').write_text(post.group(1))
command(['/bin/sh', '/root/old-post.sh'])
time.sleep(4)
assert running()
assert Path('/usr/local/share/mihomo/GeoIP.dat').exists()
assert Path('/var/db/os-mihomo/home/GeoIP.dat').exists()
assert Path('/var/db/os-mihomo/config.yaml').exists()
passed('Unmodified delayed legacy deletion cannot delete new resources or runtime state')
Path('/root/candidate.yaml').write_bytes(source.replace(b'type: socks5', b'type: invalid-protocol'))
before = Path('/var/db/os-mihomo/config.yaml').read_bytes()
action('save-config', '/root/candidate.yaml', ok=False)
assert Path('/var/db/os-mihomo/config.yaml').read_bytes() == before
assert running()
passed('Actual core validator rejects invalid protocol while retaining the active service')
# Configure and start a real isolated resolver; native configuration writes use fixtures.
command(['/usr/local/sbin/configctl', 'template', 'reload', 'OPNsense/Unbound'])
command(['/usr/local/sbin/configctl', 'unbound', 'restart'])
assert_host_dns_restored()
prepare_gateway_cycle()
action('enable-transparent')
assert command(['/sbin/ifconfig', 'tun_mihomo'], check=False).returncode == 0
assert action('status')['result']['dns_active'] == (not dnssec)
assert ET.parse('/conf/config.xml').find('./filter/rule') is not None
passed('Explicit activation creates the actual TUN and owned DNS/interface/firewall configuration')


def assert_validating_resolver_untouched():
    """A validating resolver keeps its upstreams: no journal, zone or edit."""
    unbound = ET.parse('/conf/config.xml').find('./OPNsense/unboundplus')
    assert unbound.findtext('./general/dnssec') == '1'
    assert unbound.findtext('./forwarding/enabled') == '1'
    # Transparent routing forces a real-address DNS mode, which kept this range
    # before as well, so here it only guards against a regression; the unit
    # tests cover the fake-ip and unknown modes that used to remove it.
    assert '198.18.0.0/15' in unbound.findtext('./advanced/privateaddress').split(',')
    assert not Path('/var/db/os-mihomo/dns-state.json').exists()
    assert not Path('/usr/local/etc/unbound.opnsense.d/zz-mihomo.conf').exists()
    status = action('status')['result']
    assert status['dns_active'] is False and 'DNSSEC' in status['dns_note'], status


if dnssec:
    assert_validating_resolver_untouched()
    passed('A validating resolver keeps its upstreams, private addresses and configuration while transparent routing is active')
assert_core_host_dns_marker()
passed('The running no-auto-route core preserves native DNS without creating a host DNS ownership marker')
# The forward zone is a drop-in file, not an entry in the operator's Unbound
# configuration. An entry naming the root as its domain makes OPNsense generate
# domain-insecure: "." beside it -- a negative trust anchor for a zone that
# already has one from auto-trust-anchor-file -- and Unbound then reports the
# anchor for '.' presented twice and refuses to start at all.
zone = Path('/usr/local/etc/unbound.opnsense.d/zz-mihomo.conf')
validating = ET.parse('/conf/config.xml').findtext(
    './OPNsense/unboundplus/general/dnssec') == '1'
assert validating is dnssec
if validating:
    # A validating resolver remains on its native DNS path.
    assert not zone.exists(), 'no forward zone belongs next to a validating resolver'
else:
    assert zone.exists(), 'the forward zone drop-in must be written'
    assert '127.0.0.1@1053' in zone.read_text()
    assert sorted(f.name for f in zone.parent.glob('*.conf'))[-1] == zone.name, \
        'Unbound keeps the last forward zone it reads for a name, so ours must sort last'
assert not (zone.parent / '00-mihomo.conf').exists(), \
    'the legacy name never won the root zone and must not be left behind'
assert ET.parse('/conf/config.xml').find(
    './OPNsense/unboundplus/dots/dot[@uuid="b126bf65-a985-49ca-a9d2-16f156aac198"]') is None, \
    'the plugin must own no entry in the operator Unbound configuration'
insecure = Path('/var/unbound/private_domains.conf')
assert 'domain-insecure: "."' not in (insecure.read_text() if insecure.exists() else '')
passed('Transparent DNS adds no trust anchor for the root of its own')
assert_private_routing(True)
passed('FIB0 keeps native routing while the cold owned FIB copies cyclic numeric gateways and real source-selection PF match rules capture eligible flows')
# dns_active reports that the plumbing was configured. It does not report that a
# query survives the TUN, and on a router it did not: the resolver was listening
# and answering nothing, which is a transport failure rather than an rcode.
import socket as _socket
import struct as _struct
_query = _struct.pack('!HHHHHH', 0x4d49, 0x100, 1, 0, 0, 0) + b'\x07example\x07invalid\x00\x00\x01\x00\x01'
_sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
_sock.settimeout(5)
try:
    _sock.sendto(_query, ('127.0.0.1', 53))
    _reply = _sock.recv(512)
    assert len(_reply) >= 12 and _reply[:2] == _query[:2], _reply[:32]
finally:
    _sock.close()
passed('An actual DNS query reaches the private resolver configured for DNSSEC with transparent routing active' if dnssec
       else 'An actual DNS query reaches the private resolver with transparent integration active')
# Reinstall through the native solver so upgrade suspension and hooks run again.
before_settings = json.loads(Path('/var/db/os-mihomo/settings.json').read_text())
assert before_settings['transparent_consent'] is True
reinstalled = command(['/usr/local/sbin/pkg', '-o', 'RUN_SCRIPTS=true', '-o', 'REPOS_DIR=/root/repos', 'install', '-y', '-f', 'os-mihomo'])
Path('/root/same-version-reinstall.log').write_bytes(reinstalled.stdout + reinstalled.stderr)
assert json.loads(Path('/var/db/os-mihomo/settings.json').read_text()) == before_settings
assert running(), reinstalled.stdout.decode(errors='replace') + reinstalled.stderr.decode(errors='replace')
assert action('status')['result']['dns_active'] == (not dnssec)
if dnssec:
    assert_validating_resolver_untouched()
assert_private_routing(True)
assert_core_host_dns_marker()
passed('Actual same-version reinstall preserves explicit TUN consent and restores its route/DNS policy')
action('stop')
assert_host_dns_restored()
before_settings = json.loads(Path('/var/db/os-mihomo/settings.json').read_text())
assert before_settings['service_enabled'] is False
command(['/usr/local/sbin/pkg', '-o', 'RUN_SCRIPTS=true', '-o', 'REPOS_DIR=/root/repos', 'install', '-y', '-f', 'os-mihomo'])
assert json.loads(Path('/var/db/os-mihomo/settings.json').read_text()) == before_settings
action('boot')
action('wan-restart')
assert not running()
assert not action('status')['result']['dns_active']
assert command(['/sbin/ifconfig', 'tun_mihomo'], check=False).returncode != 0
assert_host_dns_restored()
assert_private_routing(False)
passed('Actual same-version reinstall preserves administrative Stop without WAN or boot resurrection')
action('start')
assert_core_host_dns_marker()
# Test crash handling with actual PID, daemon and split routes.
pid = int(Path('/var/run/mihomo-child.pid').read_text())
os.kill(pid, signal.SIGKILL)
started = time.monotonic()
while time.monotonic() - started < 20:
    status = action('status')['result']
    if (not status['running'] and not status['dns_active']
            and command(['/sbin/ifconfig', 'tun_mihomo'], check=False).returncode != 0
            and host_dns_restored()):
        break
    time.sleep(.5)
else:
    raise AssertionError('Watchdog did not restore private host DNS, clear its marker and remove TUN')
route = command(['/sbin/route', '-n', 'get', '8.8.8.8']).stdout
assert b'tun_mihomo' not in route
assert_private_routing(False)
assert ET.parse('/conf/config.xml').findtext('./OPNsense/unboundplus/dots/dot[@uuid="owner-dot"]/enabled') == '1'
assert_host_dns_restored()
recovery_seconds = time.monotonic() - started
passed('Actual SIGKILL clears owned capture rules, restores private native defaults and removes TUN while native DNS remains usable')
action('start')
action('disable-transparent')
assert ET.parse('/conf/config.xml').find('./filter/rule') is None
assert ET.parse('/conf/config.xml').find('./interfaces/opt0') is None
# Left behind, this file would keep sending every query to a core that is no
# longer forwarding, which is the whole network without DNS.
assert not zone.exists(), 'the forward zone drop-in must be removed'
assert_private_routing(False)
passed('Disabling removes owned interface/firewall entries and keeps proxy ports running')
Path('/root/settings.json').write_text(json.dumps({'router_dns': True}))
action('set-settings', '/root/settings.json')
action('enable-transparent')
assert not action('status')['result']['dns_active']
generated = Path('/var/db/os-mihomo/config.yaml').read_text()
assert 'IP-CIDR,192.0.2.53/32,DIRECT,no-resolve' in generated
assert 'IP-CIDR6,2001:db8::53/128,DIRECT,no-resolve' in generated
assert 'DST-PORT,853,DIRECT' in generated
assert ET.parse('/conf/config.xml').findtext('./OPNsense/unboundplus/dots/dot[@uuid="owner-dot"]/enabled') == '1'
passed('Router DNS uses the actual resolver without forwarding it back to Mihomo')
# An explicit stop still kills the real core and removes routes if configd fails.
Path('/root/fail-configctl').touch()
action('stop', ok=False)
assert not running()
assert command(['/sbin/ifconfig', 'tun_mihomo'], check=False).returncode != 0
assert not json.loads(Path('/var/db/os-mihomo/settings.json').read_text())['service_enabled']
Path('/root/fail-configctl').unlink()
time.sleep(6)
action('wan-restart')
assert not running()
assert_private_routing(False)
passed('Configd failure during Stop cannot leave the core/TUN live; WAN cannot undo Stop')
# Explicit restart fails loudly when the required resolver is unavailable.
command(['/usr/bin/pkill', '-F', '/var/run/unbound.pid'])
time.sleep(.2)
action('start', ok=False)
assert not running()
passed('Unavailable router resolver blocks startup without provider DNS fallback')
action('remove')
stopped_settings = json.loads(Path('/var/db/os-mihomo/settings.json').read_text())
stopped_source = Path('/var/db/os-mihomo/subscription.yaml').read_bytes()
assert stopped_settings['service_enabled'] is False
assert ET.parse('/conf/config.xml').find('./OPNsense/Mihomo/backup') is not None
command(['/usr/local/sbin/pkg', '-o', 'RUN_SCRIPTS=false', 'delete', '-y', 'os-mihomo'])
shutil.rmtree('/var/db/os-mihomo')
shutil.rmtree('/usr/local/etc/mihomo', ignore_errors=True)
command(['/usr/local/sbin/pkg', '-o', 'RUN_SCRIPTS=true', 'add', '-M', '/root/new.pkg'])
assert json.loads(Path('/var/db/os-mihomo/settings.json').read_text()) == stopped_settings
assert Path('/var/db/os-mihomo/subscription.yaml').read_bytes() == stopped_source
action('boot')
action('wan-restart')
assert not running()
assert not action('status')['result']['dns_active']
assert command(['/sbin/ifconfig', 'tun_mihomo'], check=False).returncode != 0
passed('Actual uninstall and erased configuration stores restore administrative Stop from retained XML')
# A retained XML snapshot makes reinstall a restore. Remove only that private
# backup node to exercise an installation with no saved configuration at all.
command(['/usr/local/sbin/pkg', '-o', 'RUN_SCRIPTS=false', 'delete', '-y', 'os-mihomo'])
erase_private_saved_backup('/conf/config.xml')
assert ET.parse('/conf/config.xml').find('./OPNsense/Mihomo/backup') is None
assert ET.parse('/conf/config.xml').findtext('./system/secret') == 'MASTER_SECRET_DO_NOT_COPY'
shutil.rmtree('/var/db/os-mihomo')
shutil.rmtree('/usr/local/etc/mihomo', ignore_errors=True)
command(['/usr/local/sbin/pkg', '-o', 'RUN_SCRIPTS=true', 'add', '-M', '/root/new.pkg'])
assert running()
assert not json.loads(Path('/var/db/os-mihomo/settings.json').read_text())['transparent']
assert not action('status')['result']['dns_active']
assert command(['/sbin/ifconfig', 'tun_mihomo'], check=False).returncode != 0
assert not Path('/var/db/os-mihomo/subscription.yaml').exists()
with socket.create_connection(('127.0.0.1', 7890), timeout=3):
    pass
passed('Actual fresh package installation starts proxy ports without TUN or DNS takeover')
assert_private_routing(False)
report = {'ok': True, 'checks': checks, 'package_sha256': hashlib.sha256(Path('/root/new.pkg').read_bytes()).hexdigest(),
          'package_version': new_manifest['version'], 'crash_recovery_seconds': round(recovery_seconds, 3),
          'unbound_dnssec': dnssec,
          'cold_numeric_gateway_cycle': {'routes': list(gateway_cycle.values()),
                                         'interface': 'lo2', 'active_and_stopped_copy_verified': True},
          'boundary': {'core_pf_private_fib_and_unbound': 'genuine native execution',
                       'configd_filter_context_dns_templates_revision_service': 'synthetic private fixture adapters',
                       'lan_packet_flows': 'not exercised; covered separately by selective TUN packet and host integration tests'}}
Path('/root/test-report.json').write_text(json.dumps(report, indent=2) + '\n')
