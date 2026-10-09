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
        # Tables are numbered in device order, and the client LAN's epair sorts first.
        table = re.search(r'match in on lo1 inet proto tcp from <(mihomo_sources_[0-9]+)>', anchor)
        assert table, anchor
        sources = command(['/sbin/pfctl', '-a', 'mihomo', '-t', table.group(1), '-T', 'show']).stdout
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


# run.sh wires an epair between this router and a client jail: 10.60.0.1 here,
# 10.60.0.2 and 10.60.0.3 there. Only Mihomo's hosts know mihomo-only.test;
# the router's Unbound answers it with NXDOMAIN.
client_if = os.environ['MIHOMO_JAIL_CLIENT_IF']
ROUTER_LAN, LISTED, UNLISTED = '10.60.0.1', '10.60.0.2', '10.60.0.3'
MIHOMO_ANSWER = {'rcode': 0, 'addresses': ['192.0.2.30']}
UNBOUND_ANSWER = {'rcode': 3, 'addresses': []}
client_directory = Path('/root/dns-client')


def client_query(source, name, transport='udp', timeout=2.0):
    """Ask the router's LAN address from the client jail, through the helper running there."""
    identifier = '%d-%d' % (os.getpid(), time.monotonic_ns())
    requests, answers = client_directory / 'requests', client_directory / 'answers'
    requests.mkdir(parents=True, exist_ok=True)
    answers.mkdir(parents=True, exist_ok=True)
    temporary = requests / ('.' + identifier)
    temporary.write_text(json.dumps({'source': source, 'server': ROUTER_LAN, 'name': name,
                                     'transport': transport, 'timeout': timeout}))
    os.replace(temporary, requests / (identifier + '.json'))
    answer = answers / (identifier + '.json')
    deadline = time.monotonic() + timeout + 10
    while time.monotonic() < deadline:
        if answer.exists():
            value = json.loads(answer.read_text())
            answer.unlink()
            return value
        time.sleep(.05)
    log = Path('/root/dns-client.log')
    raise AssertionError('The LAN client jail ran no query: ' + (log.read_text()[-2000:] if log.exists() else ''))


def local_rcode(server, name):
    """The response code this router's own lookup of name gets from server port 53."""
    query = (b'\x4d\x4a\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
             + b''.join(bytes([len(label)]) + label.encode() for label in name.split('.')) + b'\x00\x00\x01\x00\x01')
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(5)
        client.connect((server, 53))
        client.send(query)
        reply = client.recv(512)
    assert len(reply) >= 12 and reply[:2] == query[:2], reply[:32]
    return reply[3] & 0x0F


# What one poll of wait_for() with a one-second client query can add to a
# measured time: the query that timed out, the pause, and the one that answered.
POLL_ALLOWANCE = 2.0
# The acceptance bounds on withdrawing the DNS redirect from a core.
CRASH_WITHDRAWAL, STALL_WITHDRAWAL = 10.0, 20.0


def wait_for(check, seconds, message):
    """Seconds until check() holds, polled twice a second."""
    started = time.monotonic()
    while time.monotonic() - started < seconds:
        if check():
            return time.monotonic() - started
        time.sleep(.5)
    raise AssertionError(message)


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
shutil.rmtree(client_directory, ignore_errors=True)
previous = command(['/usr/local/sbin/pkg', '-o', 'RUN_SCRIPTS=false', 'add', '-f', '-M', '/root/old.pkg'])
print(previous.stdout.decode(errors='replace') + previous.stderr.decode(errors='replace'), flush=True)
config = ET.fromstring('''<opnsense><system><secret>MASTER_SECRET_DO_NOT_COPY</secret></system>
<interfaces><lan><if>lo1</if></lan><guest><if>''' + client_if + '''</if><enable>1</enable><descr>Client LAN</descr></guest></interfaces>
<filter/><radvd/><dhcpdv6/>
<OPNsense><unboundplus>''' + ('<general><dnssec>1</dnssec></general>' if dnssec else '') + '''<forwarding><enabled>1</enabled></forwarding>
<advanced><privateaddress>10.0.0.0/8,198.18.0.0/15</privateaddress></advanced>
<hosts><host uuid="jail-host"><enabled>1</enabled><hostname>policy</hostname><domain>test</domain><rr>A</rr><server>192.0.2.20</server></host></hosts>
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
hosts: {mihomo-only.test: 192.0.2.30}
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
# An upgrade keeps answering every client through Mihomo, as before.
assert settings['dns_scope'] == 'all'
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
assert action('status')['result']['dns_scope'] == ('off' if dnssec else 'all')
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


def restarted_core():
    """Whether a core other than the killed one runs, as the status action sees it once the watchdog's tick ends."""
    try:
        return running() and int(Path('/var/run/mihomo-child.pid').read_text()) != pid
    except (OSError, ValueError):
        return False


# Nobody stopped that core, so the watchdog starts it again ten seconds after
# it noticed the exit, through the start action's own path.
wait_for(restarted_core, 60, 'The watchdog did not restart a core that exited without a stop')
automatic_restart_seconds = time.monotonic() - started
status = action('status')['result']
assert status['running'] and status['routing_active'] and status['error'] == '', status
assert status['last_restart']['reason'] == 'exited unexpectedly', status
assert status['restart_note'].endswith('(exited unexpectedly).'), status
restart_log = Path('/var/log/mihomo.log').read_text()
assert 'Mihomo stopped (exited unexpectedly); restarting it automatically in 10 seconds.' in restart_log
assert 'Mihomo restarted automatically.' in restart_log
assert_private_routing(True)
assert_core_host_dns_marker()
# The resident size the status reads from kern.proc.pid is the one ps reports.
restarted_pid = int(Path('/var/run/mihomo-child.pid').read_text())
resident = int(command(['/bin/ps', '-o', 'rss=', '-p', str(restarted_pid)]).stdout) * 1024
assert isinstance(status['core_memory'], int) and abs(status['core_memory'] - resident) <= max(resident // 5, 8 << 20), \
    (status['core_memory'], resident)
physical = int(command(['/sbin/sysctl', '-n', 'hw.physmem']).stdout)
assert status['core_memory_limit'] == physical // 2, status
passed('The watchdog restarts a core that exited without a stop, with capture and DNS as after Start')
# The stale-connection scan reads the kernel's view with the installed module's
# unchanged netstat call and parser, which also require the listener's own
# LISTEN line in real output. The server side of a real loopback connection to
# the core's mixed port exists as soon as the handshake ends, so it is listed
# under the client's endpoint whether or not the core accepted it.
if '/usr/local/opnsense/scripts/mihomo' not in sys.path:
    sys.path.insert(0, '/usr/local/opnsense/scripts/mihomo')
native_spec = importlib.util.spec_from_file_location('native_mihomo', '/usr/local/opnsense/scripts/mihomo/mihomo.py')
native_manager = importlib.util.module_from_spec(native_spec)
native_spec.loader.exec_module(native_manager)
with socket.create_connection(('127.0.0.1', 7890), timeout=3) as client:
    client_endpoint = client.getsockname()[:2]
    listed_sockets = native_manager.System().redirect_sockets(7890)
assert listed_sockets.get(client_endpoint) == {'ESTABLISHED'}, (client_endpoint, listed_sockets)
passed('netstat lists the core\'s loopback sockets by client endpoint as the stale-connection scan reads them')
# tcpdrop as the scan runs it, on a socket shaped like the leak: a loopback
# listener's accepted socket in FIN_WAIT_2 whose owner still reads it, because
# that side finished sending and the client never does. The listener and both
# ends are this test's own, so nothing the core or another service holds is
# touched.
native_system = native_manager.System()
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as held_listener:
    held_listener.bind(('127.0.0.1', 0))
    held_listener.listen(1)
    held_port = held_listener.getsockname()[1]
    with socket.create_connection(('127.0.0.1', held_port), timeout=3) as held_client:
        held_endpoint = held_client.getsockname()[:2]
        held_server, _ = held_listener.accept()
        with held_server:
            held_server.shutdown(socket.SHUT_WR)
            wait_for(lambda: native_system.redirect_sockets(held_port).get(held_endpoint) == {'FIN_WAIT_2'}, 10,
                     'The accepted socket did not reach FIN_WAIT_2 after its owner finished sending')
            native_system.drop_redirect_socket(held_port, held_endpoint)
            # The read the core's relay blocks in ends at once. ECONNABORTED is
            # what the kernel sets on the socket tcpdrop dropped, so it also
            # shows the listener's side was dropped rather than the client's,
            # whose reset would read ECONNRESET here.
            held_server.settimeout(3)
            try:
                held_server.recv(1)
            except ConnectionAbortedError:
                pass
            else:
                raise AssertionError('The dropped socket did not wake its reader with ECONNABORTED')
            assert native_system.redirect_sockets(held_port).get(held_endpoint, set()) <= {'CLOSED'}
            # The kernel no longer finds a dropped socket, so a second drop
            # fails with ESRCH, which the module tells apart as a socket that
            # has already ended, and its error does not name the socket.
            try:
                native_system.drop_redirect_socket(held_port, held_endpoint)
            except native_manager.NoSuchSocketError as error:
                assert str(error) == 'tcpdrop exited with status 1: No such process', str(error)
            else:
                raise AssertionError('tcpdrop did not report a socket it had already dropped as not found')
passed('tcpdrop drops a loopback FIN_WAIT_2 socket by its four-tuple and wakes the reader holding it')
action('start')
action('disable-transparent')
assert ET.parse('/conf/config.xml').find('./filter/rule') is None
assert ET.parse('/conf/config.xml').find('./interfaces/opt0') is None
# Left behind, this file would keep sending every query to a core that is no
# longer forwarding, which is the whole network without DNS.
assert not zone.exists(), 'the forward zone drop-in must be removed'
assert_private_routing(False)
passed('Disabling removes owned interface/firewall entries and keeps proxy ports running')
Path('/root/settings.json').write_text(json.dumps({'dns_scope': 'off'}))
action('set-settings', '/root/settings.json')
action('enable-transparent')
status = action('status')['result']
assert status['dns_active'] is False and status['dns_scope'] == 'off', status
assert not zone.exists(), 'a DNS scope of off must not write the forward zone'
assert ET.parse('/conf/config.xml').findtext('./OPNsense/unboundplus/forwarding/enabled') == '1'
assert_private_routing(True)
passed('A DNS scope of off leaves Unbound on its own upstreams while transparent routing is active')
Path('/root/settings.json').write_text(json.dumps({'dns_scope': 'all'}))
action('set-settings', '/root/settings.json')
status = action('status')['result']
assert status['dns_active'] == (not dnssec) and status['dns_scope'] == ('off' if dnssec else 'all'), status
assert zone.exists() == (not dnssec)
action('disable-transparent')
assert not zone.exists()
passed('Returning the DNS scope to all devices restores the resolver-wide integration')
# Captured devices only: a whitelist of one client address on the client LAN.
Path('/root/settings.json').write_text(json.dumps(
    {'dns_scope': 'captured', 'device_mode': 'whitelist', 'device_list': [LISTED + '/32']}))
action('set-settings', '/root/settings.json')
action('enable-transparent')
status = action('status')['result']
assert status['dns_active'] is False and status['dns_scope'] == 'captured', status
assert not zone.exists(), 'a captured scope must not write the forward zone'
assert ET.parse('/conf/config.xml').findtext('./OPNsense/unboundplus/forwarding/enabled') == '1'
# The start probed the real core over its loopback listener and armed the
# redirect with the first routing enable; failing that, the watchdog arms it.
wait_for(lambda: action('status')['result']['dns_redirect'] is True, 20, 'The DNS redirect was never armed')
health = Path('/var/run/mihomo-dns-health.json')
assert health.stat().st_mode & 0o777 == 0o600
verdict = json.loads(health.read_text())
assert verdict['healthy'] is True, verdict
assert verdict['core']['pid'] == int(Path('/var/run/mihomo-child.pid').read_text().strip()), verdict
status = action('status')['result']
# A validating resolver still allows the redirect; the note says what is not validated.
assert ('DNSSEC' in status['dns_note']) if dnssec else status['dns_note'] == '', status
translation = command(['/sbin/pfctl', '-a', 'mihomo', '-sn']).stdout.decode()
for protocol in ('udp', 'tcp'):
    assert re.search(r'(?m)^rdr on %s inet proto %s from <mihomo_sources_[0-9]+> to <mihomo_self> '
                     r'port = (?:53|domain) -> 127\.0\.0\.1 port 1053$' % (re.escape(client_if), protocol),
                     translation), translation
assert ' on lo1 ' not in translation, 'the whitelist leaves lo1 without captured sources'
own = command(['/sbin/pfctl', '-a', 'mihomo', '-t', 'mihomo_self', '-T', 'show']).stdout.decode().split()
assert ROUTER_LAN in own and '192.0.2.10' in own and not any(value.startswith('127.') for value in own), own
passed('A captured scope arms the router-bound DNS redirect for the listed source only and leaves Unbound alone')
for transport in ('udp', 'tcp'):
    answer = client_query(LISTED, 'mihomo-only.test', transport)
    assert answer == MIHOMO_ANSWER, (transport, answer)
    answer = client_query(UNLISTED, 'mihomo-only.test', transport)
    assert answer == UNBOUND_ANSWER, (transport, answer)
states = command(['/sbin/pfctl', '-ss', '-vv']).stdout.decode()
for protocol in ('udp', 'tcp'):
    assert re.search(r'%s 127\.0\.0\.1:1053 \(10\.60\.0\.1:53\) <- 10\.60\.0\.2:' % protocol, states), states
assert not re.search(r'127\.0\.0\.1:1053 \(\S+\) <- 10\.60\.0\.3:', states), states
# The router itself keeps its own resolver.
assert local_rcode('127.0.0.1', 'mihomo-only.test') == UNBOUND_ANSWER['rcode']
assert local_rcode(ROUTER_LAN, 'mihomo-only.test') == UNBOUND_ANSWER['rcode']
passed('The listed client asking the router is answered by Mihomo over UDP and TCP; the unlisted client and the router itself by Unbound')
# Local names reach the router DNS through Mihomo: the Unbound host override
# policy.test and the private reverse zones lead Mihomo's policy.
generated = Path('/var/db/os-mihomo/config.yaml').read_text()
assert re.search(r"(?m)^    \+\.policy\.test:\n    - 127\.0\.0\.1$", generated), generated
assert '+.168.192.in-addr.arpa' in generated and '+.in-addr.arpa' not in generated
assert client_query(LISTED, 'policy.test') == {'rcode': 0, 'addresses': ['192.0.2.20']}
passed('Local names of a captured client reach the router DNS through the generated policy')
# A crash withdraws the redirect whatever the DNS recovery policy says.
pid = int(Path('/var/run/mihomo-child.pid').read_text())
os.kill(pid, signal.SIGKILL)
killed_seconds = wait_for(lambda: client_query(LISTED, 'mihomo-only.test', timeout=1) == UNBOUND_ANSWER, 30,
                          'The watchdog did not hand the listed client back to the router DNS after SIGKILL')
assert killed_seconds <= CRASH_WITHDRAWAL + POLL_ALLOWANCE, killed_seconds
assert not command(['/sbin/pfctl', '-a', 'mihomo', '-sn']).stdout.strip()
assert '127.0.0.1:1053 (' not in command(['/sbin/pfctl', '-ss', '-vv']).stdout.decode()
status = action('status')['result']
assert status['running'] is False and status['dns_redirect'] is False, status
# The watchdog restarts the core ten seconds after it noticed the exit; the
# Start below comes first and makes that restart itself. The client is handed
# back as soon as the redirect is withdrawn, which happens before the same
# tick restores DNS and publishes the scheduled restart, so wait for the
# notice instead of reading it once.
wait_for(lambda: 'is restarted automatically at about' in action('status')['result']['error'], 8,
         'The watchdog did not publish the scheduled restart after SIGKILL')
assert not health.exists()
assert not zone.exists() and ET.parse('/conf/config.xml').findtext('./OPNsense/unboundplus/forwarding/enabled') == '1'
passed('Actual SIGKILL withdraws the DNS redirect and its states; the listed client is answered by Unbound again')
action('start')
started_seconds = wait_for(lambda: client_query(LISTED, 'mihomo-only.test', timeout=1) == MIHOMO_ANSWER, 30,
                           'Starting the service again did not re-arm the DNS redirect')
passed('Starting the service again re-arms the DNS redirect for the new core')
# A core that stops answering is withdrawn by the watchdog alone, and re-armed
# once it answers again, without a restart.
pid = int(Path('/var/run/mihomo-child.pid').read_text())
os.kill(pid, signal.SIGSTOP)
try:
    stalled_seconds = wait_for(lambda: client_query(LISTED, 'mihomo-only.test', timeout=1) == UNBOUND_ANSWER, 60,
                               'The watchdog did not withdraw the DNS redirect from a stalled core')
    assert stalled_seconds <= STALL_WITHDRAWAL + POLL_ALLOWANCE, stalled_seconds
    status = action('status')['result']
    assert status['running'] is True and status['dns_redirect'] is False, status
    assert status['dns_note'].startswith('Paused: Mihomo DNS stopped answering'), status
finally:
    os.kill(pid, signal.SIGCONT)
resumed_seconds = wait_for(lambda: client_query(LISTED, 'mihomo-only.test', timeout=1) == MIHOMO_ANSWER, 90,
                           'The watchdog did not re-arm the DNS redirect once the core answered again')
assert int(Path('/var/run/mihomo-child.pid').read_text()) == pid
assert action('status')['result']['dns_redirect'] is True
log = Path('/var/log/mihomo.log').read_text()
assert 'DNS redirect withdrawn (Mihomo DNS stopped answering)' in log and 'DNS redirect armed' in log
passed('A stalled core is withdrawn by the watchdog and re-armed once it answers, without a restart')
# IPv6 reaching captured devices. The router offers DHCPv6 on the client LAN,
# and a global address appears on it later, as a delegated prefix does after
# boot. The listed client keeps asking the router DNS throughout each change.
GLOBAL_LAN = '2001:470:ffff:60::1'
scope_record = Path('/var/db/os-mihomo/dns-scope.json')
mihomo_log = Path('/var/log/mihomo.log')


def asking(done, seconds, message):
    """Seconds until done() holds while the listed client asks the router DNS, and which asks went unanswered."""
    started = time.monotonic()
    unanswered = []
    while time.monotonic() - started < seconds:
        answer = client_query(LISTED, 'mihomo-only.test', timeout=1)
        if 'rcode' not in answer:
            unanswered.append(round(time.monotonic() - started, 1))
        if done():
            return time.monotonic() - started, unanswered
        time.sleep(.5)
    raise AssertionError(message + ': ' + json.dumps(action('status')['result']))


def scope_now():
    status = action('status')['result']
    return status['dns_scope'], status['dns_active'], status['dns_redirect']


def log_since(offset):
    with mihomo_log.open('rb') as stream:
        stream.seek(offset)
        return stream.read().decode(errors='replace')


def core_pid():
    return int(Path('/var/run/mihomo-child.pid').read_text())


def set_offer(offered):
    xml = ET.parse('/conf/config.xml')
    table = xml.find('dhcpdv6')
    for entry in list(table):
        table.remove(entry)
    if offered:
        ET.SubElement(ET.SubElement(table, 'guest'), 'enable').text = '1'
    xml.write('/conf/config.xml')


def rdr_1053():
    return 'port 1053' in command(['/sbin/pfctl', '-a', 'mihomo', '-sn']).stdout.decode()


log_offset = mihomo_log.stat().st_size
pid = core_pid()
set_offer(True)
time.sleep(12)
assert scope_now() == ('captured', False, True), action('status')['result']
assert core_pid() == pid, 'an IPv6 offer alone must not restart the service'
passed('An IPv6 offer without a global address on a captured interface leaves the captured scope running')
command(['/sbin/ifconfig', client_if, 'inet6', GLOBAL_LAN, 'prefixlen', '64', 'alias'])
ipv6_seconds = {}
if not dnssec:
    ipv6_seconds['to_all'], unanswered = asking(lambda: scope_now() == ('all', True, False), 90,
                                                'The watchdog did not move to every device once IPv6 reached captured devices')
    # Two looks five seconds apart, a restart, and the zone's Unbound restart.
    assert ipv6_seconds['to_all'] <= 40 + POLL_ALLOWANCE, ipv6_seconds
    assert len(unanswered) <= 2, unanswered
    ipv6_seconds['unanswered_to_all'] = unanswered
    status = action('status')['result']
    assert status['dns_note'].startswith('"Only devices captured by transparent routing" is running as "All devices"'), status
    assert zone.exists() and not rdr_1053()
    assert json.loads(scope_record.read_text())['ipv6_reaching'] is True
    log = log_since(log_offset)
    assert 'DNS scope: this router is now giving captured devices IPv6 addresses' in log, log
    assert 'DNS scope: Mihomo now answers every device.' in log, log
    passed('A global address on a captured interface moves the scope to every device within about 40 seconds, '
           'answering the listed client throughout')
    # A WAN reconnect restarts before the prefix is back: the start keeps every device.
    command(['/sbin/ifconfig', client_if, 'inet6', GLOBAL_LAN, '-alias'])
    action('wan-restart')
    assert scope_now() == ('all', True, False), action('status')['result']
    assert json.loads(scope_record.read_text())['ipv6_reaching'] is True
    passed('A restart that finds the prefix gone keeps every device instead of deciding from one look')
    # Gone for good: confirmed, then held with one note; no restart meanwhile.
    pid = core_pid()
    wait_for(lambda: action('status')['result']['dns_note'].startswith(
        '"Only devices captured by transparent routing" is still running as "All devices"'), 60,
        'The wait back to captured devices was never reported')
    time.sleep(60)
    assert scope_now() == ('all', True, False) and core_pid() == pid, action('status')['result']
    passed('The way back to captured devices is held with a note, without restarting the service')
    # The wait itself is the unit tests'; here the change it ends in is real.
    record = json.loads(scope_record.read_text())
    record['changed'] = time.monotonic() - 700
    temporary = scope_record.with_name('.dns-scope-test')
    temporary.write_text(json.dumps(record) + '\n')
    temporary.chmod(0o600)
    os.replace(temporary, scope_record)
    log_offset = mihomo_log.stat().st_size
    ipv6_seconds['to_captured'], unanswered = asking(lambda: scope_now() == ('captured', False, True), 90,
                                                     'The watchdog did not return to captured devices')
    assert len(unanswered) <= 2, unanswered
    ipv6_seconds['unanswered_to_captured'] = unanswered
    assert not zone.exists() and rdr_1053()
    assert client_query(LISTED, 'mihomo-only.test') == MIHOMO_ANSWER
    log = log_since(log_offset)
    assert 'DNS scope: Mihomo now answers captured devices.' in log, log
    passed('Once the wait is over the scope returns to captured devices, re-arming the redirect once the new core answers')
else:
    # A validating resolver would decline every device: nothing restarts, and
    # the status says what reaches captured devices.
    time.sleep(45)
    status = action('status')['result']
    assert scope_now() == ('captured', False, True) and core_pid() == pid, status
    assert 'Answering every device instead is not possible while Unbound validates DNSSEC' in status['dns_note'], status
    assert json.loads(scope_record.read_text()).get('ipv6_dnssec') is True
    assert client_query(LISTED, 'mihomo-only.test') == MIHOMO_ANSWER
    command(['/sbin/ifconfig', client_if, 'inet6', GLOBAL_LAN, '-alias'])
    wait_for(lambda: 'validates DNSSEC, so captured' not in action('status')['result']['dns_note'], 60,
             'The IPv6 note outlived the address')
    passed('With a validating resolver a captured scope stays captured when IPv6 reaches its devices, and says so')
# A watchdog that died half way through a change leaves its journal; the next
# one, started by a GUI start, settles it with a restart.
move = Path('/var/db/os-mihomo/dns-scope-move')
move.write_text('{"ipv6_reaching": false}\n')
move.chmod(0o600)
pid = core_pid()
log_offset = mihomo_log.stat().st_size
command(['/usr/bin/pkill', '-F', '/var/run/mihomo-watch.pid'])
wait_for(lambda: command(['/bin/pgrep', '-F', '/var/run/mihomo-watch.pid'], check=False).returncode != 0, 20,
         'The watchdog did not exit')
action('start')
ipv6_seconds['settled'], unanswered = asking(lambda: not move.exists() and core_pid() != pid
                                             and scope_now() == ('captured', False, True), 90,
                                             'The next watchdog did not settle the unfinished change')
assert len(unanswered) <= 2, unanswered
assert 'a scope change the previous watchdog did not finish' in log_since(log_offset)
# With the core gone instead, the next tick restores direct DNS and settles it.
move.write_text('{"ipv6_reaching": true}\n')
os.kill(core_pid(), signal.SIGKILL)
wait_for(lambda: not move.exists() and action('status')['result']['running'] is False, 30,
         'The watchdog did not settle an unfinished change of a stopped core')
assert not zone.exists() and ET.parse('/conf/config.xml').findtext('./OPNsense/unboundplus/forwarding/enabled') == '1'
assert client_query(LISTED, 'mihomo-only.test') == UNBOUND_ANSWER
action('start')
wait_for(lambda: scope_now() == ('captured', False, True), 60, 'The captured scope did not come back')
passed('An unfinished scope change is settled by the next watchdog: a restart for a running core, '
       'direct DNS for a stopped one')
set_offer(False)
action('disable-transparent')
assert not health.exists(), 'stopping the core must forget its DNS verdict'
assert not command(['/sbin/pfctl', '-a', 'mihomo', '-sn']).stdout.strip()
assert client_query(LISTED, 'mihomo-only.test') == UNBOUND_ANSWER
Path('/root/settings.json').write_text(json.dumps({'dns_scope': 'all', 'device_mode': 'off', 'device_list': []}))
action('set-settings', '/root/settings.json')
dns_redirect_seconds = {'withdrawn_after_sigkill': round(killed_seconds, 3),
                        'rearmed_after_start': round(started_seconds, 3),
                        'withdrawn_after_sigstop': round(stalled_seconds, 3),
                        'rearmed_after_sigcont': round(resumed_seconds, 3)}
passed('Disabling transparent routing withdraws the DNS redirect with it')
Path('/root/settings.json').write_text(json.dumps({'router_dns': True}))
action('set-settings', '/root/settings.json')
action('enable-transparent')
status = action('status')['result']
assert not status['dns_active']
# All devices with router DNS would loop; it counts as off, stored unchanged.
assert status['dns_scope'] == 'off' and 'loop' in status['dns_note'], status
assert json.loads(Path('/var/db/os-mihomo/settings.json').read_text())['dns_scope'] == 'all'
generated = Path('/var/db/os-mihomo/config.yaml').read_text()
assert 'IP-CIDR,192.0.2.53/32,DIRECT,no-resolve' in generated
assert 'IP-CIDR6,2001:db8::53/128,DIRECT,no-resolve' in generated
assert 'DST-PORT,853,DIRECT' in generated
assert ET.parse('/conf/config.xml').findtext('./OPNsense/unboundplus/dots/dot[@uuid="owner-dot"]/enabled') == '1'
passed('Router DNS uses the actual resolver without forwarding it back to Mihomo')
# Router DNS refuses an IPv6 offer while Mihomo IPv6 is off, unless the
# administrator declares that captured devices get no IPv6: then transparent
# routing activates, and the status notes the offer instead of an error.
action('disable-transparent')
set_offer(True)
refused = action('enable-transparent', ok=False)
assert 'offered IPv6 while Mihomo IPv6 is disabled' in refused['error'], refused
assert action('status')['result']['routing_active'] is False
Path('/root/settings.json').write_text(json.dumps({'ipv6_clients_restricted': True}))
action('set-settings', '/root/settings.json')
action('enable-transparent')
# Two watchdog ticks, and neither turns the declared offer back into an error.
time.sleep(12)
status = action('status')['result']
assert status['running'] and status['routing_active'] and status['error'] == '', status
assert status['dns_scope'] == 'off' and not status['dns_active'], status
assert 'declares that captured devices get no IPv6' in status['dns_note'], status
set_offer(False)
Path('/root/settings.json').write_text(json.dumps({'ipv6_clients_restricted': False}))
action('set-settings', '/root/settings.json')
passed('Router DNS activates with an IPv6 offer only while captured devices are declared to get no IPv6, and notes it')
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
# Only a fresh installation starts with the captured scope.
assert json.loads(Path('/var/db/os-mihomo/settings.json').read_text())['dns_scope'] == 'captured'
assert not action('status')['result']['dns_active']
assert command(['/sbin/ifconfig', 'tun_mihomo'], check=False).returncode != 0
assert not Path('/var/db/os-mihomo/subscription.yaml').exists()
with socket.create_connection(('127.0.0.1', 7890), timeout=3):
    pass
passed('Actual fresh package installation starts proxy ports without TUN or DNS takeover')
assert_private_routing(False)
report = {'ok': True, 'checks': checks, 'package_sha256': hashlib.sha256(Path('/root/new.pkg').read_bytes()).hexdigest(),
          'package_version': new_manifest['version'], 'crash_recovery_seconds': round(recovery_seconds, 3),
          'automatic_restart_seconds': round(automatic_restart_seconds, 3),
          'unbound_dnssec': dnssec, 'dns_redirect_seconds': dns_redirect_seconds, 'ipv6_scope_seconds': ipv6_seconds,
          'cold_numeric_gateway_cycle': {'routes': list(gateway_cycle.values()),
                                         'interface': 'lo2', 'active_and_stopped_copy_verified': True},
          'boundary': {'core_pf_private_fib_and_unbound': 'genuine native execution',
                       'configd_filter_context_dns_templates_revision_service': 'synthetic private fixture adapters',
                       'router_bound_dns': 'genuine PF redirect from an epair client jail, listed and unlisted',
                       'lan_packet_flows': 'otherwise not exercised; covered separately by selective TUN packet and host integration tests'}}
Path('/root/test-report.json').write_text(json.dumps(report, indent=2) + '\n')
