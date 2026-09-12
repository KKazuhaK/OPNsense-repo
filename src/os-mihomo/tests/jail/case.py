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
import subprocess
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


checks = []
def passed(name):
    checks.append(name)
    print('PASS:', name, flush=True)


shutil.rmtree('/var/db/os-mihomo', ignore_errors=True)
previous = command(['/usr/local/sbin/pkg', '-o', 'RUN_SCRIPTS=false', 'add', '-f', '-M', '/root/old.pkg'])
print(previous.stdout.decode(errors='replace') + previous.stderr.decode(errors='replace'), flush=True)
config = ET.fromstring('''<opnsense><system><secret>MASTER_SECRET_DO_NOT_COPY</secret></system>
<interfaces><lan><if>lo1</if></lan></interfaces><filter/><radvd/><dhcpdv6/>
<OPNsense><unboundplus><forwarding><enabled>1</enabled></forwarding>
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
shutil.copyfile('/root/new.pkg', '/root/repo/All/os-mihomo-1.1.1.pkg')
command(['/usr/local/sbin/pkg', 'repo', '/root/repo'])
Path('/root/repos').mkdir(exist_ok=True)
Path('/root/repos/test.conf').write_text('test: {url: "file:///root/repo", signature_type: "none", enabled: yes}')
command(['/usr/local/sbin/pkg', '-o', 'REPOS_DIR=/root/repos', 'update', '-f'])
installed = command(['/usr/local/sbin/pkg', '-o', 'RUN_SCRIPTS=true', '-o', 'REPOS_DIR=/root/repos', 'upgrade', '-y', 'os-mihomo'])
print(installed.stdout.decode(errors='replace') + installed.stderr.decode(errors='replace'), flush=True)
settings = json.loads(Path('/var/db/os-mihomo/settings.json').read_text())
assert settings['transparent'] is False
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
action('enable-transparent')
assert command(['/sbin/ifconfig', 'tun_mihomo'], check=False).returncode == 0
assert action('status')['result']['dns_active']
assert ET.parse('/conf/config.xml').find('./filter/rule') is not None
passed('Explicit activation creates the actual TUN and owned DNS/interface/firewall configuration')
route = command(['/sbin/route', '-n', 'get', '8.8.8.8']).stdout
assert b'tun_mihomo' in route, route
passed('VNET traffic route is captured only after explicit activation')
# Test crash handling with actual PID, daemon and split routes.
pid = int(Path('/var/run/mihomo-child.pid').read_text())
os.kill(pid, signal.SIGKILL)
started = time.monotonic()
while time.monotonic() - started < 20:
    status = action('status')['result']
    if not status['running'] and not status['dns_active'] and command(['/sbin/ifconfig', 'tun_mihomo'], check=False).returncode != 0:
        break
    time.sleep(.5)
else:
    raise AssertionError('Watchdog did not restore DNS and remove TUN')
route = command(['/sbin/route', '-n', 'get', '8.8.8.8']).stdout
assert b'tun_mihomo' not in route
assert ET.parse('/conf/config.xml').findtext('./OPNsense/unboundplus/dots/dot[@uuid="owner-dot"]/enabled') == '1'
recovery_seconds = time.monotonic() - started
passed('Actual SIGKILL triggers watchdog DNS restoration and TUN route teardown')
action('start')
action('disable-transparent')
assert ET.parse('/conf/config.xml').find('./filter/rule') is None
assert ET.parse('/conf/config.xml').find('./interfaces/opt0') is None
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
passed('Configd failure during Stop cannot leave the core/TUN live; WAN cannot undo Stop')
# Explicit restart fails loudly when the required resolver is unavailable.
command(['/usr/bin/pkill', '-F', '/var/run/unbound.pid'])
time.sleep(.2)
action('start', ok=False)
assert not running()
passed('Unavailable router resolver blocks startup without provider DNS fallback')
action('remove')
command(['/usr/local/sbin/pkg', '-o', 'RUN_SCRIPTS=false', 'delete', '-y', 'os-mihomo'])
shutil.rmtree('/var/db/os-mihomo')
command(['/usr/local/sbin/pkg', '-o', 'RUN_SCRIPTS=true', 'add', '-M', '/root/new.pkg'])
assert running()
assert not json.loads(Path('/var/db/os-mihomo/settings.json').read_text())['transparent']
assert not action('status')['result']['dns_active']
assert command(['/sbin/ifconfig', 'tun_mihomo'], check=False).returncode != 0
assert not Path('/var/db/os-mihomo/subscription.yaml').exists()
with socket.create_connection(('127.0.0.1', 7890), timeout=3):
    pass
passed('Actual fresh package installation starts proxy ports without TUN or DNS takeover')
report = {'ok': True, 'checks': checks, 'package_sha256': hashlib.sha256(Path('/root/new.pkg').read_bytes()).hexdigest(), 'crash_recovery_seconds': round(recovery_seconds, 3)}
Path('/root/test-report.json').write_text(json.dumps(report, indent=2) + '\n')
