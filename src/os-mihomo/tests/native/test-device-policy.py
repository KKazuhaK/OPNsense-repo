#!/usr/bin/env python3
"""Prove device policy does not alter a manually configured proxy connection.

Device policy selects LAN traffic before it enters TUN. This runs a proxy-only
core and makes a real explicit HTTP proxy connection for each saved mode, so a
regression cannot silently inject old SRC-IP-CIDR/DIRECT rules into the Core.

Hermetic: the core binds to loopback on unused ports, has no TUN and no DNS
takeover, and dials an address reserved for documentation, so no external
network and no other Mihomo is involved. Every case must reach the provider's
MATCH rule.

Run on a host with the core installed:  python3 test-device-policy.py
"""
import importlib.util
import json
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'src/usr/local/opnsense/scripts/mihomo'))
sys.path.insert(0, str(ROOT.parent / 'common'))
CORE = Path('/usr/local/bin/mihomo')
SOURCE = '127.0.0.1'
OTHER = '192.0.2.77'
PROXY_PORT = 17890
TARGET = '192.0.2.1:80'          # TEST-NET-1, reserved and unroutable

spec = importlib.util.spec_from_file_location(
    'mihomo', ROOT / 'src/usr/local/opnsense/scripts/mihomo/mihomo.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

SUBSCRIPTION = {
    'proxies': [{'name': 'Node', 'type': 'socks5', 'server': '192.0.2.9', 'port': 1080}],
    'proxy-groups': [{'name': 'Proxy', 'type': 'select', 'proxies': ['Node', 'DIRECT']}],
    'rules': ['MATCH,Proxy'],
}
SETTINGS = dict(m.SWITCH_DEFAULTS, secret='policy-test-secret', device='test',
                subscription_url='', transparent=False, dns_fallback=True,
                service_enabled=True, mixed_port=PROXY_PORT, socks_port=PROXY_PORT + 1,
                bind_address=SOURCE, allow_lan=False)


@unittest.skipUnless(CORE.exists(), 'the core is verified where it is installed')
class DevicePolicyTests(unittest.TestCase):
    def setUp(self):
        self.home = Path(tempfile.mkdtemp(prefix='mihomo-policy-'))
        self.addCleanup(shutil.rmtree, self.home, True)

    def matched(self, mode, listed):
        """The rule the core reports for a connection from SOURCE."""
        settings = dict(SETTINGS, device_mode=mode, device_list=listed)
        config = m.parse_yaml(m.render(dict(SUBSCRIPTION), settings, transparent=False,
                                       overlay={'dns': {'listen': '127.0.0.1:11053'}}))
        config['external-controller'] = '127.0.0.1:19090'
        config['tun'] = {'enable': False}
        config['dns'] = {'enable': False}
        config['log-level'] = 'info'
        # The core refuses a dashboard directory outside its own home.
        for key in ('external-ui', 'external-ui-name', 'external-ui-url'):
            config.pop(key, None)
        (self.home / 'config.yaml').write_text(
            m.yaml.safe_dump(config, sort_keys=False, allow_unicode=True))

        for name in ('GeoIP.dat', 'GeoSite.dat'):
            source = Path('/usr/local/share/mihomo') / name
            if source.exists():
                (self.home / name).symlink_to(source)
        log = self.home / 'core.log'
        stream = log.open('wb')
        core = subprocess.Popen([str(CORE), '-d', str(self.home), '-f', str(self.home / 'config.yaml')],
                                stdout=stream, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                time.sleep(0.2)
                if 'Start initial' in log.read_text(errors='replace') and core.poll() is None:
                    break
            self.assertIsNone(core.poll(), 'the core exited: ' + log.read_text(errors='replace')[-400:])
            time.sleep(1.0)
            subprocess.run(['/usr/local/bin/curl', '--silent', '--max-time', '4', '--output', '/dev/null',
                            '--proxy', 'http://%s:%d' % (SOURCE, PROXY_PORT), 'http://' + TARGET],
                           capture_output=True)
            time.sleep(1.0)
        finally:
            core.send_signal(signal.SIGTERM)
            core.wait(timeout=10)
            stream.close()
        return self.rule(log.read_text(errors='replace'))

    @staticmethod
    def rule(text):
        """The rule the core reports, in either of the two shapes it logs.

        A connection it could open is reported as "match RULE using OUTBOUND".
        One it could not is reported as a dial failure carrying "(match RULE/)"
        instead -- and against a reserved address the proxied cases always end
        that way, so a test that reads only the first shape sees nothing at all
        for exactly the cases it is there to check.
        """
        opened = re.findall(r'\[TCP\] \S+?:\d+(?:\(\S+?\))? --> \S+? match (.+?) using ', text)
        if opened:
            return opened[-1]
        dialled = re.findall(r'\[TCP\] dial \S+ \(match (.+?)/?\) \S+?:\d+ -->', text)
        if dialled:
            return dialled[-1]
        raise AssertionError('no connection reached the core:\n' + text[-600:])

    def steered(self, rule):
        """Whether the device policy decided this connection rather than the rules."""
        return rule.startswith(('SrcIPCIDR', 'NOT(', 'NOT/('))

    def test_all_saved_modes_leave_explicit_proxy_clients_on_provider_rules(self):
        for mode, listed in (('off', []), ('blacklist', [SOURCE]),
                             ('blacklist', [OTHER]), ('whitelist', [SOURCE]),
                             ('whitelist', [OTHER])):
            with self.subTest(mode=mode, listed=listed):
                rule = self.matched(mode, listed)
                self.assertFalse(self.steered(rule), rule)


if __name__ == '__main__':
    unittest.main(verbosity=2)
