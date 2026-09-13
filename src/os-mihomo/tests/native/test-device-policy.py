#!/usr/bin/env python3
"""Prove the device policy steers a real connection, not just a rendered rule.

The unit tests check which rules are generated and `mihomo -t` checks the core
accepts them. Neither says a listed device is actually treated differently, so
this runs a core of its own and makes a connection through it.

Hermetic: the core binds to loopback on unused ports, has no TUN and no DNS
takeover, and dials an address reserved for documentation, so no network and no
other Mihomo is involved. What is asserted is which rule the core reports
matching -- the exit cannot tell the cases apart when the node selector sits on
DIRECT, but the rule always can.

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
        return rule.startswith(('SrcIPCIDR', 'NOT('))

    def test_a_blacklisted_device_is_forced_direct(self):
        self.assertTrue(self.steered(self.matched('blacklist', [SOURCE])))

    def test_a_device_missing_from_the_blacklist_follows_the_rules(self):
        self.assertFalse(self.steered(self.matched('blacklist', [OTHER])))

    def test_a_whitelisted_device_follows_the_rules(self):
        self.assertFalse(self.steered(self.matched('whitelist', [SOURCE])))

    def test_a_device_missing_from_the_whitelist_is_forced_direct(self):
        # The inverted form is the one worth proving: a whitelist cannot be
        # written as a match on the listed devices, because matching stops at
        # the first rule that matches.
        self.assertTrue(self.steered(self.matched('whitelist', [OTHER])))


if __name__ == '__main__':
    unittest.main(verbosity=2)
