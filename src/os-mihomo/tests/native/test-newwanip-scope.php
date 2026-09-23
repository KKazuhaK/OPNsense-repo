<?php
/* Only WAN-like address events restart the core, across multi-WAN and multi-LAN layouts. */
require_once($argv[1] ?? dirname(__DIR__, 2) . '/src/usr/local/etc/inc/plugins.inc.d/mihomo.inc');

/* The firewall mapping as filter.lib.inc hands it over: gateways are already
   resolved, including the dynamic ones of DHCP and PPPoE interfaces. */
$mapping = [
    'wan' => ['if' => 'igc1'],                                     /* DHCP, name alone marks it */
    'opt1' => ['if' => 'igc2', 'gateway' => '203.0.113.1'],        /* second WAN, DHCP gateway resolved */
    'opt2' => ['if' => 'pppoe0', 'gateway' => '192.0.2.2'],        /* third WAN over PPPoE */
    'opt3' => ['if' => 'igc3', 'gatewayv6' => 'fe80::1'],          /* IPv6-only uplink */
    'opt4' => ['if' => 'wg0', 'gateway' => '10.255.255.1'],        /* VPN exit with a gateway */
    'lan' => ['if' => 'bridge0'],                                  /* bridged LAN */
    'opt5' => ['if' => 'vlan0.20'],                                /* guest VLAN */
    'opt6' => ['if' => 'igc4'],                                    /* second physical LAN */
    'opt7' => ['if' => 'ovpns1'],                                  /* VPN server without gateway */
    'opt8' => ['if' => 'tun_mihomo'],
];
$lines = explode("\n", <<<'DATA'
bridge0: flags=1008843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST>
    inet 192.168.0.1 netmask 0xfffffc00 broadcast 192.168.3.255
igc1: flags=1008843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST>
    inet 104.52.226.170 netmask 0xfffffe00 broadcast 104.52.227.255
igc2: flags=1008843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST>
    inet 203.0.113.10 netmask 0xffffff00 broadcast 203.0.113.255
pppoe0: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST>
    inet 192.0.2.1 --> 192.0.2.2 netmask 0xffffffff
igc3: flags=1008843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST>
    inet6 2001:db8:3::1 prefixlen 64
wg0: flags=10080c1<UP,RUNNING,NOARP,MULTICAST>
    inet 10.255.255.2 netmask 0xffffffff
vlan0.20: flags=1008843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST>
    inet 192.168.20.1 netmask 0xffffff00 broadcast 192.168.20.255
igc4: flags=1008843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST>
    inet 10.10.0.1 netmask 0xffff0000 broadcast 10.10.255.255
ovpns1: flags=1008043<UP,BROADCAST,RUNNING,MULTICAST>
    inet 172.31.0.1 netmask 0xffffff00 broadcast 172.31.0.255
tun_mihomo: flags=8043<UP,BROADCAST,RUNNING,MULTICAST>
    inet 198.18.0.1 netmask 0xfffffffc broadcast 198.18.0.3
DATA);
$context = json_decode(json_encode(mihomo_routing_context($mapping, $lines)), true);
$devices = array_map(fn($entry) => $entry['if'], $mapping);

$cases = [
    /* every uplink of a multi-WAN router restarts, keeping the family */
    [['wan'], 'inet', 'inet'],
    [['wan'], 'inet6', 'inet6'],
    [['opt1'], 'inet', 'inet'],
    [['opt2'], 'inet', 'inet'],
    [['opt3'], 'inet6', 'inet6'],
    [['opt4'], 'inet', 'inet'],
    /* LAN, bridge, VLAN, second LAN and VPN-without-gateway events do not */
    [['lan'], 'inet6', null],
    [['opt5'], 'inet', null],
    [['opt6'], 'inet', null],
    [['opt7'], 'inet', null],
    /* nor does the TUN that transparent routing itself brings up */
    [['opt8'], 'inet', null],
    /* one WAN among several interfaces is enough */
    [['lan', 'opt1'], 'inet', 'inet'],
    [['opt8', 'lan'], 'inet', null],
    /* unknown interfaces and events without names restart as before */
    [['opt99'], 'inet', 'inet'],
    [[], 'inet', 'inet'],
    [null, null, ''],
    ['wan', 'inet', 'inet'],
];
foreach ($cases as [$names, $family, $expected]) {
    $actual = mihomo_newwanip_restart($names, $family, $context, $devices);
    if ($actual !== $expected) {
        throw new RuntimeException(sprintf('Event %s/%s: expected %s, got %s.', json_encode($names),
            var_export($family, true), var_export($expected, true), var_export($actual, true)));
    }
}

/* Without a usable context the old behaviour holds: restart, except for the TUN. */
foreach ([null, [], ['interfaces' => 'corrupt'], ['interfaces' => [['name' => 'wan']]]] as $broken) {
    if (mihomo_newwanip_restart(['lan'], 'inet', $broken, $devices) !== 'inet') {
        throw new RuntimeException('An unreadable routing context stopped a restart.');
    }
    if (mihomo_newwanip_restart(['opt8'], 'inet', $broken, $devices) !== null) {
        throw new RuntimeException('The TUN event restarted the core without a routing context.');
    }
}
/* A context entry whose flag is not literally true is not a WAN. */
$flagged = ['interfaces' => [['name' => 'lan', 'wan' => 'yes'], ['name' => 'wan', 'wan' => true]]];
if (mihomo_newwanip_restart(['lan'], 'inet', $flagged, $devices) !== null
    || mihomo_newwanip_restart(['wan'], 'inet', $flagged, $devices) !== 'inet') {
    throw new RuntimeException('The WAN flag was not read strictly.');
}
echo "Newwanip scope checks passed.\n";
