<?php
/* Identify LAN ingress and router destinations without touching native state. */
require_once($argv[1] ?? dirname(__DIR__, 2) . '/src/usr/local/etc/inc/plugins.inc.d/mihomo.inc');

$mapping = [
    'wan' => ['if' => 'vtnet1'],
    'opt2' => ['if' => 'vtnet2', 'gateway' => 'WAN2_GW'],
    'opt3' => ['if' => 'vtnet3', 'gatewayv6' => 'WAN3_V6'],
    'opt4' => ['if' => 'pppoe0', 'gateway' => 'WAN4_GW'],
    'lan' => ['if' => 'vtnet0'],
];
$lines = explode("\n", <<<'DATA'
vtnet0: flags=1008843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST>
    inet 192.168.8.1 netmask 0xffffff00 broadcast 192.168.8.255
    inet 192.168.9.1 netmask 0xffffff00 broadcast 192.168.9.255
    inet6 fd00:8::1 prefixlen 64
    inet6 fe80::1%vtnet0 prefixlen 64 scopeid 0x1
vtnet1: flags=1008843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST>
    inet 198.51.100.1 netmask 0xfffffffc broadcast 198.51.100.3
vtnet2: flags=1008843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST>
    inet 203.0.113.1 netmask 0xfffffffc broadcast 203.0.113.3
vtnet3: flags=1008843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST>
    inet6 2001:db8:3::1 prefixlen 64
pppoe0: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST>
    inet 192.0.2.1 --> 192.0.2.2 netmask 0xffffffff
lo0: flags=1008049<UP,LOOPBACK,RUNNING,MULTICAST>
    inet 127.0.0.1 netmask 0xff000000
tun_mihomo: flags=8043<UP,BROADCAST,RUNNING,MULTICAST>
    inet 198.18.0.1 netmask 0xfffffffc broadcast 198.18.0.3
DATA);
$context = mihomo_routing_context($mapping, $lines);
$interfaces = array_column($context['interfaces'], null, 'name');
if (!$interfaces['wan']['wan'] || !$interfaces['opt2']['wan'] || !$interfaces['opt3']['wan'] || !$interfaces['opt4']['wan']
    || $interfaces['lan']['wan']) {
    throw new RuntimeException('WAN gateway interfaces were eligible for LAN source capture.');
}
if ($interfaces['lan']['networks'] !== ['192.168.8.1/24', '192.168.9.1/24', 'fd00:8::1/64', 'fe80::1/64']) {
    throw new RuntimeException('LAN secondary addresses or IPv6 scopes were lost.');
}
if ($interfaces['opt4']['networks'] !== ['192.0.2.1/32'] || in_array('192.0.2.2', $context['local_addresses'], true)) {
    throw new RuntimeException('A point-to-point interface lost its local address or included its remote peer.');
}
foreach (['192.168.8.1', '192.168.9.1', '198.51.100.1', '203.0.113.1', '2001:db8:3::1',
          '127.0.0.1', '198.18.0.1', 'fe80::1', '192.0.2.1'] as $address) {
    if (!in_array($address, $context['local_addresses'], true)) {
        throw new RuntimeException('Router address was not excluded from device capture.');
    }
}
echo "Routing context checks passed.\n";
