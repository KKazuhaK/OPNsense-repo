<?php
/* The helper's view of an interface must match core's own, on the real tree.

   Read only: the configuration is changed in memory for this process and never
   saved, and no function that stops or starts a DHCP client is called. It
   proves the calling conventions the helper relies on, such as
   legacy_interfaces_details() filtered by device and keyed by it, that the
   portable tests can only stub. */
function contract_check(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

if (!is_file('/usr/local/etc/inc/interfaces.inc')) {
    fwrite(STDERR, "Requires the native OPNsense includes.\n");
    exit(77);
}
require_once('config.inc');
require_once('util.inc');
require_once('interfaces.inc');

/* The helper's functions, without its command dispatcher. */
$helper = dirname(__DIR__, 2) . '/src/usr/local/opnsense/scripts/wanguard/helper.php';
$source = file_get_contents($helper);
$start = strpos($source, '<?php');
$end = strpos($source, '$arguments = array_slice(');
contract_check($start !== false && $end !== false, 'The helper layout changed.');
eval('?>' . substr($source, $start, $end - $start));

contract_check(wanguard_booting() === false, 'A running system reports that it is booting.');

$original = $config;
$live = legacy_interfaces_details();
$checked = [];
foreach ($original['interfaces'] as $name => $settings) {
    $device = is_array($settings) && is_string($settings['if'] ?? null) ? $settings['if'] : '';
    if ($name === 'lan' || !isset($settings['enable']) || empty($live[$device]['ipv4']) ||
        !preg_match('/^[a-zA-Z][a-zA-Z0-9_.]{0,31}$/D', $device)) {
        continue;
    }
    try {
        /* As if this interface were a watched DHCP interface. */
        $config['interfaces'][$name]['ipaddr'] = 'dhcp';
        $config['OPNsense']['wanguard']['general'] = ['enabled' => '1', 'interfaces' => $name,
            'networks' => '', 'private_ranges' => '0'];

        $one = legacy_interfaces_details($device);
        contract_check(array_keys($one) === [$device], "$name: details for $device are not keyed by that device.");
        contract_check(($one[$device]['ipv4'] ?? null) === $live[$device]['ipv4'],
            "$name: the filtered details differ from the full ones.");
        $primary = interfaces_primary_address($name)[0];
        contract_check(is_string($primary) && filter_var($primary, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false,
            "$name: core reports no primary IPv4 address.");
        contract_check(interfaces_primary_address($name, $one)[0] === $primary,
            "$name: the primary address differs when the device's details are passed in.");

        $info = null;
        contract_check(wanguard_guard($name, $info) === null, "$name: the guard refused a watched DHCP interface.");
        $carrier = isset($live[$device]) && ($live[$device]['status'] ?? '') !== 'no carrier';
        $expected = [
            'name' => $name, 'exists' => true, 'device' => $device, 'enabled' => true, 'ipaddr' => 'dhcp',
            'eligible' => true, 'address' => $primary, 'carrier' => $carrier,
            'dhclient_running' => (bool)isvalidpid("/var/run/dhclient.{$device}.pid"),
        ];
        foreach ($expected as $key => $value) {
            contract_check($info[$key] === $value, sprintf('%s: %s is %s, core says %s.', $name, $key,
                json_encode($info[$key]), json_encode($value)));
        }
        $observed = wanguard_observe();
        contract_check($observed['enabled'] === true && $observed['interfaces'] === [$info],
            "$name: observe and the action guard see the interface differently.");
        $checked[] = "$name ($device, $primary)";
    } finally {
        $config = $original;
    }
}
contract_check(count($checked) > 0, 'No enabled interface with an IPv4 address was found.');

/* The LAN stays out even when it is DHCP and listed. */
$config['interfaces']['lan'] = ['if' => 'lo0', 'enable' => '1', 'ipaddr' => 'dhcp'];
$config['OPNsense']['wanguard']['general'] = ['enabled' => '1', 'interfaces' => 'lan', 'networks' => '',
    'private_ranges' => '0'];
$info = null;
contract_check(wanguard_guard('lan', $info) === 'lan', 'The LAN was not refused.');
contract_check(wanguard_observe()['interfaces'][0]['eligible'] === false, 'The LAN was observed as eligible.');
$config = $original;

printf("WAN Guard core contract passed for %s.\n", implode(', ', $checked));
