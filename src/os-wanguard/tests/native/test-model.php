<?php
/* Validate the real WAN Guard model with OPNsense's own field types, against a private XML fixture. */
function model_check(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

function model_fields($messages): array
{
    $fields = [];
    foreach ($messages as $message) {
        $fields[] = $message->getField();
    }
    sort($fields);
    return array_values(array_unique($fields));
}

$package = $argv[1] ?? dirname(__DIR__, 2);
$loader = '/usr/local/opnsense/mvc/app/config/loader.php';
if (!is_file($loader)) {
    fwrite(STDERR, "Requires the native OPNsense Core and field types.\n");
    exit(77);
}
require_once($loader);
require_once('/usr/local/etc/inc/util.inc');
require_once('/usr/local/etc/inc/config.inc');
require_once($package . '/src/usr/local/opnsense/mvc/app/models/OPNsense/Wanguard/General.php');
/* The model loader resolves General.xml next to the class it was handed. */
$directory = sys_get_temp_dir() . '/wanguard-native-model-' . bin2hex(random_bytes(8));
mkdir($directory, 0700);
$fixture = $directory . '/config.xml';
file_put_contents($fixture, '<?xml version="1.0"?><opnsense><system><hostname>private-fixture</hostname></system>' .
    '<interfaces>' .
    '<wan><if>vtnet1</if><enable>1</enable><ipaddr>dhcp</ipaddr><ipaddrv6>dhcp6</ipaddrv6><descr>WAN</descr></wan>' .
    /* A DHCP LAN passes the type filter; only the name rule keeps it out. */
    '<lan><if>vtnet0</if><enable>1</enable><ipaddr>dhcp</ipaddr><descr>LAN</descr></lan>' .
    '<opt1><if>vtnet2</if><enable>1</enable><ipaddr>192.168.2.1</ipaddr><subnet>24</subnet><descr>LAN2</descr></opt1>' .
    '<opt2><if>vtnet3</if><enable>1</enable><ipaddr>dhcp</ipaddr><descr>WAN2</descr></opt2>' .
    '<opt3><if>vtnet4</if><ipaddr>dhcp</ipaddr><descr>DISABLED</descr></opt3>' .
    '<opt4><if>pppoe0</if><enable>1</enable><ipaddr>pppoe</ipaddr><descr>PPPOE</descr></opt4>' .
    '<opt5><if>vtnet5</if><enable>1</enable><descr>NOIP</descr></opt5>' .
    '</interfaces><unknown attr="retain">SENTINEL_UNKNOWN</unknown><OPNsense/></opnsense>');
$config = \OPNsense\Core\Config::getInstance();
$handle = new ReflectionProperty($config, 'config_file_handle');
fclose($handle->getValue($config));
$handle->setValue($config, fopen($fixture, 'r+'));
(new ReflectionProperty($config, 'config_file'))->setValue($config, $fixture);
(new ReflectionProperty($config, 'statusIsLocked'))->setValue($config, false);
try {
    $config->lock();
    $config->lock(false);
    $model = new \OPNsense\Wanguard\General();
    /* A fresh install does nothing: disabled, no networks, private ranges off, WAN preselected. */
    model_check((string)$model->enabled === '0' && (string)$model->interfaces === 'wan' &&
        (string)$model->networks === '' && (string)$model->private_ranges === '0', 'The defaults changed.');
    model_check(count($model->performValidation(true)) === 0, 'The defaults do not validate on a DHCP WAN.');
    $options = array_keys($model->interfaces->getNodeData());
    sort($options);
    model_check($options === ['lan', 'opt2', 'wan'], 'Only enabled DHCP interfaces may be offered: ' . json_encode($options));

    $cases = [
        ['interfaces', 'opt1', ['interfaces']],            /* static */
        ['interfaces', 'lan', ['interfaces']],             /* the LAN, even as DHCP */
        ['interfaces', 'wan,lan', ['interfaces']],
        ['interfaces', 'opt3', ['interfaces']],            /* disabled DHCP */
        ['interfaces', 'opt4', ['interfaces']],            /* PPPoE */
        ['interfaces', 'opt5', ['interfaces']],            /* no IPv4 type */
        ['interfaces', 'wan,opt1', ['interfaces']],
        ['interfaces', 'wan,opt2', []],
        ['interfaces', '', []],
        ['networks', '10.0.3.0/24,172.31.254.0/24', []],
        ['networks', '172.31.254.0/24', []],
        ['networks', '10.0.0.0/8', []],
        ['networks', '10.0.0.0/7', ['networks']],          /* wider than /8 */
        ['networks', '0.0.0.0/0', ['networks']],
        ['networks', '10.0.3.1/24', ['networks']],         /* host bits */
        ['networks', '10.0.3.1', ['networks']],            /* no mask */
        ['networks', 'fe80::/10', ['networks']],           /* IPv6 */
        ['networks', 'any', ['networks']],
        ['networks', 'nonsense', ['networks']],
        ['networks', implode(',', array_map(fn($i) => "10.$i.0.0/16", range(0, 31))), []],
        ['networks', implode(',', array_map(fn($i) => "10.$i.0.0/16", range(0, 32))), ['networks']],
        ['enabled', '2', ['enabled']],
        ['private_ranges', 'yes', ['private_ranges']],
    ];
    foreach ($cases as [$field, $value, $expected]) {
        $candidate = new \OPNsense\Wanguard\General();
        $candidate->$field = $value;
        $fields = model_fields($candidate->performValidation(true));
        model_check($fields === $expected, sprintf('%s=%s: expected %s, got %s', $field, $value,
            json_encode($expected), json_encode($fields)));
    }

    $model->enabled = '1';
    $model->interfaces = 'wan,opt2';
    $model->networks = '172.31.254.0/24';
    $model->private_ranges = '0';
    model_check(count($model->performValidation(true)) === 0, 'The Irvine-style settings do not validate.');
    $model->serializeToConfig(true);
    $config->save(null, false);
    $config->unlock();
    $xml = simplexml_load_file($fixture);
    $general = $xml->OPNsense->wanguard->general;
    model_check((string)$general->enabled === '1' && (string)$general->interfaces === 'wan,opt2' &&
        (string)$general->networks === '172.31.254.0/24' && (string)$general->private_ranges === '0',
        'The settings did not reach config.xml as expected.');
    model_check((string)$xml->unknown === 'SENTINEL_UNKNOWN' && (string)$xml->unknown['attr'] === 'retain',
        'Saving lost an unrelated node.');
    $config->lock();
    $config->lock(false);
    $restored = new \OPNsense\Wanguard\General();
    model_check((string)$restored->networks === '172.31.254.0/24' && (string)$restored->interfaces === 'wan,opt2',
        'The settings did not survive a reload.');
    echo "Native WAN Guard model passed: DHCP-only interface choices without the LAN, network bounds, defaults and XML roundtrip.\n";
} finally {
    $config->unlock();
    foreach (glob($directory . '/*') as $file) {
        unlink($file);
    }
    rmdir($directory);
}
