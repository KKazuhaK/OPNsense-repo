<?php
/* The optional private-range rule must match core's is_private_ipv4() address for address. */
if (!is_file('/usr/local/etc/inc/util.inc')) {
    fwrite(STDERR, "Requires the native OPNsense includes.\n");
    exit(77);
}
require_once('config.inc');
require_once('util.inc');

$addresses = ['0.0.0.1', '1.1.1.1', '255.255.255.255', '104.52.226.170', '172.31.254.254'];
foreach (['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8', '100.64.0.0/10', '169.254.0.0/16',
          '172.31.254.0/24'] as $network) {
    [$base, $bits] = explode('/', $network);
    $first = ip2long($base);
    $last = $first + (1 << (32 - (int)$bits)) - 1;
    foreach ([$first - 1, $first, $first + 1, intdiv($first + $last, 2), $last - 1, $last, $last + 1] as $value) {
        if ($value >= 0 && $value <= 0xffffffff) {
            $addresses[] = long2ip($value);
        }
    }
}
mt_srand(20260927);
for ($i = 0; $i < 10000; $i++) {
    $addresses[] = long2ip(mt_rand(1, 0xfffffffe));
}
$addresses = array_values(array_unique($addresses));

$python = is_executable('/usr/local/bin/python3') ? '/usr/local/bin/python3' : 'python3';
$scripts = dirname(__DIR__, 2) . '/src/usr/local/opnsense/scripts/wanguard';
$program = 'import json, sys; sys.path.insert(0, sys.argv[1]); import guard; ' .
    'rules = guard.Rules([], True); ' .
    'print(json.dumps([rules.classify(a)[0] == guard.UNWANTED for a in json.load(sys.stdin)]))';
$process = proc_open([$python, '-B', '-c', $program, $scripts], [['pipe', 'r'], ['pipe', 'w'], ['pipe', 'w']], $pipes);
if (!is_resource($process)) {
    throw new RuntimeException('Python could not be started.');
}
fwrite($pipes[0], json_encode($addresses));
fclose($pipes[0]);
$output = stream_get_contents($pipes[1]);
$errors = stream_get_contents($pipes[2]);
fclose($pipes[1]);
fclose($pipes[2]);
if (proc_close($process) !== 0) {
    throw new RuntimeException('The Python classifier failed: ' . $errors);
}
$verdicts = json_decode($output, true);
if (!is_array($verdicts) || count($verdicts) !== count($addresses)) {
    throw new RuntimeException('The Python classifier gave no usable answer.');
}
$mismatches = [];
foreach ($addresses as $index => $address) {
    if ((bool)is_private_ipv4($address) !== $verdicts[$index]) {
        $mismatches[] = $address;
    }
}
if ($mismatches) {
    throw new RuntimeException('Private range mismatch for ' . implode(', ', array_slice($mismatches, 0, 20)));
}
printf("Private range parity passed for %d addresses.\n", count($addresses));
