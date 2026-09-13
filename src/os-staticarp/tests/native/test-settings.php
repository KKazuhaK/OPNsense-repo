#!/usr/local/bin/php
<?php

/*
 * The binding list is the whole plugin: a wrong entry pins a device's address
 * to the wrong hardware and takes it off the network until someone notices.
 * These check what normalisation actually does with input, including the two
 * behaviours that are silent and therefore easy to break -- the router's own
 * address being dropped, and duplicates collapsing.
 *
 * Run where PHP is available:  php tests/native/test-settings.php
 */

$failures = 0;

function check($condition, $what)
{
    global $failures;
    if ($condition) {
        printf("ok   %s\n", $what);
        return;
    }
    $failures++;
    printf("FAIL %s\n", $what);
}

/* settings.php calls into the OPNsense tree at include time for its config
   helpers; the pure functions under test need none of that, so define the one
   thing they touch and load the file with the rest inert. */
if (!function_exists('gettext')) {
    function gettext($text) { return $text; }
}
/* Its three requires resolve through include_path, which only exists on a
   firewall. Empty stand-ins come first everywhere, on the firewall too: what
   these checks cover are pure functions, and they should not quietly behave
   one way here and another way on a machine that has the real tree. */
$stubs = sys_get_temp_dir() . '/staticarp-test-includes';
@mkdir($stubs, 0755, true);
foreach (['config.inc', 'interfaces.inc', 'util.inc'] as $stub) {
    file_put_contents($stubs . '/' . $stub, "<?php\n");
}
set_include_path($stubs . PATH_SEPARATOR . get_include_path());
/* The file is a CLI entry point as well as a library: including it runs its
   default action and prints the settings JSON. Swallow that; the functions are
   what is under test. */
ob_start();
require_once(__DIR__ . '/../../src/usr/local/opnsense/scripts/staticarp/settings.php');
ob_end_clean();

/* --- address and hardware address validation ------------------------- */
check(staticarp_valid_ip('192.168.10.5'), 'a dotted quad is an address');
check(!staticarp_valid_ip('192.168.10.256'), 'an octet above 255 is not');
check(!staticarp_valid_ip('2001:db8::1'), 'IPv6 is not accepted: ARP is v4 only');
check(!staticarp_valid_ip(''), 'the empty string is not an address');

check(staticarp_valid_mac('aa:bb:cc:dd:ee:ff'), 'six lowercase octets are a MAC');
check(staticarp_valid_mac('AA:BB:CC:DD:EE:FF'), 'and so are six uppercase ones');
check(!staticarp_valid_mac('aa-bb-cc-dd-ee-ff'), 'hyphens are not the accepted separator');
check(!staticarp_valid_mac('aa:bb:cc:dd:ee'), 'five octets are not a MAC');
check(!staticarp_valid_mac('aa:bb:cc:dd:ee:ff:00'), 'nor are seven');

/* --- normalisation ---------------------------------------------------- */
$errors = [];
$result = staticarp_normalize_entries("192.168.10.5 AA:BB:CC:DD:EE:FF", $errors);
check($result === '192.168.10.5 aa:bb:cc:dd:ee:ff', 'a hardware address is stored lowercase');
check($errors === [], 'a good entry reports no error');

$errors = [];
$result = staticarp_normalize_entries("192.168.10.9 aa:bb:cc:dd:ee:01\n192.168.10.2 aa:bb:cc:dd:ee:02", $errors);
check($result === "192.168.10.2 aa:bb:cc:dd:ee:02\n192.168.10.9 aa:bb:cc:dd:ee:01",
      'entries come back ordered by address, not by the order typed');

$errors = [];
$result = staticarp_normalize_entries("192.168.10.5 aa:bb:cc:dd:ee:01,192.168.10.6 aa:bb:cc:dd:ee:02", $errors);
check(substr_count($result, "\n") === 1, 'a comma separates entries as much as a newline');

$errors = [];
staticarp_normalize_entries("999.1.1.1 aa:bb:cc:dd:ee:ff", $errors);
check(count($errors) === 1 && strpos($errors[0], 'IP address') !== false,
      'an invalid address is reported rather than written');

$errors = [];
staticarp_normalize_entries("192.168.10.5 not-a-mac", $errors);
check(count($errors) === 1 && strpos($errors[0], 'MAC address') !== false,
      'an invalid hardware address is reported rather than written');

$errors = [];
$result = staticarp_normalize_entries("192.168.10.5 aa:bb:cc:dd:ee:ff\n\n   \n", $errors);
check($result === '192.168.10.5 aa:bb:cc:dd:ee:ff' && $errors === [],
      'blank lines are skipped without being called invalid');

/* The last entry for an address wins, silently. Worth pinning: an operator who
   pastes a list twice with one line edited gets the edited one, and no warning
   that the other was dropped. */
$errors = [];
$result = staticarp_normalize_entries("192.168.10.5 aa:bb:cc:dd:ee:01\n192.168.10.5 aa:bb:cc:dd:ee:02", $errors);
check($result === '192.168.10.5 aa:bb:cc:dd:ee:02', 'a repeated address keeps the last entry');
check($errors === [], 'and says nothing about the one it dropped');

/* A padded octet is ambiguous -- 010 reads as octal 8 to some resolvers -- and
   FILTER_VALIDATE_IP rejects it rather than guessing. Pinned because silently
   canonicalising it would bind a different address than the one typed. */
$errors = [];
$result = staticarp_normalize_entries("192.168.010.005 aa:bb:cc:dd:ee:ff", $errors);
check($result === '' && count($errors) === 1, 'a padded octet is refused, not guessed at');

/* --- the router's own addresses --------------------------------------- */
/* Binding an address the router itself holds would pin the gateway to one
   hardware address, so normalisation drops those entries. It does so without
   reporting anything, which is the part worth a test: nothing else would show
   that the entry went missing. */
$local = staticarp_local_ipv4_addresses();
$own = null;
foreach (array_keys($local) as $address) {
    if ($address !== '127.0.0.1') { $own = $address; break; }
}
if ($own === null) {
    printf("skip the local-address rule: this host reports no address but loopback\n");
} else {
    $errors = [];
    $result = staticarp_normalize_entries($own . ' aa:bb:cc:dd:ee:ff', $errors);
    check($result === '', sprintf("an address this host holds (%s) is not bound", $own));
    check($errors === [], 'and it is dropped silently rather than reported');
}

printf("\n%s\n", $failures === 0 ? 'Static ARP settings checks passed.' : $failures . ' check(s) failed.');
exit($failures === 0 ? 0 : 1);
