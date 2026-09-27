<?php
/* The newwanip hook only wakes the daemon, and only for watched IPv4 events. */
require_once($argv[1] ?? dirname(__DIR__, 2) . '/src/usr/local/etc/inc/plugins.inc.d/wanguard.inc');

function check($condition, $message)
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

$on = ['enabled' => '1', 'interfaces' => 'wan,opt2', 'networks' => '172.31.254.0/24', 'private_ranges' => '0'];
$cases = [
    /* the events rc.newwanip sends for each uplink of a multi-WAN router */
    [['wan'], 'inet', $on, ['wan']],
    [['opt2'], 'inet', $on, ['opt2']],
    [['opt1'], 'inet', $on, []],                     /* a WAN that is not watched */
    [['lan'], 'inet', $on, []],
    [['lan', 'opt2', 'opt2'], 'inet', $on, ['opt2']],
    [['wan', 'opt2'], 'inet', $on, ['wan', 'opt2']],
    /* older callers pass no family, which means IPv4 */
    [['wan'], null, $on, ['wan']],
    /* rc.newwanipv6 never wakes it: DHCPv6 says nothing about the IPv4 lease */
    [['wan'], 'inet6', $on, []],
    [['wan', 'opt2'], 'inet6', $on, []],
    /* events without names, and odd argument shapes */
    [null, 'inet', $on, []],
    [[], 'inet', $on, []],
    ['wan', 'inet', $on, ['wan']],
    [[null, 5, ''], 'inet', $on, []],
    /* a disabled plugin, or none configured at all, never wakes anything */
    [['wan'], 'inet', ['enabled' => '0'] + $on, []],
    [['wan'], 'inet', ['interfaces' => 'wan'], []],
    [['wan'], 'inet', [], []],
    [['wan'], 'inet', null, []],
    [['wan'], 'inet', ['enabled' => '1', 'interfaces' => ''], []],
    [['wan'], 'inet', ['enabled' => '1'], []],
    /* a name must match exactly, not as a prefix */
    [['wan'], 'inet', ['enabled' => '1', 'interfaces' => 'wan2,opt2'], []],
];
foreach ($cases as [$interfaces, $family, $settings, $expected]) {
    $actual = wanguard_newwanip_targets($interfaces, $family, $settings);
    check($actual === $expected, sprintf('Event %s/%s with %s: expected %s, got %s.', json_encode($interfaces),
        var_export($family, true), json_encode($settings), json_encode($expected), json_encode($actual)));
}

$directory = sys_get_temp_dir() . '/wanguard-newwanip-' . bin2hex(random_bytes(6));
try {
    /* No private run directory, no trace: a stopped service leaves nothing behind. */
    check(wanguard_wake($directory, ['wan']) === false, 'A wake was written without the run directory.');
    check(!file_exists($directory), 'The wake created the run directory.');
    mkdir($directory, 0700);
    check(wanguard_wake($directory, []) === false, 'An empty wake was written.');
    check(!file_exists($directory . '/wake'), 'An empty event left a wake file.');
    check(wanguard_wake($directory, ['wan', 'opt2']) === true, 'The wake was not written.');
    check(wanguard_wake($directory, ['opt2']) === true, 'The second wake was not appended.');
    check(file_get_contents($directory . '/wake') === "wan\nopt2\nopt2\n", 'The wake file content is wrong.');
    $link = $directory . '-link';
    symlink($directory, $link);
    check(wanguard_wake($link, ['wan']) === false, 'A wake followed a symbolic link.');
    unlink($link);
    $services = wanguard_configure();
    check($services === ['newwanip' => ['wanguard_newwanip:3']], 'The hook registration changed.');
    check(wanguard_syslog() === ['wanguard' => ['facility' => ['wanguard']]], 'The log facility changed.');
} finally {
    @unlink($directory . '/wake');
    @rmdir($directory);
}
echo "WAN Guard newwanip checks passed: watched IPv4 events only, disabled means no wake, private wake file.\n";
