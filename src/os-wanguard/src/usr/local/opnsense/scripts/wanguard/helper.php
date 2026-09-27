#!/usr/local/bin/php
<?php

/*
 * WAN Guard helper: observe the watched interfaces through core, and re-request
 * IPv4 DHCP on one of them the way core itself starts its client.
 *
 *   helper.php observe
 *   helper.php redhcp <interface> <expected-address> <reason>
 *   helper.php restore <interface>
 *
 * Only the WAN Guard daemon runs this script; no configd action reaches it.
 * Every answer is one JSON object on stdout. redhcp and restore re-check the
 * safety rules themselves instead of trusting the caller, and touch nothing
 * but the IPv4 DHCP client of the one device: interface_dhcp_configure() is
 * the same call interface_configure() makes for a DHCP interface, without the
 * address flush and IPv6 setup that surround it there.
 */

require_once('config.inc');
require_once('util.inc');
require_once('interfaces.inc');

const WANGUARD_RUN = '/var/run/wanguard';
const WANGUARD_DB = '/var/db/os-wanguard';
const WANGUARD_WAIT = 50;          /* polls of 200 ms: ten seconds */

function wanguard_log($priority, $message)
{
    /* Core's includes reopen the log under their own name; take it back. */
    openlog('wanguard', LOG_ODELAY, LOG_DAEMON);
    syslog($priority, $message);
}

function wanguard_answer(array $answer, $status = 0)
{
    /* An odd byte in an interface description must not cost the whole answer. */
    echo json_encode($answer, JSON_INVALID_UTF8_SUBSTITUTE) . "\n";
    exit($status);
}

function wanguard_list($value)
{
    if (!is_string($value) || $value === '') {
        return [];
    }
    return array_values(array_filter(array_map('trim', explode(',', $value)), 'strlen'));
}

function wanguard_settings()
{
    $general = config_read_array('OPNsense', 'wanguard', 'general', false);
    $watched = [];
    foreach (wanguard_list($general['interfaces'] ?? '') as $name) {
        if (preg_match('/^[a-z0-9_]{1,32}$/D', $name) && !in_array($name, $watched, true)) {
            $watched[] = $name;
        }
    }
    return [
        'enabled' => ($general['enabled'] ?? '0') === '1',
        'watched' => $watched,
        'networks' => wanguard_list($general['networks'] ?? ''),
        'private_ranges' => ($general['private_ranges'] ?? '0') === '1',
    ];
}

function wanguard_booting()
{
    return (bool)product::getInstance()->booting();
}

/* Collect what the daemon decides on; $details is legacy_interfaces_details(). */
function wanguard_interface($name, array $details)
{
    $config = config_read_array('interfaces', $name, false);
    $device = is_string($config['if'] ?? null) ? $config['if'] : '';
    $info = [
        'name' => $name,
        'descr' => is_string($config['descr'] ?? null) && $config['descr'] !== '' ? $config['descr'] : strtoupper($name),
        'exists' => !empty($config),
        'device' => $device,
        'enabled' => isset($config['enable']) && $config['enable'] !== '0',
        'ipaddr' => is_string($config['ipaddr'] ?? null) ? $config['ipaddr'] : '',
        'eligible' => false,
        'address' => null,
        'carrier' => false,
        'dhclient_running' => false,
    ];
    /* G2: an enabled interface whose IPv4 type is DHCP, with a sane device
       name, and never the LAN, whose lease is the operator's way in. */
    $info['eligible'] = $name !== 'lan' && $info['exists'] && $info['enabled'] && $info['ipaddr'] === 'dhcp' &&
        preg_match('/^[a-zA-Z][a-zA-Z0-9_.]{0,31}$/D', $device) === 1;
    if (!$info['eligible']) {
        return $info;
    }
    /* The address rc.newwanip itself reads: the first IPv4 address on the device. */
    $address = interfaces_primary_address($name, $details)[0];
    $info['address'] = is_string($address) && $address !== '' ? $address : null;
    $info['carrier'] = isset($details[$device]) && ($details[$device]['status'] ?? '') !== 'no carrier';
    $info['dhclient_running'] = isvalidpid("/var/run/dhclient.{$device}.pid");
    return $info;
}

function wanguard_observe()
{
    $settings = wanguard_settings();
    $answer = $settings + ['booting' => wanguard_booting(), 'interfaces' => []];
    if (!$settings['enabled'] || empty($settings['watched'])) {
        return $answer;
    }
    $details = legacy_interfaces_details();
    foreach ($settings['watched'] as $name) {
        $answer['interfaces'][] = wanguard_interface($name, $details);
    }
    return $answer;
}

function wanguard_private_directory($path)
{
    if (is_link($path)) {
        return false;
    }
    if (!is_dir($path) && !@mkdir($path, 0700, true)) {
        return false;
    }
    return @chmod($path, 0700);
}

/* G8: one helper action at a time; a second caller gets "busy" at once.
   Close-on-exec matters: the DHCP client started below would otherwise
   inherit the descriptor and hold the lock for as long as it runs. */
function wanguard_action_lock()
{
    if (!wanguard_private_directory(WANGUARD_RUN)) {
        return null;
    }
    $handle = @fopen(WANGUARD_RUN . '/action.lock', 'ce');
    if ($handle === false) {
        return null;
    }
    if (!flock($handle, LOCK_EX | LOCK_NB)) {
        fclose($handle);
        return null;
    }
    return $handle;
}

/* G1-G3 for an action, from core's own configuration and live data. */
function wanguard_guard($name, &$info)
{
    $settings = wanguard_settings();
    if (!$settings['enabled']) {
        return 'disabled';
    }
    if (!in_array($name, $settings['watched'], true)) {
        return 'not-watched';
    }
    if ($name === 'lan') {
        return 'lan';
    }
    $config = config_read_array('interfaces', $name, false);
    $device = is_string($config['if'] ?? null) ? $config['if'] : '';
    $details = preg_match('/^[a-zA-Z][a-zA-Z0-9_.]{0,31}$/D', $device) ? legacy_interfaces_details($device) : [];
    $info = wanguard_interface($name, $details);
    if (!$info['eligible']) {
        return 'not-dhcp';
    }
    if (wanguard_booting()) {
        return 'booting';
    }
    return null;
}

function wanguard_wait_client($pidfile, $running)
{
    for ($poll = 0; $poll < WANGUARD_WAIT; $poll++) {
        if (isvalidpid($pidfile) === $running) {
            return true;
        }
        usleep(200 * 1000);
    }
    return isvalidpid($pidfile) === $running;
}

function wanguard_redhcp($name, $expected, $reason)
{
    $lock = wanguard_action_lock();
    if ($lock === null) {
        return ['result' => 'busy'];
    }
    $info = null;
    $refusal = wanguard_guard($name, $info);
    if ($refusal !== null) {
        return ['result' => 'refused:' . $refusal];
    }
    /* G4: act only on the address the decision was based on. */
    if ($info['address'] !== $expected) {
        return ['result' => 'refused:address-changed'];
    }
    if (!$info['carrier']) {
        return ['result' => 'refused:no-carrier'];
    }
    /* Only a lease a running client holds is renewed. Without one the
       interface may still wait for an interface apply, or core stopped the
       client on purpose; starting one would be a change nobody asked for. */
    if (!$info['dhclient_running']) {
        return ['result' => 'refused:no-client'];
    }
    $device = $info['device'];
    $pidfile = "/var/run/dhclient.{$device}.pid";
    wanguard_log(LOG_NOTICE, sprintf('stopping the IPv4 DHCP client on %s (%s) to discard its lease: %s', $name, $device, $reason));

    /* Bounded stop: core's own kill waits forever, this gives up after ten
       seconds and then changes nothing else. The supervisor forwards TERM to
       dhclient and exits. */
    killbypid($pidfile, 'TERM', false);
    if (!wanguard_wait_client($pidfile, false)) {
        wanguard_log(LOG_ERR, sprintf('the IPv4 DHCP client on %s (%s) did not stop; nothing was changed', $name, $device));
        return ['result' => 'failed:old-client'];
    }

    /* dhclient re-requests the lease it remembers (INIT-REBOOT), which the
       gateway would simply confirm. Without that memory it starts from
       DHCPDISCOVER and the gateway chooses the address. The last discarded
       copy is kept for diagnosis. */
    $lease = "/var/db/dhclient.leases.{$device}";
    $memory = 'none';
    if (file_exists($lease) || is_link($lease)) {
        $copy = WANGUARD_DB . "/dhclient.leases.{$device}.discarded";
        if (wanguard_private_directory(WANGUARD_DB) && @rename($lease, $copy)) {
            if (!is_link($copy)) {
                @chmod($copy, 0600);
            }
            $memory = 'discarded';
        } elseif (@unlink($lease)) {
            $memory = 'discarded';
        } else {
            $memory = 'kept';
            wanguard_log(LOG_WARNING, sprintf('the lease memory of %s (%s) could not be discarded; the client will ask for the same lease again', $name, $device));
        }
    }

    interface_dhcp_configure($name);
    if (!wanguard_wait_client($pidfile, true)) {
        interface_dhcp_configure($name);
        if (!wanguard_wait_client($pidfile, true)) {
            wanguard_log(LOG_ERR, sprintf('the IPv4 DHCP client on %s (%s) did not start again', $name, $device));
            return ['result' => 'failed:no-client', 'lease' => $memory];
        }
    }
    wanguard_log(LOG_NOTICE, sprintf('started a new IPv4 DHCP client on %s (%s); lease memory %s', $name, $device, $memory));
    return ['result' => 'requested', 'lease' => $memory];
}

function wanguard_restore($name)
{
    $lock = wanguard_action_lock();
    if ($lock === null) {
        return ['result' => 'busy'];
    }
    $info = null;
    $refusal = wanguard_guard($name, $info);
    if ($refusal !== null) {
        return ['result' => 'refused:' . $refusal];
    }
    /* Carrier is deliberately not required: this client was stopped by our
       own action, and core starts its clients without carrier as well; a
       running client simply waits for the link. */
    $device = $info['device'];
    $pidfile = "/var/run/dhclient.{$device}.pid";
    if (isvalidpid($pidfile)) {
        return ['result' => 'running'];
    }
    wanguard_log(LOG_NOTICE, sprintf('starting the stopped IPv4 DHCP client on %s (%s)', $name, $device));
    interface_dhcp_configure($name);
    if (!wanguard_wait_client($pidfile, true)) {
        wanguard_log(LOG_ERR, sprintf('the IPv4 DHCP client on %s (%s) did not start', $name, $device));
        return ['result' => 'failed:no-client'];
    }
    return ['result' => 'restored'];
}

$arguments = array_slice($argv, 1);
$command = $arguments[0] ?? '';
$name = $arguments[1] ?? '';
if ($command !== 'observe' && !preg_match('/^[a-z0-9_]{1,32}$/D', $name)) {
    wanguard_answer(['result' => 'refused:invalid'], 2);
}
switch ($command) {
    case 'observe':
        wanguard_answer(wanguard_observe());
        break;
    case 'redhcp':
        $expected = $arguments[2] ?? '';
        $reason = preg_replace('/[^\x20-\x7e]/', '', substr($arguments[3] ?? '', 0, 200));
        if (count($arguments) !== 4 || filter_var($expected, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
            wanguard_answer(['result' => 'refused:invalid'], 2);
        }
        $answer = wanguard_redhcp($name, $expected, $reason);
        wanguard_answer($answer, $answer['result'] === 'failed:no-client' ? 3 : 0);
        break;
    case 'restore':
        if (count($arguments) !== 2) {
            wanguard_answer(['result' => 'refused:invalid'], 2);
        }
        $answer = wanguard_restore($name);
        wanguard_answer($answer, $answer['result'] === 'failed:no-client' ? 3 : 0);
        break;
    default:
        wanguard_answer(['result' => 'refused:invalid'], 2);
}
