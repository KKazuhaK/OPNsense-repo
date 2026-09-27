<?php

/*
 * WAN Guard glue for OPNsense.
 *
 * One supervised daemon watches the selected DHCP interfaces and is the only
 * process that ever re-requests a lease. The hook below only wakes it, so an
 * address change is looked at within seconds instead of at the next 30 s tick,
 * and rc.newwanip is never slowed down or made to act.
 */

function wanguard_settings_general()
{
    return config_read_array('OPNsense', 'wanguard', 'general', false);
}

function wanguard_services()
{
    $services = [];

    if ((wanguard_settings_general()['enabled'] ?? '0') === '1') {
        $services[] = [
            'description' => gettext('WAN Guard'),
            'configd' => [
                'restart' => ['wanguard restart'],
                'start' => ['wanguard start'],
                'stop' => ['wanguard stop'],
            ],
            'name' => 'wanguard',
            'pidfile' => '/var/run/wanguard.pid',
        ];
    }

    return $services;
}

function wanguard_configure()
{
    return [
        'newwanip' => ['wanguard_newwanip:3'],
    ];
}

function wanguard_syslog()
{
    $logfacilities = [];
    $logfacilities['wanguard'] = [
        'facility' => ['wanguard'],
    ];
    return $logfacilities;
}

/**
 * Decide which interfaces of an address event are worth a look.
 *
 * Only IPv4 events (rc.newwanip passes 'inet'; older callers pass nothing) of
 * interfaces the operator watches count, and only while the plugin is on.
 * rc.newwanipv6 events never do: a DHCPv6 renewal says nothing about the IPv4
 * lease this plugin cares about.
 *
 * @return string[] watched interface names from the event
 */
function wanguard_newwanip_targets($interfaces, $family, $settings)
{
    if ($family === 'inet6' || !is_array($settings) || ($settings['enabled'] ?? '0') !== '1') {
        return [];
    }
    $watched = is_string($settings['interfaces'] ?? null) ? explode(',', $settings['interfaces']) : [];
    $targets = [];
    foreach (array_filter((array)$interfaces, 'is_string') as $name) {
        if ($name !== '' && in_array($name, $watched, true) && !in_array($name, $targets, true)) {
            $targets[] = $name;
        }
    }
    return $targets;
}

/**
 * Leave a wake request for the daemon, which polls for it every second.
 *
 * Nothing is written unless the daemon's private run directory exists, so a
 * stopped or never started service leaves no trace.
 */
function wanguard_wake($directory, array $names)
{
    if (empty($names) || !is_dir($directory) || is_link($directory)) {
        return false;
    }
    $handle = @fopen($directory . '/wake', 'ae');
    if ($handle === false) {
        return false;
    }
    $written = false;
    if (flock($handle, LOCK_EX)) {
        $written = fwrite($handle, implode("\n", $names) . "\n") !== false;
        flock($handle, LOCK_UN);
    }
    fclose($handle);
    return $written;
}

function wanguard_newwanip($verbose = false, $interfaces = null, $family = null)
{
    $targets = wanguard_newwanip_targets($interfaces, $family, wanguard_settings_general());
    if (!empty($targets)) {
        wanguard_wake('/var/run/wanguard', $targets);
    }
}
