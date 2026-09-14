<?php

/*
 * Copyright (C) 2024  https://pfchina.org/
 * All rights reserved.
 *
 */

function mihomo_services()
{
    global $config;

    $services = array();

        $services[] = array(
            'description' => gettext('mihomo'),
            'configd' => array(
                'restart' => array('mihomo restart'),
                'start' => array('mihomo start'),
                'stop' => array('mihomo stop'),
            ),
            'name' => 'mihomo',
            'pidfile' => '/var/run/mihomo.pid',
        );


    return $services;
}

function mihomo_configure()
{
    return [
        'early' => ['mihomo_restore_backup'],
        'local' => ['mihomo_restore_backup'],
        'newwanip' => ['mihomo_newwanip:3'],
    ];
}

function mihomo_routing_context(iterable $mapping, array $lines): array
{
    $addresses = [];
    $networks = [];
    $device = '';
    foreach ($lines as $line) {
        if (preg_match('/^([a-zA-Z][a-zA-Z0-9_.:-]{0,63}):/', $line, $match)) {
            $device = $match[1];
        } elseif (preg_match('/^\s+inet ([0-9.]+)(?: --> [0-9.]+)? netmask (0x[0-9a-fA-F]+)/', $line, $match)) {
            $addresses[] = $match[1];
            $prefix = substr_count(decbin(hexdec($match[2])), '1');
            $networks[$device][] = $match[1] . '/' . $prefix;
        } elseif (preg_match('/^\s+inet6 ([0-9a-fA-F:]+)(?:%[^\s]+)? prefixlen ([0-9]+)/', $line, $match)) {
            $addresses[] = $match[1];
            $networks[$device][] = $match[1] . '/' . $match[2];
        }
    }
    $interfaces = [];
    foreach ($mapping as $name => $entry) {
        $device = $entry['if'] ?? '';
        if (!is_string($device) || !preg_match('/^[a-zA-Z][a-zA-Z0-9_.:-]{0,63}$/D', $device)) {
            continue;
        }
        $interfaces[] = [
            'name' => (string)$name, 'device' => $device,
            'networks' => $networks[$device] ?? [],
            'wan' => $name === 'wan' || !empty($entry['gateway']) || !empty($entry['gatewayv6']),
        ];
    }
    return ['interfaces' => $interfaces,
        'local_addresses' => array_values(array_unique($addresses))];
}

function mihomo_firewall(\OPNsense\Firewall\Plugin $fw)
{
    /* Source selection must not pass packets around the administrator's
       filtering rules. The runtime anchor contains only non-quick matches. */
    $fw->registerAnchor('mihomo', 'fw', 1, 'head', false);
    $lines = [];
    exec('/sbin/ifconfig -a', $lines);
    $context = mihomo_routing_context($fw->getInterfaceMapping(), $lines);
    $directory = '/var/db/os-mihomo';
    if (!is_dir($directory) || is_link($directory)) {
        return;
    }
    $temporary = tempnam($directory, '.routing-context-');
    if ($temporary === false) {
        throw new RuntimeException('Unable to prepare the Mihomo routing context.');
    }
    try {
        chmod($temporary, 0600);
        if (file_put_contents($temporary, json_encode($context, JSON_THROW_ON_ERROR)) === false
            || !rename($temporary, $directory . '/routing-context.json')) {
            throw new RuntimeException('Unable to save the Mihomo routing context.');
        }
    } finally {
        if (is_file($temporary)) {
            unlink($temporary);
        }
    }
}

function mihomo_restore_backup($verbose = false)
{
    exec('/usr/local/bin/python3 /usr/local/opnsense/scripts/mihomo/mihomo.py reconcile-backup >/dev/null 2>&1', $output, $status);
    if ($status !== 0) {
        error_log('The Mihomo configuration backup could not be restored.');
    }
}

function mihomo_syslog()
{
    $logfacilities = array();
    $logfacilities['mihomo'] = array(
        'facility' => array('mihomo'),
    );
    return $logfacilities;
}


function mihomo_newwanip($verbose = false, $interfaces = null, $family = null)
{
    /* Enabling transparent routing assigns and brings up tun_mihomo, and that
       raises this event. Treating it as a WAN change restarts the core that had
       just created the interface, which tears the whole thing down moments
       after it started. Only a change on some other interface is a reason to
       restart. */
    $names = array_filter((array)$interfaces, 'is_string');
    if (!empty($names)) {
        $devices = [];
        foreach (config_read_array('interfaces') as $key => $entry) {
            $devices[$key] = $entry['if'] ?? '';
        }
        $elsewhere = false;
        foreach ($names as $name) {
            if (($devices[$name] ?? '') !== 'tun_mihomo') {
                $elsewhere = true;
            }
        }
        if (!$elsewhere) {
            return;
        }
    }
    exec('/usr/local/sbin/configctl mihomo wan-restart');
}
