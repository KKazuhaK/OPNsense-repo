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
            /* For the capture interface picker: the operator's own label, and
               whether this is an interface group rather than an interface. */
            'descr' => is_string($entry['descr'] ?? null) && $entry['descr'] !== '' ? $entry['descr'] : strtoupper((string)$name),
            'virtual' => !empty($entry['virtual']),
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


/**
 * Decide whether an address event is a reason to restart the core.
 *
 * Only WAN-like interfaces carry the core's own traffic, so only their address
 * changes matter. rc.newwanip reloads the filter before it runs this hook, and
 * that reload rewrites the routing context with the same WAN flags that keep
 * those interfaces out of capture, so both decisions come from one source:
 * the name 'wan' or a gateway OPNsense resolves for the interface, which covers
 * every WAN of a multi-WAN setup whether static, DHCP or PPPoE. LAN, bridge,
 * VLAN, VPN-without-gateway and tun_mihomo events do not restart it; the last
 * one mattered most, because enabling transparent routing raises it and a
 * restart would tear down what had just been armed. Without a readable context,
 * or for an interface it does not list, the event restarts as it always did.
 *
 * @return string|null the family to pass on, or null to leave the core alone
 */
function mihomo_newwanip_restart($interfaces, $family, $context, array $devices)
{
    $family = is_string($family) ? $family : '';
    $names = array_filter((array)$interfaces, 'is_string');
    if (empty($names)) {
        return $family;
    }
    $wan = [];
    if (is_array($context) && is_array($context['interfaces'] ?? null)) {
        foreach ($context['interfaces'] as $item) {
            if (is_array($item) && is_string($item['name'] ?? null)) {
                $wan[$item['name']] = ($item['wan'] ?? null) === true;
            }
        }
    }
    foreach ($names as $name) {
        if (($devices[$name] ?? '') === 'tun_mihomo') {
            continue;
        }
        if (!array_key_exists($name, $wan) || $wan[$name]) {
            return $family;
        }
    }
    return null;
}

function mihomo_newwanip($verbose = false, $interfaces = null, $family = null)
{
    $devices = [];
    foreach (config_read_array('interfaces') as $key => $entry) {
        $devices[$key] = $entry['if'] ?? '';
    }
    $raw = @file_get_contents('/var/db/os-mihomo/routing-context.json');
    $context = is_string($raw) ? json_decode($raw, true) : null;
    $restart = mihomo_newwanip_restart($interfaces, $family, $context, $devices);
    if ($restart !== null) {
        /* The family lets the manager ignore DHCPv6 renewals while its own
           IPv6 support is off. */
        exec('/usr/local/sbin/configctl mihomo wan-restart ' . escapeshellarg($restart));
    }
}
