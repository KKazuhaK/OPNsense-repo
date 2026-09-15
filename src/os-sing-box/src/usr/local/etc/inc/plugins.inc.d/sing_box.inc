<?php

/*
 * Copyright (C) 2024  https://pfchina.org/
 * All rights reserved.
 *
 */


function sing_box_services()
{
    global $config;

    $services = array();

    $services[] = array(
        'description' => gettext('sing-box'),
        'configd' => array(
            'restart' => array('sing-box restart'),
            'start' => array('sing-box start'),
            'stop' => array('sing-box stop'),
        ),
        'name' => 'sing-box',
        'pidfile' => '/var/run/sing-box.pid',
        'enabled' => true,
        'rcfile' => '/usr/local/etc/rc.d/sing-box',
    );

    return $services;
}
function sing_box_routing_context(iterable $mapping, array $lines): array
{
    $addresses = [];
    $networks = [];
    $device = '';
    foreach ($lines as $line) {
        if (preg_match('/^([A-Za-z][A-Za-z0-9_.:-]{0,63}):/', $line, $match)) {
            $device = $match[1];
        } elseif (preg_match('/^\s+inet ([0-9.]+)(?: --> [0-9.]+)? netmask (0x[0-9a-fA-F]+)/', $line, $match)) {
            $addresses[] = $match[1];
            $networks[$device][] = $match[1] . '/' . substr_count(decbin(hexdec($match[2])), '1');
        } elseif (preg_match('/^\s+inet6 ([0-9a-fA-F:]+)(?:%[^\s]+)? prefixlen ([0-9]+)/', $line, $match)) {
            $addresses[] = $match[1];
            $networks[$device][] = $match[1] . '/' . $match[2];
        }
    }
    $interfaces = [];
    foreach ($mapping as $name => $entry) {
        $device = $entry['if'] ?? '';
        if (!is_string($device) || !preg_match('/^[A-Za-z][A-Za-z0-9_.:-]{0,63}$/D', $device)) {
            continue;
        }
        $interfaces[] = ['name' => (string)$name, 'device' => $device, 'networks' => $networks[$device] ?? [],
            'wan' => $name === 'wan' || !empty($entry['gateway']) || !empty($entry['gatewayv6'])];
    }
    return ['interfaces' => $interfaces, 'local_addresses' => array_values(array_unique($addresses))];
}

function sing_box_firewall(\OPNsense\Firewall\Plugin $fw)
{
    /* Match capture retains native filtering and explicit gateway decisions. */
    $fw->registerAnchor('singbox', 'fw', 1, 'head', false);
    $directory = '/var/db/os-sing-box';
    if (!is_dir($directory) || is_link($directory)) {
        return;
    }
    $directoryInfo = lstat($directory);
    if ($directoryInfo === false || ($directoryInfo['mode'] & 0170777) !== 0040700
        || $directoryInfo['uid'] !== 0) {
        throw new RuntimeException('The Sing-box routing context directory is invalid.');
    }
    $lines = [];
    exec('/sbin/ifconfig -a', $lines);
    $temporary = tempnam($directory, '.routing-context-');
    if ($temporary === false) {
        throw new RuntimeException('Unable to prepare the Sing-box routing context.');
    }
    try {
        $handle = fopen($temporary, 'wb');
        $content = json_encode(sing_box_routing_context($fw->getInterfaceMapping(), $lines), JSON_THROW_ON_ERROR) . "\n";
        if ($handle === false || !chmod($temporary, 0600)) {
            throw new RuntimeException('Unable to open the Sing-box routing context.');
        }
        try {
            $pathInfo = lstat($temporary);
            $handleInfo = fstat($handle);
            if ($pathInfo === false || $handleInfo === false
                || ($handleInfo['mode'] & 0170777) !== 0100600 || $handleInfo['uid'] !== 0
                || $handleInfo['dev'] !== $pathInfo['dev'] || $handleInfo['ino'] !== $pathInfo['ino']) {
                throw new RuntimeException('The Sing-box routing context temporary file is invalid.');
            }
            $offset = 0;
            while ($offset < strlen($content)) {
                $written = fwrite($handle, substr($content, $offset));
                if ($written === false || $written === 0) {
                    throw new RuntimeException('Unable to write the Sing-box routing context.');
                }
                $offset += $written;
            }
            if (!fflush($handle) || !fsync($handle)) {
                throw new RuntimeException('Unable to synchronize the Sing-box routing context.');
            }
        } finally {
            fclose($handle);
        }
        if (!rename($temporary, $directory . '/routing-context.json')) {
            throw new RuntimeException('Unable to save the Sing-box routing context.');
        }
        $directoryHandle = fopen($directory, 'r');
        if ($directoryHandle === false) {
            throw new RuntimeException('Unable to open the Sing-box routing context directory.');
        }
        try {
            if (!fsync($directoryHandle)) {
                throw new RuntimeException('Unable to synchronize the Sing-box routing context directory.');
            }
        } finally {
            fclose($directoryHandle);
        }
    } finally {
        if (is_file($temporary)) {
            unlink($temporary);
        }
    }
}
