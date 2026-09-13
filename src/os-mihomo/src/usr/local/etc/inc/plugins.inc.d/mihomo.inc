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
        'newwanip' => ['mihomo_newwanip:3'],
    ];
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
