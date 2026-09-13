<?php

/*
 * frp (https://github.com/fatedier/frp) glue for OPNsense.
 *
 * frp is two daemons, frps and frpc, and this plugin drives both.  They are
 * registered as two separate services on purpose: each has its own rc script,
 * its own configuration file, its own log and its own pidfile, so one can be
 * running while the other is stopped or broken.
 */

function frp_services()
{
    $services = [];

    $services[] = [
        'description' => gettext('frp server (frps)'),
        'configd' => [
            'restart' => ['frps restart'],
            'start' => ['frps start'],
            'stop' => ['frps stop'],
        ],
        'name' => 'frps',
        'pidfile' => '/var/run/frps.pid',
    ];

    $services[] = [
        'description' => gettext('frp client (frpc)'),
        'configd' => [
            'restart' => ['frpc restart'],
            'start' => ['frpc start'],
            'stop' => ['frpc stop'],
        ],
        'name' => 'frpc',
        'pidfile' => '/var/run/frpc.pid',
    ];

    return $services;
}

function frp_configure()
{
    /*
     * No hook is registered, deliberately.
     *
     * newwanip is the one that looks tempting and is wrong here.  frpc holds a
     * single outbound control connection: when a WAN address changes the
     * connection breaks, frpc notices by heartbeat and dials again, re-resolving
     * serverAddr as it goes.  Restarting on the event would tear down every
     * working proxy instead, and on a multi-WAN firewall it would fire for
     * interfaces frpc never used.  frps binds 0.0.0.0 and does not care either.
     *
     * Boot start needs no hook: frps_enable and frpc_enable in /etc/rc.conf.d
     * already decide that, and the web UI keeps them in step with sysrc.
     *
     * frp creates no interface and needs no firewall anchor, so there is no
     * frp_firewall() next to this; the operator allows the frps bind port in
     * Firewall > Rules like any other inbound service.
     */
    return [];
}
