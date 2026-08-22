<?php

function easytier_services()
{
    return [[
        'description' => gettext('EasyTier mesh VPN'),
        'configd' => [
            'restart' => ['easytier restart'],
            'start' => ['easytier start'],
            'stop' => ['easytier stop'],
        ],
        'name' => 'easytier',
        'pidfile' => '/var/run/easytier.pid',
    ]];
}

function easytier_firewall(\OPNsense\Firewall\Plugin $fw)
{
    $output = [];
    $status = 0;
    exec('/sbin/ifconfig easytier0 >/dev/null 2>&1', $output, $status);
    if ($status !== 0) {
        return;
    }
    /* Dynamic TUN devices are deliberately absent from the persistent
     * interface mapping. Register an anchor and let rc.d load its content. */
    $fw->registerAnchor('easytier', 'fw', 1, 'head', true);
}

function easytier_configure()
{
    return ['newwanip' => ['easytier_restart']];
}

function easytier_restart()
{
    configd_run('easytier restart');
}
