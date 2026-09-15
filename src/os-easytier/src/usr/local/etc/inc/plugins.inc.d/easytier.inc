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

function easytier_configure()
{
    return [
        'early' => ['easytier_backup_configure'],
        'local' => ['easytier_backup_configure'],
    ];
}

function easytier_backup_configure()
{
    $status = 0;
    $output = [];
    exec('/usr/local/bin/python3 /usr/local/opnsense/scripts/easytier/config_mirror.py reconcile >/dev/null 2>&1', $output, $status);
    if ($status !== 0) {
        error_log('EasyTier configuration backup could not be restored.');
        return;
    }
    exec('/usr/sbin/service os-easytier-backup onestart >/dev/null 2>&1');
}
