<?php

function ttyd_configure()
{
    return ['early' => ['ttyd_backup_configure'], 'local' => ['ttyd_backup_configure']];
}

function ttyd_backup_configure()
{
    $status = 0;
    $output = [];
    exec('/usr/local/bin/python3 /usr/local/opnsense/scripts/ttyd/config_mirror.py reconcile >/dev/null 2>&1', $output, $status);
    if ($status !== 0) {
        error_log('Terminal configuration backup could not be restored.');
        return;
    }
    exec('/usr/sbin/service os-ttyd-backup onestart >/dev/null 2>&1');
}
