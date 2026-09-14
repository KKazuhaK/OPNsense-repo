<?php

function ddnsgo_backup_configure()
{
    return ['early' => ['ddnsgo_backup_reconcile']];
}

function ddnsgo_backup_reconcile()
{
    /* Import a restored XML snapshot before external daemons read their files. */
    $output = [];
    $status = 0;
    exec('/usr/local/bin/python3 /usr/local/opnsense/scripts/ddnsgo/config_mirror.py reconcile 2>/dev/null', $output, $status);
    if ($status !== 0) {
        log_error('Ddnsgo configuration backup could not be restored.');
    }
    exec('/usr/sbin/service os-ddns-go-backup onestart >/dev/null 2>&1');
}
