<?php

function lucky_backup_configure()
{
    return ['early' => ['lucky_backup_reconcile']];
}

function lucky_backup_reconcile()
{
    /* Import a restored XML snapshot before external daemons read their files. */
    $output = [];
    $status = 0;
    exec('/usr/local/bin/python3 /usr/local/opnsense/scripts/lucky/config_mirror.py reconcile 2>/dev/null', $output, $status);
    if ($status !== 0) {
        log_error('Lucky configuration backup could not be restored.');
    }
    exec('/usr/sbin/service os-lucky-backup onestart >/dev/null 2>&1');
}
