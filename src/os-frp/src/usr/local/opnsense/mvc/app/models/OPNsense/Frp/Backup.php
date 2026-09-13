<?php

/*
 * Copyright (C) 2026 Kazuha
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

namespace OPNsense\Frp;

use OPNsense\Base\BaseModel;

/**
 * The frp state the native configuration backup carries.
 *
 * There is no behaviour here on purpose.  The model exists so that config.xml
 * has a place to hold what /usr/local/etc/frp and /etc/rc.conf.d hold, and so
 * that the section survives while the plugin is not installed: serializeToConfig
 * walks to this mountpoint and replaces only this node, and the firmware
 * resync that empties <plugins/> never reaches a model section at all.
 *
 * Everything that decides what goes in and what comes out lives in
 * /usr/local/opnsense/scripts/frp/manage.py; config_mirror.php is the only
 * caller and does no more than set these fields and read them back.
 */
class Backup extends BaseModel
{
    public function runMigrations()
    {
        /* The raw XML mirror owns its schema and preserves future fields. */
        return false;
    }
}
