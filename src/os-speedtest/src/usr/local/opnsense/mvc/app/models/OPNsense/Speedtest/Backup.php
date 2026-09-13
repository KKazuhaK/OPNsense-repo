<?php

namespace OPNsense\Speedtest;

use OPNsense\Base\BaseModel;

class Backup extends BaseModel
{
    public function runMigrations()
    {
        /* The raw XML mirror owns its schema and preserves future fields. */
        return false;
    }
}
