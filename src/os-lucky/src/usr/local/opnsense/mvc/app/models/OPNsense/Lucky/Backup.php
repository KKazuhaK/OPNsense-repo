<?php

namespace OPNsense\Lucky;

use OPNsense\Base\BaseModel;

class Backup extends BaseModel
{
    public function runMigrations()
    {
        // The raw backup transport owns schema changes and retains future fields.
        // Generic MVC migration would replace this archive record from its model.
        return false;
    }
}
