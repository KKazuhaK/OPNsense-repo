<?php

namespace OPNsense\Mihomo;

use OPNsense\Base\BaseModel;

class Backup extends BaseModel
{
    public function runMigrations(): bool
    {
        // The raw mirror owns its schema and preserves unknown or partial fields.
        // Generic MVC migration serialization would replace those fields.
        return false;
    }
}
