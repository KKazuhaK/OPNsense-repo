<?php
/* Copyright (C) 2026 Kazuha. All rights reserved. */

namespace OPNsense\SingBox;

class Backup extends \OPNsense\Base\BaseModel
{
    public function runMigrations()
    {
        // The raw backup transport owns schema changes and retains future fields.
        // Generic MVC migration would replace this archive record from its model.
        return false;
    }
}
