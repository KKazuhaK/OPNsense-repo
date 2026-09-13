<?php
/* Copyright (C) 2026 Kazuha. All rights reserved. */

namespace OPNsense\SingBox;

class IndexController extends \OPNsense\Base\IndexController
{
    public function indexAction()
    {
        $this->view->pick('OPNsense/SingBox/index');
    }
}
