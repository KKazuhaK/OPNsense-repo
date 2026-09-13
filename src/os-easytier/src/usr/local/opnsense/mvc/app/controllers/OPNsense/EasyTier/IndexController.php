<?php
namespace OPNsense\EasyTier;

class IndexController extends \OPNsense\Base\IndexController
{
    public function indexAction()
    {
        $this->view->pick('OPNsense/EasyTier/index');
    }
}
