<?php
namespace OPNsense\Pftop;

class IndexController extends \OPNsense\Base\IndexController
{
    public function indexAction()
    {
        $this->view->pick('OPNsense/Pftop/index');
    }
}
