<?php
namespace OPNsense\Staticarp;

class IndexController extends \OPNsense\Base\IndexController
{
    public function indexAction()
    {
        $this->view->pick('OPNsense/Staticarp/index');
    }
}
