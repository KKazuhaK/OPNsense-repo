<?php
namespace OPNsense\Lucky;

class IndexController extends \OPNsense\Base\IndexController
{
    public function indexAction()
    {
        $this->view->pick('OPNsense/Lucky/index');
    }
}
