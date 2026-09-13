<?php
namespace OPNsense\Ttyd;

class IndexController extends \OPNsense\Base\IndexController
{
    public function indexAction()
    {
        $this->view->pick('OPNsense/Ttyd/index');
    }
}
