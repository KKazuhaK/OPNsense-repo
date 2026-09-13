<?php
namespace OPNsense\LangTool;

class IndexController extends \OPNsense\Base\IndexController
{
    public function indexAction()
    {
        $this->view->pick('OPNsense/LangTool/index');
    }
}
