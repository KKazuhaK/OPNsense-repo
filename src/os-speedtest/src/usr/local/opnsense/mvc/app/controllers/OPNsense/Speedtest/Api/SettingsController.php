<?php
namespace OPNsense\Speedtest\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;

class SettingsController extends ApiControllerBase
{
    public function getAction(): array
    {
        return $this->call('get');
    }

    public function setAction(): array
    {
        if (!$this->request->isPost()) return ['status'=>'failed', 'error'=>gettext('A POST is required.')];
        $this->throwReadOnly();
        return $this->call('set', (array)$this->request->getPost('settings', null, []));
    }

    public function serversAction(): array
    {
        return $this->call('servers', ['interface'=>$this->request->getQuery('interface', null, 'auto')]);
    }

    public function refreshAction(): array
    {
        if (!$this->request->isPost()) return ['status'=>'failed', 'error'=>gettext('A POST is required.')];
        $this->throwReadOnly();
        return $this->call('refresh', ['interface'=>$this->request->getPost('interface', null, 'auto')]);
    }

    private function call(string $action, array $input = []): array
    {
        $raw = (new Backend())->configdpRun('speedtest ' . $action, [base64_encode(json_encode($input))], false, 60);
        $result = json_decode((string)$raw, true);
        return is_array($result) ? $result : ['status'=>'failed', 'error'=>gettext('The backend did not answer.')];
    }
}
