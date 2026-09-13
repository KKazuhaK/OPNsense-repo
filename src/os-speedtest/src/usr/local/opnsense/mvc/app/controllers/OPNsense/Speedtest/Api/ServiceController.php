<?php
namespace OPNsense\Speedtest\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;

class ServiceController extends ApiControllerBase
{
    public function progressAction(): array
    {
        return $this->call('progress');
    }

    public function runAction(): array
    {
        if (!$this->request->isPost()) return ['status'=>'failed', 'error'=>gettext('A POST is required.')];
        $this->throwReadOnly();
        return $this->call('run', (array)$this->request->getPost('settings', null, []));
    }

    public function clearAction(): array
    {
        if (!$this->request->isPost()) return ['status'=>'failed', 'error'=>gettext('A POST is required.')];
        $this->throwReadOnly();
        return $this->call('clear');
    }

    private function call(string $action, array $input = []): array
    {
        $raw = (new Backend())->configdpRun('speedtest ' . $action, [base64_encode(json_encode($input))]);
        $result = json_decode((string)$raw, true);
        return is_array($result) ? $result : ['status'=>'failed', 'error'=>gettext('The backend did not answer.')];
    }
}
