<?php
namespace OPNsense\Ttyd\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;

class ServiceController extends ApiControllerBase
{
    public function statusAction(): array
    {
        return $this->backend('status');
    }

    public function startAction(): array
    {
        return $this->backend('start', true);
    }

    public function stopAction(): array
    {
        return $this->backend('stop', true);
    }

    public function restartAction(): array
    {
        return $this->backend('restart', true);
    }


    private function backend(string $action, bool $mutation = false): array
    {
        if ($mutation && $this->request->getMethod() !== 'POST') {
            return ['status' => 'failed', 'error' => gettext('A POST is required.')];
        }
        if ($mutation) {
            $this->throwReadOnly();
        }
        $result = json_decode((string)(new Backend())->configdRun('ttyd ' . $action), true);
        return is_array($result) ? $result
            : ['status' => 'failed', 'error' => gettext('The backend did not answer.')];
    }
}
