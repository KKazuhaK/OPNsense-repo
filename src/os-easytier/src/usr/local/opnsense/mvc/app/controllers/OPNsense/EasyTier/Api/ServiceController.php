<?php
namespace OPNsense\EasyTier\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;

class ServiceController extends ApiControllerBase
{
    public function statusAction(): array
    {
        return $this->backend('status');
    }

    public function peersAction(): array
    {
        return $this->backend('peers');
    }

    public function logAction(): array
    {
        return $this->backend('log');
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

    public function clearLogAction(): array
    {
        return $this->backend('clear_log', true);
    }


    private function backend(string $action, bool $mutation = false): array
    {
        if ($mutation && $this->request->getMethod() !== 'POST') {
            return ['status' => 'failed', 'error' => gettext('A POST is required.')];
        }
        if ($mutation) {
            $this->throwReadOnly();
        }
        $result = json_decode((string)(new Backend())->configdRun('easytier ' . $action), true);
        return is_array($result) ? $result
            : ['status' => 'failed', 'error' => gettext('The backend did not answer.')];
    }
}
