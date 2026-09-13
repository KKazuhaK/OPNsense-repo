<?php
namespace OPNsense\LangTool\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;

class ServiceController extends ApiControllerBase
{
    public function statusAction(): array
    {
        return $this->backend('status');
    }

    public function updateAction(): array
    {
        return $this->backend('update', true);
    }


    private function backend(string $action, bool $mutation = false): array
    {
        if ($mutation && $this->request->getMethod() !== 'POST') {
            return ['status' => 'failed', 'error' => gettext('A POST is required.')];
        }
        if ($mutation) {
            $this->throwReadOnly();
        }
        $result = json_decode((string)(new Backend())->configdRun('langtool ' . $action), true);
        return is_array($result) ? $result
            : ['status' => 'failed', 'error' => gettext('The backend did not answer.')];
    }
}
