<?php
namespace OPNsense\Lucky\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;

class ServiceController extends ApiControllerBase
{
    public function statusAction(): array
    {
        $output = (string)(new Backend())->configdRun('lucky status');
        return ['running' => strpos($output, ' is running as pid ') !== false];
    }

    private function run(string $action): array
    {
        if ($this->request->getMethod() !== 'POST') {
            return ['status' => 'failed', 'error' => gettext('A POST is required.')];
        }
        $this->throwReadOnly();
        $output = trim((string)(new Backend())->configdRun('lucky ' . $action));
        return $output === 'OK' ? ['status' => 'ok']
            : ['status' => 'failed', 'error' => gettext('The service command failed.')];
    }

    public function startAction(): array { return $this->run('start'); }
    public function stopAction(): array { return $this->run('stop'); }
    public function restartAction(): array { return $this->run('restart'); }
}
