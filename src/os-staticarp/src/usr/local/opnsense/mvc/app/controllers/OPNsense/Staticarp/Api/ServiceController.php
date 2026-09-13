<?php
namespace OPNsense\Staticarp\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;

class ServiceController extends ApiControllerBase
{
    public function statusAction(): array
    {
        $output = (string)(new Backend())->configdRun('staticarp status');
        preg_match('/^entries=([0-9]+)$/m', $output, $entries);
        return ['enabled' => strpos($output, 'enabled=YES') !== false, 'entries' => (int)($entries[1] ?? 0)];
    }

    private function run(string $action): array
    {
        if ($this->request->getMethod() !== 'POST') {
            return ['status' => 'failed', 'error' => gettext('A POST is required.')];
        }
        $this->throwReadOnly();
        $output = (string)(new Backend())->configdRun('staticarp ' . $action);
        return trim($output) === 'OK'
            ? ['status' => 'ok'] : ['status' => 'failed', 'error' => gettext('The service command failed.')];
    }

    public function applyAction(): array { return $this->run('apply'); }
    public function resetAction(): array { return $this->run('reset'); }
}
