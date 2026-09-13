<?php
/* Copyright (C) 2026 Kazuha. All rights reserved. */

namespace OPNsense\SingBox\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;

class ServiceController extends ApiControllerBase
{
    private function run(string $action, bool $post = true): array
    {
        if ($post && $this->request->getMethod() !== 'POST') {
            return ['status' => 'failed', 'error' => gettext('A POST is required.')];
        }
        if ($post) {
            $this->throwReadOnly();
        }
        $data = json_decode((string)(new Backend())->configdRun('sing-box ' . $action), true);
        if (!is_array($data)) {
            return ['status' => 'failed', 'error' => gettext('The backend did not answer.')];
        }
        if (empty($data['ok'])) {
            return ['status' => 'failed', 'error' => $data['error'] ?? gettext('Operation failed.')];
        }
        unset($data['ok']);
        return ['status' => 'ok'] + $data;
    }

    public function statusAction(): array { return $this->run('status', false); }
    public function updateStatusAction(): array { return $this->run('update-status', false); }
    public function logAction(): array { return $this->run('log', false); }
    public function subLogAction(): array { return $this->run('sub-log', false); }
    public function startAction(): array { return $this->run('start'); }
    public function stopAction(): array { return $this->run('stop'); }
    public function restartAction(): array { return $this->run('restart'); }
    public function subUpdateAction(): array { return $this->run('sub-update'); }
    public function clearLogAction(): array { return $this->run('clear-log'); }
    public function clearSubLogAction(): array { return $this->run('clear-sub-log'); }
}
