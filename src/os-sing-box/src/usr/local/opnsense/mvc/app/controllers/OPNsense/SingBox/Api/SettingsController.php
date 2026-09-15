<?php
/* Copyright (C) 2026 Kazuha. All rights reserved. */

namespace OPNsense\SingBox\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;

class SettingsController extends ApiControllerBase
{
    private function run(string $action, ?string $argument = null): array
    {
        $backend = new Backend();
        $temporary = null;
        try {
            if ($argument === null) {
                $raw = $backend->configdRun('sing-box ' . $action);
            } else {
                if (strlen($argument) > 16 * 1024 * 1024) {
                    return ['status' => 'failed', 'error' => gettext('The configuration request is too large.')];
                }
                /* Configd logs its command arguments. Only a private file path
                   crosses that boundary, never a subscription URL or secret. */
                $temporary = tempnam('/tmp', 'singbox-request-');
                if ($temporary === false || dirname($temporary) !== '/tmp'
                    || !chmod($temporary, 0600)
                    || file_put_contents($temporary, $argument, LOCK_EX) !== strlen($argument)) {
                    return ['status' => 'failed', 'error' => gettext('Unable to stage the configuration.')];
                }
                $raw = $backend->configdpRun('sing-box ' . $action, [$temporary]);
            }
        } finally {
            if (is_string($temporary) && is_file($temporary)) {
                unlink($temporary);
            }
        }
        $data = json_decode((string)$raw, true);
        if (!is_array($data)) {
            return ['status' => 'failed', 'error' => gettext('The backend did not answer.')];
        }
        if (empty($data['ok'])) {
            return ['status' => 'failed', 'error' => $data['error'] ?? gettext('Operation failed.')];
        }
        unset($data['ok']);
        return ['status' => 'ok'] + $data;
    }

    public function getAction(): array
    {
        return $this->run('get-settings');
    }

    public function setAction(): array
    {
        if ($this->request->getMethod() !== 'POST') {
            return ['status' => 'failed', 'error' => gettext('A POST is required.')];
        }
        $this->throwReadOnly();
        $given = $this->request->getPost('settings');
        $given = is_array($given) ? $given : [];
        return $this->run('set-settings', json_encode([
            'subscription_url' => trim((string)($given['subscription_url'] ?? '')),
            'clear_url' => !empty($given['clear_url']),
        ]));
    }

    public function setIntegrationAction(): array
    {
        if ($this->request->getMethod() !== 'POST') {
            return ['status' => 'failed', 'error' => gettext('A POST is required.')];
        }
        $this->throwReadOnly();
        $given = $this->request->getPost('integration');
        $given = is_array($given) ? $given : [];
        $devices = $given['device_list'] ?? [];
        if (is_string($devices)) {
            $devices = preg_split('/[\s,]+/', trim($devices), -1, PREG_SPLIT_NO_EMPTY);
        }
        return $this->run('set-integration', json_encode([
            'transparent' => !empty($given['transparent']),
            'transparent_consent' => !empty($given['transparent_consent']),
            'device_mode' => (string)($given['device_mode'] ?? 'off'),
            'device_list' => $devices,
            'ipv6' => !empty($given['ipv6']),
        ]));
    }

    public function saveConfigAction(): array
    {
        if ($this->request->getMethod() !== 'POST') {
            return ['status' => 'failed', 'error' => gettext('A POST is required.')];
        }
        $this->throwReadOnly();
        $configuration = (string)$this->request->getPost('config', null, '');
        if (strlen($configuration) > 4 * 1024 * 1024) {
            return ['status' => 'failed', 'error' => gettext('Configuration content is larger than 4 MiB.')];
        }
        return $this->run('save-config', json_encode([
            'config' => $configuration,
            'revision' => (string)$this->request->getPost('revision', null, ''),
        ]));
    }
}
