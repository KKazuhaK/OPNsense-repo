<?php
namespace OPNsense\Lucky\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;

/* Settings remain in the plugin's existing store; configd owns all file access. */
class SettingsController extends ApiControllerBase
{
    public function getAction(): array
    {
        $decoded = json_decode((string)(new Backend())->configdRun('lucky get'), true);
        return is_array($decoded) ? $decoded : ['status' => 'failed', 'error' => gettext('The backend did not answer.')];
    }

    public function setAction(): array
    {
        if ($this->request->getMethod() !== 'POST') {
            return ['status' => 'failed', 'error' => gettext('A POST is required.')];
        }
        $this->throwReadOnly();
        $settings = $this->request->getPost('settings');
        if (!is_array($settings)) {
            return ['status' => 'failed', 'error' => gettext('Invalid settings.')];
        }
        $payload = json_encode($settings);
        if ($payload === false || strlen($payload) > 2 * 1048576) {
            return ['status' => 'failed', 'error' => gettext('The settings are invalid or too large.')];
        }
        $staged = tempnam('/tmp', 'lucky-api-');
        if ($staged === false) {
            return ['status' => 'failed', 'error' => gettext('Unable to stage the settings.')];
        }
        try {
            chmod($staged, 0600);
            if (file_put_contents($staged, $payload, LOCK_EX) === false) {
                return ['status' => 'failed', 'error' => gettext('Unable to stage the settings.')];
            }
            $decoded = json_decode((string)(new Backend())->configdpRun('lucky set', [$staged]), true);
        } finally {
            @unlink($staged);
        }
        if (!is_array($decoded)) {
            return ['status' => 'failed', 'error' => gettext('The backend did not answer.')];
        }
        if (($decoded['status'] ?? '') === 'ok') {
            $action = !empty($settings['enabled']) ? 'restart' : 'stop';
            $output = (string)(new Backend())->configdRun('lucky ' . $action);
            if (trim($output) !== 'OK') {
                return ['status' => 'failed', 'saved' => true, 'error' => gettext('Settings were saved, but the service command failed.')];
            }
        }
        return $decoded;
    }
}
