<?php
namespace OPNsense\Staticarp\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;

/* Settings remain in the plugin's existing store; configd owns all file access. */
class SettingsController extends ApiControllerBase
{
    public function getAction(): array
    {
        $decoded = json_decode((string)(new Backend())->configdRun('staticarp get'), true);
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
        $staged = tempnam('/tmp', 'staticarp-api-');
        if ($staged === false) {
            return ['status' => 'failed', 'error' => gettext('Unable to stage the settings.')];
        }
        try {
            chmod($staged, 0600);
            if (file_put_contents($staged, $payload, LOCK_EX) === false) {
                return ['status' => 'failed', 'error' => gettext('Unable to stage the settings.')];
            }
            $decoded = json_decode((string)(new Backend())->configdpRun('staticarp set', [$staged]), true);
        } finally {
            @unlink($staged);
        }
        if (!is_array($decoded)) {
            return ['status' => 'failed', 'error' => gettext('The backend did not answer.')];
        }
        if (($decoded['status'] ?? '') === 'ok') {
            $action = !empty($decoded['enabled']) ? 'apply' : 'reset';
            $output = (string)(new Backend())->configdRun('staticarp ' . $action);
            if (trim($output) !== 'OK') {
                return ['status' => 'failed', 'saved' => true, 'error' => gettext('Settings were saved, but the service command failed.')];
            }
        }
        return $decoded;
    }

    public function scriptAction(): array
    {
        $name = (string)$this->request->getQuery('interface', null, '');
        if (!preg_match('/^[a-zA-Z0-9_]+$/', $name)) {
            return ['status' => 'failed', 'error' => gettext('Invalid interface.')];
        }
        $decoded = json_decode((string)(new Backend())->configdpRun('staticarp script', [$name]), true);
        return is_array($decoded) ? $decoded : ['status' => 'failed', 'error' => gettext('The backend did not answer.')];
    }
}
