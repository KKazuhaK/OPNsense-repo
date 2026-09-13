<?php
namespace OPNsense\EasyTier\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;

class SettingsController extends ApiControllerBase
{
    public function getAction(): array
    {
        return $this->result((new Backend())->configdRun('easytier settings'));
    }

    public function setAction(): array
    {
        if ($this->request->getMethod() !== 'POST') {
            return ['status' => 'failed', 'error' => gettext('A POST is required.')];
        }
        $this->throwReadOnly();
        $configuration = (string)$this->request->getPost('config', null, '');
        if (strlen($configuration) > 1048576) {
            return ['status' => 'failed', 'error' => gettext('The configuration is too large.')];
        }
        // configdpRun quotes parameters; only a private filename crosses configd.
        $temporary = tempnam('/tmp', 'easytier_mvc_');
        if ($temporary === false) {
            return ['status' => 'failed', 'error' => gettext('Unable to stage configuration.')];
        }
        try {
            if (!chmod($temporary, 0600) || file_put_contents($temporary, $configuration, LOCK_EX) === false) {
                return ['status' => 'failed', 'error' => gettext('Unable to stage configuration.')];
            }
            return $this->result((new Backend())->configdpRun('easytier save', [$temporary]));
        } finally {
            @unlink($temporary);
        }
    }

    private function result($raw): array
    {
        $result = json_decode((string)$raw, true);
        return is_array($result) ? $result
            : ['status' => 'failed', 'error' => gettext('The backend did not answer.')];
    }
}
