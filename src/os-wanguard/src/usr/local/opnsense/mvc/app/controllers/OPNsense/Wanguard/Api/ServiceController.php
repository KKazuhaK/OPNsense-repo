<?php

namespace OPNsense\Wanguard\Api;

use OPNsense\Base\ApiMutableServiceControllerBase;
use OPNsense\Core\Backend;

class ServiceController extends ApiMutableServiceControllerBase
{
    protected static $internalServiceClass = '\OPNsense\Wanguard\General';
    protected static $internalServiceEnabled = 'enabled';
    protected static $internalServiceTemplate = 'OPNsense/Wanguard';
    protected static $internalServiceName = 'wanguard';

    /* The running daemon keeps its rate limits; new settings reach it through
       a reload, which asks for an observation at once, instead of a restart. */
    protected function reconfigureForceRestart()
    {
        return 0;
    }

    private function mutation()
    {
        if ($this->request->getMethod() !== 'POST') {
            return false;
        }
        $this->throwReadOnly();
        return true;
    }

    public function startAction()
    {
        return $this->mutation() ? parent::startAction() : ['response' => []];
    }

    public function stopAction()
    {
        return $this->mutation() ? parent::stopAction() : ['response' => []];
    }

    public function restartAction()
    {
        return $this->mutation() ? parent::restartAction() : ['response' => []];
    }

    public function reconfigureAction()
    {
        return $this->mutation() ? parent::reconfigureAction() : ['status' => 'failed'];
    }

    public function stateAction()
    {
        $response = trim((new Backend())->configdRun('wanguard state'));
        $decoded = json_decode($response, true);
        if (!is_array($decoded) || !isset($decoded['status'])) {
            return ['status' => 'failed', 'message' => gettext('The WAN Guard status is unavailable.'), 'interfaces' => []];
        }
        return $decoded;
    }

    public function retryAction()
    {
        if ($this->request->getMethod() !== 'POST') {
            return ['status' => 'failed', 'message' => gettext('POST required')];
        }
        $this->throwReadOnly();
        $interface = $this->request->getPost('interface');
        if (!is_string($interface) || !preg_match('/^[a-z0-9_]{1,32}$/D', $interface)) {
            return ['status' => 'refused', 'message' => gettext('Unknown interface.')];
        }
        $response = trim((new Backend())->configdpRun('wanguard retry', [$interface]));
        $decoded = json_decode($response, true);
        $messages = [
            'queued' => gettext('Retry queued; it runs within a few seconds if the address is still unwanted.'),
            'queued-already' => gettext('A retry for this interface is already queued.'),
            'disabled' => gettext('WAN Guard is disabled.'),
            'stopped' => gettext('The WAN Guard service is not running.'),
            'not-watched' => gettext('This interface is not watched.'),
            'unavailable' => gettext('The interfaces could not be observed.'),
            'invalid' => gettext('Unknown interface.'),
        ];
        if (!is_array($decoded) || !in_array($decoded['status'] ?? '', ['queued', 'refused'], true)) {
            return ['status' => 'failed', 'message' => gettext('No usable response from the WAN Guard backend.')];
        }
        $code = is_string($decoded['code'] ?? null) ? $decoded['code'] : '';
        return ['status' => $decoded['status'], 'message' => $messages[$code] ?? gettext('The retry was refused.')];
    }
}
