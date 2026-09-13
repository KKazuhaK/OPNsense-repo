<?php
namespace OPNsense\Pftop\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;

class ServiceController extends ApiControllerBase
{
    public function snapshotAction(): array
    {
        $parameters = [];
        foreach (['view' => 'default', 'sort' => 'bytes', 'count' => '100', 'filter' => ''] as $key => $default) {
            $parameters[$key] = (string)$this->request->getQuery($key, null, $default);
        }
        $output = (new Backend())->configdpRun('pftop snapshot', [base64_encode(json_encode($parameters))]);
        $decoded = json_decode((string)$output, true);
        return is_array($decoded) ? $decoded : ['status' => 'failed', 'error' => gettext('The backend did not answer.')];
    }
}
