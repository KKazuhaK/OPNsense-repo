<?php

namespace OPNsense\Wanguard;

use OPNsense\Base\BaseModel;
use OPNsense\Base\Messages\Message;

class General extends BaseModel
{
    /* The daemon enforces the same bounds, and refuses the LAN, again when it reads the settings. */
    const MAX_NETWORKS = 32;
    const MIN_PREFIX = 8;

    public function performValidation($validateFullModel = false)
    {
        $messages = parent::performValidation($validateFullModel);
        if ($validateFullModel || $this->interfaces->isFieldChanged()) {
            /* Even a DHCP LAN is never watched: its lease is the operator's way in. */
            if (in_array('lan', explode(',', (string)$this->interfaces), true)) {
                $messages->appendMessage(new Message(
                    gettext('The LAN interface cannot be watched.'),
                    'interfaces'
                ));
            }
        }
        if ($validateFullModel || $this->networks->isFieldChanged()) {
            $entries = array_values(array_filter(explode(',', (string)$this->networks), 'strlen'));
            if (count($entries) > self::MAX_NETWORKS) {
                $messages->appendMessage(new Message(
                    sprintf(gettext('List at most %d networks.'), self::MAX_NETWORKS),
                    'networks'
                ));
            }
            foreach ($entries as $entry) {
                $parts = explode('/', $entry);
                /* A wide network such as 0.0.0.0/0 would make every address unwanted. */
                if (count($parts) === 2 && ctype_digit($parts[1]) && (int)$parts[1] < self::MIN_PREFIX) {
                    $messages->appendMessage(new Message(
                        sprintf(gettext('%s is too wide; use a prefix of /%d or longer.'), $entry, self::MIN_PREFIX),
                        'networks'
                    ));
                }
            }
        }
        return $messages;
    }
}
