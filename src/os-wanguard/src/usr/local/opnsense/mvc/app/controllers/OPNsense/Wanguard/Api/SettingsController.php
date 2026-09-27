<?php

namespace OPNsense\Wanguard\Api;

use OPNsense\Base\ApiMutableModelControllerBase;

/* get and set come from the base class; set validates the model and refuses
   read-only accounts before it saves. */
class SettingsController extends ApiMutableModelControllerBase
{
    protected static $internalModelClass = '\OPNsense\Wanguard\General';
    protected static $internalModelName = 'general';
}
