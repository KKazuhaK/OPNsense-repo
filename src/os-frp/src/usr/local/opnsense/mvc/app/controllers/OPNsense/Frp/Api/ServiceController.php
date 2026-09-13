<?php

/*
 * Copyright (C) 2026 Kazuha
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

namespace OPNsense\Frp\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;

/**
 * frp is two daemons, so every action names the side it acts on and the side
 * is also the configd command group: "frps status", "frpc restart". Nothing
 * here touches the daemons or their files directly.
 *
 * Starting a daemon also enables it for boot and stopping it disables it
 * again, because manage.py flips <side>_enable with sysrc(8) around the rc
 * call. The view says so on the buttons rather than offering a second switch
 * the backend has no verb for.
 */
class ServiceController extends ApiControllerBase
{
    /* The only two strings that may ever be interpolated into a configd
       command. Anything else is refused before it reaches the backend. */
    private const SIDES = ['frps', 'frpc'];

    public function statusAction(string $side = ''): array
    {
        return $this->backend($side, 'status');
    }

    public function logAction(string $side = ''): array
    {
        return $this->backend($side, 'log');
    }

    public function startAction(string $side = ''): array
    {
        return $this->backend($side, 'start', true);
    }

    public function stopAction(string $side = ''): array
    {
        return $this->backend($side, 'stop', true);
    }

    public function restartAction(string $side = ''): array
    {
        return $this->backend($side, 'restart', true);
    }

    private function backend(string $side, string $action, bool $mutation = false): array
    {
        if (!in_array($side, self::SIDES, true)) {
            return ['status' => 'failed', 'error' => gettext('Unknown frp side.')];
        }
        if ($mutation) {
            if ($this->request->getMethod() !== 'POST') {
                return ['status' => 'failed', 'error' => gettext('A POST is required.')];
            }
            $this->throwReadOnly();
        }
        $answer = json_decode((string)(new Backend())->configdRun($side . ' ' . $action), true);
        if (!is_array($answer)) {
            /* manage.py answers with JSON and exit status 0 either way, so
               anything else means configd itself could not run it. */
            return ['status' => 'failed', 'error' => gettext('The backend did not answer.')];
        }
        return !empty($answer['ok'])
            ? ['status' => 'ok', 'result' => $answer['result'] ?? null]
            : ['status' => 'failed', 'error' => (string)($answer['error'] ?? gettext('The operation failed.'))];
    }
}
