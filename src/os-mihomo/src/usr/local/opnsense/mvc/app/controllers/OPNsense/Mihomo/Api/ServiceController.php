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

namespace OPNsense\Mihomo\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;

/**
 * Every state change goes through configd, which already owns the entry points
 * the boot and WAN hooks use. Nothing here reaches into the state directory.
 */
class ServiceController extends ApiControllerBase
{
    /* Actions taking no argument, mapped to their configd command. */
    private const PLAIN = [
        'start' => 'start', 'stop' => 'stop', 'restart' => 'restart',
        'enableTransparent' => 'enable-transparent',
        'disableTransparent' => 'disable-transparent',
        'subUpdate' => 'sub-update',
        'clearLog' => 'clear-log', 'clearSubLog' => 'clear-sub-log',
    ];

    private function run(string $command, string $argument = null): array
    {
        $backend = new Backend();
        $raw = $argument === null
            ? $backend->configdRun('mihomo ' . $command)
            : $backend->configdpRun('mihomo ' . $command, [$argument]);
        $decoded = json_decode((string)$raw, true);
        if (!is_array($decoded)) {
            /* A backend that answers with anything else has failed in a way the
               caller cannot interpret; say so rather than invent a result. */
            return ['status' => 'failed', 'error' => gettext('The backend did not answer.')];
        }
        return $decoded['ok'] ?? false
            ? ['status' => 'ok', 'result' => $decoded['result'] ?? null]
            : ['status' => 'failed', 'error' => $decoded['error'] ?? gettext('Operation failed.')];
    }

    public function __call($name, $arguments)
    {
        /* Phalcon dispatches <verb>Action; map the no-argument ones in one place. */
        $verb = preg_replace('/Action$/', '', $name);
        if (!$this->request->isPost() || !isset(self::PLAIN[$verb])) {
            return ['status' => 'failed', 'error' => gettext('Unknown or non-POST action.')];
        }
        return $this->run(self::PLAIN[$verb]);
    }

    public function statusAction(): array
    {
        $raw = @file_get_contents('/var/run/mihomo-status.json');
        $status = is_string($raw) ? json_decode($raw, true) : null;
        if (!is_array($status) || time() - ($status['updated'] ?? 0) > 20) {
            return ['running' => false, 'dns_active' => false,
                    'error' => gettext('Service status is unavailable.')];
        }
        return $status;
    }

    public function updateStatusAction(): array
    {
        $raw = @file_get_contents('/var/run/mihomo-update.json');
        $state = is_string($raw) && $raw !== '' ? json_decode($raw, true) : null;
        return is_array($state) ? $state : [];
    }

    public function devicesAction(): array
    {
        /* Read only, and a read the page makes on every load, so it stays a
           GET like the other status endpoints rather than joining PLAIN. */
        $answer = $this->run('devices');
        $found = ($answer['status'] ?? '') === 'ok' && is_array($answer['result'] ?? null)
            ? $answer['result'] : [];
        /* Flattened, because a page that cannot list devices still has to draw
           the rest of the tab rather than render an error in place of it. */
        return ['devices' => $found['devices'] ?? [], 'rules' => $found['rules'] ?? []];
    }

    public function logAction(): array
    {
        return ['log' => $this->tail('/var/log/mihomo.log')];
    }

    public function subLogAction(): array
    {
        return ['log' => $this->tail('/var/log/mihomo_sub.log')];
    }

    private function tail(string $path, int $limit = 64000): string
    {
        $handle = @fopen($path, 'r');
        if ($handle === false) {
            return '';
        }
        fseek($handle, 0, SEEK_END);
        $size = ftell($handle);
        fseek($handle, max(0, $size - $limit));
        $text = (string)stream_get_contents($handle);
        fclose($handle);
        return $size > $limit ? substr($text, (int)strpos($text, "\n") + 1) : $text;
    }
}
