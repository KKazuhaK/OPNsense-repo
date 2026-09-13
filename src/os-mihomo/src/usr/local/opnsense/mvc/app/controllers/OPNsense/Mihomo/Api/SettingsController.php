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
 * Settings live in the plugin's own state directory rather than config.xml, so
 * the framework's model layer does not apply: this reads and writes that state
 * through the same backend entry point every other caller uses.
 */
class SettingsController extends ApiControllerBase
{
    private const STATE = '/var/db/os-mihomo';

    /* Fields the form owns. Anything absent keeps whatever is stored. */
    private const FLAGS = ['dns_fallback', 'router_dns', 'ipv6', 'dns_hijack', 'dashboard_any'];
    private const CHOICES = ['dns_mode' => 'fake-ip', 'geo_source' => 'metacubex', 'device_mode' => 'off'];
    private const LISTS = ['dns_default', 'dns_nameserver', 'dns_proxy_nameserver', 'device_list'];

    public function getAction(): array
    {
        $settings = $this->stored();
        unset($settings['secret'], $settings['subscription_url']);
        return [
            'settings' => $settings,
            /* The stored URL and secret are never sent to the browser; the form
               shows whether one exists so it can say "leave empty to keep". */
            'has_url' => ($this->stored()['subscription_url'] ?? '') !== '',
            'effective_dns' => $this->effectiveDns(),
            'overrides' => $this->fromStatus('overrides'),
            'policy_orphans' => $this->warnings(),
            'presets' => $this->presets(),
            'dashboard' => $this->dashboardUrl(),
            'merge' => (string)@file_get_contents(self::STATE . '/merge.yaml'),
            'subscription' => (string)@file_get_contents(self::STATE . '/subscription.yaml'),
        ];
    }

    public function setAction(): array
    {
        if (!$this->request->isPost()) {
            return ['status' => 'failed', 'error' => gettext('A POST is required.')];
        }
        $stored = $this->stored();
        $given = $this->request->getPost('settings');
        $given = is_array($given) ? $given : [];
        $payload = [
            'subscription_url' => !empty($given['clear_url']) ? ''
                : (trim((string)($given['subscription_url'] ?? '')) ?: ($stored['subscription_url'] ?? '')),
            'secret' => trim((string)($given['secret'] ?? '')) ?: ($stored['secret'] ?? ''),
            'device' => trim((string)($given['device'] ?? '')),
        ];
        foreach (self::FLAGS as $flag) {
            $payload[$flag] = !empty($given[$flag]);
        }
        foreach (self::CHOICES as $field => $fallback) {
            $payload[$field] = (string)($given[$field] ?? $fallback);
        }
        foreach (self::LISTS as $field) {
            /* Commas and newlines both separate; an empty field inherits. */
            $payload[$field] = array_values(preg_split('/[\s,]+/', (string)($given[$field] ?? ''), -1, PREG_SPLIT_NO_EMPTY));
        }
        return $this->backend('set-settings', json_encode($payload));
    }

    public function saveMergeAction(): array
    {
        return $this->text('save-merge', 'merge');
    }

    public function saveSubscriptionAction(): array
    {
        return $this->text('save-config', 'subscription');
    }

    public function loadPresetAction(): array
    {
        $preset = (string)$this->request->getPost('preset', null, '');
        if (!preg_match('/^[a-z0-9-]+\.yaml$/', $preset)) {
            return ['status' => 'failed', 'error' => gettext('Invalid preset.')];
        }
        return $this->backend('load-preset', $preset);
    }

    private function text(string $command, string $field): array
    {
        if (!$this->request->isPost()) {
            return ['status' => 'failed', 'error' => gettext('A POST is required.')];
        }
        return $this->backend($command, (string)$this->request->getPost($field, null, ''));
    }

    private function backend(string $command, string $argument): array
    {
        $raw = (new Backend())->configdpRun('mihomo ' . $command, [$argument]);
        $decoded = json_decode((string)$raw, true);
        if (!is_array($decoded)) {
            return ['status' => 'failed', 'error' => gettext('The backend did not answer.')];
        }
        return $decoded['ok'] ?? false
            ? ['status' => 'ok']
            : ['status' => 'failed', 'error' => $decoded['error'] ?? gettext('Operation failed.')];
    }

    private function stored(): array
    {
        $raw = @file_get_contents(self::STATE . '/settings.json');
        $value = is_string($raw) ? json_decode($raw, true) : null;
        return is_array($value) ? $value : [];
    }

    private function fromStatus(string $key): array
    {
        $raw = @file_get_contents('/var/run/mihomo-status.json');
        $status = is_string($raw) ? json_decode($raw, true) : null;
        return is_array($status) && is_array($status[$key] ?? null) ? $status[$key] : [];
    }

    private function warnings(): array
    {
        $raw = @file_get_contents(self::STATE . '/warnings.json');
        $value = is_string($raw) ? json_decode($raw, true) : null;
        return is_array($value) && is_array($value['policy_orphans'] ?? null) ? $value['policy_orphans'] : [];
    }

    private function presets(): array
    {
        $names = [];
        foreach (glob('/usr/local/share/mihomo/presets/*.yaml') ?: [] as $path) {
            $names[] = basename($path);
        }
        return $names;
    }

    /**
     * The upstreams actually in force, so an empty field can show what it
     * inherits. The dns block sits near the top of the rendered file, so the
     * scan stops as soon as it ends.
     */
    private function effectiveDns(): array
    {
        $wanted = ['default-nameserver' => [], 'nameserver' => [], 'proxy-server-nameserver' => []];
        $handle = @fopen(self::STATE . '/config.yaml', 'r');
        if ($handle === false) {
            return $wanted;
        }
        $inside = false;
        $key = null;
        while (($line = fgets($handle)) !== false) {
            $line = rtrim($line, "\r\n");
            if ($line === '' || $line[0] === '#') {
                continue;
            }
            if ($line[0] !== ' ') {
                if ($inside) {
                    break;
                }
                $inside = rtrim($line) === 'dns:';
                continue;
            }
            if (!$inside) {
                continue;
            }
            if (preg_match('/^  ([a-z0-9-]+):\s*(.*)$/', $line, $found)) {
                $key = array_key_exists($found[1], $wanted) ? $found[1] : null;
            } elseif ($key !== null && preg_match('/^  - (.+)$/', $line, $found)) {
                $wanted[$key][] = trim($found[1], " '\"");
            }
        }
        fclose($handle);
        return $wanted;
    }

    /**
     * Zashboard accepts address and secret from the fragment, which is never
     * sent to a server or a referrer. Empty while the control API is on
     * loopback, because no such link could reach it.
     */
    private function dashboardUrl(): string
    {
        $stored = $this->stored();
        $controller = (string)($stored['controller'] ?? '127.0.0.1:9090');
        $secret = (string)($stored['secret'] ?? '');
        if ($secret === '' || strpos($controller, '127.0.0.1:') === 0 || strpos($controller, ':') === false) {
            return '';
        }
        $port = substr($controller, strrpos($controller, ':') + 1);
        /* OPNsense has its own Request; it exposes headers, not Phalcon's helpers. */
        $host = (string)$this->request->getHeader('Host');
        $host = $host !== '' && $host[0] === '[' ? substr($host, 0, strpos($host, ']') + 1)
                                                 : preg_replace('/:[0-9]+$/', '', $host);
        if (!preg_match('/^[0-9]{1,5}$/', $port) || $host === '') {
            return '';
        }
        return 'http://' . $host . ':' . $port . '/ui/#/setup?hostname=' . rawurlencode(trim($host, '[]'))
            . '&port=' . rawurlencode($port) . '&secret=' . rawurlencode($secret);
    }
}
