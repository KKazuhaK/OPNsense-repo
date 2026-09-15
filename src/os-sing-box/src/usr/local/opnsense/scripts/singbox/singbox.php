<?php
/* Copyright (C) 2026 Kazuha. All rights reserved. */

/* Plugin files remain authoritative; successful writes mirror into config.xml. */
const SINGBOX_KEEP = '__SING_BOX_KEEP_STORED_VALUE__';

function singbox_mirror_result(array $result): array
{
    if (empty($result['ok'])) {
        return $result;
    }
    $root = getenv('SINGBOX_ROOT') ?: '';
    if ($root !== '') {
        putenv('OS_SINGBOX_BACKUP_ROOT=' . $root);
    }
    $output = [];
    $code = 1;
    exec('/usr/local/bin/python3 ' . escapeshellarg(singbox_path('/usr/local/opnsense/scripts/singbox/config_mirror.py'))
        . ' mirror 2>/dev/null', $output, $code);
    $answer = json_decode(implode("\n", $output), true);
    if ($code !== 0 || !is_array($answer) || empty($answer['ok'])) {
        $result['warning'] = 'The settings were saved, but the configuration backup could not be synchronized.';
    }
    return $result;
}

function singbox_mvc_key(): string
{
    $path = singbox_path('/usr/local/etc/sing-box/.mvc-key');
    $directory = dirname($path);
    if (!is_dir($directory) && !@mkdir($directory, 0700, true) && !is_dir($directory)) {
        throw new RuntimeException('Unable to initialize the plugin settings directory.');
    }
    if (is_link($path)) {
        throw new RuntimeException('Invalid configuration protection key.');
    }
    $handle = @fopen($path, 'c+e');
    if ($handle === false) {
        throw new RuntimeException('Unable to open the configuration protection key.');
    }
    try {
        if (!chmod($path, 0600) || !flock($handle, LOCK_EX)) {
            throw new RuntimeException('Unable to protect the configuration key.');
        }
        $key = (string)stream_get_contents($handle);
        if (strlen($key) !== 32) {
            $key = random_bytes(32);
            rewind($handle);
            if (!ftruncate($handle, 0) || fwrite($handle, $key) !== 32 || !fflush($handle)) {
                throw new RuntimeException('Unable to write the configuration protection key.');
            }
        }
        return $key;
    } finally {
        flock($handle, LOCK_UN);
        fclose($handle);
    }
}

function singbox_revision(): string
{
    return hash_hmac('sha256', (string)@file_get_contents(singbox_path('/usr/local/etc/sing-box/config.json')), singbox_mvc_key());
}

function singbox_marker($value, string $path): string
{
    return SINGBOX_KEEP . ':' . hash_hmac('sha256', $path . "\n" . json_encode($value), singbox_mvc_key());
}

function singbox_child_path(string $path, $key, $value): string
{
    if (is_int($key) && is_object($value) && isset($value->tag)) {
        return $path . '/@tag=' . rawurlencode((string)$value->tag);
    }
    return $path . '/' . rawurlencode((string)$key);
}

function singbox_path(string $path): string
{
    return (getenv('SINGBOX_ROOT') ?: '') . $path;
}

function singbox_config(): object
{
    $data = json_decode((string)@file_get_contents(singbox_path('/usr/local/etc/sing-box/config.json')));
    return is_object($data) ? $data : (object)[];
}

function singbox_sensitive(string $key): bool
{
    return preg_match('/(?:secret|password|passwd|token|uuid|private.?key|pre.?shared.?key|access.?key|credential|authentication|^auth(?:_str|_string|_key)?$|^key(?:_path)?$|^username$|^user$|^users$|^headers$|^short_id$|^public_key$)/i', $key) === 1;
}

function singbox_redact($value, string $key = '', string $path = '')
{
    if ($value === null || $value === '') {
        return $value;
    }
    if (singbox_sensitive($key) || (is_string($value) && preg_match('~(?:https?|ss|vmess|vless|trojan)://~i', $value))) {
        return singbox_marker($value, $path);
    }
    if (is_object($value)) {
        $value = clone $value;
        foreach (get_object_vars($value) as $name => $item) {
            $value->$name = singbox_redact($item, $name, singbox_child_path($path, $name, $item));
        }
    } elseif (is_array($value)) {
        foreach ($value as $name => $item) {
            $value[$name] = singbox_redact($item, (string)$name, singbox_child_path($path, $name, $item));
        }
    }
    return $value;
}

function singbox_restore($value, $stored, string $path = '')
{
    if (is_string($value) && str_starts_with($value, SINGBOX_KEEP)) {
        if ($stored === null) {
            throw new RuntimeException('A protected value has no stored counterpart. Enter a new value.');
        }
        if (!hash_equals(singbox_marker($stored, $path), $value)) {
            throw new RuntimeException('A protected value changed or moved. Reload the configuration before saving.');
        }
        return $stored;
    }
    if (is_object($value)) {
        foreach (get_object_vars($value) as $key => $item) {
            $value->$key = singbox_restore($item, is_object($stored) ? ($stored->$key ?? null) : null, singbox_child_path($path, $key, $item));
        }
    } elseif (is_array($value)) {
        foreach ($value as $key => $item) {
            /* Tags identify proxy objects even when the editor reorders them. */
            $previous = is_array($stored) ? ($stored[$key] ?? null) : null;
            if (is_int($key) && is_object($item) && isset($item->tag) && is_array($stored)) {
                $previous = null;
                foreach ($stored as $candidate) {
                    if (is_object($candidate) && ($candidate->tag ?? null) === $item->tag) {
                        $previous = $candidate;
                        break;
                    }
                }
            }
            $value[$key] = singbox_restore($item, $previous, singbox_child_path($path, $key, $item));
        }
    }
    return $value;
}

function singbox_env(): array
{
    $values = [];
    foreach (@file(singbox_path('/usr/local/etc/sing-box/sub/env'), FILE_IGNORE_NEW_LINES) ?: [] as $line) {
        if (preg_match('/^\s*(?:export\s+)?([A-Z_][A-Z0-9_]*)=(.*)$/', $line, $match)) {
            $raw = trim($match[2]);
            if (strlen($raw) >= 2 && $raw[0] === "'" && substr($raw, -1) === "'") {
                $raw = str_replace("'\\''", "'", substr($raw, 1, -1));
            } elseif (strlen($raw) >= 2 && $raw[0] === '"' && substr($raw, -1) === '"') {
                $raw = stripcslashes(substr($raw, 1, -1));
            }
            $values[$match[1]] = $raw;
        }
    }
    return $values;
}

function singbox_url(): string
{
    $values = singbox_env();
    return (string)(($values['SING_BOX_URL'] ?? '') !== '' ? $values['SING_BOX_URL'] : ($values['CLASH_URL'] ?? ''));
}

function singbox_write(string $path, string $content): void
{
    $directory = dirname($path);
    if (!is_dir($directory) && !@mkdir($directory, 0700, true) && !is_dir($directory)) {
        throw new RuntimeException('Unable to initialize the plugin settings directory.');
    }
    $temporary = tempnam(dirname($path), '.singbox-');
    if ($temporary === false) {
        throw new RuntimeException('Unable to create a temporary file.');
    }
    try {
        if (file_put_contents($temporary, $content, LOCK_EX) === false || !chmod($temporary, 0600)) {
            throw new RuntimeException('Unable to write the settings.');
        }
        if (!rename($temporary, $path)) {
            throw new RuntimeException('Unable to replace the settings.');
        }
    } finally {
        if (is_file($temporary)) {
            unlink($temporary);
        }
    }
}

function singbox_request(string $path): string
{
    if (!preg_match('~^/tmp/singbox-request-[a-zA-Z0-9]+$~', $path)) {
        throw new RuntimeException('Invalid configuration request file.');
    }
    $before = @lstat($path);
    /* FreeBSD's www account has UID 80; PHP POSIX is optional on OPNsense. */
    $owners = [0, 80];
    if (!is_array($before) || ($before['mode'] & 0170000) !== 0100000
        || ($before['mode'] & 0777) !== 0600 || !in_array($before['uid'], $owners, true)) {
        throw new RuntimeException('The configuration request file is not private.');
    }
    $handle = @fopen($path, 'rb');
    if ($handle === false) {
        throw new RuntimeException('Unable to read the configuration request.');
    }
    try {
        $after = fstat($handle);
        if (!is_array($after) || $after['dev'] !== $before['dev'] || $after['ino'] !== $before['ino']
            || ($after['mode'] & 0777) !== 0600 || !in_array($after['uid'], $owners, true)) {
            throw new RuntimeException('The configuration request file changed.');
        }
        $content = stream_get_contents($handle, 16 * 1024 * 1024 + 1);
        if ($content === false || strlen($content) > 16 * 1024 * 1024) {
            throw new RuntimeException('The configuration request is too large.');
        }
        return $content;
    } finally {
        fclose($handle);
    }
}

function singbox_config_lock()
{
    $handle = fopen(singbox_path('/var/run/sing-box-config.lock'), 'ce');
    if ($handle === false || !flock($handle, LOCK_EX | LOCK_NB)) {
        if (is_resource($handle)) {
            fclose($handle);
        }
        throw new RuntimeException('A configuration operation is already running.');
    }
    return $handle;
}

function singbox_validate_url(string $url): void
{
    $parts = parse_url($url);
    if (strlen($url) > 8192 || preg_match('/[\x00-\x20\x7f]/', $url) || !filter_var($url, FILTER_VALIDATE_URL)
        || !is_array($parts) || !in_array(strtolower($parts['scheme'] ?? ''), ['http', 'https'], true)
        || empty($parts['host'])) {
        throw new RuntimeException('A valid HTTP or HTTPS subscription URL is required.');
    }
    $host = trim($parts['host'], '[]');
    $addresses = [];
    if (filter_var($host, FILTER_VALIDATE_IP)) {
        $addresses[] = $host;
    } else {
        foreach (@dns_get_record($host, DNS_A | DNS_AAAA) ?: [] as $record) {
            if (!empty($record['ip'])) {
                $addresses[] = $record['ip'];
            }
            if (!empty($record['ipv6'])) {
                $addresses[] = $record['ipv6'];
            }
        }
    }
    if (!$addresses) {
        throw new RuntimeException('The subscription host could not be resolved.');
    }
    foreach ($addresses as $address) {
        if (!filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
            throw new RuntimeException('Private or reserved subscription addresses are not allowed.');
        }
    }
}

function singbox_save_url(string $payload): array
{
    $data = json_decode($payload, true);
    if (!is_array($data)) {
        throw new RuntimeException('Invalid settings.');
    }
    $url = !empty($data['clear_url']) ? '' : trim((string)($data['subscription_url'] ?? ''));
    if ($url === '' && empty($data['clear_url'])) {
        return ['ok' => true];
    }
    if ($url !== '') {
        singbox_validate_url($url);
    }
    $lines = [];
    foreach (@file(singbox_path('/usr/local/etc/sing-box/sub/env'), FILE_IGNORE_NEW_LINES) ?: [] as $line) {
        if (!preg_match('/^\s*(?:export\s+)?(?:SING_BOX_URL|CLASH_URL)=/', $line)) {
            $lines[] = $line;
        }
    }
    $content = $lines ? implode("\n", $lines) . "\n" : '';
    foreach (['SING_BOX_URL', 'CLASH_URL'] as $key) {
        $content .= "export " . $key . "='" . str_replace("'", "'\\''", $url) . "'\n";
    }
    singbox_write(singbox_path('/usr/local/etc/sing-box/sub/env'), $content);
    return ['ok' => true];
}

function singbox_save_config(string $content): array
{
    if (strlen($content) > 4 * 1024 * 1024) {
        throw new RuntimeException('Configuration content is larger than 4 MiB.');
    }
    $config = json_decode($content);
    if (!is_object($config)) {
        throw new RuntimeException('A JSON configuration object is required.');
    }
    $config = singbox_restore($config, singbox_config());
    $path = singbox_path('/usr/local/etc/sing-box/config.json');
    $temporary = tempnam(dirname($path), '.singbox-check-');
    if ($temporary === false) {
        throw new RuntimeException('Unable to create a temporary configuration.');
    }
    try {
        chmod($temporary, 0600);
        if (file_put_contents($temporary, json_encode($config, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n") === false) {
            throw new RuntimeException('Unable to write the temporary configuration.');
        }
        $output = [];
        $code = 1;
        exec(escapeshellarg(getenv('SING_BOX_BIN') ?: '/usr/local/bin/sing-box') . ' check -c '
            . escapeshellarg($temporary) . ' 2>&1', $output, $code);
        if ($code !== 0) {
            /* Core errors can contain proxy credentials. Never return them. */
            throw new RuntimeException('Sing-box rejected the configuration. The active file was kept.');
        }
        if (is_file($path) && (!copy($path, $path . '.bak') || !chmod($path . '.bak', 0600))) {
            throw new RuntimeException('Unable to back up the active configuration.');
        }
        if (!rename($temporary, $path)) {
            throw new RuntimeException('Unable to save the configuration.');
        }
    } finally {
        if (is_file($temporary)) {
            unlink($temporary);
        }
    }
    return ['ok' => true];
}

function singbox_secrets($value, string $key = ''): array
{
    $found = [];
    if (is_string($value) && $value !== '' && (singbox_sensitive($key) || preg_match('~[a-z]+://~i', $value))) {
        $found[] = $value;
    }
    if (is_array($value) || is_object($value)) {
        foreach ($value as $name => $item) {
            $found = array_merge($found, singbox_secrets($item, singbox_sensitive($key) ? 'secret' : (string)$name));
        }
    }
    return $found;
}

function singbox_scrub(string $text): string
{
    $secrets = singbox_secrets(singbox_config());
    $backup = json_decode((string)@file_get_contents(singbox_path('/usr/local/etc/sing-box/config.json.bak')));
    $secrets = array_merge($secrets, singbox_secrets($backup));
    $secrets[] = singbox_url();
    usort($secrets, function ($a, $b) { return strlen($b) <=> strlen($a); });
    foreach (array_unique($secrets) as $secret) {
        if ($secret !== '') {
            $text = str_replace($secret, '[redacted]', $text);
        }
    }
    $text = (string)preg_replace('~(?:https?|ss|vmess|vless|trojan)://[^\s<>"\x27]+~i', '[redacted URL]', $text);
    $text = (string)preg_replace('/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/i', '[redacted UUID]', $text);
    return (string)preg_replace('/\b(secret|password|passwd|token|uuid|username)\s*[=:]\s*[^\s,;]+/i', '$1=[redacted]', $text);
}

function singbox_tail(string $name): string
{
    $handle = @fopen(singbox_path('/var/log/' . $name), 'rb');
    if ($handle === false) {
        return '';
    }
    fseek($handle, 0, SEEK_END);
    $size = ftell($handle);
    fseek($handle, max(0, $size - 64000));
    $text = (string)stream_get_contents($handle);
    fclose($handle);
    if ($size > 64000) {
        $newline = strpos($text, "\n");
        $text = $newline === false ? '' : substr($text, $newline + 1);
    }
    return singbox_scrub($text);
}

function singbox_update_state(array $state): void
{
    $state['updated'] = time();
    singbox_write(singbox_path('/var/run/sing-box-update.json'), json_encode($state));
}

function singbox_update_status(): array
{
    $state = json_decode((string)@file_get_contents(singbox_path('/var/run/sing-box-update.json')), true);
    $state = is_array($state) ? $state : ['running' => false, 'message' => ''];
    if (!empty($state['running']) && time() - (int)($state['updated'] ?? 0) > 180) {
        $state = ['running' => false, 'message' => 'Subscription update did not finish.', 'ok' => false];
    }
    return $state;
}

function singbox_update(bool $background, bool $wait = false): array
{
    /* Do not inherit the starter's lock into the detached runner. */
    $handle = fopen(singbox_path('/var/run/sing-box-sub.lock'), 'ce');
    if ($handle === false || !flock($handle, $wait ? LOCK_EX : LOCK_EX | LOCK_NB)) {
        if (is_resource($handle)) {
            fclose($handle);
        }
        throw new RuntimeException('A subscription update is already running.');
    }
    try {
        if ($background) {
            if (!empty(singbox_update_status()['running'])) {
                throw new RuntimeException('A subscription update is already running.');
            }
            singbox_update_state(['running' => true, 'message' => 'Subscription update started.']);
            $output = [];
            $code = 1;
            exec('nohup ' . escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(__FILE__)
                . ' run-update >/dev/null 2>&1 </dev/null &', $output, $code);
            if ($code !== 0) {
                singbox_update_state(['running' => false, 'ok' => false, 'message' => 'Unable to launch subscription update.']);
                throw new RuntimeException('Unable to launch subscription update.');
            }
            return ['ok' => true];
        }
        if (!$wait && !empty(singbox_update_status()['running'])) {
            throw new RuntimeException('A subscription update is already running.');
        }
        singbox_update_state(['running' => true, 'message' => 'Subscription update started.']);
        try {
            $configurationLock = singbox_config_lock();
        } catch (Throwable $error) {
            singbox_update_state(['running' => false, 'ok' => false, 'message' => 'Subscription update failed. A configuration operation is running.']);
            throw $error;
        }
        try {
            $output = [];
            $code = 1;
            exec('/bin/sh ' . escapeshellarg(singbox_path('/usr/local/etc/sing-box/sub/sub.sh')) . ' 2>&1', $output, $code);
        } finally {
            flock($configurationLock, LOCK_UN);
            fclose($configurationLock);
        }
        $message = $code === 0 ? 'Subscription validated and applied.' : 'Subscription update failed. Check the subscription log.';
        file_put_contents(singbox_path('/var/log/sing-box_sub.log'), date('[Y-m-d H:i:s] ') . singbox_scrub(implode("\n", $output)) . "\n", FILE_APPEND | LOCK_EX);
        singbox_update_state(['running' => false, 'ok' => $code === 0, 'message' => $message]);
        $result = singbox_mirror_result(['ok' => $code === 0, 'error' => $code === 0 ? '' : $message]);
        if (!empty($result['warning'])) {
            singbox_update_state(['running' => false, 'ok' => $code === 0, 'message' => $message . ' ' . $result['warning']]);
        }
        return $result;
    } finally {
        flock($handle, LOCK_UN);
        fclose($handle);
    }
}

function singbox_integration_settings(): array
{
    $defaults = ['schema' => 1, 'transparent' => false, 'transparent_consent' => false,
        'device_mode' => 'off', 'device_list' => [], 'ipv6' => false];
    $value = json_decode((string)@file_get_contents(singbox_path('/usr/local/etc/sing-box/integration.json')), true);
    return is_array($value) ? array_intersect_key($value + $defaults, $defaults) : $defaults;
}

function singbox_save_integration(string $content): array
{
    $given = json_decode($content, true);
    if (!is_array($given) || strlen($content) > 65536) {
        throw new RuntimeException('Invalid integration settings.');
    }
    $process = proc_open(['/usr/local/bin/python3', singbox_path('/usr/local/opnsense/scripts/singbox/integration.py'), 'set-policy'],
        [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
    if (!is_resource($process)) {
        throw new RuntimeException('Unable to save the integration settings.');
    }
    fwrite($pipes[0], json_encode($given));
    fclose($pipes[0]);
    $output = stream_get_contents($pipes[1]);
    fclose($pipes[1]);
    stream_get_contents($pipes[2]);
    fclose($pipes[2]);
    $code = proc_close($process);
    $answer = json_decode($output, true);
    if ($code !== 0 || !is_array($answer) || empty($answer['ok'])) {
        throw new RuntimeException('The integration settings were rejected. Check IP/CIDR entries and confirm LAN capture.');
    }
    return ['ok' => true];
}

function singbox_action(string $action, string $argument = ''): array
{
    switch ($action) {
        case 'get-settings':
            $handle = singbox_config_lock();
            try {
                return ['ok' => true, 'config' => json_encode(singbox_redact(singbox_config()), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES),
                    'revision' => singbox_revision(), 'has_url' => singbox_url() !== '',
                    'integration' => singbox_integration_settings()];
            } finally {
                flock($handle, LOCK_UN);
                fclose($handle);
            }
        case 'set-integration':
            $handle = singbox_config_lock();
            try {
                $result = singbox_save_integration(singbox_request($argument));
            } finally {
                flock($handle, LOCK_UN);
                fclose($handle);
            }
            return singbox_mirror_result($result);
        case 'set-settings':
            $handle = singbox_config_lock();
            try {
                $result = singbox_save_url(singbox_request($argument));
            } finally {
                flock($handle, LOCK_UN);
                fclose($handle);
            }
            return singbox_mirror_result($result);
        case 'save-config':
            $handle = singbox_config_lock();
            try {
                $request = json_decode(singbox_request($argument), true);
                if (!is_array($request) || !is_string($request['config'] ?? null) || !is_string($request['revision'] ?? null)) {
                    throw new RuntimeException('Invalid configuration save request.');
                }
                if (!hash_equals(singbox_revision(), $request['revision'])) {
                    throw new RuntimeException('The configuration changed. Reload it before saving.');
                }
                $result = singbox_save_config($request['config']);
            } finally {
                flock($handle, LOCK_UN);
                fclose($handle);
            }
            return singbox_mirror_result($result);
        case 'status':
            $output = [];
            $code = 1;
            exec('/usr/sbin/service sing-box status 2>&1', $output, $code);
            foreach (array_reverse($output) as $line) {
                $state = json_decode($line, true);
                if (!is_array($state) || empty($state['ok']) || !is_bool($state['running'] ?? null)) {
                    continue;
                }
                $result = ['ok' => true, 'running' => $code === 0 && $state['running']];
                foreach (['process_alive', 'healthy', 'paused', 'transparent', 'routing_active',
                          'recovery_pending', 'routing_fallback', 'restart_required'] as $field) {
                    $result[$field] = ($state[$field] ?? false) === true;
                }
                $result['routing_error'] = is_string($state['routing_error'] ?? null)
                    ? singbox_scrub($state['routing_error']) : '';
                return $result;
            }
            return ['ok' => false, 'error' => 'The service status could not be established.'];
        case 'start':
        case 'stop':
        case 'restart':
            $output = [];
            $code = 1;
            exec('/usr/sbin/service sing-box ' . 'one' . $action . ' 2>&1', $output, $code);
            return singbox_mirror_result(['ok' => $code === 0, 'error' => $code === 0 ? '' : 'Service operation failed. Check the service log.']);
        case 'log':
        case 'sub-log':
            return ['ok' => true, 'log' => singbox_tail($action === 'log' ? 'sing-box.log' : 'sing-box_sub.log')];
        case 'clear-log':
        case 'clear-sub-log':
            $path = singbox_path('/var/log/' . ($action === 'clear-log' ? 'sing-box.log' : 'sing-box_sub.log'));
            if (file_put_contents($path, '', LOCK_EX) === false) {
                throw new RuntimeException('Unable to clear the log.');
            }
            return ['ok' => true];
        case 'sub-update':
            return singbox_update(true);
        case 'update':
            return singbox_update(false);
        case 'run-update':
            return singbox_update(false, true);
        case 'update-status':
            return ['ok' => true] + singbox_update_status();
        default:
            throw new RuntimeException('Unknown action.');
    }
}

if (realpath($_SERVER['SCRIPT_FILENAME'] ?? '') === __FILE__) {
    try {
        $result = singbox_action($argv[1] ?? '', $argv[2] ?? '');
    } catch (Throwable $error) {
        $result = ['ok' => false, 'error' => singbox_scrub($error->getMessage())];
    }
    echo json_encode($result, JSON_UNESCAPED_SLASHES) . "\n";
    /* Configd transports failures as JSON; the standalone updater also needs
       a conventional exit status for Cron and shell callers. */
    exit(($argv[1] ?? '') === 'update' && empty($result['ok']) ? 1 : 0);
}
