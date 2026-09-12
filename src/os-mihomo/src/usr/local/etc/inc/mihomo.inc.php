<?php
/* Share structured configd results and local status reads across Mihomo pages. */
function mihomo_action(string $action, ?string $payload = null): array
{
    $allowed = ['start', 'stop', 'restart', 'enable-transparent', 'disable-transparent', 'sub-update', 'set-settings', 'save-config', 'save-merge', 'load-preset', 'clear-log', 'clear-sub-log'];
    if (!in_array($action, $allowed, true)) {
        return ['ok' => false, 'error' => 'Invalid action.'];
    }
    $temporary = null;
    $command = '/usr/local/sbin/configctl mihomo ' . $action;
    if ($payload !== null) {
        $temporary = tempnam('/tmp', 'mihomo-web-');
        if ($temporary === false || file_put_contents($temporary, $payload) === false) {
            return ['ok' => false, 'error' => 'Unable to stage configuration.'];
        }
        chmod($temporary, 0600);
        $command .= ' ' . escapeshellarg($temporary);
    }
    try {
        $output = [];
        $status = 0;
        exec($command . ' 2>&1', $output, $status);
        $result = json_decode(implode("\n", $output), true);
        if ($status !== 0 || !is_array($result) || !isset($result['ok'])) {
            return ['ok' => false, 'error' => 'The configuration service did not return a valid result.'];
        }
        return $result;
    } finally {
        if ($temporary !== null) {
            @unlink($temporary);
        }
    }
}

function mihomo_settings(): array
{
    $settings = @file_get_contents('/var/db/os-mihomo/settings.json');
    return is_string($settings) ? (json_decode($settings, true) ?: []) : [];
}

function mihomo_override_badge(array $overrides, string $key): string
{
    /* The merge YAML states this key by hand, so the switch beside it is inert. */
    if (!in_array($key, $overrides, true)) {
        return '';
    }
    return '<span class="label label-warning" style="margin-left:6px">'
        . htmlspecialchars(gettext('Overridden by the merge YAML'), ENT_QUOTES | ENT_HTML5, 'UTF-8')
        . '</span>';
}

function mihomo_overrides(): array
{
    /* Switches the stored merge YAML dictates by hand; independent of service state. */
    $status = @file_get_contents('/var/run/mihomo-status.json');
    $result = is_string($status) ? json_decode($status, true) : null;
    return is_array($result) && is_array($result['overrides'] ?? null) ? $result['overrides'] : [];
}

function mihomo_status(): array
{
    $status = @file_get_contents('/var/run/mihomo-status.json');
    $result = is_string($status) ? json_decode($status, true) : null;
    if (is_array($result) && time() - ($result['updated'] ?? 0) > 20 && empty(mihomo_settings()['service_enabled'])) {
        $result['running'] = false;
        return $result;
    }
    if (!is_array($result) || time() - ($result['updated'] ?? 0) > 20) {
        return ['running' => false, 'dns_active' => false, 'error' => 'Service status is unavailable.'];
    }
    return $result;
}

function mihomo_csrf(): string
{
    if (session_status() !== PHP_SESSION_ACTIVE) {
        session_start();
    }
    if (empty($_SESSION['mihomo_csrf'])) {
        $_SESSION['mihomo_csrf'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['mihomo_csrf'];
}

function mihomo_verify_csrf($token): bool
{
    return is_string($token) && hash_equals(mihomo_csrf(), $token);
}

function mihomo_escape($text): string
{
    return htmlspecialchars((string)$text, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}
