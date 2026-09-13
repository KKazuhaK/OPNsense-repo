<?php
/* This CLI uses real interface discovery; its dependencies must be explicit. */
require_once('config.inc');
require_once('interfaces.inc');
require_once('util.inc');

const STATICARP_CONFIG_DIR = '/usr/local/etc/staticarp';
const STATICARP_SETTINGS_FILE = STATICARP_CONFIG_DIR . '/settings.conf';
const STATICARP_ENTRIES_FILE = STATICARP_CONFIG_DIR . '/entries.conf';
const STATICARP_INTERFACES_FILE = STATICARP_CONFIG_DIR . '/interfaces.conf';

function staticarp_write_file($path, $content, $flags = 0)
{
    $temporary = tempnam(dirname($path), '.staticarp-');
    if ($temporary === false || file_put_contents($temporary, $content, LOCK_EX) === false) {
        throw new RuntimeException('Could not write the settings file.');
    }
    chmod($temporary, 0644);
    if (!rename($temporary, $path)) {
        @unlink($temporary);
        throw new RuntimeException('Could not replace the settings file.');
    }
}

function staticarp_ensure_config_dir()
{
    if (!is_dir(STATICARP_CONFIG_DIR)) {
        mkdir(STATICARP_CONFIG_DIR, 0755, true);
    }
}

function staticarp_read_enabled()
{
    if (!is_readable(STATICARP_SETTINGS_FILE)) {
        return false;
    }

    $contents = file_get_contents(STATICARP_SETTINGS_FILE);
    return preg_match('/^enabled=YES$/m', (string)$contents) === 1;
}

function staticarp_read_entries()
{
    if (!is_readable(STATICARP_ENTRIES_FILE)) {
        return '';
    }

    return trim((string)file_get_contents(STATICARP_ENTRIES_FILE));
}

function staticarp_read_interface_modes()
{
    $modes = [];
    if (!is_readable(STATICARP_INTERFACES_FILE)) {
        return $modes;
    }

    foreach (file(STATICARP_INTERFACES_FILE, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
        if (preg_match('/^\s*#/', $line)) {
            continue;
        }
        $parts = preg_split('/\s+/', trim($line));
        if (count($parts) >= 3) {
            $modes[$parts[0]] = $parts[2];
        }
    }

    return $modes;
}

function staticarp_write_config($enabled, $entries, $interface_rows)
{
    staticarp_ensure_config_dir();
    staticarp_write_file(STATICARP_SETTINGS_FILE, 'enabled=' . ($enabled ? 'YES' : 'NO') . "\n", LOCK_EX);
    staticarp_write_file(STATICARP_ENTRIES_FILE, rtrim($entries) . "\n", LOCK_EX);

    $lines = [];
    foreach ($interface_rows as $row) {
        $lines[] = implode(' ', [$row['name'], $row['device'], $row['mode']]);
    }
    staticarp_write_file(STATICARP_INTERFACES_FILE, implode("\n", $lines) . "\n", LOCK_EX);
}

function staticarp_valid_ip($ip)
{
    return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false;
}

function staticarp_valid_mac($mac)
{
    return preg_match('/^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$/', $mac) === 1;
}

function staticarp_local_ipv4_addresses()
{
    $addresses = [];
    exec('/sbin/ifconfig 2>/dev/null', $output);
    foreach ($output as $line) {
        if (preg_match('/^\s+inet\s+([0-9.]+)/', $line, $matches) && staticarp_valid_ip($matches[1])) {
            $addresses[$matches[1]] = true;
        }
    }
    return $addresses;
}

function staticarp_normalize_entries($raw, &$errors)
{
    $rows = [];
    $local_addresses = staticarp_local_ipv4_addresses();
    foreach (preg_split('/[\r\n,]+/', trim((string)$raw)) as $line) {
        $line = trim($line);
        if ($line === '') {
            continue;
        }
        $parts = preg_split('/\s+/', $line);
        $ip = $parts[0] ?? '';
        $mac = strtolower($parts[1] ?? '');
        if (!staticarp_valid_ip($ip)) {
            $errors[] = sprintf(gettext('The binding list contains an invalid IP address: %s'), $ip);
            continue;
        }
        if (!staticarp_valid_mac($mac)) {
            $errors[] = sprintf(gettext('The binding list contains an invalid MAC address: %s'), $mac);
            continue;
        }
        if (isset($local_addresses[$ip])) {
            continue;
        }
        $rows[ip2long($ip)] = long2ip(ip2long($ip)) . ' ' . $mac;
    }
    ksort($rows, SORT_NUMERIC);
    return implode("\n", array_values($rows));
}

function staticarp_current_arp_list()
{
    exec('/usr/sbin/arp -an 2>/dev/null', $rawdata);
    $rows = [];
    $local_addresses = staticarp_local_ipv4_addresses();
    foreach ($rawdata as $line) {
        $parts = preg_split('/\s+/', trim($line));
        if (!isset($parts[1], $parts[3]) || $parts[3] === '(incomplete)') {
            continue;
        }
        $ip = trim($parts[1], '()');
        $mac = strtolower($parts[3]);
        if (staticarp_valid_ip($ip) && staticarp_valid_mac($mac) && !isset($local_addresses[$ip])) {
            $rows[ip2long($ip)] = long2ip(ip2long($ip)) . ' ' . $mac;
        }
    }
    ksort($rows, SORT_NUMERIC);
    return implode("\n", array_values($rows));
}

function staticarp_get_interfaces()
{
    global $config;

    $iflist = function_exists('get_interface_list') ? get_interface_list() : [];
    $rows = [];
    foreach (($config['interfaces'] ?? []) as $name => $info) {
        if (empty($info['if'])) {
            continue;
        }
        $device = $info['if'];
        if ($device === 'lo0' || str_starts_with($device, 'lo')) {
            continue;
        }
        if (!empty($info['gateway']) && !in_array(strtolower((string)$info['gateway']), ['none', 'dynamic'], true)) {
            continue;
        }
        $device_info = $iflist[$device] ?? [];
        $ipaddr = $info['ipaddr'] ?? '';
        $subnet = $info['subnet'] ?? '';
        $descr = trim((string)($info['descr'] ?? ''));
        if ($descr === '') {
            $descr = strtoupper($name);
        }
        $rows[$name] = [
            'name' => $name,
            'device' => $device,
            'descr' => $descr,
            'ipaddr' => staticarp_valid_ip($ipaddr) && $subnet !== '' ? $ipaddr . '/' . $subnet : $ipaddr,
            'mac' => $device_info['mac'] ?? '',
            'status' => !empty($device_info['up']) ? 'up' : 'down',
        ];
    }

    return $rows;
}


try {
    $interfaces = staticarp_get_interfaces();
    $action = $argv[1] ?? 'get';
    if ($action === 'get') {
        $result = ['settings' => ['enabled' => staticarp_read_enabled(), 'entries' => staticarp_read_entries(),
            'modes' => staticarp_read_interface_modes()], 'interfaces' => array_values($interfaces),
            'arp' => staticarp_current_arp_list()];
    } elseif ($action === 'set') {
        $given = json_decode((string)file_get_contents($argv[2] ?? ''), true);
        if (!is_array($given)) {
            throw new InvalidArgumentException('Invalid settings.');
        }
        $errors = [];
        $entries = staticarp_normalize_entries($given['entries'] ?? '', $errors);
        $enabled = in_array($given['enabled'] ?? false, [true, 1, '1', 'yes'], true);
        if ($enabled && $entries === '') {
            $errors[] = 'The binding list is empty. Static binding cannot be enabled.';
        }
        if ($errors) {
            throw new InvalidArgumentException(implode("\n", $errors));
        }
        $rows = [];
        foreach ($interfaces as $name => $interface) {
            $mode = $given['modes'][$name] ?? 'normal';
            if (!in_array($mode, ['normal', 'staticarp', '-arp'], true)) {
                throw new InvalidArgumentException('Invalid interface reply mode.');
            }
            $rows[] = ['name' => $name, 'device' => $interface['device'], 'mode' => $mode];
        }
        staticarp_write_config($enabled, $entries, $rows);
        $result = ['status' => 'ok', 'enabled' => $enabled];
    } elseif ($action === 'script') {
        $name = $argv[2] ?? '';
        if (!isset($interfaces[$name])) {
            throw new InvalidArgumentException('Invalid interface.');
        }
        $interface = $interfaces[$name];
        $script = "@echo off\r\n@color 0A\r\n@echo Firewall client ARP binding script\r\narp -d\r\n";
        $ip = explode('/', $interface['ipaddr'])[0];
        if (staticarp_valid_ip($ip) && staticarp_valid_mac($interface['mac'])) {
            $script .= 'arp -s ' . $ip . ' ' . str_replace(':', '-', $interface['mac']) . "\r\n";
        }
        foreach (preg_split('/\r?\n/', staticarp_read_entries()) as $line) {
            $parts = preg_split('/\s+/', trim($line));
            if (isset($parts[0], $parts[1]) && staticarp_valid_ip($parts[0]) && staticarp_valid_mac($parts[1])) {
                $script .= 'arp -s ' . $parts[0] . ' ' . str_replace(':', '-', $parts[1]) . "\r\n";
            }
        }
        $result = ['status' => 'ok', 'filename' => 'arp_' . preg_replace('/[^A-Za-z0-9_.-]/', '_', $interface['device']) . '.cmd',
            'script' => $script . "arp -a\r\npause\r\n"];
    } else {
        throw new InvalidArgumentException('Unknown action.');
    }
} catch (Throwable $exception) {
    $result = ['status' => 'failed', 'error' => $exception->getMessage()];
}
echo json_encode($result, JSON_INVALID_UTF8_SUBSTITUTE) . "\n";
