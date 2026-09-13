<?php
/* Settings retain their existing JSON store; configd owns all filesystem writes. */
require_once('util.inc');
require_once('config.inc');
const SPEEDTEST_STATE_DIR = '/var/db/speedtest';
const SPEEDTEST_SETTINGS = SPEEDTEST_STATE_DIR . '/settings.json';
const SPEEDTEST_RESULT = SPEEDTEST_STATE_DIR . '/result.json';
const SPEEDTEST_PROGRESS = SPEEDTEST_STATE_DIR . '/progress.json';
const SPEEDTEST_RUNNER = '/usr/local/opnsense/scripts/speedtest/speedtest.py';

function speedtest_lang(): string {
    global $config;
    $language = strtolower(str_replace('-', '_', (string)($config['system']['language'] ?? 'en')));
    if (in_array($language, ['zh_cn', 'zh_hans_cn'], true)) return 'zh_Hans';
    if (in_array($language, ['zh_tw', 'zh_hant_tw', 'zh_hk', 'zh_hant_hk'], true)) return 'zh_Hant';
    return 'en';
}

function speedtest_t(string $key): string {
    static $messages = [
        'en' => [
            'diagnostics'=>'Diagnostics','title'=>'Speedtest','run'=>'Start Test','clear'=>'Clear Result','settings'=>'Test Settings','interface'=>'Outbound Interface','interface_help'=>'Only enabled interfaces with an IPv4 gateway are shown.','automatic'=>'Automatic','server'=>'Test Server','server_auto'=>'Automatic selection','server_help'=>'Refresh the server list after changing the outbound interface.','refresh'=>'Refresh Servers','refreshing'=>'Retrieving test servers.','server_list_failed'=>'Unable to retrieve available test servers.','threads'=>'Connections','result'=>'Test Result','time'=>'Test Time','isp'=>'ISP / Public IP','test_server'=>'Test Server','latency'=>'Latency','jitter'=>'Jitter','loss'=>'Packet Loss','download'=>'Download','upload'=>'Upload','running'=>'Testing, please wait.......','failed'=>'The speed test failed.','invalid_server'=>'Select a valid test server.','invalid_threads'=>'Connections must be between 1 and 16.','engine'=>'Engine','distance'=>'Distance'
        ],
        'zh_Hans' => [
            'diagnostics'=>'诊断','title'=>'Speedtest','run'=>'开始测速','clear'=>'清除结果','settings'=>'测速设置','interface'=>'出站接口','interface_help'=>'仅显示已启用且配置 IPv4 网关的接口。','automatic'=>'自动选择','server'=>'测速服务器','server_auto'=>'自动选择','server_help'=>'更改出站接口后，请刷新服务器列表。','refresh'=>'刷新服务器','refreshing'=>'正在获取测速服务器。','server_list_failed'=>'无法获取可用测速服务器。','threads'=>'并发连接','result'=>'测速结果','time'=>'测试时间','isp'=>'运营商 / 公网 IP','test_server'=>'测速服务器','latency'=>'延迟','jitter'=>'抖动','loss'=>'丢包率','download'=>'下载','upload'=>'上传','running'=>'正在测速，请等待.......','failed'=>'互联网测速失败。','invalid_server'=>'请选择有效的测速服务器。','invalid_threads'=>'并发连接必须在 1 到 16 之间。','engine'=>'测速引擎','distance'=>'距离'
        ],
        'zh_Hant' => [
            'diagnostics'=>'診斷','title'=>'Speedtest','run'=>'開始測速','clear'=>'清除結果','settings'=>'測速設定','interface'=>'出站介面','interface_help'=>'僅顯示已啟用且設定 IPv4 閘道的介面。','automatic'=>'自動選擇','server'=>'測速伺服器','server_auto'=>'自動選擇','server_help'=>'變更出站介面後，請重新整理伺服器清單。','refresh'=>'重新整理伺服器','refreshing'=>'正在取得測速伺服器。','server_list_failed'=>'無法取得可用測速伺服器。','threads'=>'並行連線','result'=>'測速結果','time'=>'測試時間','isp'=>'電信業者 / 公網 IP','test_server'=>'測速伺服器','latency'=>'延遲','jitter'=>'抖動','loss'=>'封包遺失率','download'=>'下載','upload'=>'上傳','running'=>'正在測速，請等待.......','failed'=>'網際網路測速失敗。','invalid_server'=>'請選擇有效的測速伺服器。','invalid_threads'=>'並行連線必須介於 1 到 16 之間。','engine'=>'測速引擎','distance'=>'距離'
        ],
    ];
    $language = speedtest_lang();
    return $messages[$language][$key] ?? $messages['en'][$key] ?? $key;
}

function speedtest_ensure_state(): void {
    if (!is_dir(SPEEDTEST_STATE_DIR) && !mkdir(SPEEDTEST_STATE_DIR, 0700, true)) throw new RuntimeException('Unable to create the state directory.');
    chmod(SPEEDTEST_STATE_DIR, 0700);
}

function speedtest_settings(): array {
    $defaults = ['interface'=>'auto','server_id'=>'','threads'=>'4'];
    if (!is_readable(SPEEDTEST_SETTINGS)) return $defaults;
    $value = json_decode((string)file_get_contents(SPEEDTEST_SETTINGS), true);
    return is_array($value) ? array_merge($defaults, $value) : $defaults;
}

function speedtest_save_settings(array $settings): void {
    speedtest_ensure_state();
    $temporary = tempnam(SPEEDTEST_STATE_DIR, '.settings.');
    if ($temporary === false) throw new RuntimeException('Unable to save settings.');
    try {
        chmod($temporary, 0600);
        if (file_put_contents($temporary, json_encode($settings, JSON_UNESCAPED_SLASHES), LOCK_EX) === false || !rename($temporary, SPEEDTEST_SETTINGS)) throw new RuntimeException('Unable to save settings.');
    } finally {
        if (file_exists($temporary)) unlink($temporary);
    }
}

function speedtest_runtime_ipv4(string $device): string {
    if (!preg_match('/^[a-zA-Z0-9_.:-]+$/', $device)) return '';
    exec('/sbin/ifconfig ' . escapeshellarg($device) . ' inet 2>/dev/null', $output);
    foreach ($output as $line) {
        if (preg_match('/\binet\s+([0-9.]+)/', $line, $match) && filter_var($match[1], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) return $match[1];
    }
    return '';
}

function speedtest_outbound_interfaces(): array {
    global $config;
    $result = [];
    foreach ((array)($config['interfaces'] ?? []) as $name => $item) {
        if (!is_array($item) || empty($item['enable']) || empty($item['if'])) continue;
        $is_dhcp = strtolower((string)($item['ipaddr'] ?? '')) === 'dhcp';
        if (empty($item['gateway']) && !$is_dhcp) continue;
        $address = speedtest_runtime_ipv4((string)$item['if']);
        if ($address === '') continue;
        $description = trim((string)($item['descr'] ?? '')) ?: strtoupper((string)$name);
        $result[$name] = ['description'=>$description, 'device'=>(string)$item['if'], 'address'=>$address];
    }
    return $result;
}

function speedtest_source_address(string $interface, array $interfaces): string {
    return isset($interfaces[$interface]) ? (string)$interfaces[$interface]['address'] : '';
}

function speedtest_server_cache(string $interface): string {
    $key = preg_replace('/[^a-z0-9_]/i', '', $interface) ?: 'auto';
    return SPEEDTEST_STATE_DIR . "/servers-{$key}.json";
}

function speedtest_load_servers(string $interface): array {
    $file = speedtest_server_cache($interface);
    if (!is_readable($file)) return [];
    $items = json_decode((string)file_get_contents($file), true);
    if (!is_array($items)) return [];
    return array_values(array_filter($items, function($server) {
        return is_array($server) && preg_match('/^\d+(?:\.\d+)?ms$/i', (string)($server['latency'] ?? ''));
    }));
}

function speedtest_fetch_servers(string $interface, array $interfaces): array {
    $command = '/bin/timeout 40 /usr/local/bin/opnsense-speedtest --list';
    $source = speedtest_source_address($interface, $interfaces);
    if ($source !== '') $command .= ' --source ' . escapeshellarg($source);
    exec($command . ' 2>&1', $output, $status);
    if ($status !== 0) return [];
    $servers = [];
    foreach ($output as $line) {
        if (!preg_match('/^\[\s*(\d+)\]\s+([0-9.]+)km\s+(\S+)\s+(.+?)\s+\((.*?)\)\s+by\s+(.+)$/u', trim($line), $match)) continue;
        if (!preg_match('/^\d+(?:\.\d+)?ms$/i', $match[3])) continue;
        $servers[] = ['id'=>$match[1], 'distance'=>(float)$match[2], 'latency'=>$match[3], 'name'=>$match[4], 'country'=>$match[5], 'sponsor'=>$match[6]];
    }
    if ($servers) {
        speedtest_ensure_state();
        file_put_contents(speedtest_server_cache($interface), json_encode($servers, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES), LOCK_EX);
        chmod(speedtest_server_cache($interface), 0600);
    }
    return $servers;
}

function speedtest_load_result(): ?array {
    if (!is_readable(SPEEDTEST_RESULT)) return null;
    $value = json_decode((string)file_get_contents(SPEEDTEST_RESULT), true);
    return is_array($value) ? $value : null;
}

function speedtest_duration_ms($value): float { return is_numeric($value) ? (float)$value / 1000000 : 0.0; }

function speedtest_packet_loss(array $value): ?float {
    $sent = (int)($value['sent'] ?? 0); $duplicate = (int)($value['dup'] ?? 0); $maximum = (int)($value['max'] ?? 0);
    if ($sent === 0 || $maximum < 0) return null;
    return max(0.0, (1.0 - (($sent - $duplicate) / ($maximum + 1))) * 100.0);
}


function speedtest_reply(array $value): void {
    echo json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n";
}

function speedtest_validate(array $given, array $interfaces): array {
    $interface = (string)($given['interface'] ?? 'auto');
    if ($interface !== 'auto' && !isset($interfaces[$interface])) throw new InvalidArgumentException(speedtest_t('interface_help'));
    $id = trim((string)($given['server_id'] ?? ''));
    $threads = filter_var($given['threads'] ?? null, FILTER_VALIDATE_INT, ['options'=>['min_range'=>1,'max_range'=>16]]);
    if ($threads === false) throw new InvalidArgumentException(speedtest_t('invalid_threads'));
    if ($id !== '' && !in_array($id, array_column(speedtest_load_servers($interface), 'id'), true)) throw new InvalidArgumentException(speedtest_t('invalid_server'));
    return ['interface'=>$interface, 'server_id'=>$id, 'threads'=>(string)$threads];
}

try {
    $action = $argv[1] ?? 'get';
    $input = json_decode(base64_decode($argv[2] ?? '', true) ?: '{}', true);
    if (!is_array($input)) throw new InvalidArgumentException('Invalid request.');
    if ($action === 'get') {
        $settings = speedtest_settings();
        speedtest_reply(['settings'=>$settings, 'interfaces'=>speedtest_outbound_interfaces(), 'servers'=>speedtest_load_servers($settings['interface']), 'result'=>speedtest_load_result(), 'language'=>speedtest_lang()]);
    } elseif ($action === 'progress') {
        $progress = json_decode((string)@file_get_contents(SPEEDTEST_PROGRESS), true);
        speedtest_reply(is_array($progress) ? $progress : ['state'=>'idle', 'stages'=>[]]);
    } elseif ($action === 'servers' || $action === 'refresh') {
        $interfaces = speedtest_outbound_interfaces();
        $interface = (string)($input['interface'] ?? 'auto');
        if ($interface !== 'auto' && !isset($interfaces[$interface])) throw new InvalidArgumentException('Invalid outbound interface.');
        $servers = $action === 'refresh' ? speedtest_fetch_servers($interface, $interfaces) : speedtest_load_servers($interface);
        if ($action === 'refresh' && !$servers) throw new RuntimeException(speedtest_t('server_list_failed'));
        speedtest_reply(['status'=>'ok', 'servers'=>$servers]);
    } elseif ($action === 'set' || $action === 'run') {
        $interfaces = speedtest_outbound_interfaces();
        $settings = speedtest_validate($input, $interfaces);
        if ($action === 'run') {
            $args = ['--background', '--thread', $settings['threads']];
            if ($settings['server_id'] !== '') array_push($args, '--server', $settings['server_id']);
            $source = speedtest_source_address($settings['interface'], $interfaces);
            if ($source !== '') array_push($args, '--source', $source);
            $command = '/usr/local/bin/python3 ' . escapeshellarg(SPEEDTEST_RUNNER);
            foreach ($args as $arg) $command .= ' ' . escapeshellarg($arg);
            exec($command . ' 2>/dev/null', $output, $status);
            $reply = json_decode(implode("\n", $output), true);
            if ($status !== 0 || !is_array($reply) || ($reply['status'] ?? '') !== 'ok') throw new RuntimeException('A speed test is already running or could not be started.');
        }
        speedtest_save_settings($settings);
        speedtest_reply(['status'=>'ok']);
    } elseif ($action === 'clear') {
        speedtest_ensure_state();
        $guard = fopen(SPEEDTEST_STATE_DIR . '/run.lock', 'a');
        if ($guard === false || !flock($guard, LOCK_EX | LOCK_NB)) throw new RuntimeException('A speed test is running.');
        @unlink(SPEEDTEST_RESULT);
        @unlink(SPEEDTEST_PROGRESS);
        speedtest_reply(['status'=>'ok']);
    } else {
        throw new InvalidArgumentException('Unknown action.');
    }
} catch (Throwable $error) {
    speedtest_reply(['status'=>'failed', 'error'=>$error->getMessage()]);
}
