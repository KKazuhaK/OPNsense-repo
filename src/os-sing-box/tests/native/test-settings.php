<?php
/* Exercise the real PHP backend with isolated files and a validating core stub. */
$helper = $argv[1] ?? '/usr/local/opnsense/scripts/singbox/singbox.php';
require_once($helper);

function check(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

function singbox_test_mutation(string $action, string $content, ?string $revision = null): array
{
    if ($action === 'save-config') {
        $content = json_encode(['config' => $content, 'revision' => $revision ?? singbox_revision()]);
    }
    $path = tempnam('/tmp', 'singbox-request-');
    if ($path === false) {
        throw new RuntimeException('Unable to stage the test request.');
    }
    try {
        chmod($path, 0600);
        file_put_contents($path, $content, LOCK_EX);
        return singbox_action($action, $path);
    } finally {
        unlink($path);
    }
}

$directory = sys_get_temp_dir() . '/singbox-mvc-test-' . bin2hex(random_bytes(8));
mkdir($directory, 0700);
putenv('SINGBOX_ROOT=' . $directory);
$configDirectory = $directory . '/usr/local/etc/sing-box';
mkdir($configDirectory . '/sub', 0700, true);
mkdir($directory . '/var/run', 0700, true);
mkdir($directory . '/var/log', 0700, true);
$core = $directory . '/core';
file_put_contents($core, "#!/bin/sh\n[ \"\$SINGBOX_FAIL_CHECK\" != 1 ]\n");
chmod($core, 0700);
putenv('SING_BOX_BIN=' . $core);
$original = (object)[
    'experimental' => (object)['clash_api' => (object)['secret' => 'SENTINEL_DASHBOARD']],
    'outbounds' => [
        (object)['tag' => 'first', 'type' => 'trojan', 'password' => 'SENTINEL_PASSWORD', 'tls' => (object)[]],
        (object)['tag' => 'second', 'type' => 'vless', 'uuid' => 'SENTINEL_UUID'],
    ],
    'route' => (object)['rule_set' => [(object)['url' => 'https://example.invalid/SENTINEL_RULESET']]],
    'headers' => (object)['Authorization' => ['SENTINEL_BEARER']],
    'tls' => (object)['key' => ['SENTINEL_TLS_PRIVATE_KEY'], 'key_path' => '/SENTINEL_KEY_PATH'],
    'auth_str' => 'SENTINEL_LEGACY_AUTH',
];
file_put_contents($configDirectory . '/config.json', json_encode($original));
file_put_contents($configDirectory . '/sub/env', "# Keep custom environment settings.\nexport http_proxy='https://example.invalid/custom-proxy'\nexport SING_BOX_URL=''\nexport CLASH_URL='https://example.invalid/SENTINEL_SUBSCRIPTION'\n");
try {
    $fresh = $directory . '/fresh';
    mkdir($fresh . '/var/run', 0700, true);
    putenv('SINGBOX_ROOT=' . $fresh);
    $empty = singbox_action('get-settings');
    check(!empty($empty['ok']) && $empty['config'] === '{}' && empty($empty['has_url']), 'Settings get failed before state was initialized.');
    check((fileperms($fresh . '/usr/local/etc/sing-box') & 0777) === 0700, 'The new state directory is not private.');
    check((fileperms($fresh . '/usr/local/etc/sing-box/.mvc-key') & 0777) === 0600, 'The fresh protection key is not private.');
    singbox_test_mutation('set-settings', json_encode(['subscription_url' => 'https://8.8.8.8/SENTINEL_FRESH_URL']));
    check(singbox_url() === 'https://8.8.8.8/SENTINEL_FRESH_URL', 'The fresh subscription directory was not initialized.');
    putenv('SINGBOX_ROOT=' . $directory);
    $result = singbox_action('get-settings');
    check(!empty($result['ok']) && !empty($result['has_url']), 'Settings read failed.');
    check(singbox_url() === 'https://example.invalid/SENTINEL_SUBSCRIPTION', 'The legacy URL fallback was not retained.');
    check(strpos(json_encode($result), 'SENTINEL_') === false, 'The settings response leaked a credential.');
    $edit = json_decode($result['config']);
    $edit->outbounds = array_reverse($edit->outbounds);
    $edit->outbounds[1]->server_port = 8443;
    singbox_test_mutation('save-config', json_encode($edit));
    $saved = json_decode(file_get_contents($configDirectory . '/config.json'));
    check($saved->outbounds[0]->uuid === 'SENTINEL_UUID', 'Reordering lost the VLESS credential.');
    check($saved->outbounds[1]->password === 'SENTINEL_PASSWORD', 'Reordering lost the Trojan credential.');
    check($saved->outbounds[1]->server_port === 8443, 'The editable setting was not saved.');
    check(is_object($saved->outbounds[1]->tls), 'An empty JSON object became an array.');
    check($saved->headers->Authorization[0] === 'SENTINEL_BEARER', 'Protected headers were not retained.');
    check((fileperms($configDirectory . '/config.json') & 0777) === 0600, 'The active configuration is not private.');
    check((fileperms($configDirectory . '/config.json.bak') & 0777) === 0600, 'The backup is not private.');
    check((fileperms($configDirectory . '/.mvc-key') & 0777) === 0600, 'The protection key is not private.');
    $snapshot = singbox_action('get-settings');
    $subscription = json_decode(file_get_contents($configDirectory . '/config.json'));
    $subscription->outbounds[1]->password = 'SENTINEL_NEW_SUBSCRIPTION_PASSWORD';
    $subscription->outbounds[1]->server = 'new.example.invalid';
    singbox_write($configDirectory . '/config.json', json_encode($subscription));
    $newSubscription = file_get_contents($configDirectory . '/config.json');
    try {
        singbox_test_mutation('save-config', $snapshot['config'], $snapshot['revision']);
        check(false, 'A stale editor overwrote a subscription configuration.');
    } catch (RuntimeException $error) {
        check(strpos($error->getMessage(), 'configuration changed') !== false, 'The stale editor was not rejected.');
    }
    check($newSubscription === file_get_contents($configDirectory . '/config.json'), 'A stale save changed subscription state.');
    $snapshot = singbox_action('get-settings');
    $relocated = json_decode($snapshot['config']);
    $relocated->outbounds[0]->uuid = $relocated->outbounds[1]->password;
    try {
        singbox_test_mutation('save-config', json_encode($relocated), $snapshot['revision']);
        check(false, 'A protected credential was relocated to another proxy.');
    } catch (RuntimeException $error) {
        check(strpos($error->getMessage(), 'protected value changed or moved') !== false, 'Credential relocation was not rejected.');
    }
    check($newSubscription === file_get_contents($configDirectory . '/config.json'), 'Credential relocation changed the active file.');
    $before = file_get_contents($configDirectory . '/config.json');
    putenv('SINGBOX_FAIL_CHECK=1');
    try {
        singbox_test_mutation('save-config', '{"outbounds":[]}');
        check(false, 'The invalid configuration was accepted.');
    } catch (RuntimeException $error) {
        check(strpos($error->getMessage(), 'rejected') !== false, 'The validation error was not reported.');
    }
    check($before === file_get_contents($configDirectory . '/config.json'), 'Validation failure changed the active file.');
    putenv('SINGBOX_FAIL_CHECK=');
    try {
        singbox_test_mutation('set-settings', json_encode(['subscription_url' => 'http://127.0.0.1/private']));
        check(false, 'A private subscription URL was accepted.');
    } catch (RuntimeException $error) {
        check(strpos($error->getMessage(), 'Private') !== false, 'Private URL rejection failed.');
    }
    singbox_test_mutation('set-settings', json_encode(['subscription_url' => 'https://8.8.8.8/SENTINEL_NEW_SUBSCRIPTION']));
    check(singbox_url() === 'https://8.8.8.8/SENTINEL_NEW_SUBSCRIPTION', 'The direct URL was not stored.');
    check(strpos(file_get_contents($configDirectory . '/sub/env'), "# Keep custom environment settings.\nexport http_proxy=") !== false, 'Saving a URL discarded unrelated environment lines.');
    check(strpos(json_encode(singbox_action('get-settings')), 'SENTINEL_') === false, 'Saving leaked the subscription URL.');
    singbox_test_mutation('set-settings', json_encode(['subscription_url' => '']));
    check(singbox_url() !== '', 'An empty field discarded the stored URL.');
    file_put_contents($directory . '/var/log/sing-box.log', "SENTINEL_PASSWORD SENTINEL_NEW_SUBSCRIPTION_PASSWORD --> https://example.invalid/SENTINEL_OLD_URL secret=SENTINEL_UNKNOWN\n");
    $log = singbox_action('log')['log'];
    check(strpos($log, 'SENTINEL_') === false && strpos($log, '-->') !== false, 'Log redaction or plain text failed.');
    singbox_test_mutation('set-settings', json_encode(['clear_url' => true]));
    check(singbox_url() === '' && !singbox_action('get-settings')['has_url'], 'The stored URL was not cleared.');
    file_put_contents($configDirectory . '/sub/sub.sh', "#!/bin/sh\nsleep 1\necho 'Isolated subscription update finished.'\n");
    check(!empty(singbox_action('sub-update')['ok']), 'The background updater did not launch.');
    try {
        singbox_action('sub-update');
        check(false, 'A duplicate subscription update was accepted.');
    } catch (RuntimeException $error) {
        check(strpos($error->getMessage(), 'already running') !== false, 'Duplicate update rejection failed.');
    }
    for ($attempt = 0; $attempt < 60 && !empty(singbox_update_status()['running']); $attempt++) {
        usleep(100000);
    }
    $update = singbox_update_status();
    check(empty($update['running']) && !empty($update['ok']), 'The detached updater failed or inherited its parent lock.');
    foreach (['{"subscription_url":"SENTINEL_RAW_ARGUMENT"}', $configDirectory . '/config.json'] as $invalid) {
        try {
            singbox_action('set-settings', $invalid);
            check(false, 'Raw or arbitrary-file request transport was accepted.');
        } catch (RuntimeException $error) {
            check(strpos($error->getMessage(), 'Invalid configuration request file') !== false, 'The request path was not rejected.');
        }
    }
    $publicRequest = tempnam('/tmp', 'singbox-request-');
    file_put_contents($publicRequest, '{"clear_url":true}');
    chmod($publicRequest, 0644);
    try {
        singbox_action('set-settings', $publicRequest);
        check(false, 'A public request file was accepted.');
    } catch (RuntimeException $error) {
        check(strpos($error->getMessage(), 'not private') !== false, 'Public request rejection failed.');
    } finally {
        unlink($publicRequest);
    }
    $linkedRequest = '/tmp/singbox-request-' . bin2hex(random_bytes(8));
    symlink($configDirectory . '/config.json', $linkedRequest);
    try {
        singbox_action('set-settings', $linkedRequest);
        check(false, 'A symlink request file was accepted.');
    } catch (RuntimeException $error) {
        check(strpos($error->getMessage(), 'not private') !== false, 'Symlink request rejection failed.');
    } finally {
        unlink($linkedRequest);
    }
    echo "Settings, config validation, private storage, credential retention, stale-save and credential-relocation rejection, log redaction, detached update locking and private file transport passed.\n";
} finally {
    $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($directory, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
    foreach ($iterator as $file) {
        $file->isDir() ? rmdir($file->getPathname()) : unlink($file->getPathname());
    }
    rmdir($directory);
}
