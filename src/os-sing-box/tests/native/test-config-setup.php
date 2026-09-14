<?php
/* Exercise the actual Core writer on private XML fixtures, without network changes. */
function setup_check(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

function setup_fixture_config(string $path): \OPNsense\Core\Config
{
    $config = \OPNsense\Core\Config::getInstance();
    $handle = new ReflectionProperty($config, 'config_file_handle');
    fclose($handle->getValue($config));
    $handle->setValue($config, fopen($path, 'r+'));
    (new ReflectionProperty($config, 'config_file'))->setValue($config, $path);
    (new ReflectionProperty($config, 'statusIsLocked'))->setValue($config, false);
    return $config;
}

if (($argv[1] ?? '') === 'worker') {
    require_once($argv[2]);
    putenv('SINGBOX_SETUP_FIXTURE=' . $argv[3]);
    $config = setup_fixture_config($argv[3]);
    $deadline = microtime(true) + 10;
    while (!is_file($argv[5])) {
        setup_check(microtime(true) < $deadline, 'The test start gate timed out.');
        usleep(1000);
    }
    try {
        if ($argv[4] === 'setup') {
            $changed = singbox_setup_network($config, false);
            echo $changed ? "changed\n" : "unchanged\n";
        } else {
            try {
                backup_lock_current($config);
                $root = $config->object();
                if (!isset($root->OPNsense)) {
                    $root->addChild('OPNsense');
                }
                $root->OPNsense->addChild($argv[4])->addChild('archive', 'SENTINEL_PEER_BACKUP');
                $config->save(null, false);
            } finally {
                $config->unlock();
            }
            echo "saved\n";
        }
    } catch (Throwable $error) {
        fwrite(STDERR, "The isolated configuration operation failed.\n");
        exit(1);
    }
    exit;
}

function setup_worker(string $helper, string $fixture, string $operation, string $gate): array
{
    $process = proc_open(['/usr/local/bin/php', __FILE__, 'worker', $helper, $fixture, $operation, $gate],
        [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
    setup_check(is_resource($process), 'Unable to launch a native fixture worker.');
    fclose($pipes[0]);
    return [$process, $pipes];
}

function setup_finish(array $worker, bool $ok = true): string
{
    [$process, $pipes] = $worker;
    $output = stream_get_contents($pipes[1]);
    $error = stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    $code = proc_close($process);
    setup_check($ok ? $code === 0 : $code === 1, 'Unexpected native fixture worker status.');
    setup_check(!str_contains($error, 'SENTINEL_'), 'A private fixture value escaped into diagnostics.');
    return $output;
}

function setup_remove(string $path): void
{
    if (is_dir($path) && !is_link($path)) {
        foreach (scandir($path) as $name) {
            if ($name !== '.' && $name !== '..') {
                setup_remove($path . '/' . $name);
            }
        }
        rmdir($path);
    } else {
        unlink($path);
    }
}

$source = $argv[1] ?? dirname(__DIR__, 2) . '/src/usr/local/opnsense/scripts/singbox/config_setup.php';
$directory = sys_get_temp_dir() . '/singbox-setup-test-' . bin2hex(random_bytes(8));
mkdir($directory, 0700);
mkdir($directory . '/conf', 0700);
$helper = $directory . '/config_setup.php';
$fixture = $directory . '/conf/config.xml';
$gate = $directory . '/gate';
try {
    $script = file_get_contents($source);
    $count = 0;
    $script = str_replace("file_get_contents(\$settings->application->configDir . '/config.xml')",
                          "file_get_contents(getenv('SINGBOX_SETUP_FIXTURE'))", $script, $count);
    setup_check($count === 1, 'The native fixture must redirect exactly one XML reader.');
    file_put_contents($helper, $script);
    chmod($helper, 0600);
    $original = '<opnsense><interfaces><lo0><if>lo0</if></lo0><wan><if>em0</if></wan>' .
                '<opt2><if>em2</if><descr>retain</descr></opt2></interfaces>' .
                '<filter><rule uuid="existing-rule"><type>block</type><interface>wan</interface></rule></filter>' .
                '<unknown attr="retain"><value>SENTINEL_UNKNOWN_PRIVATE</value><unrecognized/></unknown>' .
                '<OPNsense><OtherPlugin><backup><archive>SENTINEL_EXISTING_BACKUP</archive></backup></OtherPlugin></OPNsense></opnsense>';
    file_put_contents($fixture, $original);
    chmod($fixture, 0600);
    touch($gate);
    setup_check(trim(setup_finish(setup_worker($helper, $fixture, 'setup', $gate))) === 'changed', 'First setup must add the absent interface and rule.');
    $xml = simplexml_load_file($fixture);
    setup_check((string)$xml->interfaces->opt3->if === 'tun_singbox', 'The next OPT index was not preserved.');
    $names = array_keys(iterator_to_array($xml->interfaces->children()));
    setup_check($names === ['lo0', 'opt3', 'wan', 'opt2'], 'The interface insertion order changed.');
    setup_check((string)$xml->filter->rule[0]['uuid'] === '762b3ec8-79c2-48b4-9793-c653bb3d2265', 'The pass rule must retain its original first position.');
    setup_check((string)$xml->filter->rule[0]->source->network === 'opt3' && isset($xml->filter->rule[0]->destination->any), 'The existing pass rule policy changed.');
    setup_check((string)$xml->unknown['attr'] === 'retain' && isset($xml->unknown->unrecognized) &&
                (string)$xml->OPNsense->OtherPlugin->backup->archive === 'SENTINEL_EXISTING_BACKUP', 'Unknown configuration and other backups were lost.');
    $after = file_get_contents($fixture);
    setup_check(trim(setup_finish(setup_worker($helper, $fixture, 'setup', $gate))) === 'unchanged', 'Repeated setup must be idempotent.');
    setup_check(file_get_contents($fixture) === $after, 'Unchanged setup must not create another native save.');

    file_put_contents($fixture, str_replace('<opt2><if>em2</if><descr>retain</descr></opt2>', '<opt7><if>tun_singbox</if><enable>0</enable><descr>custom</descr></opt7>', $original));
    setup_finish(setup_worker($helper, $fixture, 'setup', $gate));
    $xml = simplexml_load_file($fixture);
    setup_check((string)$xml->interfaces->opt7->enable === '0' && (string)$xml->interfaces->opt7->descr === 'custom', 'An existing TUN interface was rewritten.');
    setup_check((string)$xml->filter->rule[0]->interface === 'opt7', 'An existing TUN interface was not reused.');

    $missing = str_replace('<lo0><if>lo0</if></lo0>', '', $original);
    file_put_contents($fixture, $missing);
    setup_finish(setup_worker($helper, $fixture, 'setup', $gate), false);
    setup_check(file_get_contents($fixture) === $missing, 'Invalid native interface state was partially saved.');

    file_put_contents($fixture, $original);
    unlink($gate);
    $workers = [];
    for ($index = 0; $index < 8; $index++) {
        $workers[] = setup_worker($helper, $fixture, 'setup', $gate);
        $workers[] = setup_worker($helper, $fixture, 'NativePeer' . $index, $gate);
    }
    usleep(100000);
    touch($gate);
    foreach ($workers as $worker) {
        setup_finish($worker);
    }
    $xml = simplexml_load_file($fixture);
    for ($index = 0; $index < 8; $index++) {
        $name = 'NativePeer' . $index;
        setup_check((string)$xml->OPNsense->$name->archive === 'SENTINEL_PEER_BACKUP', 'A concurrent plugin backup was lost.');
    }
    setup_check(count($xml->interfaces->xpath('*[if="tun_singbox"]')) === 1 &&
                count($xml->filter->xpath('rule[@uuid="762b3ec8-79c2-48b4-9793-c653bb3d2265"]')) === 1,
                'Concurrent setup duplicated the plugin interface or rule.');
    setup_check((string)$xml->unknown->value === 'SENTINEL_UNKNOWN_PRIVATE' &&
                (string)$xml->OPNsense->OtherPlugin->backup->archive === 'SENTINEL_EXISTING_BACKUP',
                'Concurrent native saves lost existing private configuration.');
    echo "Native private Core setup preserves policy order, existing state, idempotency and all 8 concurrent plugin backups.\n";
} finally {
    setup_remove($directory);
}
