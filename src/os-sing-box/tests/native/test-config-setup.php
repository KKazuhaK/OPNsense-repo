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
        if (in_array($argv[4], ['setup', 'remove', 'retire'], true)) {
            $changed = $argv[4] === 'retire'
                ? singbox_retire_legacy($config, false)
                : singbox_setup_network($config, false, $argv[4] === 'remove');
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
    setup_check((string)$xml->filter->rule[1]['uuid'] === '762b3ec8-79c2-48b4-9793-c653bb3d2265', 'The generated pass rule must follow existing administrator policy.');
    setup_check(isset($xml->filter->rule[1]->source->any) && (string)$xml->filter->rule[1]->ipprotocol === 'inet46' && isset($xml->filter->rule[1]->destination->any), 'The generated TUN rule must accept captured original source addresses.');
    setup_check((string)$xml->unknown['attr'] === 'retain' && isset($xml->unknown->unrecognized) &&
                (string)$xml->OPNsense->OtherPlugin->backup->archive === 'SENTINEL_EXISTING_BACKUP', 'Unknown configuration and other backups were lost.');
    $reloadReceipt = $directory . '/state/filter-reload-pending.json';
    setup_check((fileperms(dirname($reloadReceipt)) & 0777) === 0700
                && is_file($reloadReceipt) && (fileperms($reloadReceipt) & 0777) === 0600
                && json_decode(file_get_contents($reloadReceipt), true) === ['schema' => 1, 'pending' => true],
                'A saved native firewall change must leave a durable private reload receipt.');
    $after = file_get_contents($fixture);
    setup_check(trim(setup_finish(setup_worker($helper, $fixture, 'setup', $gate))) === 'unchanged', 'Repeated setup must be idempotent.');
    setup_check(file_get_contents($fixture) === $after, 'Unchanged setup must not create another native save.');

    $journalPath = $directory . '/state/tun-state.json';
    $journal = json_decode(file_get_contents($journalPath), true);
    chmod($journalPath, 0644);
    setup_finish(setup_worker($helper, $fixture, 'setup', $gate), false);
    chmod($journalPath, 0600);
    setup_check(file_get_contents($fixture) === $after,
                'A public ownership journal was accepted or changed native configuration.');
    $journalBytes = file_get_contents($journalPath);
    $foreignJournal = $directory . '/foreign-journal';
    file_put_contents($foreignJournal, 'SENTINEL_FOREIGN_JOURNAL');
    rename($journalPath, $journalPath . '.saved');
    symlink($foreignJournal, $journalPath);
    setup_finish(setup_worker($helper, $fixture, 'setup', $gate), false);
    setup_check(file_get_contents($foreignJournal) === 'SENTINEL_FOREIGN_JOURNAL',
                'A journal symlink target was changed.');
    unlink($journalPath);
    rename($journalPath . '.saved', $journalPath);
    setup_check(file_get_contents($journalPath) === $journalBytes,
                'The private journal changed during symlink rejection.');

    $foreignRule = $journal;
    $foreignRule['created_rule'] = false;
    unset($foreignRule['previous_rule_xml']);
    file_put_contents($journalPath, json_encode($foreignRule));
    chmod($journalPath, 0600);
    setup_check(trim(setup_finish(setup_worker($helper, $fixture, 'remove', $gate))) === 'unchanged',
                'A matching rule without an ownership action must not report a firewall change.');
    setup_check(file_get_contents($fixture) === $after, 'A foreign matching rule was rewritten during cleanup.');
    file_put_contents($journalPath, json_encode($journal));
    chmod($journalPath, 0600);

    $filterLock = $directory . '/state/filter-reload.lock';
    unlink($filterLock);
    $foreignLock = $directory . '/foreign-lock';
    file_put_contents($foreignLock, 'SENTINEL_FOREIGN_LOCK');
    symlink($foreignLock, $filterLock);
    file_put_contents($fixture, $original);
    setup_finish(setup_worker($helper, $fixture, 'setup', $gate), false);
    setup_check(file_get_contents($foreignLock) === 'SENTINEL_FOREIGN_LOCK'
                && file_get_contents($fixture) === $original,
                'A filter lock symlink was followed or a failed save changed native configuration.');
    unlink($filterLock);
    touch($filterLock);
    chmod($filterLock, 0600);
    file_put_contents($fixture, $after);

    file_put_contents($fixture, str_replace('<opt2><if>em2</if><descr>retain</descr></opt2>', '<opt7><if>tun_singbox</if><enable>0</enable><descr>custom</descr></opt7>', $original));
    setup_finish(setup_worker($helper, $fixture, 'setup', $gate));
    $xml = simplexml_load_file($fixture);
    setup_check((string)$xml->interfaces->opt7->enable === '0' && (string)$xml->interfaces->opt7->descr === 'custom', 'An existing TUN interface was rewritten.');
    setup_check((string)$xml->filter->rule[1]->interface === 'opt7', 'An existing TUN interface was not reused.');

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
    setup_check(trim(setup_finish(setup_worker($helper, $fixture, 'remove', $gate))) === 'changed', 'Owned cleanup must remove unchanged generated policy.');
    $cleaned = simplexml_load_file($fixture);
    setup_check(count($cleaned->interfaces->xpath('*[if="tun_singbox"]')) === 0 &&
                count($cleaned->filter->xpath('rule[@uuid="762b3ec8-79c2-48b4-9793-c653bb3d2265"]')) === 0,
                'Unchanged owned interface or rule survived cleanup.');
    for ($index = 0; $index < 8; $index++) {
        $name = 'NativePeer' . $index;
        setup_check((string)$cleaned->OPNsense->$name->archive === 'SENTINEL_PEER_BACKUP', 'Cleanup changed another plugin backup.');
    }
    setup_finish(setup_worker($helper, $fixture, 'setup', $gate));
    $edited = simplexml_load_file($fixture);
    $edited->interfaces->opt3->descr = 'ADMINISTRATOR_EDIT';
    $edited->filter->rule[1]->descr = 'ADMINISTRATOR_EDIT';
    $edited->asXML($fixture);
    $editedBytes = file_get_contents($fixture);
    setup_check(trim(setup_finish(setup_worker($helper, $fixture, 'remove', $gate))) === 'unchanged', 'Edited resources must be treated as foreign.');
    setup_check(file_get_contents($fixture) === $editedBytes, 'Cleanup rewrote administrator interface/rule edits.');

    $legacy = '<opnsense><interfaces><lo0><if>lo0</if></lo0>' .
              '<opt3><if>tun_singbox</if><descr>TUN</descr><enable>1</enable></opt3></interfaces>' .
              '<filter><rule uuid="762b3ec8-79c2-48b4-9793-c653bb3d2265"><type>pass</type>' .
              '<interface>opt3</interface><ipprotocol>inet</ipprotocol><source><network>opt3</network></source>' .
              '<destination><any/></destination><descr>sing-box TUN Allow</descr></rule></filter>' .
              '<unknown>SENTINEL_LEGACY_UNKNOWN</unknown></opnsense>';
    file_put_contents($fixture, $legacy);
    setup_check(trim(setup_finish(setup_worker($helper, $fixture, 'retire', $gate))) === 'changed',
                'The exact 1.1.1 policy must be retired during upgrade.');
    $retired = simplexml_load_file($fixture);
    setup_check(count($retired->interfaces->xpath('*[if="tun_singbox"]')) === 0 &&
                count($retired->filter->xpath('rule[@uuid="762b3ec8-79c2-48b4-9793-c653bb3d2265"]')) === 0,
                'The exact legacy interface assignment or pass rule survived retirement.');
    setup_check((string)$retired->unknown === 'SENTINEL_LEGACY_UNKNOWN', 'Legacy retirement changed unrelated configuration.');

    $editedLegacy = str_replace('<descr>sing-box TUN Allow</descr>', '<descr>ADMINISTRATOR_EDIT</descr>', $legacy);
    file_put_contents($fixture, $editedLegacy);
    setup_check(trim(setup_finish(setup_worker($helper, $fixture, 'retire', $gate))) === 'unchanged',
                'An edited legacy rule must be preserved.');
    setup_check(file_get_contents($fixture) === $editedLegacy, 'Legacy retirement rewrote an administrator rule edit.');

    $referencedLegacy = str_replace('</opnsense>', '<groups><member>opt3</member></groups></opnsense>', $legacy);
    file_put_contents($fixture, $referencedLegacy);
    setup_finish(setup_worker($helper, $fixture, 'retire', $gate));
    $referenced = simplexml_load_file($fixture);
    setup_check(count($referenced->filter->xpath('rule[@uuid="762b3ec8-79c2-48b4-9793-c653bb3d2265"]')) === 0 &&
                count($referenced->interfaces->xpath('*[if="tun_singbox"]')) === 1,
                'A referenced legacy interface was removed or its exact generated rule was retained.');

    $customLegacy = str_replace('<descr>TUN</descr>', '<descr>ADMINISTRATOR_INTERFACE</descr>', $legacy);
    file_put_contents($fixture, $customLegacy);
    setup_finish(setup_worker($helper, $fixture, 'retire', $gate));
    $custom = simplexml_load_file($fixture);
    setup_check(count($custom->filter->xpath('rule[@uuid="762b3ec8-79c2-48b4-9793-c653bb3d2265"]')) === 0 &&
                (string)$custom->interfaces->opt3->descr === 'ADMINISTRATOR_INTERFACE',
                'A customized legacy interface was removed or its exact generated rule was retained.');
    echo "Native private Core setup preserves policy order, administrator edits, idempotency, scoped cleanup and all 8 concurrent plugin backups.\n";
} finally {
    setup_remove($directory);
}
