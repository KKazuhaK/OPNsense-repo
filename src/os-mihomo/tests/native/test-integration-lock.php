<?php
/* Exercise the shipped native integration writer against private Core fixtures. */
function integration_check(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

function integration_config(string $path): \OPNsense\Core\Config
{
    $config = \OPNsense\Core\Config::getInstance();
    $handle = new ReflectionProperty($config, 'config_file_handle');
    fclose($handle->getValue($config));
    $handle->setValue($config, fopen($path, 'r+'));
    (new ReflectionProperty($config, 'config_file'))->setValue($config, $path);
    (new ReflectionProperty($config, 'statusIsLocked'))->setValue($config, false);
    $config->lock();
    $config->unlock();
    return $config;
}

if (($argv[1] ?? '') === 'worker') {
    [$script, $worker, $helper, $root, $operation, $gate, $ready] = $argv;
    require_once('/usr/local/etc/inc/util.inc');
    require_once('/usr/local/etc/inc/config.inc');
    putenv('OS_MIHOMO_ROOT=' . $root);
    putenv('MIHOMO_NATIVE_FIXTURE=' . $root . '/conf/config.xml');
    $config = integration_config($root . '/conf/config.xml');
    touch($ready);
    $deadline = microtime(true) + 10;
    while (!is_file($gate)) {
        integration_check(microtime(true) < $deadline, 'The private fixture start gate timed out.');
        usleep(1000);
    }
    if ($operation === 'backup-model-migration') {
        require_once(dirname(__DIR__, 2) . '/src/usr/local/opnsense/mvc/app/models/OPNsense/Mihomo/Backup.php');
        $before = file_get_contents($root . '/conf/config.xml');
        $model = new \OPNsense\Mihomo\Backup();
        integration_check($model->runMigrations() === false, 'The mirror model requested generic serialization.');
        integration_check(file_get_contents($root . '/conf/config.xml') === $before, 'The model migration overwrote opaque or unknown mirror fields.');
        integration_check((string)$config->object()->OPNsense->Mihomo->backup->future_tree->keep === 'SENTINEL_FUTURE_FIELD',
                          'The native model migration discarded future fields.');
        echo "preserved\n";
    } elseif (str_starts_with($operation, 'NativePeer')) {
        require($root . '/functions.php');
        try {
            mihomoLockCurrent($config);
            $config->object()->OPNsense->addChild($operation)->addChild('archive', 'SENTINEL_PEER_BACKUP');
            $config->save(null, false);
        } finally {
            $config->unlock();
        }
        echo "saved\n";
    } else {
        $argv = [$helper, $operation, '1'];
        require($helper);
    }
    exit;
}

function integration_worker(string $helper, string $root, string $operation, string $gate, string $ready, ?array $payload = null): array
{
    $process = proc_open(['/usr/local/bin/php', __FILE__, 'worker', $helper, $root, $operation, $gate, $ready],
        [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
    integration_check(is_resource($process), 'Unable to launch a private native worker.');
    if ($payload !== null) {
        fwrite($pipes[0], json_encode($payload, JSON_THROW_ON_ERROR));
    }
    fclose($pipes[0]);
    return [$process, $pipes];
}

function integration_finish(array $worker, bool $success = true): string
{
    [$process, $pipes] = $worker;
    $output = stream_get_contents($pipes[1]);
    $error = stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    integration_check((proc_close($process) === 0) === $success, 'A private native worker returned an unexpected status.');
    integration_check(!str_contains($error, 'SENTINEL_'), 'A private fixture value escaped into diagnostics.');
    return $output;
}

function integration_ready(array $paths): void
{
    $deadline = microtime(true) + 10;
    foreach ($paths as $path) {
        while (!is_file($path)) {
            integration_check(microtime(true) < $deadline, 'A private worker failed to reach its start gate.');
            usleep(1000);
        }
    }
}

function integration_remove(string $path): void
{
    if (is_dir($path) && !is_link($path)) {
        foreach (scandir($path) as $name) {
            if ($name !== '.' && $name !== '..') {
                integration_remove($path . '/' . $name);
            }
        }
        rmdir($path);
    } else {
        unlink($path);
    }
}

$source = $argv[1] ?? dirname(__DIR__, 2) . '/src/usr/local/opnsense/scripts/mihomo/setup_unbound.php';
$directory = sys_get_temp_dir() . '/mihomo-integration-lock-' . bin2hex(random_bytes(8));
mkdir($directory, 0700);
mkdir($directory . '/conf', 0700);
mkdir($directory . '/var/db/os-mihomo', 0700, true);
$helper = $directory . '/setup_unbound.php';
$fixture = $directory . '/conf/config.xml';
$state = $directory . '/var/db/os-mihomo';
$gate = $directory . '/gate';
try {
    $script = file_get_contents($source);
    foreach ([
        "file_get_contents(\$settings->application->configDir . '/config.xml')" => "file_get_contents(getenv('MIHOMO_NATIVE_FIXTURE'))",
        "if (\$root === '') {" => "if (getenv('MIHOMO_NATIVE_FIXTURE') !== false) {",
        "\$native->save(make_config_revision_entry('Update Mihomo transparent integration'));" => '$native->save(null, false);'
    ] as $before => $after) {
        $count = 0;
        $script = str_replace($before, $after, $script, $count);
        integration_check($count === 1, 'Each native fixture redirection must match exactly once.');
    }
    file_put_contents($helper, $script);
    chmod($helper, 0600);
    $boundary = strpos($script, '$mode = $argv[1]');
    integration_check($boundary !== false, 'Unable to isolate the shipped integration lock functions.');
    file_put_contents($directory . '/functions.php', substr($script, 0, $boundary));
    $original = '<opnsense><interfaces><lo0><if>lo0</if></lo0><wan><if>em0</if></wan>' .
        '<opt9><if>tun_mihomo</if></opt9><opt10><if>em2</if><descr>retain</descr></opt10></interfaces>' .
        '<filter><rule uuid="5a73c3dc-69b1-4e15-89cb-b542aa2c1154"><interface>opt9</interface></rule>' .
        '<rule uuid="retain-rule"><interface>wan</interface></rule></filter>' .
        '<unknown attr="retain"><value>SENTINEL_UNKNOWN_PRIVATE</value><unrecognized/></unknown>' .
        '<OPNsense><OtherPlugin><backup><archive>SENTINEL_EXISTING_BACKUP</archive></backup></OtherPlugin>' .
        '<unboundplus><forwarding><enabled>0</enabled></forwarding><advanced><privateaddress>192.0.2.0/24</privateaddress></advanced>' .
        '<dots><dot uuid="operator-root"><domain>.</domain><enabled>0</enabled><server>retain.invalid</server></dot>' .
        '<dot uuid="b126bf65-a985-49ca-a9d2-16f156aac198"><domain>.</domain></dot></dots></unboundplus></OPNsense></opnsense>';
    file_put_contents($fixture, $original);
    chmod($fixture, 0600);
    file_put_contents($state . '/dns-state.json', '{"forwarding":"1","roots":{"operator-root":"1"},"had_fake_ip_private_address":true}');
    file_put_contents($state . '/tun-state.json', '{"interface":"opt9","created_interface":true,"created_rule":true}');
    $ready = $directory . '/ready-stale';
    $worker = integration_worker($helper, $directory, 'disable', $gate, $ready);
    integration_ready([$ready]);
    file_put_contents($fixture, str_replace('<unknown attr="retain">', '<unknown attr="retain" latest="retain">', $original));
    touch($gate);
    integration_check(str_contains(integration_finish($worker), 'updated'), 'The integration cleanup did not save the fixture.');
    $xml = simplexml_load_file($fixture);
    integration_check((string)$xml->unknown['latest'] === 'retain', 'A stale native object overwrote a newer configuration field.');
    integration_check(!isset($xml->interfaces->opt9) && isset($xml->interfaces->opt10), 'Cleanup removed an unowned interface or retained its owned one.');
    integration_check(count($xml->filter->rule) === 1 && (string)$xml->filter->rule['uuid'] === 'retain-rule', 'Cleanup changed an unowned firewall rule.');
    integration_check((string)$xml->OPNsense->unboundplus->forwarding->enabled === '1' &&
        (string)$xml->OPNsense->unboundplus->dots->dot->enabled === '1' &&
        str_contains((string)$xml->OPNsense->unboundplus->advanced->privateaddress, '198.18.0.0/15'), 'Cleanup failed to restore the ownership journal.');
    integration_check(!is_file($state . '/dns-state.json') && !is_file($state . '/tun-state.json'), 'Successfully applied journals were not retired.');
    $after = file_get_contents($fixture);
    integration_check(str_contains(integration_finish(integration_worker($helper, $directory, 'disable', $gate, $directory . '/ready-repeat')), 'unchanged'), 'Repeated cleanup was not idempotent.');
    integration_check(file_get_contents($fixture) === $after, 'Unchanged cleanup issued another native save.');

    unlink($gate);
    $workers = $readyPaths = [];
    for ($index = 0; $index < 8; $index++) {
        foreach (['enable-tun', 'NativePeer' . $index] as $operation) {
            $readyPaths[] = $directory . '/ready-' . count($readyPaths);
            $workers[] = integration_worker($helper, $directory, $operation, $gate, end($readyPaths));
        }
    }
    integration_ready($readyPaths);
    touch($gate);
    foreach ($workers as $worker) {
        integration_finish($worker);
    }
    $xml = simplexml_load_file($fixture);
    for ($index = 0; $index < 8; $index++) {
        $name = 'NativePeer' . $index;
        integration_check((string)$xml->OPNsense->$name->archive === 'SENTINEL_PEER_BACKUP', 'A concurrent plugin backup was lost.');
    }
    integration_check(count($xml->interfaces->xpath('*[if="tun_mihomo"]')) === 1 &&
        count($xml->filter->xpath('rule[@uuid="5a73c3dc-69b1-4e15-89cb-b542aa2c1154"]')) === 1, 'Concurrent integration duplicated its interface or rule.');
    integration_check((string)$xml->unknown->value === 'SENTINEL_UNKNOWN_PRIVATE' && (string)$xml->unknown['latest'] === 'retain' &&
        (string)$xml->OPNsense->OtherPlugin->backup->archive === 'SENTINEL_EXISTING_BACKUP', 'Concurrent native saves lost existing or unknown configuration.');
    $identity = '<system><uuid>system-A</uuid><hostname>router</hostname><domain>test.invalid</domain></system>';
    $scope = hash('sha256', 'system-A|router|test.invalid');
    $fields = ['secret' => '"SENTINEL_SAVED_SECRET"', 'consent_scope' => $scope, 'checksum' => str_repeat('0', 64)];
    $section = '<Mihomo><backup><secret>' . $fields['secret'] . '</secret><consent_scope>' . $scope .
        '</consent_scope><checksum>' . $fields['checksum'] . '</checksum></backup></Mihomo>';
    $archived = ['dns_state' => ['forwarding' => '1', 'roots' => ['operator-root' => '1'], 'had_fake_ip_private_address' => true],
                 'tun_state' => ['interface' => 'opt9', 'created_interface' => true, 'created_rule' => true]];
    $seed = str_replace('<opnsense>', '<opnsense>' . $identity, str_replace('<OPNsense>', '<OPNsense>' . $section, $original));
    $canonical = $fields;
    ksort($canonical, SORT_STRING);
    $payload = ['expected' => hash('sha256', json_encode((object)$canonical, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR)),
                'scope' => $scope, 'current_scope' => $scope, 'journals' => $archived, 'repair_checksum' => str_repeat('a', 64)];

    // Stale and malformed recovery never changes XML or retires local journals.
    foreach (['stale', 'malformed', 'identity-changed'] as $case) {
        file_put_contents($fixture, $seed);
        file_put_contents($state . '/dns-state.json', 'SENTINEL_LOCAL_JOURNAL');
        $invalid = $payload;
        if ($case === 'stale') {
            $invalid['expected'] = str_repeat('f', 64);
        } elseif ($case === 'identity-changed') {
            $invalid['current_scope'] = str_repeat('f', 64);
        } else {
            $invalid['journals']['tun_state']['interface'] = 'opt9/../../wan';
        }
        integration_finish(integration_worker($helper, $directory, 'restore-backup', $gate, $directory . '/ready-' . $case, $invalid), false);
        integration_check(file_get_contents($fixture) === $seed && file_get_contents($state . '/dns-state.json') === 'SENTINEL_LOCAL_JOURNAL',
                          'Rejected recovery changed XML or current journals.');
    }

    // Only imported, scoped journals are consumed; corrupt older local files are not consulted.
    file_put_contents($fixture, $seed);
    file_put_contents($state . '/tun-state.json', 'SENTINEL_CORRUPT_OLDER_JOURNAL');
    integration_finish(integration_worker($helper, $directory, 'restore-backup', $gate, $directory . '/ready-repair', $payload));
    $xml = simplexml_load_file($fixture);
    integration_check((string)$xml->OPNsense->Mihomo->backup->checksum === str_repeat('a', 64) && !isset($xml->interfaces->opt9)
        && (string)$xml->OPNsense->unboundplus->forwarding->enabled === '1', 'Scoped native repair did not atomically save the checksum and ownership rollback.');
    integration_check((string)$xml->OPNsense->OtherPlugin->backup->archive === 'SENTINEL_EXISTING_BACKUP', 'Repair changed another plugin backup.');

    // A different scope cannot roll back borrowed interface or DNS state.
    file_put_contents($fixture, $seed);
    $unowned = $payload;
    $unowned['scope'] = str_repeat('b', 64);
    $unowned['repair_checksum'] = '';
    integration_finish(integration_worker($helper, $directory, 'restore-backup', $gate, $directory . '/ready-unowned', $unowned));
    $xml = simplexml_load_file($fixture);
    integration_check(isset($xml->interfaces->opt9) && count($xml->filter->rule) === 2
        && (string)$xml->OPNsense->unboundplus->forwarding->enabled === '0'
        && (string)$xml->OPNsense->unboundplus->dots->dot->enabled === '0'
        && !str_contains((string)$xml->OPNsense->unboundplus->advanced->privateaddress, '198.18.0.0/15'), 'Unowned recovery applied an archived ownership journal.');

    // Operator changes to the owned slot or a DNS entry remain authoritative.
    $repurposed = str_replace('<opt9><if>tun_mihomo</if>', '<opt9><if>em7</if>',
        str_replace('<domain>.</domain><enabled>0</enabled><server>retain.invalid', '<domain>private.invalid</domain><enabled>0</enabled><server>retain.invalid', $seed));
    file_put_contents($fixture, $repurposed);
    integration_finish(integration_worker($helper, $directory, 'restore-backup', $gate, $directory . '/ready-repurposed', $payload));
    $xml = simplexml_load_file($fixture);
    integration_check((string)$xml->interfaces->opt9->if === 'em7' && count($xml->filter->rule) === 2
        && (string)$xml->OPNsense->unboundplus->dots->dot->enabled === '0', 'Recovery overwrote a repurposed interface, firewall rule, or DNS entry.');

    // Crash rescue removes the intrinsic forwarder despite corrupt/pending journals.
    file_put_contents($fixture, $seed);
    file_put_contents($state . '/dns-state.json', 'SENTINEL_PENDING_JOURNAL');
    file_put_contents($state . '/tun-state.json', 'SENTINEL_PENDING_JOURNAL');
    integration_finish(integration_worker($helper, $directory, 'rescue', $gate, $directory . '/ready-rescue'));
    $xml = simplexml_load_file($fixture);
    integration_check(isset($xml->interfaces->opt9) && count($xml->OPNsense->unboundplus->dots->dot) === 1
        && file_get_contents($state . '/dns-state.json') === 'SENTINEL_PENDING_JOURNAL'
        && (string)$xml->OPNsense->unboundplus->forwarding->enabled === '0', 'Crash rescue consumed unpaired journals or retained the stopped-core forwarder.');
    $migration = str_replace('<backup>', '<backup version="0.0.0"><future_tree><keep>SENTINEL_FUTURE_FIELD</keep></future_tree>', $seed);
    file_put_contents($fixture, $migration);
    integration_finish(integration_worker($helper, $directory, 'backup-model-migration', $gate, $directory . '/ready-model-migration'));
    integration_check(file_get_contents($fixture) === $migration, 'Native mirror migrations changed the saved XML.');
    echo "Native private Core Mihomo cleanup preserves concurrent plugin backups and verifies scoped recovery, checksum repair, XML races, repurposed ownership, and crash rescue.\n";
} finally {
    integration_remove($directory);
}
