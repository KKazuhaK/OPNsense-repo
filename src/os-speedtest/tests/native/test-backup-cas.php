<?php
/* Exercise the shipped transport against actual Core and private XML only. */
function cas_check(bool $condition, string $message): void
{
    if (!$condition) { throw new RuntimeException($message); }
}

if (($argv[1] ?? '') === 'worker') {
    require_once('script/load_phalcon.php');
    require_once('util.inc');
    require_once('config.inc');
    $config = OPNsense\Core\Config::getInstance();
    $property = new ReflectionProperty($config, 'config_file_handle');
    fclose($property->getValue($config));
    $property->setValue($config, fopen($argv[2], 'r+'));
    (new ReflectionProperty($config, 'config_file'))->setValue($config, $argv[2]);
    (new ReflectionProperty($config, 'statusIsLocked'))->setValue($config, false);
    $config->lock();
    $config->unlock();
    require_once($argv[4]);
    putenv('SPEEDTEST_CAS_XML=' . $argv[2]);
    $source = $argv[3];
    $argv = [$source, $argv[5]];
    require($source);
    exit;
}

function cas_revision(array $fields): string
{
    ksort($fields, SORT_STRING);
    $encoded = json_encode((object)$fields, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    return hash('sha256', str_replace("\x7f", '\\u007f', $encoded));
}

function cas_run(string $verb, ?array $payload = null): array
{
    global $fixture, $shim, $model;
    $process = proc_open([PHP_BINARY, __FILE__, 'worker', $fixture, $shim, $model, $verb],
        [['pipe', 'r'], ['pipe', 'w'], ['pipe', 'w']], $pipes);
    cas_check(is_resource($process), 'Unable to start a native fixture worker.');
    if ($payload !== null) { fwrite($pipes[0], json_encode((object)$payload)); }
    fclose($pipes[0]);
    $stdout = stream_get_contents($pipes[1]);
    $stderr = stream_get_contents($pipes[2]);
    fclose($pipes[1]); fclose($pipes[2]);
    $code = proc_close($process);
    cas_check(!str_contains($stderr, 'SENTINEL_'), 'Private fixture XML escaped into diagnostics.');
    return [$code, json_decode($stdout, true, 32, JSON_THROW_ON_ERROR)];
}

function cas_remove(string $path): void
{
    if (is_dir($path) && !is_link($path)) {
        foreach (scandir($path) as $name) {
            if ($name !== '.' && $name !== '..') { cas_remove($path . '/' . $name); }
        }
        rmdir($path);
    } else { unlink($path); }
}

$package = dirname(__DIR__, 2);
$root = sys_get_temp_dir() . '/speedtest-backup-cas-' . bin2hex(random_bytes(8));
mkdir($root, 0700);
$fixture = $root . '/config.xml';
$shim = $root . '/config_mirror.php';
$model = $root . '/Backup.php';
try {
    $source = file_get_contents($package . '/src/usr/local/opnsense/scripts/speedtest/config_mirror.php');
    $source = str_replace("file_get_contents(\$settings->application->configDir . '/config.xml')",
                          "file_get_contents(getenv('SPEEDTEST_CAS_XML'))", $source, $count);
    cas_check($count === 1, 'The fixture must redirect exactly one fresh reader.');
    $source = str_replace("Config::getInstance()->save(['description' => 'speedtest settings mirrored into the configuration']);",
                          'Config::getInstance()->save(null, false);', $source, $count);
    cas_check($count === 1, 'The fixture must disable native config events on its private save.');
    file_put_contents($shim, $source);
    copy($package . '/src/usr/local/opnsense/mvc/app/models/OPNsense/Speedtest/Backup.php', $model);
    copy($package . '/src/usr/local/opnsense/mvc/app/models/OPNsense/Speedtest/Backup.xml', $root . '/Backup.xml');
    $fields = ['interface' => 'wan', 'server_id' => '16781', 'threads' => '8',
               'future' => "中文😀/\r\n\x7f"];
    cas_check(cas_revision($fields) === 'a02203e54dd0d333e8b232d4d6eca3e4cafe55456d5502fd3d2099b71f294fbc',
              'PHP and Python canonical revision hashes differ.');
    foreach ([false, true] as $absent) {
        $xml = new SimpleXMLElement('<opnsense><OPNsense><Speedtest/></OPNsense>' .
            '<peer attr="keep"><backup>SENTINEL_OTHER_BACKUP</backup></peer></opnsense>');
        if (!$absent) {
            $backup = $xml->OPNsense->Speedtest->addChild('backup');
            $backup->addAttribute('future-attribute', 'keep');
            foreach ($fields as $name => $value) {
                $element = $backup->addChild($name);
                $element[0] = $value;
            }
        }
        file_put_contents($fixture, $xml->asXML());
        chmod($fixture, 0600);
        [$code, $imported] = cas_run('import');
        cas_check($code === 0 && $imported === ($absent ? [] : $fields), 'Native import changed actual stored fields.');
        $expected = cas_revision($imported);
        $xml = simplexml_load_file($fixture);
        if (!isset($xml->OPNsense->Speedtest->backup)) { $xml->OPNsense->Speedtest->addChild('backup'); }
        $xml->OPNsense->Speedtest->backup->interface = 'lan';
        file_put_contents($fixture, $xml->asXML());
        $restoredBytes = file_get_contents($fixture);
        [$code] = cas_run('export', ['interface' => 'wan', '_expected' => $expected]);
        cas_check($code === 1 && file_get_contents($fixture) === $restoredBytes,
                  'A stale mirror overwrote the restored system XML.');
        [$code, $current] = cas_run('import');
        [$code, $answer] = cas_run('export', ['server_id' => '42', '_expected' => cas_revision($current)]);
        cas_check($code === 0 && $answer['changed'], 'A current revision could not be saved.');
        $saved = simplexml_load_file($fixture);
        cas_check((string)$saved->OPNsense->Speedtest->backup->interface === 'lan' &&
            (string)$saved->peer->backup === 'SENTINEL_OTHER_BACKUP' &&
            !isset($saved->OPNsense->Speedtest->backup->_expected), 'The transport metadata or unrelated XML changed.');
        if (!$absent) {
            cas_check((string)$saved->OPNsense->Speedtest->backup->future === $fields['future'] &&
                (string)$saved->OPNsense->Speedtest->backup['future-attribute'] === 'keep',
                'A current export replaced future configuration fields or attributes.');
        }
        [$code, $current] = cas_run('import');
        $before = file_get_contents($fixture);
        [$code, $answer] = cas_run('export', ['server_id' => '42', '_expected' => cas_revision($current)]);
        cas_check($code === 0 && !$answer['changed'] && file_get_contents($fixture) === $before,
                  'An identical revision produced another save.');
    }
    echo "Native Speedtest restored-XML compare-and-swap tests passed.\n";
} finally {
    cas_remove($root);
}
