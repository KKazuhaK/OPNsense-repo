<?php
/* Run the shipped embedded PHP with actual Core on private XML fixtures. */
function manifest_check(bool $condition, string $message): void
{
    if (!$condition) { throw new RuntimeException($message); }
}

function manifest_worker(string $program, string $fixture, string $gate, string $peer = ''): array
{
    $environment = array_merge(getenv(), ['KAZUHA_REPO_ROOT' => '', 'KAZUHA_NATIVE_XML' => $fixture,
        'KAZUHA_NATIVE_GATE' => $gate, 'KAZUHA_NATIVE_PEER' => $peer, '_KAZUHA_VERB' => 'write',
        '_KAZUHA_PLUGINS' => "os-kazuha-repo 1.0.0\nos-mihomo 1.2.0", '_KAZUHA_SCHEMA' => '1.0.0']);
    $process = proc_open([PHP_BINARY, $program], [['pipe', 'r'], ['pipe', 'w'], ['pipe', 'w']], $pipes, null, $environment);
    manifest_check(is_resource($process), 'Unable to start the native fixture worker.');
    fclose($pipes[0]);
    return [$process, $pipes];
}

function manifest_finish(array $worker): string
{
    [$process, $pipes] = $worker;
    $output = stream_get_contents($pipes[1]);
    $error = stream_get_contents($pipes[2]);
    fclose($pipes[1]); fclose($pipes[2]);
    manifest_check(proc_close($process) === 0, 'The native fixture operation failed.');
    manifest_check(!str_contains($error, 'SENTINEL_'), 'Private XML escaped into diagnostics.');
    return $output;
}

function manifest_remove(string $path): void
{
    if (is_dir($path) && !is_link($path)) {
        foreach (scandir($path) as $name) {
            if ($name !== '.' && $name !== '..') { manifest_remove($path . '/' . $name); }
        }
        rmdir($path);
    } else { unlink($path); }
}

$hook = $argv[1] ?? dirname(__DIR__, 2) . '/src/usr/local/opnsense/scripts/firmware/repos/kazuha.sh';
$root = sys_get_temp_dir() . '/kazuha-core-manifest-' . bin2hex(random_bytes(8));
mkdir($root . '/conf', 0700, true);
$fixture = $root . '/conf/config.xml';
$program = $root . '/manifest.php';
$gate = $root . '/gate';
try {
    $source = file_get_contents($hook);
    manifest_check(preg_match('/php <<\x27PHP\x27\n(.*?)\nPHP\n\}/s', $source, $match) === 1, 'Unable to find the shipped embedded PHP.');
    $php = $match[1];
    $count = 0;
    $php = str_replace("file_get_contents(\$settings->application->configDir . '/config.xml')",
                       "file_get_contents(getenv('KAZUHA_NATIVE_XML'))", $php, $count);
    manifest_check($count === 1, 'The fixture must redirect exactly one fresh XML reader.');
    $php = str_replace('$config->save();', '$config->save(null, false);', $php, $count);
    manifest_check($count === 1, 'The fixture must disable config-event backups only on the native save.');
    $prefix = <<<'PHP'
require_once('script/load_phalcon.php');
$private = OPNsense\Core\Config::getInstance();
$handle = new ReflectionProperty($private, 'config_file_handle');
fclose($handle->getValue($private));
$handle->setValue($private, fopen(getenv('KAZUHA_NATIVE_XML'), 'r+'));
(new ReflectionProperty($private, 'config_file'))->setValue($private, getenv('KAZUHA_NATIVE_XML'));
(new ReflectionProperty($private, 'statusIsLocked'))->setValue($private, false);
$private->lock();
$private->unlock();
$deadline = microtime(true) + 10;
while (!is_file(getenv('KAZUHA_NATIVE_GATE'))) {
    if (microtime(true) > $deadline) { exit(1); }
    usleep(1000);
}
PHP;
    $php = preg_replace('/^<\?php\n/', "<?php\n" . $prefix . "\n", $php, 1);
    $peer = <<<'PHP'
    if ((getenv('KAZUHA_NATIVE_PEER') ?: '') !== '') {
        $config = OPNsense\Core\Config::getInstance();
        try {
            backup_lock_current($config);
            $xml = $config->object();
            if (!isset($xml->OPNsense)) { $xml->addChild('OPNsense'); }
            $name = getenv('KAZUHA_NATIVE_PEER');
            $xml->OPNsense->addChild($name)->addChild('archive', 'SENTINEL_OTHER_BACKUP');
            $config->save(null, false);
        } finally { $config->unlock(); }
        exit(0);
    }
    exit(kazuha_manifest_shim());
PHP;
    $php = str_replace('    exit(kazuha_manifest_shim());', $peer, $php, $count);
    manifest_check($count === 1, 'Unable to select the isolated peer writer.');
    file_put_contents($program, $php);
    chmod($program, 0600);
    $original = '<opnsense><system><firmware><plugins>preserve</plugins></firmware></system>' .
                '<unknown attr="retain"><private>SENTINEL_PRIVATE_XML</private><nested/></unknown>' .
                '<OPNsense><Existing><archive>SENTINEL_EXISTING_BACKUP</archive></Existing>' .
                '<KazuhaRepo><backup extra="retain"><future><value>retain</value></future></backup></KazuhaRepo></OPNsense></opnsense>';
    file_put_contents($fixture, $original);
    chmod($fixture, 0600);
    touch($gate);
    manifest_check(trim(manifest_finish(manifest_worker($program, $fixture, $gate))) === 'changed', 'First native write must change the manifest.');
    $xml = simplexml_load_file($fixture);
    manifest_check((string)$xml->system->firmware->plugins === 'preserve' &&
        (string)$xml->unknown['attr'] === 'retain' && isset($xml->unknown->nested) &&
        (string)$xml->OPNsense->KazuhaRepo->backup['extra'] === 'retain' &&
        (string)$xml->OPNsense->KazuhaRepo->backup->future->value === 'retain', 'Native write replaced unknown or firmware fields.');
    $saved = file_get_contents($fixture);
    manifest_check(trim(manifest_finish(manifest_worker($program, $fixture, $gate))) === 'unchanged', 'Identical native write must report unchanged.');
    manifest_check(file_get_contents($fixture) === $saved, 'Unchanged native write rewrote config.xml.');

    file_put_contents($fixture, $original);
    unlink($gate);
    $workers = [];
    for ($index = 0; $index < 8; $index++) {
        $workers[] = manifest_worker($program, $fixture, $gate);
        $workers[] = manifest_worker($program, $fixture, $gate, 'NativePeer' . $index);
    }
    usleep(100000);
    touch($gate);
    foreach ($workers as $worker) { manifest_finish($worker); }
    $xml = simplexml_load_file($fixture);
    for ($index = 0; $index < 8; $index++) {
        $name = 'NativePeer' . $index;
        manifest_check((string)$xml->OPNsense->$name->archive === 'SENTINEL_OTHER_BACKUP', 'A concurrent plugin backup was lost.');
    }
    manifest_check((string)$xml->OPNsense->KazuhaRepo->backup->plugins === "os-kazuha-repo 1.0.0\nos-mihomo 1.2.0" &&
        (string)$xml->OPNsense->Existing->archive === 'SENTINEL_EXISTING_BACKUP' &&
        (string)$xml->unknown->private === 'SENTINEL_PRIVATE_XML', 'Concurrent native writers lost the manifest or existing private state.');
    echo "Native repository manifest preserves unknown fields, unchanged writes and all 8 concurrent plugin backups.\n";
} finally { manifest_remove($root); }
