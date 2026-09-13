<?php
/* Use genuine CoreConfig with a private configDir and disabled event logging. */
$shim = $argv[1] ?? dirname(__DIR__, 2) . '/config_backup.php';
$native = '/usr/local/opnsense/mvc/script/load_phalcon.php';
if (!is_file($native)) {
    throw new RuntimeException('This contract requires native OPNsense PHP.');
}
$fixture = sys_get_temp_dir() . '/opnsense-backup-cas-' . bin2hex(random_bytes(8));
mkdir($fixture . '/script', 0700, true);
$bootstrap = <<<'BOOT'
<?php
namespace OPNsense\Core {
    /* Suppress audit/config-event dispatch; persistence and locks remain real. */
    function openlog(...$args): bool { return true; }
    function syslog(...$args): bool { return true; }
    class Syslog {
        public function __construct(...$args) {}
        public function __call($name, $args) {}
    }
}
namespace {
    require_once('/usr/local/opnsense/mvc/script/load_phalcon.php');
    $settings = new \OPNsense\Core\AppConfig();
    if (!$settings->update('application.configDir', getenv('BACKUP_CAS_ROOT'))) {
        throw new RuntimeException('The private configDir could not be selected.');
    }
    register_shutdown_function(function (): void {
        $config = \OPNsense\Core\Config::getInstance();
        $property = new ReflectionProperty($config, 'statusIsLocked');
        file_put_contents(getenv('BACKUP_CAS_ROOT') . '/lock-' . getmypid() . '.json',
            json_encode(['unlocked' => !$property->getValue($config)], JSON_THROW_ON_ERROR));
    });
}
BOOT;
file_put_contents($fixture . '/script/load_phalcon.php', $bootstrap);
$emptyHash = '44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a';
$partialHash = '6b0352a535a067aac0c4381fb79eb8bcf74e5dacab231858992baf397c95b7c6';
$hashA = 'f62ea9e42932077ed5947041812ef2f26881bb6051382d2cf2d0d000a310b3d8';
$hashB = '229450db82e2ab163a01df46430663a1a671220f42e8c86f287f07cf18474077';
/* Golden hashes above and below were computed with Python ensure_ascii=True,
   sort_keys=True and separators=(',', ':'); no second archive is transported. */
$vectorHash = '6a88b0ef3f853f26a521eabbf71d17bf9840283500af540782bd2d55c8f8dae4';
$a = ['schema' => '1', 'archive' => 'YQ==', 'checksum' => str_repeat('1', 64)];
$b = ['schema' => '1', 'archive' => 'Yg==', 'checksum' => str_repeat('2', 64)];

function cas_check(bool $condition, string $message): void
{
    if (!$condition) { throw new RuntimeException($message); }
}
function cas_run(string $action, ?array $payload = null, string $module = 'Staticarp'): array
{
    global $shim, $fixture;
    $environment = array_merge(getenv(), ['BACKUP_CAS_ROOT' => $fixture]);
    $process = proc_open([PHP_BINARY, '-d', 'include_path=' . $fixture, $shim, $module, $action],
        [['pipe', 'r'], ['pipe', 'w'], ['pipe', 'w']], $pipes, null, $environment);
    fwrite($pipes[0], $payload === null ? '' : json_encode($payload, JSON_THROW_ON_ERROR));
    fclose($pipes[0]);
    $stdout = stream_get_contents($pipes[1]); $stderr = stream_get_contents($pipes[2]);
    fclose($pipes[1]); fclose($pipes[2]);
    return [proc_close($process), $stdout, $stderr];
}
function cas_ok(string $action, ?array $payload = null, string $module = 'Staticarp'): array
{
    [$status, $stdout, $stderr] = cas_run($action, $payload, $module);
    cas_check($status === 0 && $stderr === '', 'Native CAS transport failed.');
    return json_decode($stdout, true, 8, JSON_THROW_ON_ERROR);
}
function cas_rejected(array $payload, string $module = 'Staticarp'): void
{
    global $fixture;
    $before = file_get_contents($fixture . '/config.xml');
    $revisions = cas_revisions();
    [$status, $stdout, $stderr] = cas_run('export', $payload, $module);
    cas_check($status === 1 && $stdout === '' && $stderr === "The native configuration backup operation failed.\n",
        'A stale or invalid export succeeded or exposed its payload.');
    cas_check(file_get_contents($fixture . '/config.xml') === $before && cas_revisions() === $revisions,
        'A rejected export modified XML or created a revision.');
}
function cas_revisions(): int
{
    global $fixture;
    return count(glob($fixture . '/backup/config-*.xml'));
}
function cas_remove(string $directory): void
{
    foreach (new DirectoryIterator($directory) as $item) {
        if ($item->isDot()) { continue; }
        $item->isDir() ? cas_remove($item->getPathname()) : unlink($item->getPathname());
    }
    rmdir($directory);
}

try {
    file_put_contents($fixture . '/config.xml', '<opnsense><OPNsense><Other custom="keep"><sentinel>untouched</sentinel></Other></OPNsense></opnsense>');
    [$status, $stdout] = cas_run('import');
    cas_check($status === 0 && $stdout === "{}\n" && cas_revisions() === 0, 'An absent import manufactured fields.');
    cas_rejected($a + ['_expected' => str_repeat('0', 64)], 'Lucky');
    $xml = simplexml_load_file($fixture . '/config.xml');
    cas_check(!isset($xml->OPNsense->Lucky), 'Stale CAS created a module before rejecting.');
    cas_check(cas_ok('export', $a + ['_expected' => $emptyHash]) === ['changed' => true], 'CAS could not create an absent snapshot.');
    cas_check(cas_ok('import') === $a, 'The reserved digest entered the stored fields.');
    $revisions = cas_revisions();
    cas_check(cas_ok('export', $a + ['_expected' => $hashA]) === ['changed' => false] && cas_revisions() === $revisions,
        'An identical CAS export created a revision.');

    /* Import A, restore B, then attempt the old export with A's expected hash. */
    $imported = cas_ok('import');
    cas_check($imported === $a, 'The stale-import fixture was not captured.');
    cas_check(cas_ok('export', $b + ['_expected' => $hashA])['changed'], 'The new restore did not reach native XML.');
    cas_rejected($a + ['_expected' => $hashA]);
    cas_check(cas_ok('import') === $b, 'A stale export replaced the restored snapshot.');
    cas_check(cas_ok('export', $b + ['_expected' => $hashB]) === ['changed' => false], 'The current digest was rejected.');
    cas_rejected($a + ['_expected' => null]);
    cas_rejected($a + ['_expected' => 'private-invalid-digest']);
    $oversize = $a;
    $oversize['archive'] = str_repeat('A', 1398108);
    cas_rejected($oversize);

    /* Old literal fixture clients remain supported when _expected is omitted. */
    cas_check(cas_ok('export', $a)['changed'], 'The optional legacy export was refused.');
    $xml = simplexml_load_file($fixture . '/config.xml');
    cas_check(!isset($xml->OPNsense->Staticarp->backup->_expected) &&
        (string)$xml->OPNsense->Other['custom'] === 'keep' &&
        (string)$xml->OPNsense->Other->sentinel === 'untouched', 'CAS metadata or updates changed unrelated XML.');

    $vector = ['schema' => '1', 'archive' => "雪/🙂\x7f\r\n", 'checksum' => str_repeat('a', 64)];
    cas_ok('export', $vector);
    cas_check(cas_ok('import') === $vector, 'The canonical vector lost Unicode, DEL or CRLF.');
    cas_check(cas_ok('export', $vector + ['_expected' => $vectorHash]) === ['changed' => false],
        'The PHP digest differs from the Python Unicode/emoji/slash/DEL/CRLF golden hash.');

    /* A present empty archive hashes differently from an absent {} map. */
    file_put_contents($fixture . '/config.xml', '<opnsense><OPNsense><Staticarp><backup><archive/></backup></Staticarp></OPNsense></opnsense>');
    cas_check(cas_ok('import') === ['archive' => ''], 'A partial raw field was hidden or defaulted.');
    cas_rejected($a + ['_expected' => $emptyHash]);
    cas_check(cas_ok('export', $a + ['_expected' => $partialHash])['changed'], 'The actual partial-map digest was refused.');
    foreach (glob($fixture . '/lock-*.json') as $path) {
        cas_check(json_decode(file_get_contents($path), true)['unlocked'], 'An export exited without releasing the native exclusive lock.');
    }
    echo "Native backup CAS passed: stale restore protection, no rejected revisions/nodes, optional legacy export, exact golden hashes, partial raw fields and explicit unlock.\n";
} finally {
    cas_remove($fixture);
}
