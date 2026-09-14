<?php
/* Run the real transport against private XML, model-name and locking stubs. */
$shim = $argv[1] ?? dirname(__DIR__, 2) . '/src/usr/local/opnsense/scripts/mihomo/config_mirror.php';
$model = $argv[2] ?? dirname(__DIR__, 2) . '/src/usr/local/opnsense/mvc/app/models/OPNsense/Mihomo/Backup.xml';
$fixture = sys_get_temp_dir() . '/mihomo-backup-fields-' . bin2hex(random_bytes(8));
mkdir($fixture . '/script', 0700, true);
$bootstrap = <<<'BOOT'
<?php
namespace OPNsense\Core {
    class AppConfig {
        public object $application;
        public function __construct() { $this->application = (object)['configDir' => getenv('M_FIELD_ROOT')]; }
    }
    class Config {
        private static ?self $instance = null;
        private $handle;
        private \SimpleXMLElement $xml;
        public string $mode = '';
        public static function getInstance(): self { return self::$instance ??= new self(); }
        private function __construct() {
            $this->handle = fopen(getenv('M_FIELD_ROOT') . '/config.xml', 'r+');
            $initial = getenv('M_FIELD_STALE') ?: getenv('M_FIELD_ROOT') . '/config.xml';
            $this->xml = simplexml_load_file($initial);
        }
        private function event(string $event): void {
            file_put_contents(getenv('M_FIELD_ROOT') . '/events', getmypid() . ':' . $event . "\n", FILE_APPEND | LOCK_EX);
        }
        public function lock(bool $reload = true): void {
            flock($this->handle, LOCK_EX);
            $this->mode = 'EX';
            $this->event($reload ? 'lock-reload' : 'lock-exclusive');
            if ($reload) {
                /* Reproduce the genuine Core reader's lock downgrade. */
                flock($this->handle, LOCK_SH);
                $this->mode = 'SH';
            }
        }
        public function object(): \SimpleXMLElement { return $this->xml; }
        public function save($revision = null): void {
            if ($this->mode !== 'EX') { throw new \RuntimeException('Save without exclusive lock.'); }
            $probe = fopen(getenv('M_FIELD_ROOT') . '/config.xml', 'r+');
            if (flock($probe, LOCK_EX | LOCK_NB)) { throw new \RuntimeException('Exclusive lock was lost.'); }
            fclose($probe);
            ftruncate($this->handle, 0);
            rewind($this->handle);
            fwrite($this->handle, $this->xml->asXML());
            fflush($this->handle);
            $this->event('save');
        }
        public function unlock(): void { $this->event('unlock'); flock($this->handle, LOCK_UN); $this->mode = ''; }
    }
}
namespace OPNsense\Mihomo {
    class Field {
        public function isContainer(): bool { return false; }
    }
    class Backup {
        private array $fields = [];
        public function __construct() {
            if (\OPNsense\Core\Config::getInstance()->mode !== 'EX') {
                throw new \RuntimeException('The model read occurred before exclusive lock.');
            }
            foreach (simplexml_load_file(getenv('M_FIELD_MODEL'))->items->children() as $name => $item) {
                $this->fields[(string)$name] = new Field();
            }
        }
        public function getNodeByReference(string $field): ?Field { return $this->fields[$field] ?? null; }
    }
}
BOOT;
file_put_contents($fixture . '/script/load_phalcon.php', $bootstrap);
file_put_contents($fixture . '/util.inc', '<?php function make_config_revision_entry($text) { return []; }');
file_put_contents($fixture . '/config.inc', '<?php');
$environment = array_merge(getenv(), ['M_FIELD_ROOT' => $fixture, 'M_FIELD_MODEL' => $model]);

function field_check(bool $condition, string $message): void
{
    if (!$condition) { throw new RuntimeException($message); }
}
function field_start(string $verb, string $payload = '', array $extra = []): array
{
    global $shim, $fixture, $environment;
    $process = proc_open([PHP_BINARY, '-d', 'include_path=' . $fixture, $shim, $verb],
        [['pipe', 'r'], ['pipe', 'w'], ['pipe', 'w']], $pipes, null, array_merge($environment, $extra));
    fwrite($pipes[0], $payload);
    fclose($pipes[0]);
    return [$process, $pipes];
}
function field_finish(array $running): array
{
    [$process, $pipes] = $running;
    $stdout = stream_get_contents($pipes[1]);
    $stderr = stream_get_contents($pipes[2]);
    fclose($pipes[1]); fclose($pipes[2]);
    return [proc_close($process), $stdout, $stderr];
}
function field_run(string $verb, string $payload = '', array $extra = []): array
{
    return field_finish(field_start($verb, $payload, $extra));
}
function field_ok(string $verb, $payload = null, array $extra = [])
{
    [$status, $stdout, $stderr] = field_run($verb, $payload === null ? '' : json_encode($payload, JSON_THROW_ON_ERROR), $extra);
    field_check($status === 0 && $stderr === '', 'The isolated field transport failed.');
    return json_decode($stdout, true, 32, JSON_THROW_ON_ERROR);
}
function field_seed(string $xml): void
{
    global $fixture;
    file_put_contents($fixture . '/config.xml', $xml);
}
function field_saves(): int
{
    global $fixture;
    return is_file($fixture . '/events') ? substr_count(file_get_contents($fixture . '/events'), ':save') : 0;
}
function field_remove(string $directory): void
{
    foreach (new DirectoryIterator($directory) as $item) {
        if ($item->isDot()) { continue; }
        $item->isDir() ? field_remove($item->getPathname()) : unlink($item->getPathname());
    }
    rmdir($directory);
}

try {
    field_seed('<opnsense><OPNsense><Other><sentinel>untouched</sentinel></Other></OPNsense></opnsense>');
    field_check(field_ok('import') === [], 'An absent backup manufactured defaults.');
    field_check(field_ok('export', (object)[]) === ['changed' => false], 'Empty export changed an absent backup.');
    field_check(field_saves() === 0, 'Read/empty operations saved XML.');

    $schema = simplexml_load_file($model);
    field_check((string)$schema->items->subscription_snapshot['type'] === 'Base64Field', 'The snapshot field is no longer opaque Base64 text.');
    $snapshot = base64_encode(gzencode("proxies: []\r\n# 服务\n", 9));
    $payload = ['subscription_url' => 'https://fixture.invalid/sub?token=private-fixture',
        'secret' => 'private<&>"fixture', 'merge_yaml' => "# 中文\r\nsecret: private-fixture\r\n",
        'subscription_snapshot' => $snapshot, 'device_list' => '["192.0.2.7/32","2001:db8::1/128"]',
        'proxy_selections' => '{"节点组":"香港"}', 'dns_state' => '{"owned":["dns.1"],"revision":1}',
        'tun_state' => '{"interface":"opt9","if":"tun_mihomo"}', 'checksum' => str_repeat('a', 64)];
    field_check(field_ok('export', $payload) === ['changed' => true], 'The first field export did not change XML.');
    field_check(field_ok('import') === $payload, 'Credentials, CRLF, Unicode, JSON or Base64 text changed.');
    $saves = field_saves();
    field_check(field_ok('export', $payload) === ['changed' => false] && field_saves() === $saves,
        'Identical field export created a revision.');

    field_seed('<opnsense><OPNsense><Other><sentinel>untouched</sentinel></Other><Mihomo custom="keep"><backup version="next"><secret>old</secret><device/><future_scalar>future</future_scalar><future_tree><keep>nested</keep></future_tree></backup></Mihomo></OPNsense></opnsense>');
    field_check(field_ok('import') === ['secret' => 'old', 'device' => '', 'future_scalar' => 'future'],
        'Partial XML manufactured or omitted actual scalar fields.');
    field_check(field_ok('export', ['secret' => 'new', 'unknown_new' => 'skip'])['changed'], 'A known partial field did not update.');
    field_check(field_ok('import') === ['secret' => 'new', 'device' => '', 'future_scalar' => 'future'],
        'A partial export changed missing or unknown fields.');
    $xml = simplexml_load_file($fixture . '/config.xml');
    field_check((string)$xml->OPNsense->Mihomo['custom'] === 'keep' &&
        (string)$xml->OPNsense->Mihomo->backup['version'] === 'next' &&
        (string)$xml->OPNsense->Mihomo->backup->future_tree->keep === 'nested' &&
        (string)$xml->OPNsense->Other->sentinel === 'untouched', 'Unknown XML or attributes were lost.');

    $current = file_get_contents($fixture . '/config.xml');
    foreach (['[]', 'null', '{bad', '{"secret":{"private-fixture":"nested"}}',
        '{"secret":null}', '{"secret":"private-fixture\\u000b"}', str_repeat(' ', 25165825)] as $bad) {
        [$status, $stdout, $stderr] = field_run('export', $bad);
        field_check($status !== 0 && $stdout === '' && !str_contains($stderr, 'private-fixture'), 'Invalid input succeeded or exposed a value.');
        field_check(file_get_contents($fixture . '/config.xml') === $current, 'Invalid input changed XML.');
    }

    /* Both children start with stale XML; the lock function must refresh it
       while EX so neither independent update replaces the other's field. */
    file_put_contents($fixture . '/stale.xml', '<opnsense><OPNsense><Mihomo><backup><secret>stale</secret></backup></Mihomo></OPNsense></opnsense>');
    $extra = ['M_FIELD_STALE' => $fixture . '/stale.xml'];
    $one = field_start('export', json_encode(['secret' => 'fresh'], JSON_THROW_ON_ERROR), $extra);
    $two = field_start('export', json_encode(['device' => 'fresh-device'], JSON_THROW_ON_ERROR), $extra);
    foreach ([$one, $two] as $running) {
        [$status, $stdout, $stderr] = field_finish($running);
        field_check($status === 0 && $stderr === '', 'A concurrent field export failed.');
    }
    $stored = field_ok('import');
    field_check($stored['secret'] === 'fresh' && $stored['device'] === 'fresh-device' &&
        $stored['future_scalar'] === 'future', 'Stale or concurrent exports lost fields.');
    $xml = simplexml_load_file($fixture . '/config.xml');
    field_check((string)$xml->OPNsense->Other->sentinel === 'untouched' &&
        (string)$xml->OPNsense->Mihomo->backup->future_tree->keep === 'nested', 'Fresh DOM reload lost unrelated XML.');
    // Export rejects a restore that interleaves after the caller's import.
    $imported = field_ok('import');
    ksort($imported, SORT_STRING);
    $revision = hash('sha256', str_replace("\x7f", '\u007f',
        json_encode((object)$imported, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR)));
    field_ok('export', ['secret' => 'restored-between-import-and-export']);
    $current = file_get_contents($fixture . '/config.xml');
    [$status, $stdout, $stderr] = field_run('export', json_encode(['secret' => 'old-runtime', '_expected' => $revision]));
    field_check($status !== 0 && $stdout === '' && !str_contains($stderr, 'old-runtime'), 'Stale export succeeded or exposed a value.');
    field_check(file_get_contents($fixture . '/config.xml') === $current, 'Stale export overwrote restored fields.');
    $fresh = field_ok('import');
    ksort($fresh, SORT_STRING);
    $revision = hash('sha256', str_replace("\x7f", '\u007f',
        json_encode((object)$fresh, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR)));
    field_check(field_ok('export', ['device' => 'CAS-current-device', '_expected' => $revision])['changed'], 'Fresh export was rejected.');
    field_check(!array_key_exists('_expected', field_ok('import')), 'CAS metadata entered the XML snapshot.');
    field_seed('<opnsense><OPNsense><Mihomo><backup><secret>raw-中文/' . "\x7f" . '</secret><checksum>' . str_repeat('f', 64) . '</checksum></backup></Mihomo></OPNsense></opnsense>');
    field_check(field_ok('export', ['device' => 'python-canonical-token',
        '_expected' => '208a63f49e187cbcc15d5ca107663e00f748f1f18cfd8bbaea0ac3e0562a1492'])['changed'],
        'Native revision hashing disagreed with Python ensure_ascii for Unicode/slashes/DEL.');
    $events = file_get_contents($fixture . '/events');
    field_check(substr_count($events, ':lock-reload') === substr_count($events, ':lock-exclusive') &&
        substr_count($events, ':unlock') === substr_count($events, ':lock-exclusive'), 'The native lock protocol was not paired.');
    echo "Mihomo backup field contract passed: raw partial XML, exact opaque text, bounded secret-safe input, idempotence, fresh EX locking and concurrent preservation.\n";
} finally {
    field_remove($fixture);
}
