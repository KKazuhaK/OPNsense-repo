<?php
/* Run the real transport against private XML, model-name and locking stubs. */
$shim = $argv[1] ?? dirname(__DIR__, 2) . '/src/usr/local/opnsense/scripts/frp/config_mirror.php';
$model = $argv[2] ?? dirname(__DIR__, 2) . '/src/usr/local/opnsense/mvc/app/models/OPNsense/Frp/Backup.xml';
$fixture = sys_get_temp_dir() . '/frp-backup-fields-' . bin2hex(random_bytes(8));
mkdir($fixture . '/script', 0700, true);
$bootstrap = <<<'BOOT'
<?php
namespace OPNsense\Core {
    class AppConfig {
        public object $application;
        public function __construct() { $this->application = (object)['configDir' => getenv('FRP_FIELD_ROOT')]; }
    }
    class Config {
        private static ?self $instance = null;
        private $handle;
        private \SimpleXMLElement $xml;
        public string $mode = '';
        public static function getInstance(): self { return self::$instance ??= new self(); }
        private function __construct() {
            $this->handle = fopen(getenv('FRP_FIELD_ROOT') . '/config.xml', 'r+');
            $initial = getenv('FRP_FIELD_STALE') ?: getenv('FRP_FIELD_ROOT') . '/config.xml';
            $this->xml = simplexml_load_file($initial);
        }
        private function event(string $event): void {
            file_put_contents(getenv('FRP_FIELD_ROOT') . '/events', getmypid() . ':' . $event . "\n", FILE_APPEND | LOCK_EX);
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
            $probe = fopen(getenv('FRP_FIELD_ROOT') . '/config.xml', 'r+');
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
namespace OPNsense\Frp {
    class Field {
        public function isContainer(): bool { return false; }
    }
    class Backup {
        private array $fields = [];
        public function __construct() {
            if (\OPNsense\Core\Config::getInstance()->mode !== 'EX') {
                throw new \RuntimeException('The model read occurred before exclusive lock.');
            }
            foreach (simplexml_load_file(getenv('FRP_FIELD_MODEL'))->items->children() as $name => $item) {
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
$environment = array_merge(getenv(), ['FRP_FIELD_ROOT' => $fixture, 'FRP_FIELD_MODEL' => $model]);

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
function field_token(array $stored): string
{
    ksort($stored, SORT_STRING);
    $encoded = json_encode((object)$stored, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    return hash('sha256', str_replace("\x7f", '\u007f', $encoded));
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

    $payload = ['frps_toml' => "# 服务端\r\n[auth]\r\ntoken = \"private-fixture\"\r\n",
        'frpc_toml' => "# 客户端\r\n[auth]\r\ntoken = \"private-client-fixture\"\r\n",
        'frps_enable' => false, 'frpc_enable' => true];
    $expected = array_merge($payload, ['frps_enable' => '0', 'frpc_enable' => '1']);
    field_check(field_ok('export', $payload) === ['changed' => true], 'The first field export did not change XML.');
    field_check(field_ok('import') === $expected, 'Credentials, CRLF, Unicode or enable flags changed.');
    $saves = field_saves();
    field_check(field_ok('export', $payload) === ['changed' => false] && field_saves() === $saves,
        'Identical field export created a revision.');

    field_seed('<opnsense><OPNsense><Other><sentinel>untouched</sentinel></Other><Frp custom="keep"><backup version="next"><frps_toml>old</frps_toml><frps_enable/><future_scalar>future</future_scalar><future_tree><keep>nested</keep></future_tree></backup></Frp></OPNsense></opnsense>');
    field_check(field_ok('import') === ['frps_toml' => 'old', 'frps_enable' => '', 'future_scalar' => 'future'],
        'Partial XML manufactured or omitted actual scalar fields.');
    field_check(field_ok('export', ['frps_toml' => 'new', 'unknown_new' => 'skip'])['changed'], 'A known partial field did not update.');
    field_check(field_ok('import') === ['frps_toml' => 'new', 'frps_enable' => '', 'future_scalar' => 'future'],
        'A partial export changed missing or unknown fields.');
    $xml = simplexml_load_file($fixture . '/config.xml');
    field_check((string)$xml->OPNsense->Frp['custom'] === 'keep' &&
        (string)$xml->OPNsense->Frp->backup['version'] === 'next' &&
        (string)$xml->OPNsense->Frp->backup->future_tree->keep === 'nested' &&
        (string)$xml->OPNsense->Other->sentinel === 'untouched', 'Unknown XML or attributes were lost.');

    $beforeCas = file_get_contents($fixture . '/config.xml');
    $vector = ['checksum' => 'legacy-checksum', 'frps_enable' => '0',
        'frps_toml' => "slash / DEL\x7f CRLF\r\n中文 🔒", 'future_scalar' => "future / 🔒\x7f"];
    $document = new DOMDocument();
    $document->loadXML('<opnsense><OPNsense><Frp><backup/></Frp></OPNsense></opnsense>');
    $section = $document->getElementsByTagName('backup')->item(0);
    foreach ($vector as $name => $value) {
        $node = $section->appendChild($document->createElement($name));
        $node->appendChild($document->createTextNode($value));
    }
    field_seed($document->saveXML());
    field_check(field_ok('import') === $vector, 'The CAS parity vector changed in XML.');
    /* This token is generated independently by Python ensure_ascii=True. */
    $vectorToken = 'a4002d355d89f6109903e07c35e4253832e7fffc126d3137daded8f8dcdb92ec';
    field_check(field_token($vector) === $vectorToken, 'PHP and Python disagree on the raw snapshot token.');
    field_check(field_ok('export', ['_expected' => $vectorToken, 'frps_toml' => 'accepted'])['changed'],
        'A matching DEL/emoji/slash/CRLF/Unicode snapshot was refused.');
    $imported = field_ok('import');
    field_check(!array_key_exists('_expected', $imported), 'Transport metadata was written into native XML.');
    $expectedToken = field_token($imported);
    $document = new DOMDocument();
    $document->load($fixture . '/config.xml');
    $document->getElementsByTagName('frps_toml')->item(0)->nodeValue = 'newly restored private-fixture';
    field_seed($document->saveXML());
    $restored = file_get_contents($fixture . '/config.xml');
    $saves = field_saves();
    foreach ([$expectedToken, str_repeat('0', 64), 123, null, false, 'private-fixture'] as $badToken) {
        [$status, $stdout, $stderr] = field_run('export', json_encode([
            '_expected' => $badToken, 'frps_toml' => 'old runtime private-fixture',
            'frpc_toml' => 'must not manufacture a new node'], JSON_THROW_ON_ERROR));
        field_check($status !== 0 && $stdout === '' && !str_contains($stderr, 'private-fixture'),
            'A stale or malformed snapshot token succeeded or exposed a value.');
        field_check(field_saves() === $saves && file_get_contents($fixture . '/config.xml') === $restored,
            'A concurrent native restore was overwritten before the CAS check.');
    }
    field_seed('<opnsense><OPNsense/></opnsense>');
    field_check(field_ok('export', ['_expected' => hash('sha256', '{}'), 'frpc_enable' => false])['changed'],
        'The empty native field map was not encoded as an object.');
    field_seed($beforeCas);

    $current = file_get_contents($fixture . '/config.xml');
    foreach (['[]', 'null', '{bad', '{"frps_toml":{"private-fixture":"nested"}}',
        '{"frps_toml":null}', '{"frps_toml":"private-fixture\\u000b"}', str_repeat(' ', 4194305)] as $bad) {
        [$status, $stdout, $stderr] = field_run('export', $bad);
        field_check($status !== 0 && $stdout === '' && !str_contains($stderr, 'private-fixture'), 'Invalid input succeeded or exposed a value.');
        field_check(file_get_contents($fixture . '/config.xml') === $current, 'Invalid input changed XML.');
    }

    /* Both children start with stale XML; the lock function must refresh it
       while EX so neither independent update replaces the other's field. */
    file_put_contents($fixture . '/stale.xml', '<opnsense><OPNsense><Frp><backup><frps_toml>stale</frps_toml></backup></Frp></OPNsense></opnsense>');
    $extra = ['FRP_FIELD_STALE' => $fixture . '/stale.xml'];
    $one = field_start('export', json_encode(['frps_toml' => 'fresh'], JSON_THROW_ON_ERROR), $extra);
    $two = field_start('export', json_encode(['frps_enable' => '1'], JSON_THROW_ON_ERROR), $extra);
    foreach ([$one, $two] as $running) {
        [$status, $stdout, $stderr] = field_finish($running);
        field_check($status === 0 && $stderr === '', 'A concurrent field export failed.');
    }
    $stored = field_ok('import');
    field_check($stored['frps_toml'] === 'fresh' && $stored['frps_enable'] === '1' &&
        $stored['future_scalar'] === 'future', 'Stale or concurrent exports lost fields.');
    $xml = simplexml_load_file($fixture . '/config.xml');
    field_check((string)$xml->OPNsense->Other->sentinel === 'untouched' &&
        (string)$xml->OPNsense->Frp->backup->future_tree->keep === 'nested', 'Fresh DOM reload lost unrelated XML.');
    $events = file_get_contents($fixture . '/events');
    field_check(substr_count($events, ':lock-reload') === substr_count($events, ':lock-exclusive') &&
        substr_count($events, ':unlock') === substr_count($events, ':lock-exclusive'), 'The native lock protocol was not paired.');
    echo "Frp backup field contract passed: raw partial XML, exact documents, safe input, idempotence, fresh EX locking, snapshot CAS parity and concurrent preservation.\n";
} finally {
    field_remove($fixture);
}
