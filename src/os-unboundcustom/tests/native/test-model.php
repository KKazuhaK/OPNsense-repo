<?php
/* Load the actual model and Core writer only against a private XML fixture. */
function model_check(bool $condition, string $message): void
{
    if (!$condition) { throw new RuntimeException($message); }
}
$package = $argv[1] ?? dirname(__DIR__, 2);
$loader = '/usr/local/opnsense/mvc/app/config/loader.php';
if (!is_file($loader)) {
    fwrite(STDERR, "Requires the native OPNsense Core and field types.\n");
    exit(77);
}
require_once($loader);
require_once('/usr/local/etc/inc/util.inc');
require_once('/usr/local/etc/inc/config.inc');
require_once($package . '/src/opnsense/mvc/app/models/OPNsense/Unboundcustom/General.php');
$directory = sys_get_temp_dir() . '/unboundcustom-native-model-' . bin2hex(random_bytes(8));
mkdir($directory, 0700);
$fixture = $directory . '/config.xml';
$directives = "# 中文 directives\r\nserver:\r\n  verbosity: 2\r\n  private-domain: \"example.invalid\"\r\n";
$document = new DOMDocument();
$document->loadXML('<opnsense><system><hostname>private-fixture</hostname></system>' .
    '<unknown attr="retain"><nested>SENTINEL_UNKNOWN</nested></unknown><OPNsense>' .
    '<Other><backup><archive>SENTINEL_OTHER_BACKUP</archive></backup></Other>' .
    '<unboundcustom><general version="1.0.0"><enabled>0</enabled><customoptions/></general></unboundcustom>' .
    '</OPNsense></opnsense>');
$document->getElementsByTagName('customoptions')->item(0)->appendChild($document->createTextNode($directives));
file_put_contents($fixture, $document->saveXML());
$config = \OPNsense\Core\Config::getInstance();
$handle = new ReflectionProperty($config, 'config_file_handle');
fclose($handle->getValue($config));
$handle->setValue($config, fopen($fixture, 'r+'));
(new ReflectionProperty($config, 'config_file'))->setValue($config, $fixture);
(new ReflectionProperty($config, 'statusIsLocked'))->setValue($config, false);
try {
    $config->lock();
    $config->lock(false);
    $model = new \OPNsense\Unboundcustom\General();
    model_check(count($model->performValidation(true)) === 0, 'Valid disabled native settings failed validation.');
    model_check((string)$model->enabled === '0' && (string)$model->customoptions === $directives,
                'The actual model replaced disabled state or altered directive bytes.');
    $model->enabled = '1';
    $model->serializeToConfig(true);
    $config->save(null, false);
    $config->unlock();
    $backup = $directory . '/native-download.xml';
    file_put_contents($backup, file_get_contents($fixture));
    file_put_contents($fixture, file_get_contents($backup));
    $config->lock();
    $config->lock(false);
    $restored = new \OPNsense\Unboundcustom\General();
    model_check((string)$restored->enabled === '1' && (string)$restored->customoptions === $directives,
                'The normal native XML roundtrip changed enabled state or CRLF/Unicode directives.');
    $restored->enabled = '0';
    $restored->serializeToConfig(true);
    $config->save(null, false);
    $config->unlock();
    $xml = simplexml_load_file($fixture);
    model_check((string)$xml->OPNsense->unboundcustom->general->enabled === '0', 'Disabling settings did not persist in native XML.');
    model_check((string)$xml->unknown['attr'] === 'retain' && (string)$xml->unknown->nested === 'SENTINEL_UNKNOWN' &&
                (string)$xml->OPNsense->Other->backup->archive === 'SENTINEL_OTHER_BACKUP',
                'A normal native model save lost unknown or unrelated plugin fields.');
    echo "Native Unboundcustom model passed: actual field validation, false/true state and private Core XML roundtrip retaining exact CRLF/Unicode directives and unrelated fields.\n";
} finally {
    $config->unlock();
    foreach (glob($directory . '/*') as $file) { unlink($file); }
    rmdir($directory);
}
