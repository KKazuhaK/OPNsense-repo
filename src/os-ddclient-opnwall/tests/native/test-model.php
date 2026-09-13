<?php
/* Use genuine Core and field types, while provider queries and XML are private. */
namespace OPNsense\Core {
    class Backend {
        public function configdRun(string $command): string {
            return str_contains($command, 'supported') ?
                '{"aliyun":"Aliyun DNS","tencentcloud":"Tencent Cloud DNS","custom":"Custom","powerdns":"PowerDNS"}' : '{}';
        }
    }
}
namespace {
    function model_check(bool $condition, string $message): void {
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
    $models = $package . '/src/usr/local/opnsense/mvc/app/models/';
    spl_autoload_register(static function ($name) use ($models): void {
        if (str_starts_with($name, 'OPNsense\\DynDNS\\')) {
            $file = $models . str_replace('\\', '/', $name) . '.php';
            if (is_file($file)) { require_once($file); }
        }
    }, true, true);
    $directory = sys_get_temp_dir() . '/ddclient-native-model-' . bin2hex(random_bytes(8));
    mkdir($directory, 0700);
    $fixture = $directory . '/config.xml';
    $uuid = '11111111-2222-4333-8444-555555555555';
    $credential = 'SENTINEL_PRIVATE_"\\&秘密';
    $document = new DOMDocument();
    $document->loadXML('<opnsense><system><hostname>private-fixture</hostname></system>' .
        '<unknown attr="retain"><nested>SENTINEL_UNKNOWN</nested></unknown><OPNsense>' .
        '<Other><backup><archive>SENTINEL_OTHER_BACKUP</archive></backup></Other>' .
        '<DynDNS version="1.5.1"><general><enabled>0</enabled><verbose>0</verbose><allowipv6>0</allowipv6>' .
        '<daemon_delay>120</daemon_delay><backend>opnsense</backend></general><accounts>' .
        '<account uuid="' . $uuid . '"><enabled>0</enabled><service>aliyun</service><protocol>dyndns2</protocol>' .
        '<username>fixture-user</username><password/><hostnames>router.example.invalid</hostnames>' .
        '<zone>example.invalid</zone><checkip>web_ipify-ipv4</checkip><checkip_timeout>10</checkip_timeout>' .
        '<force_ssl>1</force_ssl><ttl>300</ttl><description>fixture</description></account>' .
        '</accounts></DynDNS></OPNsense></opnsense>');
    $document->getElementsByTagName('password')->item(0)->appendChild($document->createTextNode($credential));
    file_put_contents($fixture, $document->saveXML());
    $config = \OPNsense\Core\Config::getInstance();
    $handle = new ReflectionProperty($config, 'config_file_handle');
    $originalHandle = $handle->getValue($config);
    fclose($originalHandle);
    $handle->setValue($config, fopen($fixture, 'r+'));
    (new ReflectionProperty($config, 'config_file'))->setValue($config, $fixture);
    (new ReflectionProperty($config, 'statusIsLocked'))->setValue($config, false);
    try {
        $config->lock();
        $config->lock(false);
        $model = new \OPNsense\DynDNS\DynDNS();
        model_check(count($model->performValidation(true)) === 0, 'A valid disabled account failed native model validation.');
        model_check((string)$model->general->enabled === '0', 'The disabled service state was replaced by a default.');
        $password = $model->getNodeByReference('accounts.account.' . $uuid . '.password');
        model_check((string)$password === '' && $password->getValue() === $credential,
                    'The actual update-only field leaked or lost its credential.');
        $password->setValue('');
        model_check($password->getValue() === $credential, 'A blank API credential cleared the stored password.');
        $account = $model->getNodeByReference('accounts.account.' . $uuid);
        $account->service = 'powerdns';
        model_check(count($model->performValidation(false)) > 0,
                    'Changing only the native provider field bypassed its required server URI.');
        $account->service = 'aliyun';
        $model->general->daemon_delay = '0';
        model_check(count($model->performValidation(true)) > 0, 'The native interval minimum was not enforced.');
        $model->general->daemon_delay = '120';
        $account->service = 'custom';
        $account->protocol = 'post';
        $account->server = '';
        model_check(count($model->performValidation(true)) > 0, 'A native custom HTTP account accepted a missing server URI.');
        $account->server = 'https://provider.invalid/update';
        model_check(count($model->performValidation(true)) === 0, 'A valid custom URI failed native model validation.');
        $account->description = 'new caption';
        $model->serializeToConfig(true);
        $config->save(null, false);
        $config->unlock();
        $download = file_get_contents($fixture);
        $backup = $directory . '/native-download.xml';
        file_put_contents($backup, $download);
        file_put_contents($fixture, file_get_contents($backup));
        $config->lock();
        $config->lock(false);
        $restored = new \OPNsense\DynDNS\DynDNS();
        model_check((string)$restored->general->enabled === '0' &&
            $restored->getNodeByReference('accounts.account.' . $uuid . '.password')->getValue() === $credential,
            'The native XML roundtrip changed disabled state or private credential bytes.');
        $xml = $config->object();
        model_check((string)$xml->unknown['attr'] === 'retain' && (string)$xml->unknown->nested === 'SENTINEL_UNKNOWN' &&
                    (string)$xml->OPNsense->Other->backup->archive === 'SENTINEL_OTHER_BACKUP',
                    'A normal native model save lost unknown or unrelated plugin fields.');
        echo "Native DynDNS model passed: actual validation, update-only credential retention/redaction, disabled state and private Core XML roundtrip preserving unrelated fields.\n";
    } finally {
        $config->unlock();
        foreach (glob($directory . '/*') as $file) { unlink($file); }
        rmdir($directory);
    }
}
