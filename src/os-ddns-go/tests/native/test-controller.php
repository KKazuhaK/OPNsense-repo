<?php
/* Execute the actual controllers against isolated request files and backend replies. */
namespace Tests\ServiceContract {
    class Files {
        public static string $root;
        public static array $created = [];
        public static function stage(string $prefix): string {
            $path = \tempnam(self::$root, $prefix);
            self::$created[] = $path;
            return $path;
        }
    }
}
namespace OPNsense\Lucky\Api {
    function tempnam($directory, $prefix) { return \Tests\ServiceContract\Files::stage($prefix); }
}
namespace OPNsense\Ddnsgo\Api {
    function tempnam($directory, $prefix) { return \Tests\ServiceContract\Files::stage($prefix); }
}
namespace OPNsense\Base {
    class ApiControllerBase {
        public $request;
        public bool $readOnly = false;
        public int $guards = 0;
        protected function throwReadOnly(): void {
            $this->guards++;
            if ($this->readOnly) { throw new \RuntimeException('readonly'); }
        }
    }
}
namespace OPNsense\Core {
    class Backend {
        public static array $calls = [];
        public static string $plain = 'OK';
        public static string $reply = '{"status":"ok"}';
        public static bool $fail = false;
        public static array $payload = [];
        public function configdRun(string $command): string {
            self::$calls[] = [$command, []];
            return self::$plain;
        }
        public function configdpRun(string $command, array $parameters): string {
            self::$calls[] = [$command, $parameters];
            \contract(count($parameters) === 1 && is_file($parameters[0]), 'Missing settings handoff');
            \contract((fileperms($parameters[0]) & 0777) === 0600, 'Settings handoff is not private');
            \contract(json_decode(file_get_contents($parameters[0]), true) === self::$payload, 'Settings bytes changed');
            if (self::$fail) { throw new \RuntimeException('PRIVATE_BACKEND_EXCEPTION'); }
            return self::$reply;
        }
    }
}
namespace {
    use OPNsense\Core\Backend;
    use Tests\ServiceContract\Files;
    class Request {
        public string $method = 'POST';
        public $settings;
        public function getMethod(): string { return $this->method; }
        public function getPost($field) { return $field === 'settings' ? $this->settings : null; }
    }
    function contract(bool $ok, string $message): void {
        if (!$ok) { throw new \RuntimeException($message); }
    }
    function clean(): void {
        foreach (Files::$created as $path) { contract(!file_exists($path), 'Private handoff was retained'); }
    }
    $package = dirname(__DIR__, 2);
    $lucky = basename($package) === 'os-lucky';
    $route = $lucky ? 'lucky' : 'ddnsgo';
    $module = $lucky ? 'Lucky' : 'Ddnsgo';
    Files::$root = $argv[1];
    $directory = $package . '/src/usr/local/opnsense/mvc/app/controllers/OPNsense/' . $module . '/Api/';
    require($directory . 'SettingsController.php');
    require($directory . 'ServiceController.php');
    $settingsClass = 'OPNsense\\' . $module . '\\Api\\SettingsController';
    $serviceClass = 'OPNsense\\' . $module . '\\Api\\ServiceController';
    $settings = new $settingsClass();
    $service = new $serviceClass();
    $request = new Request();
    $settings->request = $service->request = $request;
    $payload = $lucky ? ['enabled' => true, 'conf_dir' => '/private/lucky', 'web_port' => 16601]
        : ['config_content' => "token: PRIVATE_REQUEST_CREDENTIAL\r\nenabled: true\r\n", 'revision' => 'isolated-revision'];
    $request->settings = Backend::$payload = $payload;
    foreach ([[$settings, ['setAction']], [$service, ['startAction', 'stopAction', 'restartAction']]] as [$controller, $actions]) {
        foreach ($actions as $action) {
            Backend::$calls = [];
            $created = count(Files::$created);
            $request->method = 'POST';
            $controller->readOnly = true;
            $guards = $controller->guards;
            try { $controller->$action(); contract(false, 'Readonly mutation accepted'); }
            catch (\RuntimeException $error) { contract($error->getMessage() === 'readonly', 'Unexpected readonly error'); }
            contract($controller->guards === $guards + 1, 'Readonly guard skipped');
            contract(Backend::$calls === [] && count(Files::$created) === $created, 'Readonly denial occurred after file/backend access');
            $controller->readOnly = false;
            $request->method = 'GET';
            contract($controller->$action()['status'] === 'failed', 'GET accepted a mutation');
            contract(Backend::$calls === [] && count(Files::$created) === $created, 'GET reached file/backend access');
        }
    }
    $request->method = 'POST';
    foreach (['start', 'stop', 'restart'] as $action) {
        foreach ([" OK\n" => 'ok', '' => 'failed', 'OK extra' => 'failed', "PRIVATE_COMMAND_DIAGNOSTIC\nOK" => 'failed'] as $reply => $expected) {
            Backend::$calls = [];
            Backend::$plain = $reply;
            $response = $service->{$action . 'Action'}();
            contract($response['status'] === $expected, 'Service result was inferred from incidental output');
            contract(Backend::$calls === [[$route . ' ' . $action, []]], 'Wrong service dispatch');
            contract(!str_contains(json_encode($response), 'PRIVATE_'), 'Service diagnostic leaked');
        }
    }
    $request->method = 'GET';
    $service->readOnly = $settings->readOnly = true;
    foreach (['daemon is running as pid 123.' => true, 'daemon is not running.' => false] as $plain => $running) {
        Backend::$calls = [];
        Backend::$plain = $plain;
        contract($service->statusAction()['running'] === $running, 'Wrong status result');
        contract(Backend::$calls === [[$route . ' status', []]], 'Status mutated services');
    }
    Backend::$plain = 'PRIVATE_INVALID_JSON';
    contract($settings->getAction()['status'] === 'failed', 'Invalid settings backend accepted');
    if (!$lucky) {
        contract($service->logAction()['log'] === '', 'Invalid log backend accepted');
    }
    $request->method = 'POST';
    $settings->readOnly = false;
    foreach (['not JSON', '{"status":"failed","error":"isolated"}', '{"status":"failed","saved":true,"error":"backup failure"}'] as $reply) {
        Backend::$reply = $reply;
        Backend::$calls = [];
        contract($settings->setAction()['status'] === 'failed', 'Failed save accepted');
        contract(count(Backend::$calls) === 1, 'Failed save restarted a service');
        clean();
    }
    Backend::$reply = '{"status":"ok"}';
    foreach ([true, false] as $enabled) {
        if ($lucky) { $request->settings['enabled'] = $enabled; }
        Backend::$payload = $request->settings;
        Backend::$plain = 'OK';
        Backend::$calls = [];
        contract($settings->setAction()['status'] === 'ok', 'Allowed save failed');
        $action = $lucky && !$enabled ? 'stop' : 'restart';
        contract(count(Backend::$calls) === 2 && Backend::$calls[1] === [$route . ' ' . $action, []], 'Save used wrong lifecycle action');
        contract(!str_contains(json_encode(Backend::$calls), 'PRIVATE_REQUEST_CREDENTIAL'), 'Credential reached configd command arguments');
        clean();
    }
    Backend::$plain = 'PRIVATE_SERVICE_FAILURE';
    $failed = $settings->setAction();
    contract($failed['status'] === 'failed' && $failed['saved'] === true, 'Save/service failure distinction lost');
    contract(!str_contains(json_encode($failed), 'PRIVATE_'), 'Service failure leaked');
    clean();
    Backend::$fail = true;
    try { $settings->setAction(); contract(false, 'Backend failure did not occur'); }
    catch (\RuntimeException $error) { contract($error->getMessage() === 'PRIVATE_BACKEND_EXCEPTION', 'Unexpected backend exception'); }
    clean();
    Backend::$fail = false;
    foreach ([null, 'invalid', ['large' => str_repeat('x', 2 * 1048576)], ['not-json' => NAN]] as $invalid) {
        Backend::$calls = [];
        $created = count(Files::$created);
        $request->settings = $invalid;
        contract($settings->setAction()['status'] === 'failed', 'Invalid settings accepted');
        contract(Backend::$calls === [] && count(Files::$created) === $created, 'Invalid settings staged a request');
    }
    echo "controller contract passed\n";
}
