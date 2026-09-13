<?php
/* Exercise the real controllers with an isolated backend; never run the helper. */
namespace OPNsense\Base {
    class ApiControllerBase
    {
        public $request;
        public bool $readOnly = false;
        public int $permissionChecks = 0;

        protected function throwReadOnly(): void
        {
            $this->permissionChecks++;
            if ($this->readOnly) {
                throw new \RuntimeException('Read-only account.');
            }
        }
    }
}

namespace OPNsense\Core {
    class Backend
    {
        public static array $calls = [];
        public static string $reply = '{"status":"ok","sentinel":"isolated-backend"}';

        /* Match the real Backend.php positional signature, including detach. */
        public function configdpRun(
            string $command,
            array $parameters = [],
            bool $detach = false,
            int $timeout = 120,
            int $connectTimeout = 10
        ): string {
            self::$calls[] = ['command' => $command, 'parameters' => $parameters,
                'detach' => $detach, 'timeout' => $timeout, 'arguments' => func_num_args()];
            return self::$reply;
        }

        public function configdRun(string $command): string
        {
            throw new \RuntimeException('Expected parameterized configd transport: ' . $command);
        }
    }
}

namespace {
    use OPNsense\Core\Backend;
    use OPNsense\Speedtest\Api\ServiceController;
    use OPNsense\Speedtest\Api\SettingsController;

    $controllers = $argv[1] ?? '/usr/local/opnsense/mvc/app/controllers/OPNsense/Speedtest/Api';
    require_once($controllers . '/SettingsController.php');
    require_once($controllers . '/ServiceController.php');

    class TestRequest
    {
        public string $method = 'POST';
        public array $post = [];
        public array $query = [];

        public function isPost(): bool { return $this->method === 'POST'; }
        public function getMethod(): string { return $this->method; }
        public function getPost($field, $filter = null, $fallback = null)
        {
            return $this->post[$field] ?? $fallback;
        }
        public function getQuery($field, $filter = null, $fallback = null)
        {
            return $this->query[$field] ?? $fallback;
        }
    }

    function api_check(bool $condition, string $message): void
    {
        if (!$condition) {
            throw new \RuntimeException($message);
        }
    }

    function expect_call($controller, string $method, string $action, array $payload, bool $settings): void
    {
        Backend::$calls = [];
        $response = $controller->$method();
        api_check(($response['sentinel'] ?? '') === 'isolated-backend', 'The backend response was not returned: ' . $method);
        api_check(count(Backend::$calls) === 1, 'Expected one backend call: ' . $method);
        $call = Backend::$calls[0];
        api_check($call['command'] === 'speedtest ' . $action, 'Wrong configd action: ' . $method);
        api_check(count($call['parameters']) === 1, 'Expected one encoded request: ' . $method);
        $decoded = base64_decode($call['parameters'][0], true);
        api_check($decoded !== false && json_decode($decoded, true) === $payload, 'The request payload changed: ' . $method);
        api_check($call['detach'] === false, 'The backend request was detached: ' . $method);
        if ($settings) {
            api_check($call['arguments'] >= 4 && $call['timeout'] === 60,
                'Settings transport must pass false as argument 3 and timeout 60 as argument 4: ' . $method);
        }
    }

    $settings = new SettingsController();
    $settings->request = new TestRequest();
    $settings->request->post = ['settings' => ['interface' => 'wan', 'server_id' => '123', 'threads' => '4'], 'interface' => 'wan'];
    $settings->request->query = ['interface' => 'lan'];
    $service = new ServiceController();
    $service->request = new TestRequest();
    $service->request->post = ['settings' => ['interface' => 'wan', 'server_id' => '123', 'threads' => '4']];

    foreach ([[$settings, ['setAction', 'refreshAction']], [$service, ['runAction', 'clearAction']]] as [$controller, $actions]) {
        foreach ($actions as $action) {
            $controller->readOnly = true;
            $controller->request->method = 'POST';
            Backend::$calls = [];
            $checks = $controller->permissionChecks;
            try {
                $controller->$action();
                api_check(false, 'A mutation accepted a read-only account: ' . $action);
            } catch (\RuntimeException $error) {
                api_check($error->getMessage() === 'Read-only account.',
                    'Unexpected permission failure: ' . $action . ' (' . $error->getMessage() . ')');
            }
            api_check($controller->permissionChecks === $checks + 1, 'The read-only guard was skipped: ' . $action);
            api_check(Backend::$calls === [], 'A read-only mutation reached configd: ' . $action);
            foreach ([false, true] as $readOnly) {
                $controller->readOnly = $readOnly;
                $controller->request->method = 'GET';
                api_check(($controller->$action()['status'] ?? '') === 'failed', 'A GET reached a mutation: ' . $action);
                api_check(Backend::$calls === [], 'A GET mutation reached configd: ' . $action);
            }
        }
        $controller->readOnly = false;
        $controller->request->method = 'POST';
    }

    /* A read-only account can read without invoking a write guard or action. */
    $settings->readOnly = true;
    $service->readOnly = true;
    $settings->request->method = 'GET';
    $service->request->method = 'GET';
    $settingsChecks = $settings->permissionChecks;
    $serviceChecks = $service->permissionChecks;
    expect_call($settings, 'getAction', 'get', [], true);
    expect_call($settings, 'serversAction', 'servers', ['interface' => 'lan'], true);
    expect_call($service, 'progressAction', 'progress', [], false);
    api_check($settings->permissionChecks === $settingsChecks && $service->permissionChecks === $serviceChecks,
        'A read action invoked a write guard.');

    $settings->readOnly = false;
    $service->readOnly = false;
    $settings->request->method = 'POST';
    $service->request->method = 'POST';
    expect_call($settings, 'setAction', 'set', $settings->request->post['settings'], true);
    expect_call($settings, 'refreshAction', 'refresh', ['interface' => 'wan'], true);
    expect_call($service, 'runAction', 'run', $service->request->post['settings'], false);
    expect_call($service, 'clearAction', 'clear', [], false);

    /* Empty and invalid transport responses must never report success. */
    foreach (['', 'not-json', '{"status":"failed","error":"isolated failure"}'] as $reply) {
        Backend::$reply = $reply;
        foreach ([[$settings, 'getAction'], [$settings, 'setAction'], [$service, 'progressAction'], [$service, 'runAction']] as [$controller, $action]) {
            api_check(($controller->$action()['status'] ?? '') === 'failed', 'A backend failure reported success: ' . $action);
        }
    }
    echo "Speedtest API contract passed: POST/read-only guards, read actions, payloads, synchronous 60-second settings transport, and failure handling.\n";
}
