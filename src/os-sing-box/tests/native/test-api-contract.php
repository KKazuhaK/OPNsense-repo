<?php
/* Verify controller permissions and transport without touching a router service. */
namespace OPNsense\Base {
    class ApiControllerBase
    {
        public $request;
        public bool $readOnly = false;

        protected function throwReadOnly(): void
        {
            if ($this->readOnly) {
                throw new \RuntimeException('Read-only account.');
            }
        }
    }
}

namespace OPNsense\Core {
    class Backend
    {
        public static array $commands = [];
        public static array $requests = [];
        public static bool $fail = false;

        public function configdRun(string $command): string
        {
            self::$commands[] = $command;
            return '{"ok":true}';
        }

        public function configdpRun(string $command, array $arguments): string
        {
            self::$commands[] = $command . ' ' . implode(' ', $arguments);
            $path = $arguments[0] ?? '';
            if (count($arguments) !== 1 || !preg_match('~^/tmp/singbox-request-[a-zA-Z0-9]+$~', $path)
                || !is_file($path) || (fileperms($path) & 0777) !== 0600) {
                throw new \RuntimeException('The controller did not pass one private request file.');
            }
            self::$requests[$path] = file_get_contents($path);
            if (self::$fail) {
                throw new \RuntimeException('Isolated backend failure.');
            }
            return '{"ok":true}';
        }
    }
}

namespace OPNsense\SingBox\Api {
    function tempnam(string $directory, string $prefix): string|false
    {
        $created = \tempnam($directory, $prefix);
        // Preserve the requested spelling when /tmp is a filesystem alias.
        $path = $created === false ? false : $directory . '/' . basename($created);
        if ($path !== false && realpath($path) !== realpath($created)) {
            throw new \RuntimeException('Request file escaped its staging directory.');
        }
        return $path;
    }
}

namespace {
    use OPNsense\Core\Backend;
    use OPNsense\SingBox\Api\ServiceController;
    use OPNsense\SingBox\Api\SettingsController;

    $controllers = $argv[1] ?? '/usr/local/opnsense/mvc/app/controllers/OPNsense/SingBox/Api';
    require_once($controllers . '/SettingsController.php');
    require_once($controllers . '/ServiceController.php');

    class TestRequest
    {
        public string $method = 'POST';
        public array $post = [];
        public function getMethod(): string { return $this->method; }
        public function getPost($field, $filter = null, $fallback = null) { return $this->post[$field] ?? $fallback; }
    }

    function api_check(bool $condition, string $message): void
    {
        if (!$condition) { throw new \RuntimeException($message); }
    }

    $settings = new SettingsController();
    $settings->request = new TestRequest();
    $settings->request->post = ['settings' => ['subscription_url' => 'https://example.invalid/SENTINEL_URL'],
        'config' => '{"password":"SENTINEL_PASSWORD"}', 'revision' => str_repeat('a', 64)];
    $service = new ServiceController();
    $service->request = new TestRequest();
    foreach ([[$settings, ['setAction', 'setIntegrationAction', 'saveConfigAction']], [$service,
        ['startAction', 'stopAction', 'restartAction', 'subUpdateAction', 'clearLogAction', 'clearSubLogAction']]] as [$controller, $actions]) {
        $controller->readOnly = true;
        foreach ($actions as $action) {
            $count = count(Backend::$commands);
            try {
                $controller->$action();
                api_check(false, 'A mutation accepted a read-only account: ' . $action);
            } catch (\RuntimeException $error) {
                api_check($error->getMessage() === 'Read-only account.', 'Unexpected mutation failure: ' . $action);
            }
            api_check(count(Backend::$commands) === $count, 'Read-only mutation reached configd.');
            $controller->request->method = 'GET';
            api_check($controller->$action()['status'] === 'failed', 'GET reached a mutation.');
            $controller->request->method = 'POST';
        }
        $controller->readOnly = false;
    }
    api_check($settings->setAction()['status'] === 'ok', 'The URL request failed.');
    api_check($settings->saveConfigAction()['status'] === 'ok', 'The config request failed.');
    api_check(strpos(implode("\n", Backend::$commands), 'SENTINEL_') === false, 'A credential reached configd command arguments.');
    api_check(strpos(implode("\n", Backend::$requests), 'SENTINEL_URL') !== false, 'The file did not carry the requested URL.');
    api_check(strpos(implode("\n", Backend::$requests), 'SENTINEL_PASSWORD') !== false, 'The file did not carry the configuration.');
    Backend::$fail = true;
    try {
        $settings->saveConfigAction();
        api_check(false, 'The isolated backend failure was not raised.');
    } catch (\RuntimeException $error) {
        api_check($error->getMessage() === 'Isolated backend failure.', 'Unexpected transport failure.');
    }
    foreach (array_keys(Backend::$requests) as $path) {
        api_check(!file_exists($path), 'A request file was retained after the backend finished.');
    }
    echo "All mutations reject read-only accounts; private file transport avoids credential arguments and always cleans up.\n";
}
