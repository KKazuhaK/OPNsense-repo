<?php
/* Exercise utility controller permissions and private transport on native PHP. */
namespace OPNsense\Base {
    class ApiControllerBase
    {
        public $request;
        public bool $readOnly = false;
        protected function throwReadOnly(): void
        {
            if ($this->readOnly) { throw new \RuntimeException('Read-only account.'); }
        }
    }
}

namespace OPNsense\Core {
    class Backend
    {
        public static array $commands = [];
        public static array $requests = [];
        public static array $staged = [];
        public static bool $fail = false;
        public function configdRun(string $command): string
        {
            self::$commands[] = $command;
            return '{"status":"ok"}';
        }
        public function configdpRun(string $command, array $arguments): string
        {
            self::$commands[] = $command . ' ' . implode(' ', $arguments);
            $path = $arguments[0] ?? '';
            if (count($arguments) !== 1 || !preg_match('~^/tmp/easytier_mvc_[a-zA-Z0-9]+$~', $path)
                || !is_file($path) || (fileperms($path) & 0777) !== 0600) {
                throw new \RuntimeException('Expected one private request file.');
            }
            self::$requests[$path] = file_get_contents($path);
            if (self::$fail) { throw new \RuntimeException('Isolated backend failure.'); }
            return '{"status":"ok"}';
        }
    }
}

namespace OPNsense\EasyTier\Api {
    function tempnam(string $directory, string $prefix): string|false
    {
        $created = \tempnam($directory, $prefix);
        // Preserve the requested spelling when /tmp is a filesystem alias.
        $path = $created === false ? false : $directory . '/' . basename($created);
        if ($path !== false && realpath($path) !== realpath($created)) {
            throw new \RuntimeException('Request file escaped its staging directory.');
        }
        \OPNsense\Core\Backend::$staged[] = $path;
        return $path;
    }
}

namespace {
    use OPNsense\Core\Backend;

    $root = $argv[1] ?? dirname(__DIR__, 2);
    foreach (['os-easytier' => 'EasyTier', 'os-lang' => 'LangTool', 'os-ttyd' => 'Ttyd'] as $package => $module) {
        $path = $root . '/src/' . $package . '/src/usr/local/opnsense/mvc/app/controllers/OPNsense/' . $module . '/Api';
        require_once($path . '/ServiceController.php');
        if ($module === 'EasyTier') { require_once($path . '/SettingsController.php'); }
    }
    require_once($root . '/src/os-unboundcustom/src/opnsense/mvc/app/controllers/OPNsense/Unboundcustom/Api/ServiceController.php');

    class TestRequest
    {
        public string $method = 'POST';
        public array $post = [];
        public function getMethod(): string { return $this->method; }
        public function getPost($field, $filter = null, $fallback = null) { return $this->post[$field] ?? $fallback; }
    }
    function utility_check(bool $condition, string $message): void
    {
        if (!$condition) { throw new \RuntimeException($message); }
    }

    $settings = new \OPNsense\EasyTier\Api\SettingsController();
    $settings->request = new TestRequest();
    $payload = "hostname = \"firewall's node\"\nnetwork_secret = \"SENTINEL_PRIVATE_SECRET\"\n";
    $settings->request->post = ['config' => $payload];
    $controllers = [
        [$settings, ['setAction']],
        [new \OPNsense\EasyTier\Api\ServiceController(), ['startAction','stopAction','restartAction','clearLogAction']],
        [new \OPNsense\LangTool\Api\ServiceController(), ['updateAction']],
        [new \OPNsense\Ttyd\Api\ServiceController(), ['startAction','stopAction','restartAction']],
        [new \OPNsense\Unboundcustom\Api\ServiceController(), ['applyAction']],
    ];
    foreach ($controllers as [$controller, $actions]) {
        if (!$controller->request) { $controller->request = new TestRequest(); }
        $controller->readOnly = true;
        foreach ($actions as $action) {
            $commands = count(Backend::$commands);
            $staged = count(Backend::$staged);
            try {
                $controller->$action();
                utility_check(false, 'Read-only account accepted by ' . get_class($controller) . '::' . $action);
            } catch (\RuntimeException $error) {
                utility_check($error->getMessage() === 'Read-only account.', 'Unexpected write denial.');
            }
            utility_check(count(Backend::$commands) === $commands, 'Read-only mutation reached configd.');
            utility_check(count(Backend::$staged) === $staged, 'Read-only mutation staged a file.');
            $controller->request->method = 'GET';
            utility_check($controller->$action()['status'] === 'failed', 'Mutation accepted GET.');
            utility_check(count(Backend::$commands) === $commands, 'GET mutation reached configd.');
            $controller->request->method = 'POST';
        }
        $controller->readOnly = false;
    }
    utility_check($settings->setAction()['status'] === 'ok', 'Private request save failed.');
    utility_check(strpos(implode("\n", Backend::$commands), 'SENTINEL_') === false, 'A secret reached configd arguments.');
    utility_check(array_values(Backend::$requests) === [$payload], 'The staged request changed its content.');
    foreach (array_keys(Backend::$requests) as $path) { utility_check(!file_exists($path), 'Successful request retained its private file.'); }
    Backend::$fail = true;
    try {
        $settings->setAction();
        utility_check(false, 'Backend failure was not raised.');
    } catch (\RuntimeException $error) {
        utility_check($error->getMessage() === 'Isolated backend failure.', 'Unexpected backend failure.');
    }
    foreach (array_keys(Backend::$requests) as $path) { utility_check(!file_exists($path), 'Failed request retained its private file.'); }
    Backend::$fail = false;
    $settings->request->post = ['config' => str_repeat('x', 1048577)];
    $staged = count(Backend::$staged);
    utility_check($settings->setAction()['status'] === 'failed', 'Oversize configuration accepted.');
    utility_check(count(Backend::$staged) === $staged, 'Oversize configuration staged a file.');
    foreach ([$settings, $controllers[1][0], $controllers[2][0], $controllers[3][0]] as $controller) {
        $controller->readOnly = true;
        $action = $controller === $settings ? 'getAction' : 'statusAction';
        utility_check($controller->$action()['status'] === 'ok', 'Read-only account denied a read action.');
    }
    echo "Utility mutations enforce read-only accounts; private transport preserves bytes, rejects oversize requests and cleans up on success/failure.\n";
}
