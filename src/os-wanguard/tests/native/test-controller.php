<?php
/* Execute the real API controllers against recording stand-ins for the framework. */
namespace OPNsense\Base {
    class ApiControllerBase
    {
        public $request;
        public bool $readOnly = false;
        public int $permissionChecks = 0;

        protected function throwReadOnly()
        {
            $this->permissionChecks++;
            if ($this->readOnly) {
                throw new \RuntimeException('Read-only account.');
            }
        }
    }

    class ApiMutableModelControllerBase extends ApiControllerBase
    {
    }

    /* The inherited service actions, reduced to what they send to configd. */
    class ApiMutableServiceControllerBase extends ApiControllerBase
    {
        public static array $parents = [];

        private function run(string $verb): array
        {
            self::$parents[] = $verb;
            if ($this->request->isPost()) {
                (new \OPNsense\Core\Backend())->configdRun(static::$internalServiceName . ' ' . $verb);
            }
            return ['response' => 'OK'];
        }

        public function startAction() { return $this->run('start'); }
        public function stopAction() { return $this->run('stop'); }
        public function restartAction() { return $this->run('restart'); }
        public function reconfigureAction() { $this->run('reconfigure'); return ['status' => 'ok']; }
    }
}

namespace OPNsense\Core {
    class Backend
    {
        public static array $calls = [];
        public static string $reply = '';

        public function configdRun($command)
        {
            self::$calls[] = [$command];
            return self::$reply;
        }

        public function configdpRun($command, $parameters = [])
        {
            self::$calls[] = [$command, $parameters];
            return self::$reply;
        }
    }
}

namespace {
    use OPNsense\Base\ApiMutableServiceControllerBase;
    use OPNsense\Core\Backend;

    if (!function_exists('gettext')) {
        function gettext($text) { return $text; }
    }

    class TestRequest
    {
        public string $method = 'POST';
        public array $post = [];

        public function getMethod() { return $this->method; }
        public function isPost() { return $this->method === 'POST'; }
        public function getPost($key = null, $filter = null, $default = null) { return $this->post[$key] ?? $default; }
    }

    function check(bool $condition, string $message): void
    {
        if (!$condition) {
            throw new RuntimeException($message);
        }
    }

    function controller(string $method = 'POST', array $post = [], bool $readOnly = false)
    {
        $controller = new OPNsense\Wanguard\Api\ServiceController();
        $controller->request = new TestRequest();
        $controller->request->method = $method;
        $controller->request->post = $post;
        $controller->readOnly = $readOnly;
        Backend::$calls = [];
        ApiMutableServiceControllerBase::$parents = [];
        return $controller;
    }

    $api = dirname(__DIR__, 2) . '/src/usr/local/opnsense/mvc/app/controllers/OPNsense/Wanguard/Api';
    require $api . '/ServiceController.php';
    require $api . '/SettingsController.php';

    /* The bindings the framework reads. */
    $statics = [];
    foreach (['internalServiceClass', 'internalServiceEnabled', 'internalServiceTemplate', 'internalServiceName'] as $name) {
        $statics[$name] = (new ReflectionProperty(OPNsense\Wanguard\Api\ServiceController::class, $name))->getValue();
    }
    check($statics === ['internalServiceClass' => '\OPNsense\Wanguard\General', 'internalServiceEnabled' => 'enabled',
        'internalServiceTemplate' => 'OPNsense/Wanguard', 'internalServiceName' => 'wanguard'], 'Service bindings changed.');
    $restart = new ReflectionMethod(OPNsense\Wanguard\Api\ServiceController::class, 'reconfigureForceRestart');
    check($restart->invoke(controller()) === 0, 'Reconfigure must reload the daemon, not restart it.');
    check((new ReflectionProperty(OPNsense\Wanguard\Api\SettingsController::class, 'internalModelName'))->getValue() === 'general'
        && (new ReflectionProperty(OPNsense\Wanguard\Api\SettingsController::class, 'internalModelClass'))->getValue()
            === '\OPNsense\Wanguard\General', 'Settings bindings changed.');

    /* Service mutations: POST only, and read-only accounts are refused before configd. */
    foreach (['start', 'stop', 'restart', 'reconfigure'] as $action) {
        $method = $action . 'Action';
        $c = controller('GET');
        $c->$method();
        check(Backend::$calls === [] && ApiMutableServiceControllerBase::$parents === [] && $c->permissionChecks === 0,
            "GET reached the backend through $action.");
        $c = controller('POST', [], true);
        try {
            $c->$method();
            check(false, "A read-only account ran $action.");
        } catch (RuntimeException $error) {
            check($error->getMessage() === 'Read-only account.', $error->getMessage());
        }
        check(Backend::$calls === [], "A read-only account reached configd through $action.");
        $c = controller();
        $c->$method();
        check(ApiMutableServiceControllerBase::$parents === [$action] && $c->permissionChecks === 1, "$action did not run once.");
    }

    /* Retry: POST only, read-only refused, the name validated before configd. */
    $c = controller('GET', ['interface' => 'opt2']);
    check($c->retryAction() === ['status' => 'failed', 'message' => 'POST required'] && Backend::$calls === [],
        'GET queued a retry.');
    $c = controller('POST', ['interface' => 'opt2'], true);
    try {
        $c->retryAction();
        check(false, 'A read-only account queued a retry.');
    } catch (RuntimeException $error) {
        check(Backend::$calls === [], 'A read-only account reached configd.');
    }
    foreach ([null, '', 'WAN', '../etc', 'wan;id', 'wan opt2', str_repeat('a', 33), ['wan'], "wan\n"] as $name) {
        $c = controller('POST', ['interface' => $name]);
        $answer = $c->retryAction();
        check($answer['status'] === 'refused' && Backend::$calls === [], 'Invalid interface reached configd: ' . json_encode($name));
    }
    $replies = [
        '{"status": "queued", "code": "queued"}' => 'queued',
        '{"status": "refused", "code": "queued-already"}' => 'refused',
        '{"status": "refused", "code": "disabled"}' => 'refused',
        '{"status": "refused", "code": "stopped"}' => 'refused',
        '{"status": "refused", "code": "not-watched"}' => 'refused',
        '{"status": "refused", "code": "something-new"}' => 'refused',
    ];
    foreach ($replies as $reply => $status) {
        Backend::$reply = $reply;
        $c = controller('POST', ['interface' => 'opt2']);
        $answer = $c->retryAction();
        check(Backend::$calls === [['wanguard retry', ['opt2']]], 'The retry was not dispatched once.');
        check($answer['status'] === $status && is_string($answer['message']) && $answer['message'] !== '',
            'Unexpected retry answer for ' . $reply);
    }
    check($answer['message'] === 'The retry was refused.', 'An unknown refusal was not worded generically.');
    foreach (['', 'garbage', '[]', '{"status": "running"}'] as $reply) {
        Backend::$reply = $reply;
        $answer = controller('POST', ['interface' => 'opt2'])->retryAction();
        check($answer['status'] === 'failed', 'A broken backend reply was accepted: ' . $reply);
    }

    /* State: the backend JSON passes through; anything else is a failure. */
    Backend::$reply = '{"status": "ok", "enabled": true, "interfaces": [{"name": "wan"}]}';
    $answer = controller('GET')->stateAction();
    check($answer === ['status' => 'ok', 'enabled' => true, 'interfaces' => [['name' => 'wan']]], 'State was altered.');
    check(Backend::$calls === [['wanguard state']], 'State used the wrong action.');
    foreach (['', 'garbage', '{"enabled": true}', '[1]'] as $reply) {
        Backend::$reply = $reply;
        $answer = controller('GET')->stateAction();
        check($answer['status'] === 'failed' && $answer['interfaces'] === [], 'A broken state reply was accepted.');
    }
    echo "WAN Guard controllers passed: bindings, POST-only read-only-checked mutations, retry validation and replies, state.\n";
}
