<?php
/* Test real controllers without loading framework helpers or touching services. */
namespace Tests\SmallApi {
    class RequestFiles
    {
        public static array $paths = [];

        public static function create(string $directory, string $prefix)
        {
            $created = \tempnam($directory, $prefix);
            // Preserve the requested spelling when /tmp is a filesystem alias.
            $path = $created === false ? false : $directory . '/' . basename($created);
            if ($path !== false && realpath($path) !== realpath($created)) {
                throw new \RuntimeException('Request file escaped its staging directory.');
            }
            self::$paths[] = $path;
            return $path;
        }
    }
}

/* Intercept creation, including files later removed, to prove guard ordering. */
namespace OPNsense\Staticarp\Api {
    function tempnam($directory, $prefix) { return \Tests\SmallApi\RequestFiles::create($directory, $prefix); }
}
namespace OPNsense\Lucky\Api {
    function tempnam($directory, $prefix) { return \Tests\SmallApi\RequestFiles::create($directory, $prefix); }
}
namespace OPNsense\Ddnsgo\Api {
    function tempnam($directory, $prefix) { return \Tests\SmallApi\RequestFiles::create($directory, $prefix); }
}

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
        public static array $requests = [];
        public static bool $throwSet = false;
        public static string $setReply = '{"status":"ok","enabled":true}';
        public static string $mutationReply = 'OK';

        public function configdRun(string $command): string
        {
            self::$calls[] = ['command' => $command, 'parameters' => []];
            [$group, $action] = explode(' ', $command, 2);
            if ($action === 'status') {
                return $group === 'staticarp' ? "enabled=YES\nentries=2\n" : $group . ' is running as pid 123.';
            }
            if ($action === 'get') {
                return '{"settings":{"sentinel":"isolated-read"}}';
            }
            if ($action === 'log') {
                return '{"log":"isolated --> log"}';
            }
            if (!in_array($action, ['apply', 'reset', 'start', 'stop', 'restart'], true)) {
                throw new \RuntimeException('Unexpected plain action: ' . $command);
            }
            return self::$mutationReply;
        }

        public function configdpRun(string $command, array $parameters): string
        {
            self::$calls[] = ['command' => $command, 'parameters' => $parameters];
            [$group, $action] = explode(' ', $command, 2);
            if ($action === 'set') {
                $path = $parameters[0] ?? '';
                if (count($parameters) !== 1 || !preg_match('~^/tmp/' . $group . '-api-[a-zA-Z0-9]+$~', $path)
                    || !is_file($path) || (fileperms($path) & 0777) !== 0600) {
                    throw new \RuntimeException('Expected one private settings request file.');
                }
                self::$requests[$path] = file_get_contents($path);
                if (self::$throwSet) {
                    throw new \RuntimeException('Isolated backend failure.');
                }
                return self::$setReply;
            }
            if ($group === 'staticarp' && $action === 'script' && $parameters === ['lan']) {
                return '{"status":"ok","script":"arp -a"}';
            }
            if ($group === 'pftop' && $action === 'snapshot') {
                return '{"status":"ok","output":"isolated snapshot"}';
            }
            throw new \RuntimeException('Unexpected parameterized action: ' . $command);
        }
    }
}

namespace {
    use OPNsense\Core\Backend;
    use Tests\SmallApi\RequestFiles;

    class TestRequest
    {
        public string $method = 'POST';
        public array $post = [];
        public array $query = ['interface' => 'lan'];
        public function getMethod(): string { return $this->method; }
        public function getPost($field, $filter = null, $fallback = null) { return $this->post[$field] ?? $fallback; }
        public function getQuery($field, $filter = null, $fallback = null) { return $this->query[$field] ?? $fallback; }
    }

    function contract_check(bool $condition, string $message): void
    {
        if (!$condition) { throw new \RuntimeException($message); }
    }

    function files_cleaned(): void
    {
        foreach (RequestFiles::$paths as $path) {
            contract_check(!is_file($path), 'The settings request file was retained: ' . $path);
        }
    }

    $root = $argv[1] ?? dirname(__DIR__, 2);
    $cases = [];
    foreach ([['os-staticarp', 'Staticarp', 'staticarp', ['applyAction', 'resetAction']],
              ['os-lucky', 'Lucky', 'lucky', ['startAction', 'stopAction', 'restartAction']],
              ['os-ddns-go', 'Ddnsgo', 'ddnsgo', ['startAction', 'stopAction', 'restartAction']],
              ['os-pftop', 'Pftop', 'pftop', []]] as [$package, $module, $group, $mutations]) {
        $directory = $root . '/src/' . $package . '/src/usr/local/opnsense/mvc/app/controllers/OPNsense/' . $module . '/Api';
        foreach (['Settings', 'Service'] as $name) {
            if ($group === 'pftop' && $name === 'Settings') { continue; }
            require_once($directory . '/' . $name . 'Controller.php');
            $class = 'OPNsense\\' . $module . '\\Api\\' . $name . 'Controller';
            $controller = new $class();
            $controller->request = new TestRequest();
            $payload = $group === 'ddnsgo' ? ['config_content' => 'token: SENTINEL_CREDENTIAL', 'revision' => 'example']
                : ($group === 'lucky' ? ['enabled' => 1, 'conf_dir' => '/usr/local/etc/lucky', 'web_port' => 16601]
                : ['enabled' => 1, 'entries' => '192.0.2.10 aa:bb:cc:dd:ee:ff', 'modes' => ['lan' => 'normal']]);
            $controller->request->post = ['settings' => $payload];
            $writes = $name === 'Settings' ? ['setAction'] : $mutations;
            $reads = $name === 'Settings' ? ['getAction' => $group . ' get'] : ['statusAction' => $group . ' status'];
            if ($group === 'staticarp' && $name === 'Settings') { $reads['scriptAction'] = 'staticarp script'; }
            if ($group === 'ddnsgo' && $name === 'Service') { $reads['logAction'] = 'ddnsgo log'; }
            if ($group === 'pftop') { $reads = ['snapshotAction' => 'pftop snapshot']; }
            $declared = [];
            foreach ((new \ReflectionClass($controller))->getMethods(\ReflectionMethod::IS_PUBLIC) as $method) {
                if ($method->getDeclaringClass()->getName() === $class && str_ends_with($method->getName(), 'Action')) {
                    $declared[] = $method->getName();
                }
            }
            $covered = array_merge($writes, array_keys($reads)); sort($declared); sort($covered);
            contract_check($declared === $covered, 'An exposed API action is not covered: ' . $class);
            $cases[] = [$controller, $group, $payload, $writes, $reads];
        }
    }

    $writeCount = 0;
    foreach ($cases as [$controller, $group, $payload, $writes, $reads]) {
        foreach ($writes as $action) {
            Backend::$calls = [];
            $created = count(RequestFiles::$paths);
            $controller->readOnly = true;
            $controller->request->method = 'POST';
            $checks = $controller->permissionChecks;
            try {
                $controller->$action();
                contract_check(false, 'A mutation accepted a read-only account: ' . $action);
            } catch (\RuntimeException $error) {
                contract_check($error->getMessage() === 'Read-only account.',
                    'Unexpected permission failure: ' . $action . ' (' . $error->getMessage() . ')');
            }
            contract_check($controller->permissionChecks === $checks + 1, 'The write guard was skipped: ' . $action);
            contract_check(Backend::$calls === [] && count(RequestFiles::$paths) === $created,
                'The denied mutation reached configd or created a file: ' . $action);
            foreach ([false, true] as $readOnly) {
                $controller->readOnly = $readOnly;
                $controller->request->method = 'GET';
                contract_check(($controller->$action()['status'] ?? '') === 'failed', 'A GET reached a mutation: ' . $action);
                contract_check(Backend::$calls === [] && count(RequestFiles::$paths) === $created,
                    'A GET mutation reached configd or created a file: ' . $action);
            }
            $writeCount++;
        }
        $controller->readOnly = true;
        $controller->request->method = 'GET';
        $checks = $controller->permissionChecks;
        $created = count(RequestFiles::$paths);
        foreach ($reads as $action => $command) {
            Backend::$calls = [];
            $response = $controller->$action();
            contract_check(is_array($response) && count(Backend::$calls) === 1 && Backend::$calls[0]['command'] === $command,
                'The read action dispatched a mutation or wrong command: ' . $action);
            contract_check($controller->permissionChecks === $checks && count(RequestFiles::$paths) === $created,
                'The read action invoked a write guard or created a file: ' . $action);
            if ($group === 'pftop') {
                $decoded = json_decode(base64_decode(Backend::$calls[0]['parameters'][0], true), true);
                contract_check($decoded === ['view' => 'default', 'sort' => 'bytes', 'count' => '100', 'filter' => ''],
                    'The pfTop snapshot parameters changed.');
            }
        }
        if (!in_array('setAction', $writes, true)) { continue; }
        $controller->readOnly = false;
        $controller->request->method = 'POST';
        Backend::$calls = [];
        contract_check(($controller->setAction()['status'] ?? '') === 'ok', 'An allowed settings request failed: ' . $group);
        contract_check(count(Backend::$calls) === 2 && Backend::$calls[0]['command'] === $group . ' set', 'Incorrect save command sequence.');
        $path = Backend::$calls[0]['parameters'][0];
        contract_check(json_decode(Backend::$requests[$path], true) === $payload, 'The private file did not carry the submitted settings.');
        contract_check(!str_contains(json_encode(Backend::$calls), 'SENTINEL_CREDENTIAL'), 'A credential reached command arguments.');
        files_cleaned();

        Backend::$throwSet = true;
        Backend::$calls = [];
        try {
            $controller->setAction();
            contract_check(false, 'The isolated backend exception was not raised.');
        } catch (\RuntimeException $error) {
            contract_check($error->getMessage() === 'Isolated backend failure.', 'Unexpected backend exception.');
        } finally {
            Backend::$throwSet = false;
        }
        contract_check(count(Backend::$calls) === 1, 'A failed save dispatched a service mutation.');
        files_cleaned();
        foreach (['', 'not-json', '{"status":"failed","error":"isolated failure"}'] as $reply) {
            Backend::$setReply = $reply;
            Backend::$calls = [];
            contract_check(($controller->setAction()['status'] ?? '') === 'failed', 'A failed settings backend reported success.');
            contract_check(count(Backend::$calls) === 1, 'A rejected save dispatched a service mutation.');
            files_cleaned();
        }
        Backend::$setReply = '{"status":"ok","enabled":true}';
    }
    echo $writeCount . " small-plugin mutations reject GET/read-only access before configd or tempfile creation; reads, private payloads, and exception cleanup passed.\n";
}
