<?php
/* Execute the real controller with a recording backend; no PF device is opened. */
namespace OPNsense\Base {
    class ApiControllerBase { public $request; }
}
namespace OPNsense\Core {
    class Backend {
        public static array $calls = [];
        public static string $reply = '{"status":"ok","output":"native snapshot -->"}';
        public function configdpRun(string $command, array $parameters): string {
            self::$calls[] = [$command, $parameters];
            return self::$reply;
        }
    }
}
namespace {
    use OPNsense\Core\Backend;
    class SnapshotRequest {
        public array $query = [];
        public function getQuery($key, $filter = null, $default = null) { return $this->query[$key] ?? $default; }
    }
    function expect(bool $condition, string $message): void {
        if (!$condition) { throw new RuntimeException($message); }
    }
    require dirname(__DIR__, 2) . '/src/usr/local/opnsense/mvc/app/controllers/OPNsense/Pftop/Api/ServiceController.php';
    $controller = new OPNsense\Pftop\Api\ServiceController();
    $controller->request = new SnapshotRequest();
    $response = $controller->snapshotAction();
    expect($response === ['status' => 'ok', 'output' => 'native snapshot -->'], 'Snapshot text was changed.');
    expect(count(Backend::$calls) === 1 && Backend::$calls[0][0] === 'pftop snapshot', 'Incorrect snapshot dispatch.');
    $parameters = Backend::$calls[0][1];
    expect(count($parameters) === 1 && json_decode(base64_decode($parameters[0], true), true) ===
           ['view' => 'default', 'sort' => 'bytes', 'count' => '100', 'filter' => ''], 'Snapshot defaults changed.');
    $query = ['view' => 'queue', 'sort' => 'age', 'count' => 'all',
              'filter' => 'host 192.0.2.1; $(touch SHOULD_NOT_EXIST)'];
    $controller->request->query = $query;
    Backend::$calls = [];
    $controller->snapshotAction();
    expect(count(Backend::$calls) === 1 && count(Backend::$calls[0][1]) === 1, 'Query was split into shell parameters.');
    $encoded = Backend::$calls[0][1][0];
    expect(preg_match('/^[A-Za-z0-9+\/=]+$/D', $encoded) === 1, 'Query transport is not base64.');
    expect(json_decode(base64_decode($encoded, true), true) === $query, 'The filter or options were modified in transport.');
    foreach (['', 'not-json', 'null', '123'] as $reply) {
        Backend::$reply = $reply;
        $response = $controller->snapshotAction();
        expect(($response['status'] ?? '') === 'failed' && !empty($response['error']), 'Malformed backend reply reported success.');
    }
    Backend::$reply = '{"status":"failed","error":"PF unavailable","output":"diagnostic"}';
    expect($controller->snapshotAction() === ['status' => 'failed', 'error' => 'PF unavailable', 'output' => 'diagnostic'],
           'Backend failure diagnostics were lost.');
    echo "Pftop controller passed: default/query transport, literal filters, snapshot text and backend failures.\n";
}
