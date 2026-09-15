<?php
namespace OPNsense\Base {
    class ApiControllerBase {
        public $request;
        public bool $readOnly = false;
        protected function throwReadOnly(): void {
            if ($this->readOnly) { throw new \RuntimeException('Read-only account.'); }
        }
    }
    class ApiMutableModelControllerBase extends ApiControllerBase {
        public function metadata(): array { return [static::$internalModelClass, static::$internalModelName]; }
    }
}
namespace OPNsense\Core {
    class Backend {
        public static string $response = '';
        public static array $calls = [];
        public function configdRun(string $command): string {
            self::$calls[] = $command;
            return self::$response;
        }
    }
}
namespace {
    use OPNsense\Core\Backend;
    use OPNsense\Unboundcustom\Api\ServiceController;
    use OPNsense\Unboundcustom\Api\GeneralController;
    $root = $argv[1] ?? dirname(__DIR__, 2);
    require($root . '/src/opnsense/mvc/app/controllers/OPNsense/Unboundcustom/Api/ServiceController.php');
    require($root . '/src/opnsense/mvc/app/controllers/OPNsense/Unboundcustom/Api/GeneralController.php');
    function api_check(bool $condition, string $message): void {
        if (!$condition) { throw new RuntimeException($message); }
    }
    class Request {
        public string $method = 'POST';
        public function getMethod(): string { return $this->method; }
    }
    $controller = new ServiceController();
    $controller->request = new Request();
    foreach (['GET', 'PUT', 'DELETE'] as $method) {
        $controller->request->method = $method;
        api_check($controller->applyAction()['status'] === 'failed', 'A non-POST request was accepted.');
    }
    api_check(Backend::$calls === [], 'A non-POST request reached configd.');
    $controller->request->method = 'POST';
    $controller->readOnly = true;
    try {
        $controller->applyAction();
        throw new LogicException('A read-only request was accepted.');
    } catch (RuntimeException $error) {
        api_check(Backend::$calls === [], 'A read-only request reached configd.');
    }
    $controller->readOnly = false;
    foreach (['busy', 'backup_failed', 'template_failed', 'stage_failed', 'validation_failed', 'restart_failed', 'recovery_failed', 'apply_failed', 'state_failed', 'success'] as $code) {
        Backend::$response = json_encode(['status' => $code === 'success' ? 'ok' : 'failed',
                                          'code' => $code, 'detail' => 'isolated detail'], JSON_THROW_ON_ERROR);
        $answer = $controller->applyAction();
        api_check($answer['status'] === ($code === 'success' ? 'ok' : 'failed'), 'An apply failure was reported as success.');
        api_check(str_ends_with($answer['message'], "\nisolated detail") &&
                  !str_contains($answer['message'], 'Unknown apply'), 'The known result or its detail was lost.');
        api_check(end(Backend::$calls) === 'unboundcustom apply', 'The controller invoked an unrelated backend action.');
    }
    foreach (['', 'not JSON', '{}'] as $raw) {
        Backend::$response = $raw;
        $answer = $controller->applyAction();
        api_check($answer['status'] === 'failed' && $answer['message'] !== '', 'An empty/invalid apply result succeeded.');
    }
    api_check((new GeneralController())->metadata() === ['\\OPNsense\\Unboundcustom\\General', 'general'],
              'The inherited settings API points at another model or mount.');
    echo "Unboundcustom API contract passed: POST/read-only guards, exact action/model and all apply failure codes.\n";
}
