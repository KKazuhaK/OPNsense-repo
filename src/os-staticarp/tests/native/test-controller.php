<?php
/* Run real API routes with private tempfiles and scripted configd replies. */
namespace OPNsense\Base {
    class ApiControllerBase {
        public $request;
        public bool $readOnly = false;
        public int $checks = 0;
        protected function throwReadOnly(): void {
            $this->checks++;
            if ($this->readOnly) { throw new \RuntimeException('Read-only fixture.'); }
        }
    }
}
namespace OPNsense\Core {
    class Backend {
        public static array $calls = [];
        public static array $responses = [];
        public static array $requests = [];
        public static bool $throwSet = false;
        public function configdRun(string $command): string {
            self::$calls[] = [$command, []];
            return self::$responses[$command] ?? 'OK';
        }
        public function configdpRun(string $command, array $parameters): string {
            self::$calls[] = [$command, $parameters];
            if ($command === 'staticarp set') {
                $path = $parameters[0] ?? '';
                if (count($parameters) !== 1 || !is_file($path) || (fileperms($path) & 0777) !== 0600) {
                    throw new \RuntimeException('Settings must use one private request file.');
                }
                self::$requests[$path] = json_decode(file_get_contents($path), true);
                if (self::$throwSet) { throw new \RuntimeException('Isolated set failure.'); }
            }
            return self::$responses[$command] ?? '{"status":"ok","enabled":true}';
        }
    }
}
namespace {
    use OPNsense\Core\Backend;
    class StaticarpRequest {
        public string $method = 'POST';
        public array $post = ['settings' => ['enabled' => true, 'entries' => '192.0.2.7 aa:bb:cc:dd:ee:07']];
        public array $query = ['interface' => 'lan'];
        public function getMethod(): string { return $this->method; }
        public function getPost($key, $filter = null, $default = null) { return $this->post[$key] ?? $default; }
        public function getQuery($key, $filter = null, $default = null) { return $this->query[$key] ?? $default; }
    }
    function expect(bool $condition, string $message): void {
        if (!$condition) { throw new RuntimeException($message); }
    }
    function fresh_calls(): void { Backend::$calls = []; }
    function private_requests_removed(): void {
        foreach (Backend::$requests as $path => $payload) { expect(!file_exists($path), 'A settings request file was retained.'); }
    }
    $directory = dirname(__DIR__, 2) . '/src/usr/local/opnsense/mvc/app/controllers/OPNsense/Staticarp/Api/';
    require $directory . 'SettingsController.php';
    require $directory . 'ServiceController.php';
    $settings = new OPNsense\Staticarp\Api\SettingsController();
    $service = new OPNsense\Staticarp\Api\ServiceController();
    foreach ([$settings, $service] as $controller) { $controller->request = new StaticarpRequest(); }
    foreach ([[$settings, 'setAction'], [$service, 'applyAction'], [$service, 'resetAction']] as [$controller, $method]) {
        fresh_calls();
        $controller->request->method = 'GET';
        expect(($controller->$method()['status'] ?? '') === 'failed' && Backend::$calls === [], 'GET dispatched a mutation.');
        $controller->request->method = 'POST';
        $controller->readOnly = true;
        $before = $controller->checks;
        try { $controller->$method(); throw new RuntimeException('Read-only mutation was accepted.'); }
        catch (RuntimeException $error) { expect($error->getMessage() === 'Read-only fixture.', 'Wrong permission failure.'); }
        expect($controller->checks === $before + 1 && Backend::$calls === [], 'Guard ran after backend dispatch.');
        $controller->readOnly = false;
    }
    foreach ([true => 'apply', false => 'reset'] as $enabled => $action) {
        fresh_calls();
        Backend::$responses = ['staticarp set' => json_encode(['status' => 'ok', 'enabled' => (bool)$enabled])];
        expect($settings->setAction()['status'] === 'ok', 'A valid settings save failed.');
        expect(array_column(Backend::$calls, 0) === ['staticarp set', 'staticarp ' . $action], 'Saved enable state chose the wrong action.');
        $path = Backend::$calls[0][1][0];
        expect(Backend::$requests[$path] === $settings->request->post['settings'], 'Settings changed in private transport.');
        private_requests_removed();
    }
    Backend::$responses = ['staticarp set' => '{"status":"ok","enabled":true}', 'staticarp apply' => 'failed'];
    fresh_calls();
    $result = $settings->setAction();
    expect($result['status'] === 'failed' && $result['saved'] === true, 'Service failure concealed already-saved settings.');
    foreach (['', 'not-json', '{"status":"failed","saved":true,"error":"backup failed"}'] as $reply) {
        Backend::$responses = ['staticarp set' => $reply];
        fresh_calls();
        expect(($settings->setAction()['status'] ?? '') === 'failed', 'Invalid/rejected set reported success.');
        expect(count(Backend::$calls) === 1, 'Rejected settings applied kernel state.');
        private_requests_removed();
    }
    Backend::$throwSet = true;
    fresh_calls();
    try { $settings->setAction(); throw new RuntimeException('Backend exception was lost.'); }
    catch (RuntimeException $error) { expect($error->getMessage() === 'Isolated set failure.', 'Wrong backend failure.'); }
    Backend::$throwSet = false;
    expect(count(Backend::$calls) === 1, 'Backend exception dispatched apply.');
    private_requests_removed();
    foreach ([null, 'bad', ['entries' => str_repeat('x', 2 * 1048576)]] as $payload) {
        $settings->request->post['settings'] = $payload;
        fresh_calls();
        expect($settings->setAction()['status'] === 'failed' && Backend::$calls === [], 'Invalid/oversized request reached configd.');
    }
    Backend::$responses = ['staticarp get' => '{"settings":{"enabled":false},"arp":"isolated"}',
                           'staticarp script' => '{"status":"ok","filename":"arp_vtnet1.cmd","script":"arp -a\\r\\n"}'];
    fresh_calls();
    expect($settings->getAction()['arp'] === 'isolated' && Backend::$calls === [['staticarp get', []]], 'Read dispatched a mutation.');
    fresh_calls();
    expect($settings->scriptAction()['filename'] === 'arp_vtnet1.cmd' && Backend::$calls === [['staticarp script', ['lan']]],
           'Client script did not use one validated interface parameter.');
    foreach (['', 'lan;id', '../lan', 'wan$(id)', 'lan name'] as $name) {
        $settings->request->query['interface'] = $name;
        fresh_calls();
        expect($settings->scriptAction()['status'] === 'failed' && Backend::$calls === [], 'Invalid interface reached the backend.');
    }
    foreach (["enabled=YES\nentries=12\n" => ['enabled' => true, 'entries' => 12],
              "enabled=NO\nentries=0\n" => ['enabled' => false, 'entries' => 0],
              "not_enabled=YES\nentries=12\n" => ['enabled' => false, 'entries' => 12],
              "enabled=YES-invalid\nentries=unknown\n" => ['enabled' => false, 'entries' => 0],
              'unavailable' => ['enabled' => false, 'entries' => 0]] as $output => $expected) {
        Backend::$responses = ['staticarp status' => $output];
        expect($service->statusAction() === $expected, 'Status parsing changed.');
    }
    foreach (['applyAction', 'resetAction'] as $method) {
        Backend::$responses = [];
        expect($service->$method() === ['status' => 'ok'], 'Successful kernel action reported failure.');
        Backend::$responses = ['staticarp apply' => 'ERROR', 'staticarp reset' => 'ERROR'];
        expect($service->$method()['status'] === 'failed', 'Failed kernel action reported success.');
    }
    echo "Staticarp API passed: guards, private transport/cleanup, enable/reset selection, saved failures, scripts and status.\n";
}
