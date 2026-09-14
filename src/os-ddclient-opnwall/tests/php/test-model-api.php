<?php
namespace OPNsense\Base\Messages {
    class Message {
        public function __construct(public string $message, public string $field) {}
    }
    class Messages extends \ArrayObject {
        public function appendMessage(Message $message): void { $this->append($message); }
    }
}
namespace OPNsense\Base {
    class BaseModel {
        public array $nodes = [];
        public function performValidation($all = false) { return new \OPNsense\Base\Messages\Messages(); }
        public function getFlatNodes(): array { return $this->nodes; }
    }
    class ApiMutableModelControllerBase {
        public array $calls = [];
        public string $method = 'POST';
        public bool $readOnly = false;
        public function getAction() {
            return ['ddclient' => ['general' => ['enabled' => '1'], 'accounts' => ['password' => 'SENTINEL_PRIVATE']]];
        }
        private function operation(string $name, array $arguments): array {
            if ($this->method !== 'POST' || $this->readOnly) { throw new \RuntimeException('Mutation denied.'); }
            $this->calls[] = [$name, $arguments];
            return ['result' => 'saved'];
        }
        protected function setBase(...$arguments): array { return $this->operation('set', $arguments); }
        protected function addBase(...$arguments): array { return $this->operation('add', $arguments); }
        protected function delBase(...$arguments): array { return $this->operation('delete', $arguments); }
        protected function toggleBase(...$arguments): array { return $this->operation('toggle', $arguments); }
        protected function getBase(...$arguments): array { $this->calls[] = ['get', $arguments]; return ['account' => []]; }
        protected function searchBase($path, $columns, $sort): array {
            $this->calls[] = ['search', [$path, $columns, $sort]];
            return ['rows' => [['service' => 'Custom', 'protocol' => 'post'], ['service' => 'Aliyun DNS', 'protocol' => 'dyndns2']]];
        }
        public function metadata(): array { return [static::$internalModelClass, static::$internalModelName]; }
    }
    class ApiMutableServiceControllerBase {
        public function metadata(): array { return [static::$internalServiceClass, static::$internalServiceEnabled,
            static::$internalServiceTemplate, static::$internalServiceName]; }
    }
}
namespace {
    $root = $argv[1] ?? dirname(__DIR__, 2);
    $modelFile = $root . '/src/usr/local/opnsense/mvc/app/models/OPNsense/DynDNS/DynDNS.php';
    require($modelFile);
    foreach (['Accounts', 'Settings', 'Service'] as $controller) {
        require($root . '/src/usr/local/opnsense/mvc/app/controllers/OPNsense/DynDNS/Api/' . $controller . 'Controller.php');
    }
    function check(bool $condition, string $message): void {
        if (!$condition) { throw new RuntimeException($message); }
    }
    class Value {
        public function __construct(public string $value) {}
        public function __toString(): string { return $this->value; }
        public function isEqual($value): bool { return $this->value === $value; }
    }
    class Account {
        public string $__reference = 'accounts.account.fixture';
        public $service;
        public $server;
        public $protocol;
        public function __construct(string $service, string $protocol, string $server) {
            foreach (compact('service', 'protocol', 'server') as $name => $value) { $this->$name = new Value($value); }
        }
        public function getInternalXMLTagName(): string { return 'account'; }
    }
    class Node {
        public function __construct(public string $tag, public Account $parent, public bool $changed) {}
        public function getInternalXMLTagName(): string { return $this->tag; }
        public function getParentNode(): Account { return $this->parent; }
        public function isFieldChanged(): bool { return $this->changed; }
    }
    function validate(string $service, string $protocol, string $server, string $changed = 'server', bool $full = false): array {
        $account = new Account($service, $protocol, $server);
        $model = new \OPNsense\DynDNS\DynDNS();
        foreach (['service', 'protocol', 'server'] as $name) { $model->nodes[$name] = new Node($name, $account, $name === $changed); }
        return iterator_to_array($model->performValidation($full));
    }
    foreach ([['custom', 'post', 'https://provider.invalid/update', false], ['custom', 'post', 'not a URI', true],
              ['custom', 'dyndns2', 'provider.invalid', false], ['custom', 'dyndns2', 'https://provider.invalid/', true],
              ['powerdns', 'dyndns2', 'https://provider.invalid/', false], ['powerdns', 'dyndns2', '', true],
              ['aliyun', 'dyndns2', '', false]] as [$service, $protocol, $server, $invalid]) {
        $messages = validate($service, $protocol, $server);
        check(!empty($messages) === $invalid, 'Provider-dependent URI/domain validation did not match the configuration.');
        if ($invalid) { check($messages[0]->field === 'accounts.account.fixture.server', 'A validation error points at another account.'); }
    }
    check(!empty(validate('custom', 'post', '', 'service')), 'Changing only service bypassed its required server validation.');
    check(!empty(validate('custom', 'post', '', 'unchanged', true)), 'Full validation skipped an unchanged invalid server.');
    $accounts = new \OPNsense\DynDNS\Api\AccountsController();
    $rows = $accounts->searchItemAction()['rows'];
    check($rows[0]['service'] === 'Custom (post)' && !isset($rows[0]['protocol']) && !isset($rows[1]['protocol']), 'Account search lost its custom protocol label or exposed the internal column.');
    $search = $accounts->calls[0][1];
    check($search[0] === 'accounts.account' && !in_array('password', $search[1], true), 'Search selected another mount or included credentials.');
    $accounts->setItemAction('fixture-uuid');
    check(end($accounts->calls) === ['set', ['account', 'accounts.account', 'fixture-uuid']], 'Set account targets the wrong model node.');
    $accounts->addItemAction();
    check(end($accounts->calls) === ['add', ['account', 'accounts.account']], 'Add account targets the wrong model node.');
    $accounts->delItemAction('fixture-uuid');
    check(end($accounts->calls) === ['delete', ['accounts.account', 'fixture-uuid']], 'Delete account targets the wrong model node.');
    $accounts->toggleItemAction('fixture-uuid', '0');
    check(end($accounts->calls) === ['toggle', ['accounts.account', 'fixture-uuid', '0']], 'Toggle lost its requested state or account UUID.');
    foreach (['GET', 'readonly'] as $denied) {
        $accounts->method = $denied === 'GET' ? 'GET' : 'POST';
        $accounts->readOnly = $denied === 'readonly';
        $before = count($accounts->calls);
        foreach ([fn() => $accounts->setItemAction('fixture'), fn() => $accounts->addItemAction(),
                  fn() => $accounts->delItemAction('fixture'), fn() => $accounts->toggleItemAction('fixture')] as $mutation) {
            try { $mutation(); throw new LogicException('A denied mutation succeeded.'); } catch (RuntimeException $error) {}
        }
        check(count($accounts->calls) === $before, 'A controller bypassed inherited mutation permissions.');
    }
    check((new \OPNsense\DynDNS\Api\SettingsController())->getAction() === ['ddclient' => ['general' => ['enabled' => '1']]], 'General settings exposed account credentials.');
    check((new \OPNsense\DynDNS\Api\ServiceController())->metadata() === ['\\OPNsense\\DynDNS\\DynDNS', 'general.enabled', 'OPNsense/ddclient', 'ddclient'], 'The inherited service targets another template, model or daemon.');
    echo "DynDNS model/API contract passed: provider validation, inherited mutation guards, account scopes and credential-free general/search data.\n";
}
