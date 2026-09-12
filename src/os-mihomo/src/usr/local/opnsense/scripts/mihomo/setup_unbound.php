#!/usr/local/bin/php
<?php

/* Integrate only the plugin's own DNS forwarder and TUN interface. */
const FORWARD_UUID = 'b126bf65-a985-49ca-a9d2-16f156aac198';
const RULE_UUID = '5a73c3dc-69b1-4e15-89cb-b542aa2c1154';
const FAKE_IP_CIDR = '198.18.0.0/15';

function mihomoChild(DOMDocument $doc, DOMElement $parent, string $name, string $value = ''): DOMElement
{
    foreach ($parent->childNodes as $node) {
        if ($node instanceof DOMElement && $node->tagName === $name) {
            $node->nodeValue = $value;
            return $node;
        }
    }
    $node = $doc->createElement($name);
    if ($value !== '') {
        $node->appendChild($doc->createTextNode($value));
    }
    $parent->appendChild($node);
    return $node;
}

function mihomoPersist(string $path, array $state): void
{
    $temporary = tempnam(dirname($path), '.mihomo-state-');
    if ($temporary === false || file_put_contents($temporary, json_encode($state, JSON_THROW_ON_ERROR)) === false) {
        throw new RuntimeException('Unable to write integration state.');
    }
    chmod($temporary, 0600);
    if (!rename($temporary, $path)) {
        @unlink($temporary);
        throw new RuntimeException('Unable to persist integration state.');
    }
}

function mihomoState(string $path): ?array
{
    if (!file_exists($path)) {
        return null;
    }
    $value = json_decode((string)file_get_contents($path), true, 512, JSON_THROW_ON_ERROR);
    if (!is_array($value)) {
        throw new RuntimeException('Invalid integration state.');
    }
    return $value;
}

function mihomoEnsureTun(DOMDocument $doc, DOMXPath $xpath, string $statePath): void
{
    $saved = mihomoState($statePath);
    $interfaces = $xpath->query('/opnsense/interfaces')->item(0);
    $filter = $xpath->query('/opnsense/filter')->item(0);
    if (!$interfaces instanceof DOMElement || !$filter instanceof DOMElement) {
        throw new RuntimeException('The interface or firewall model is missing.');
    }
    $target = '';
    $maximum = -1;
    foreach ($interfaces->childNodes as $node) {
        if (!$node instanceof DOMElement) {
            continue;
        }
        if (preg_match('/^opt([0-9]+)$/', $node->tagName, $matches)) {
            $maximum = max($maximum, (int)$matches[1]);
        }
        if (trim($xpath->evaluate('string(./if)', $node)) === 'tun_mihomo') {
            $target = $node->tagName;
        }
    }
    $created = $target === '';
    $target = $target ?: 'opt' . ($maximum + 1);
    $existingRule = $xpath->query('/opnsense/filter/rule[@uuid="' . RULE_UUID . '"]')->item(0);
    if ($saved === null) {
        mihomoPersist($statePath, ['interface' => $target, 'created_interface' => $created, 'created_rule' => !$existingRule]);
    } elseif ($saved['interface'] !== $target && !$created) {
        throw new RuntimeException('The Mihomo interface assignment changed.');
    }
    if ($saved !== null && $created) {
        $target = $saved['interface'];
        if ($xpath->query('/opnsense/interfaces/' . $target)->length > 0) {
            throw new RuntimeException('The saved interface assignment is occupied.');
        }
    }
    if ($created) {
        $interface = $doc->createElement($target);
        $interfaces->appendChild($interface);
        mihomoChild($doc, $interface, 'if', 'tun_mihomo');
        mihomoChild($doc, $interface, 'descr', 'Mihomo TUN');
        mihomoChild($doc, $interface, 'enable', '1');
    }
    if (!$existingRule) {
        $rule = $doc->createElement('rule');
        $rule->setAttribute('uuid', RULE_UUID);
        $filter->appendChild($rule);
        mihomoChild($doc, $rule, 'type', 'pass');
        mihomoChild($doc, $rule, 'interface', $target);
        mihomoChild($doc, $rule, 'ipprotocol', 'inet');
        $source = mihomoChild($doc, $rule, 'source');
        mihomoChild($doc, $source, 'network', $target);
        $destination = mihomoChild($doc, $rule, 'destination');
        mihomoChild($doc, $destination, 'any');
        mihomoChild($doc, $rule, 'descr', 'Mihomo TUN Allow');
    }
}

function mihomoCronCommand(string $command): bool
{
    return in_array($command, ['mihomo sub-update', 'mihomolocal update', 'mihomolocal repair',
        '/usr/bin/mihomo_sub', '/usr/local/etc/mihomo/sub/sub.sh'], true);
}

function mihomoRemoveTun(DOMXPath $xpath, string $path): void
{
    $tun = mihomoState($path);
    if ($tun !== null && $tun['created_interface']) {
        $node = $xpath->query('/opnsense/interfaces/' . $tun['interface'])->item(0);
        if ($node instanceof DOMElement && trim($xpath->evaluate('string(./if)', $node)) === 'tun_mihomo') {
            $node->parentNode->removeChild($node);
        }
    }
    if ($tun !== null && $tun['created_rule']) {
        foreach ($xpath->query('/opnsense/filter/rule[@uuid="' . RULE_UUID . '"]') as $node) {
            $node->parentNode->removeChild($node);
        }
    }
}

$mode = $argv[1] ?? '';
// The old package may call the replacement helper during its removal phase.
if ($mode === 'uninstall') {
    $mode = 'disable';
}
$fallback = ($argv[2] ?? '1') === '1';
if (!in_array($mode, ['enable', 'enable-tun', 'disable', 'remove', 'restore-cron'], true)) {
    fwrite(STDERR, "usage: setup_unbound.php enable|enable-tun|disable|remove|restore-cron [fallback:0|1]\n");
    exit(64);
}
$root = rtrim(getenv('OS_MIHOMO_ROOT') ?: '', '/');
$stateDir = $root . '/var/db/os-mihomo';
$dnsStatePath = $stateDir . '/dns-state.json';
$tunStatePath = $stateDir . '/tun-state.json';
$configPath = $root . '/conf/config.xml';
if (!is_dir($stateDir) && !mkdir($stateDir, 0700, true)) {
    fwrite(STDERR, "Unable to create integration state directory.\n");
    exit(1);
}
$native = null;
$handle = null;
try {
    if ($root === '') {
        require_once('/usr/local/etc/inc/config.inc');
        $native = OPNsense\Core\Config::getInstance();
        $native->lock();
        $doc = dom_import_simplexml($native->object())->ownerDocument;
    } else {
        $handle = fopen($configPath, 'r');
        if ($handle === false || !flock($handle, LOCK_EX)) {
            throw new RuntimeException('Unable to lock configuration.');
        }
        $doc = new DOMDocument();
        $doc->preserveWhiteSpace = true;
        if (!$doc->load($configPath, LIBXML_NONET)) {
            throw new RuntimeException('Unable to read configuration.');
        }
    }
    $before = $doc->saveXML();
    $xpath = new DOMXPath($doc);
    if ($mode === 'restore-cron') {
        $legacyPath = $stateDir . '/migrate/cron.json';
        if (file_exists($legacyPath)) {
            foreach (json_decode((string)file_get_contents($legacyPath), true, 512, JSON_THROW_ON_ERROR) as $item) {
                if (!mihomoCronCommand(trim($item['command'] ?? ''))) {
                    continue;
                }
                $clone = $doc->createElement('item');
                foreach (['minutes', 'hours', 'mday', 'month', 'wday'] as $field) {
                    mihomoChild($doc, $clone, $field, (string)($item[$field] ?? '*'));
                }
                mihomoChild($doc, $clone, 'command', 'mihomo sub-update');
                $cron = $xpath->query('/opnsense/cron')->item(0);
                if (!$cron instanceof DOMElement) {
                    $cron = $doc->createElement('cron');
                    $doc->documentElement->appendChild($cron);
                }
                $duplicate = false;
                foreach ($xpath->query('./item', $cron) as $existing) {
                    $signature = static function ($node) use ($xpath): array {
                        $value = [];
                        foreach (['command', 'minutes', 'hours', 'mday', 'month', 'wday'] as $field) {
                            $value[$field] = trim($xpath->evaluate('string(./' . $field . ')', $node));
                        }
                        return $value;
                    };
                    if ($signature($existing) === $signature($clone)) {
                        $duplicate = true;
                    }
                }
                if (!$duplicate) {
                    $cron->appendChild($clone);
                }
            }
        }
    } elseif ($mode === 'enable-tun') {
        mihomoEnsureTun($doc, $xpath, $tunStatePath);
    } else {
        $unbound = $xpath->query('/opnsense/OPNsense/unboundplus')->item(0);
        $forwarding = $xpath->query('./forwarding/enabled', $unbound)->item(0);
        $private = $xpath->query('./advanced/privateaddress', $unbound)->item(0);
        $dots = $xpath->query('./dots', $unbound)->item(0);
        if (!$unbound instanceof DOMElement || !$forwarding instanceof DOMElement || !$private instanceof DOMElement || !$dots instanceof DOMElement) {
            throw new RuntimeException('The Unbound model is incomplete.');
        }
        $snapshot = mihomoState($dnsStatePath);
        $forwarder = $xpath->query('./dot[@uuid="' . FORWARD_UUID . '"]', $dots)->item(0);
        if ($mode === 'enable') {
            mihomoEnsureTun($doc, $xpath, $tunStatePath);
            if ($snapshot === null) {
                $roots = [];
                foreach ($xpath->query('./dot', $dots) as $dot) {
                    $domain = trim($xpath->evaluate('string(./domain)', $dot));
                    if (in_array($domain, ['', '.'], true) && $dot->getAttribute('uuid') !== FORWARD_UUID) {
                        if ($dot->getAttribute('uuid') === '') {
                            throw new RuntimeException('Existing root DNS entries must have UUIDs.');
                        }
                        $roots[$dot->getAttribute('uuid')] = trim($xpath->evaluate('string(./enabled)', $dot));
                    }
                }
                $snapshot = ['forwarding' => $forwarding->textContent, 'roots' => $roots,
                             'had_fake_ip_private_address' => in_array(FAKE_IP_CIDR, explode(',', $private->textContent), true)];
                mihomoPersist($dnsStatePath, $snapshot);
            }
            $forwarding->nodeValue = '0';
            foreach ($snapshot['roots'] as $uuid => $enabled) {
                $node = $xpath->query('./dot[@uuid="' . $uuid . '"]', $dots)->item(0);
                if ($node instanceof DOMElement) {
                    mihomoChild($doc, $node, 'enabled', '0');
                }
            }
            $addresses = array_filter(array_map('trim', explode(',', $private->textContent)), static fn($v) => $v !== '' && $v !== FAKE_IP_CIDR);
            $private->nodeValue = implode(',', $addresses);
            if (!$forwarder instanceof DOMElement) {
                $forwarder = $doc->createElement('dot');
                $forwarder->setAttribute('uuid', FORWARD_UUID);
                $dots->appendChild($forwarder);
            }
            foreach (['enabled' => '1', 'type' => 'forward', 'domain' => '.', 'server' => '127.0.0.1',
                      'port' => '1053', 'verify' => '', 'forward_tcp_upstream' => '0',
                      'forward_first' => $fallback ? '1' : '0', 'description' => 'Mihomo DNS forwarding'] as $key => $value) {
                mihomoChild($doc, $forwarder, $key, $value);
            }
        } else {
            if ($forwarder instanceof DOMElement) {
                $dots->removeChild($forwarder);
            }
            if ($snapshot !== null) {
                if (trim($forwarding->textContent) === '0') {
                    $forwarding->nodeValue = (string)$snapshot['forwarding'];
                }
                foreach ($snapshot['roots'] as $uuid => $enabled) {
                    $node = $xpath->query('./dot[@uuid="' . $uuid . '"]', $dots)->item(0);
                    if ($node instanceof DOMElement && trim($xpath->evaluate('string(./enabled)', $node)) === '0') {
                        mihomoChild($doc, $node, 'enabled', (string)$enabled);
                    }
                }
                if ($snapshot['had_fake_ip_private_address']) {
                    $addresses = array_values(array_filter(array_map('trim', explode(',', $private->textContent))));
                    if (!in_array(FAKE_IP_CIDR, $addresses, true)) {
                        $addresses[] = FAKE_IP_CIDR;
                        $private->nodeValue = implode(',', $addresses);
                    }
                }
            }
            if ($mode === 'remove') {
                foreach ($xpath->query('/opnsense/cron/item') as $item) {
                    if (mihomoCronCommand(trim($xpath->evaluate('string(./command)', $item)))) {
                        $item->parentNode->removeChild($item);
                    }
                }
            }
            mihomoRemoveTun($xpath, $tunStatePath);
        }
    }
    if ($before !== $doc->saveXML()) {
        if ($native !== null) {
            $native->save(make_config_revision_entry('Update Mihomo transparent integration'));
        } else {
            $temporary = tempnam(dirname($configPath), '.mihomo-config-');
            if ($temporary === false || $doc->save($temporary) === false || !rename($temporary, $configPath)) {
                throw new RuntimeException('Unable to save configuration.');
            }
        }
    }
    if (in_array($mode, ['disable', 'remove'], true)) {
        @unlink($dnsStatePath);
        @unlink($tunStatePath);
    }
    if ($mode === 'restore-cron') {
        @unlink($stateDir . '/migrate/cron.json');
        @unlink($stateDir . '/migrate/config.xml');
    }
    echo $before !== $doc->saveXML() ? "Mihomo integration updated.\n" : "Mihomo integration unchanged.\n";
} catch (Throwable $error) {
    fwrite(STDERR, "Mihomo integration failed. Existing DNS state is retained for recovery.\n");
    exit(1);
} finally {
    if ($native !== null) {
        $native->unlock();
    }
    if (is_resource($handle)) {
        fclose($handle);
    }
}
