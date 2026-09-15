#!/usr/local/bin/php
<?php
/** Add the plugin's existing TUN interface and pass rule under the native lock. */
require_once('script/load_phalcon.php');

use OPNsense\Core\Config;

function backup_lock_current(Config $config): void
{
    $config->lock();
    /* Core's stream reader can downgrade the lock during reload. Reacquire
       exclusive mode and refresh the mutable document without another reader. */
    $config->lock(false);
    $settings = new \OPNsense\Core\AppConfig();
    $fresh = simplexml_load_string(
        file_get_contents($settings->application->configDir . '/config.xml'),
        'SimpleXMLElement',
        LIBXML_NOBLANKS | LIBXML_NONET
    );
    if ($fresh === false) {
        throw new RuntimeException('The current configuration could not be read.');
    }
    $source = dom_import_simplexml($fresh);
    $destination = dom_import_simplexml($config->object());
    while ($destination->firstChild !== null) {
        $destination->removeChild($destination->firstChild);
    }
    foreach ($source->childNodes as $child) {
        $destination->appendChild($destination->ownerDocument->importNode($child, true));
    }
}

function singbox_setup_state_path(): string
{
    $fixture = getenv('SINGBOX_SETUP_FIXTURE');
    return ($fixture ? dirname(dirname($fixture)) . '/state' : '/var/db/os-sing-box') . '/tun-state.json';
}

function singbox_filter_reload_path(): string
{
    return dirname(singbox_setup_state_path()) . '/filter-reload-pending.json';
}

function singbox_prepare_private_directory(string $directory): void
{
    if (is_link($directory)
        || (!is_dir($directory) && !mkdir($directory, 0700, true) && !is_dir($directory))) {
        throw new RuntimeException('The private integration directory could not be created.');
    }
    $info = lstat($directory);
    if ($info === false || ($info['mode'] & 0170000) !== 0040000
        || $info['uid'] !== 0 || !chmod($directory, 0700)) {
        throw new RuntimeException('The private integration directory is invalid.');
    }
}

function singbox_fsync_directory(string $directory): void
{
    $handle = fopen($directory, 'r');
    if ($handle === false) {
        throw new RuntimeException('The private integration directory could not be opened.');
    }
    try {
        $info = fstat($handle);
        if ($info === false || ($info['mode'] & 0170777) !== 0040700
            || $info['uid'] !== 0) {
            throw new RuntimeException('The private integration directory is invalid.');
        }
        if (!fsync($handle)) {
            throw new RuntimeException('The private integration directory could not be synchronized.');
        }
    } finally {
        fclose($handle);
    }
}

function singbox_read_private_file(string $path, int $limit): ?string
{
    $before = @lstat($path);
    if ($before === false) {
        return null;
    }
    if (($before['mode'] & 0170777) !== 0100600 || $before['uid'] !== 0
        || $before['size'] > $limit) {
        throw new RuntimeException('Invalid private integration file.');
    }
    $handle = @fopen($path, 'rb');
    if ($handle === false) {
        throw new RuntimeException('The private integration file could not be opened.');
    }
    try {
        $opened = fstat($handle);
        if ($opened === false || ($opened['mode'] & 0170777) !== 0100600
            || $opened['uid'] !== 0 || $opened['size'] > $limit
            || $opened['dev'] !== $before['dev'] || $opened['ino'] !== $before['ino']) {
            throw new RuntimeException('The private integration file changed before it was opened.');
        }
        $content = stream_get_contents($handle, $limit + 1);
        $after = fstat($handle);
        if ($content === false || strlen($content) > $limit || $after === false) {
            throw new RuntimeException('The private integration file could not be read.');
        }
        foreach (['dev', 'ino', 'size', 'mtime', 'ctime'] as $field) {
            if ($opened[$field] !== $after[$field]) {
                throw new RuntimeException('The private integration file changed while it was read.');
            }
        }
        return $content;
    } finally {
        fclose($handle);
    }
}

function singbox_write_private_file(string $path, string $content, string $prefix): void
{
    $directory = dirname($path);
    singbox_prepare_private_directory($directory);
    if (is_link($path)) {
        throw new RuntimeException('The private integration file path is invalid.');
    }
    $temporary = tempnam($directory, $prefix);
    if ($temporary === false) {
        throw new RuntimeException('The private integration file could not be created.');
    }
    try {
        $handle = fopen($temporary, 'wb');
        if ($handle === false || !chmod($temporary, 0600)) {
            throw new RuntimeException('The private integration file could not be opened.');
        }
        try {
            $pathInfo = lstat($temporary);
            $handleInfo = fstat($handle);
            if ($pathInfo === false || $handleInfo === false
                || ($handleInfo['mode'] & 0170777) !== 0100600 || $handleInfo['uid'] !== 0
                || $handleInfo['dev'] !== $pathInfo['dev'] || $handleInfo['ino'] !== $pathInfo['ino']) {
                throw new RuntimeException('The private integration temporary file is invalid.');
            }
            $offset = 0;
            while ($offset < strlen($content)) {
                $written = fwrite($handle, substr($content, $offset));
                if ($written === false || $written === 0) {
                    throw new RuntimeException('The private integration file could not be written.');
                }
                $offset += $written;
            }
            if (!fflush($handle) || !fsync($handle)) {
                throw new RuntimeException('The private integration file could not be synchronized.');
            }
        } finally {
            fclose($handle);
        }
        if (!rename($temporary, $path)) {
            throw new RuntimeException('The private integration file could not be published.');
        }
        singbox_fsync_directory($directory);
    } finally {
        if (is_file($temporary)) {
            unlink($temporary);
        }
    }
}

function singbox_mark_filter_reload_pending(): void
{
    singbox_write_private_file(
        singbox_filter_reload_path(),
        "{\"schema\":1,\"pending\":true}\n",
        '.filter-reload-'
    );
}

function singbox_save_filter_change(Config $config, bool $backup): void
{
    $directory = dirname(singbox_filter_reload_path());
    singbox_prepare_private_directory($directory);
    $path = $directory . '/filter-reload.lock';
    $existing = @lstat($path);
    if ($existing !== false && (($existing['mode'] & 0170000) !== 0100000
        || $existing['uid'] !== 0)) {
        throw new RuntimeException('Invalid filter reload lock path.');
    }
    $handle = fopen($path, 'c+');
    if ($handle === false) {
        throw new RuntimeException('The filter reload lock could not be opened.');
    }
    try {
        if (!chmod($path, 0600) || !flock($handle, LOCK_EX)) {
            throw new RuntimeException('The filter reload lock could not be acquired.');
        }
        $info = fstat($handle);
        $pathInfo = lstat($path);
        if ($info === false || $pathInfo === false
            || ($info['mode'] & 0170777) !== 0100600 || $info['uid'] !== 0
            || $info['dev'] !== $pathInfo['dev'] || $info['ino'] !== $pathInfo['ino']) {
            throw new RuntimeException('The filter reload lock is invalid.');
        }
        singbox_mark_filter_reload_pending();
        $config->save(null, $backup);
    } finally {
        flock($handle, LOCK_UN);
        fclose($handle);
    }
}

function singbox_setup_journal(?array $record = null): array
{
    $path = singbox_setup_state_path();
    if (is_link($path) || is_link(dirname($path))) {
        throw new RuntimeException('Invalid TUN ownership path.');
    }
    if ($record === null) {
        $content = singbox_read_private_file($path, 65536);
        if ($content === null) {
            return [];
        }
        $value = json_decode($content, true, 32, JSON_THROW_ON_ERROR);
        if (!is_array($value)
            || !preg_match('/^[A-Za-z][A-Za-z0-9_]{0,63}$/D', $value['interface_name'] ?? '')
            || !is_bool($value['created_interface'] ?? null)
            || !is_bool($value['created_rule'] ?? null)
            || !is_string($value['interface_xml'] ?? null)
            || !is_string($value['rule_xml'] ?? null)
            || (isset($value['previous_rule_xml']) && !is_string($value['previous_rule_xml']))) {
            throw new RuntimeException('Invalid TUN ownership journal.');
        }
        return $value;
    }
    singbox_write_private_file($path, json_encode($record, JSON_THROW_ON_ERROR) . "\n", '.tun-');
    return $record;
}

function singbox_node_identity(SimpleXMLElement $node): string
{
    return dom_import_simplexml($node)->C14N();
}

function singbox_legacy_rule_target(SimpleXMLElement $rule): ?string
{
    $uuid = '762b3ec8-79c2-48b4-9793-c653bb3d2265';
    $target = (string)$rule->interface;
    if ((string)$rule['uuid'] !== $uuid || count($rule->attributes()) !== 1
        || count($rule->children()) !== 6 || (string)$rule->type !== 'pass'
        || !preg_match('/^[A-Za-z][A-Za-z0-9_]{0,63}$/D', $target)
        || (string)$rule->ipprotocol !== 'inet' || (string)$rule->descr !== 'sing-box TUN Allow'
        || count($rule->source->children()) !== 1 || (string)$rule->source->network !== $target
        || count($rule->destination->children()) !== 1 || !isset($rule->destination->any)) {
        return null;
    }
    return $target;
}

function singbox_exact_legacy_interface(SimpleXMLElement $interface): bool
{
    return count($interface->attributes()) === 0 && count($interface->children()) === 3
        && isset($interface->if, $interface->descr, $interface->enable)
        && (string)$interface->if === 'tun_singbox' && (string)$interface->descr === 'TUN'
        && (string)$interface->enable === '1';
}

function singbox_retire_legacy(Config $config, bool $backup = true): bool
{
    try {
        backup_lock_current($config);
        $root = $config->object();
        $legacy = null;
        $target = null;
        foreach ($root->filter->rule ?? [] as $rule) {
            $candidate = singbox_legacy_rule_target($rule);
            if ($candidate !== null) {
                $legacy = $rule;
                $target = $candidate;
                break;
            }
        }
        if ($legacy === null) {
            return false;
        }
        $node = dom_import_simplexml($legacy);
        $node->parentNode->removeChild($node);
        $interface = $root->interfaces->$target ?? null;
        if ($interface !== null && singbox_exact_legacy_interface($interface)) {
            $xpath = new DOMXPath(dom_import_simplexml($root)->ownerDocument);
            $referenced = false;
            foreach ($xpath->query('//*[not(*)]') as $candidate) {
                if (preg_match('/(?<![A-Za-z0-9_])' . preg_quote($target, '/') . '(?![A-Za-z0-9_])/', $candidate->textContent)) {
                    $referenced = true;
                    break;
                }
            }
            if (!$referenced) {
                $interfaceNode = dom_import_simplexml($interface);
                $interfaceNode->parentNode->removeChild($interfaceNode);
            }
        }
        singbox_save_filter_change($config, $backup);
        return true;
    } finally {
        $config->unlock();
    }
}

function singbox_setup_network(Config $config, bool $backup = true, bool $remove = false): bool
{
    try {
        backup_lock_current($config);
        $root = $config->object();
        $record = singbox_setup_journal();
        $uuid = '762b3ec8-79c2-48b4-9793-c653bb3d2265';
        $changed = false;
        if ($remove) {
            foreach ($root->filter->rule ?? [] as $rule) {
                if ((string)$rule['uuid'] === $uuid && isset($record['rule_xml'])
                    && hash_equals($record['rule_xml'], singbox_node_identity($rule))) {
                    $node = dom_import_simplexml($rule);
                    if (!empty($record['created_rule'])) {
                        $node->parentNode->removeChild($node);
                    } elseif (!empty($record['previous_rule_xml'])) {
                        $previous = new DOMDocument();
                        $previous->loadXML($record['previous_rule_xml'], LIBXML_NONET);
                        $node->parentNode->replaceChild($node->ownerDocument->importNode($previous->documentElement, true), $node);
                    }
                    if (!empty($record['created_rule'])) {
                        $changed = true;
                    } elseif (!empty($record['previous_rule_xml'])) {
                        $changed = true;
                    }
                    break;
                }
            }
            $name = $record['interface_name'] ?? '';
            if (!empty($record['created_interface']) && isset($root->interfaces->$name)
                && hash_equals($record['interface_xml'] ?? '', singbox_node_identity($root->interfaces->$name))) {
                $xpath = new DOMXPath(dom_import_simplexml($root)->ownerDocument);
                $referenced = false;
                foreach ($xpath->query('//*[not(*)]') as $candidate) {
                    /* Include groups and future references, not only rule fields. */
                    if (preg_match('/(?<![A-Za-z0-9_])' . preg_quote($name, '/') . '(?![A-Za-z0-9_])/', $candidate->textContent)) {
                        $referenced = true;
                        break;
                    }
                }
                if (!$referenced) {
                    $node = dom_import_simplexml($root->interfaces->$name);
                    $node->parentNode->removeChild($node);
                    $changed = true;
                }
            }
            if ($changed) {
                singbox_save_filter_change($config, $backup);
            }
            return $changed;
        }
        $target = '';
        $maximum = -1;
        if (!isset($root->interfaces->lo0)) {
            throw new RuntimeException('The interface configuration is unavailable.');
        }
        foreach ($root->interfaces->children() as $interface) {
            $name = $interface->getName();
            if (preg_match('/^opt([0-9]+)$/D', $name, $found)) {
                $maximum = max($maximum, (int)$found[1]);
            }
            if ((string)$interface->if === 'tun_singbox') {
                $target = $name;
            }
        }
        $created = false;
        if ($target === '') {
            $target = 'opt' . ($maximum + 1);
            $interface = $root->interfaces->addChild($target);
            $interface->addChild('if', 'tun_singbox');
            $interface->addChild('descr', 'Sing-box TUN');
            $interface->addChild('enable', '1');
            $node = dom_import_simplexml($interface);
            $after = dom_import_simplexml($root->interfaces->lo0)->nextSibling;
            if ($after !== $node) {
                $node->parentNode->insertBefore($node, $after);
            }
            $changed = $created = true;
        }
        if (($record['interface_name'] ?? '') !== $target) {
            $record = ['interface_name' => $target, 'created_interface' => $created,
                'interface_xml' => singbox_node_identity($root->interfaces->$target), 'created_rule' => false];
        }
        $existing = null;
        foreach ($root->filter->rule ?? [] as $rule) {
            if ((string)$rule['uuid'] === $uuid) {
                $existing = $rule;
                break;
            }
        }
        if ($existing === null) {
            if (!isset($root->filter)) {
                $root->addChild('filter');
            }
            $existing = $root->filter->addChild('rule');
            $existing->addAttribute('uuid', $uuid);
            $existing->addChild('type', 'pass');
            $existing->addChild('interface', $target);
            $existing->addChild('ipprotocol', 'inet46');
            $existing->addChild('source')->addChild('any');
            $existing->addChild('destination')->addChild('any');
            $existing->addChild('descr', 'sing-box TUN Allow');
            /* Append after administrator TUN restrictions, never ahead of them. */
            $record['created_rule'] = true;
            $changed = true;
        } elseif ((string)$existing->type === 'pass' && (string)$existing->interface === $target
            && (string)$existing->descr === 'sing-box TUN Allow'
            && (string)$existing->ipprotocol === 'inet' && (string)$existing->source->network === $target
            && isset($existing->destination->any) && count($existing->children()) === 6) {
            /* Migrate only the exact legacy generated policy, preserving edits. */
            $record['previous_rule_xml'] = singbox_node_identity($existing);
            $source = dom_import_simplexml($existing->source);
            while ($source->firstChild !== null) {
                $source->removeChild($source->firstChild);
            }
            $source->appendChild($source->ownerDocument->createElement('any'));
            $existing->ipprotocol = 'inet46';
            $changed = true;
        }
        if ($changed || !isset($record['rule_xml'])) {
            $record['rule_xml'] = singbox_node_identity($existing);
            singbox_setup_journal($record);
        }
        if ($changed) {
            singbox_save_filter_change($config, $backup);
        }
        return $changed;
    } finally {
        $config->unlock();
    }
}

if (realpath($_SERVER['SCRIPT_FILENAME'] ?? '') === __FILE__) {
    try {
        $mode = $argv[1] ?? 'enable';
        if (!in_array($mode, ['enable', 'remove', 'retire-legacy'], true)) {
            throw new RuntimeException('Invalid integration operation.');
        }
        $changed = $mode === 'retire-legacy'
            ? singbox_retire_legacy(Config::getInstance())
            : singbox_setup_network(Config::getInstance(), true, $mode === 'remove');
        fwrite(STDOUT, $changed ? "changed\n" : "unchanged\n");
    } catch (Throwable $error) {
        fwrite(STDERR, "The Sing-box interface configuration could not be synchronized.\n");
        exit(1);
    }
}
