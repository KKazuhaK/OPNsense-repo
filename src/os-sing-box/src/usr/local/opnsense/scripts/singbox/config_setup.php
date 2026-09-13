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

function singbox_setup_network(Config $config, bool $backup = true): bool
{
    try {
        backup_lock_current($config);
        $root = $config->object();
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
        $changed = false;
        if ($target === '') {
            $target = 'opt' . ($maximum + 1);
            $interface = $root->interfaces->addChild($target);
            $interface->addChild('if', 'tun_singbox');
            $interface->addChild('descr', 'TUN');
            $interface->addChild('enable', '1');
            $node = dom_import_simplexml($interface);
            $after = dom_import_simplexml($root->interfaces->lo0)->nextSibling;
            if ($after !== $node) {
                $node->parentNode->insertBefore($node, $after);
            }
            $changed = true;
        }
        $uuid = '762b3ec8-79c2-48b4-9793-c653bb3d2265';
        $found = false;
        if (isset($root->filter)) {
            foreach ($root->filter->rule as $rule) {
                $found = $found || (string)$rule['uuid'] === $uuid;
            }
        }
        if (!$found) {
            if (!isset($root->filter)) {
                $root->addChild('filter');
            }
            $rule = $root->filter->addChild('rule');
            $rule->addAttribute('uuid', $uuid);
            $rule->addChild('type', 'pass');
            $rule->addChild('interface', $target);
            $rule->addChild('ipprotocol', 'inet');
            $rule->addChild('source')->addChild('network', $target);
            $rule->addChild('destination')->addChild('any');
            $rule->addChild('descr', 'sing-box TUN Allow');
            $node = dom_import_simplexml($rule);
            if ($node->parentNode->firstChild !== $node) {
                $node->parentNode->insertBefore($node, $node->parentNode->firstChild);
            }
            $changed = true;
        }
        if ($changed) {
            $config->save(null, $backup);
        }
        return $changed;
    } finally {
        $config->unlock();
    }
}

if (realpath($_SERVER['SCRIPT_FILENAME'] ?? '') === __FILE__) {
    try {
        singbox_setup_network(Config::getInstance());
    } catch (Throwable $error) {
        fwrite(STDERR, "The Sing-box interface configuration could not be synchronized.\n");
        exit(1);
    }
}
