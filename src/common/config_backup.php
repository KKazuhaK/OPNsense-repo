#!/usr/local/bin/php
<?php
/** Persist only a plugin's backup section using the native configuration lock. */
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

function backup_stored_fields(Config $config, string $module): array
{
    $found = $config->object()->xpath('/opnsense/OPNsense/' . $module . '/backup');
    $fields = [];
    if (count($found) > 0) {
        foreach (['schema', 'archive', 'checksum'] as $field) {
            if (isset($found[0]->$field)) {
                $fields[$field] = (string)$found[0]->$field;
            }
        }
    }
    return $fields;
}

$module = $argv[1] ?? '';
$action = $argv[2] ?? '';
$config = null;
$locked = false;
$exitStatus = 0;
try {
    if (!preg_match('/^[A-Z][A-Za-z0-9]{0,63}$/D', $module) || !in_array($action, ['import', 'export'], true)) {
        throw new RuntimeException('Invalid operation.');
    }
    $config = Config::getInstance();
    if ($action === 'import') {
        echo json_encode((object)backup_stored_fields($config, $module), JSON_THROW_ON_ERROR) . "\n";
    } else {
        /* A 1 MiB compressed archive needs at most 1,398,104 Base64 bytes.
           Bound the transport too so direct clients cannot bypass the writer
           budget or create an XML text node beyond normal libxml limits. */
        $raw = stream_get_contents(STDIN, 1400001);
        if ($raw === false || strlen($raw) > 1400000) {
            throw new RuntimeException('Invalid payload.');
        }
        $payload = json_decode($raw, true, 8, JSON_THROW_ON_ERROR);
        if (!is_array($payload) || array_diff(array_keys($payload), ['schema', 'archive', 'checksum', '_expected'])) {
            throw new RuntimeException('Invalid payload.');
        }
        $expected = $payload['_expected'] ?? null;
        if (array_key_exists('_expected', $payload) &&
            (!is_string($expected) || !preg_match('/^[a-f0-9]{64}$/D', $expected))) {
            throw new RuntimeException('Invalid payload.');
        }
        unset($payload['_expected']);
        if (
            ($payload['schema'] ?? '') !== '1' || !is_string($payload['archive'] ?? null) ||
            strlen($payload['archive']) > 1398104 ||
            !preg_match('/^[a-f0-9]{64}$/D', $payload['checksum'] ?? '')) {
            throw new RuntimeException('Invalid payload.');
        }
        backup_lock_current($config);
        $locked = true;
        if ($expected !== null) {
            /* Compare after refreshing under EX. A configuration restore that
               arrived after the caller's import must not be replaced by it. */
            $current = backup_stored_fields($config, $module);
            ksort($current, SORT_STRING);
            $encoded = json_encode((object)$current, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
            /* Python's ensure_ascii also escapes ASCII DEL. */
            $currentHash = hash('sha256', str_replace("\x7f", '\\u007f', $encoded));
            if (!hash_equals($currentHash, $expected)) {
                throw new RuntimeException('The stored configuration changed.');
            }
        }
        $root = $config->object();
        if (!isset($root->OPNsense)) {
            $root->addChild('OPNsense');
        }
        if (!isset($root->OPNsense->$module)) {
            $root->OPNsense->addChild($module);
        }
        $section = $root->OPNsense->$module;
        $changed = !isset($section->backup);
        if (!$changed) {
            foreach ($payload as $field => $value) {
                $changed = $changed || (string)$section->backup->$field !== $value;
            }
        }
        if ($changed) {
            if (!isset($section->backup)) {
                $section->addChild('backup');
            }
            foreach ($payload as $field => $value) {
                $section->backup->$field = $value;
            }
            $config->save();
        }
        echo json_encode(['changed' => $changed], JSON_THROW_ON_ERROR) . "\n";
    }
} catch (Throwable $error) {
    fwrite(STDERR, "The native configuration backup operation failed.\n");
    $exitStatus = 1;
} finally {
    if ($locked) {
        $config->unlock();
    }
}
exit($exitStatus);
