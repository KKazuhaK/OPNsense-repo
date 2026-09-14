#!/usr/local/bin/php
<?php

/*
 * Move the Mihomo backup section between config.xml and stdin/stdout, and do
 * nothing else.
 *
 * Every decision about what belongs in that section, what a field means, what a
 * missing one should fall back to and whether a restored one may be acted upon
 * lives in mihomo.py. This file exists because only PHP can reach the
 * configuration model, and it is kept deliberately ignorant so that the policy
 * has exactly one home. Adding a default or a "sensible" fallback here would
 * create a second one that nobody thinks to look at.
 */

require_once('script/load_phalcon.php');
require_once('util.inc');
require_once('config.inc');

use OPNsense\Core\Config;
use OPNsense\Mihomo\Backup;

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


const MOUNT = 'OPNsense/Mihomo/backup';
const PAYLOAD_LIMIT = 25165824;

function mihomoStoredFields(): array
{
    $nodes = Config::getInstance()->object()->xpath(MOUNT);
    $stored = [];
    if (!empty($nodes)) {
        foreach ($nodes[0]->children() as $name => $node) {
            if ($node->count() === 0) {
                $stored[(string)$name] = (string)$node;
            }
        }
    }
    return $stored;
}

function mihomoExport(): int
{
    $raw = stream_get_contents(STDIN, PAYLOAD_LIMIT + 1);
    if ($raw === false || strlen($raw) > PAYLOAD_LIMIT) {
        throw new RuntimeException('Invalid payload.');
    }
    $payload = json_decode($raw, false, 32, JSON_THROW_ON_ERROR);
    if (!$payload instanceof stdClass) {
        throw new RuntimeException('Invalid payload.');
    }
    $config = Config::getInstance();
    backup_lock_current($config);
    try {
        $model = new Backup();
        $stored = mihomoStoredFields();
        if (property_exists($payload, '_expected')) {
            if (!is_string($payload->_expected) || !preg_match('/^[a-f0-9]{64}$/D', $payload->_expected)) {
                throw new RuntimeException('Invalid payload.');
            }
            $canonical = $stored;
            ksort($canonical, SORT_STRING);
            $encoded = json_encode((object)$canonical, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
            // Match Python ensure_ascii for the printable ASCII boundary.
            $encoded = str_replace("\x7f", '\u007f', $encoded);
            if (!hash_equals($payload->_expected, hash('sha256', $encoded))) {
                throw new RuntimeException('The stored backup changed.');
            }
            unset($payload->_expected);
        }
        $updates = [];
        foreach ($payload as $field => $value) {
            if (!is_scalar($value)) {
                throw new RuntimeException('Invalid payload.');
            }
            $value = is_bool($value) ? ($value ? '1' : '0') : (string)$value;
            if (preg_match('/[^\x{9}\x{A}\x{D}\x{20}-\x{D7FF}\x{E000}-\x{FFFD}\x{10000}-\x{10FFFF}]/u', $value)) {
                throw new RuntimeException('Invalid payload.');
            }
            /* A newer caller may send fields this model cannot carry yet. */
            $node = $model->getNodeByReference((string)$field);
            if ($node !== null && !$node->isContainer() &&
                (!array_key_exists($field, $stored) || $stored[$field] !== $value)) {
                $updates[$field] = $value;
            }
        }
        $changed = !empty($updates);
        if ($changed) {
            $root = $config->object();
            if (!isset($root->OPNsense)) {
                $root->addChild('OPNsense');
            }
            if (!isset($root->OPNsense->Mihomo)) {
                $root->OPNsense->addChild('Mihomo');
            }
            if (!isset($root->OPNsense->Mihomo->backup)) {
                $root->OPNsense->Mihomo->addChild('backup');
            }
            $section = dom_import_simplexml($root->OPNsense->Mihomo->backup);
            /* Update named text only: model serialization would manufacture
               missing fields and can replace unknown nodes from newer versions.
               Base64Field is text validation, so its padding must remain text. */
            foreach ($updates as $field => $value) {
                $element = null;
                foreach ($section->childNodes as $child) {
                    if ($child instanceof DOMElement && $child->tagName === $field) {
                        $element = $child;
                        break;
                    }
                }
                if ($element === null) {
                    $element = $section->ownerDocument->createElement($field);
                    $section->appendChild($element);
                }
                while ($element->firstChild !== null) {
                    $element->removeChild($element->firstChild);
                }
                $element->appendChild($section->ownerDocument->createTextNode($value));
            }
            $config->save(make_config_revision_entry('Mirror the Mihomo configuration'));
        }
    } finally {
        $config->unlock();
    }
    echo json_encode(['changed' => $changed], JSON_THROW_ON_ERROR) . "\n";
    return 0;
}

function mihomoImport(): int
{
    /* Read only actual XML fields. Empty and missing fields are different, and
       neither defaults nor Base64 decoding belong in this transport. */
    echo json_encode((object)mihomoStoredFields(), JSON_THROW_ON_ERROR |
        JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n";
    return 0;
}

$verb = $argv[1] ?? '';
if (!in_array($verb, ['export', 'import'], true)) {
    fwrite(STDERR, "usage: config_mirror.php export|import\n");
    exit(64);
}
try {
    exit($verb === 'export' ? mihomoExport() : mihomoImport());
} catch (Throwable $error) {
    /* The message is the plugin's own, never the exception's: a validation
       failure quotes the offending value back, and the section carries the
       subscription URL and the control secret. */
    fwrite(STDERR, "The Mihomo configuration mirror could not be " . $verb . "ed.\n");
    exit(1);
}
