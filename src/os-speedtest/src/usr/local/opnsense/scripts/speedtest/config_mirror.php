#!/usr/local/bin/php
<?php
/* Move one section between config.xml and one JSON object, understanding
   neither. This script exists because only PHP can read and write an OPNsense
   configuration the way OPNsense does; every question of what a field means,
   which value is sane and what to do about a missing one is answered in
   config_mirror.py, so that it can be answered under test. Adding knowledge
   here would put policy somewhere no test can reach it. */
require_once('script/load_phalcon.php');

use OPNsense\Core\Config;
use OPNsense\Speedtest\Backup;

/* The same address as <mount> in models/OPNsense/Speedtest/Backup.xml. The
   suite compares the two, so moving the model cannot silently orphan the
   section a restored configuration still carries. */
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


const SPEEDTEST_SECTION = '//OPNsense/Speedtest/backup';

function speedtest_stored_section(): array
{
    /* Read the raw document rather than the model: a section that was never
       written has to stay distinguishable from one whose fields are all empty,
       and a field a later version added has to survive being read by this one. */
    $found = Config::getInstance()->object()->xpath(SPEEDTEST_SECTION);
    if (empty($found)) {
        return [];
    }
    $section = [];
    foreach ($found[0]->children() as $name => $value) {
        if ($value->count() === 0) {
            $section[(string)$name] = (string)$value;
        }
    }
    return $section;
}

function speedtest_shim_reply(array $value): void
{
    /* An object even when it is empty: the caller reads {} as "nothing stored". */
    echo json_encode((object)$value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n";
}

$locked = false;
$exitCode = 0;
try {
    $verb = $argv[1] ?? '';
    if ($verb === 'import') {
        speedtest_shim_reply(speedtest_stored_section());
    } elseif ($verb === 'export') {
        $payload = json_decode((string)stream_get_contents(STDIN), true);
        if (!is_array($payload)) {
            throw new InvalidArgumentException('Expected one JSON object on standard input.');
        }
        /* Lock first: reading, changing and writing the configuration is one
           step, and another process may be saving its own section meanwhile. */
        backup_lock_current(Config::getInstance());
        $locked = true;
        $stored = speedtest_stored_section();
        if (array_key_exists('_expected', $payload)) {
            $expected = $payload['_expected'];
            unset($payload['_expected']);
            $fields = $stored;
            ksort($fields, SORT_STRING);
            $encoded = json_encode((object)$fields, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
            $revision = hash('sha256', str_replace("\x7f", '\\u007f', $encoded));
            if (!is_string($expected) || !preg_match('/^[a-f0-9]{64}$/D', $expected) ||
                !hash_equals($revision, $expected)) {
                throw new RuntimeException('The configuration changed before the backup was saved.');
            }
        }
        $model = new Backup();
        $updates = [];
        foreach ($payload as $name => $value) {
            $field = $model->getNodeByReference((string)$name);
            if ($field !== null && !$field->isContainer() && is_scalar($value)) {
                $text = (string)$value;
                if (preg_match('/[^\x{0009}\x{000A}\x{000D}\x{0020}-\x{D7FF}\x{E000}-\x{FFFD}\x{10000}-\x{10FFFF}]/u', $text)) {
                    throw new InvalidArgumentException('A backup value cannot be represented in XML.');
                }
                $updates[(string)$name] = $text;
            }
        }
        $changed = false;
        foreach ($updates as $name => $value) {
            if (!array_key_exists($name, $stored) || $stored[$name] !== $value) {
                $changed = true;
            }
        }
        if ($changed) {
            /* Update named fields only; future fields and node attributes belong
               to the restored configuration and survive an older plugin save. */
            $root = Config::getInstance()->object();
            if (!isset($root->OPNsense)) {
                $root->addChild('OPNsense');
            }
            if (!isset($root->OPNsense->Speedtest)) {
                $root->OPNsense->addChild('Speedtest');
            }
            if (!isset($root->OPNsense->Speedtest->backup)) {
                $root->OPNsense->Speedtest->addChild('backup');
            }
            $parent = dom_import_simplexml($root->OPNsense->Speedtest->backup);
            foreach ($updates as $name => $value) {
                $matches = [];
                foreach ($parent->childNodes as $child) {
                    if ($child instanceof DOMElement && $child->nodeName === $name) {
                        $matches[] = $child;
                    }
                }
                $target = $matches[0] ?? $parent->appendChild($parent->ownerDocument->createElement($name));
                while ($target->firstChild !== null) {
                    $target->removeChild($target->firstChild);
                }
                $target->appendChild($parent->ownerDocument->createTextNode($value));
                foreach (array_slice($matches, 1) as $duplicate) {
                    $parent->removeChild($duplicate);
                }
            }
            Config::getInstance()->save(['description' => 'speedtest settings mirrored into the configuration']);
        }
        Config::getInstance()->unlock();
        $locked = false;
        speedtest_shim_reply(['changed' => $changed]);
    } else {
        throw new InvalidArgumentException('Usage: config_mirror.php export|import');
    }
} catch (Throwable $error) {
    speedtest_shim_reply(['status' => 'failed', 'error' => 'The native Speedtest configuration backup operation failed.']);
    $exitCode = 1;
} finally {
    if ($locked) {
        Config::getInstance()->unlock();
    }
}
exit($exitCode);
