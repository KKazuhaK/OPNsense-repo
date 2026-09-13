#!/usr/local/bin/php
<?php

/*
 * Copyright (C) 2026 Kazuha
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * The two ends of //OPNsense/Frp/backup, and nothing else.
 *
 *   config_mirror.php export   reads one JSON object on standard input, sets
 *                              the field of each name it recognises and saves
 *                              config.xml only when the section really changed.
 *                              Prints {"changed":true|false}.
 *   config_mirror.php import   prints the stored section as one JSON object,
 *                              {} when the section is not there at all.
 *
 * There is deliberately no policy here: no defaults, no field is special, and
 * nothing in this file knows what a frp configuration is.  What belongs in the
 * mirror, what a value means and what may be written back onto disk is decided
 * in manage.py, which is the only caller.  Keeping this file ignorant is what
 * lets the two sides be versioned apart: a field a newer manage.py sends and
 * this model has never heard of is skipped rather than guessed at, and a field
 * the model has that manage.py did not send keeps whatever it held.
 *
 * The payload arrives on standard input because it carries auth.token and the
 * dashboard password, and a command line is readable in the process table.
 */

require_once('script/load_phalcon.php');

use OPNsense\Core\Config;
use OPNsense\Frp\Backup;

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

/* The model's own mountpoint.  It is asked about directly for one question the
   model cannot answer -- whether the section exists at all -- because a freshly
   constructed model is indistinguishable from a stored one full of defaults. */
const MOUNT = '//OPNsense/Frp/backup';
const LIMIT = 4194304;

function fail(string $message): void
{
    fwrite(STDERR, $message . "\n");
    exit(1);
}

/** Read only scalar fields actually present in the native document. */
function frpStoredFields(): array
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

function emit($answer): void
{
    $encoded = json_encode($answer, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    if ($encoded === false) {
        fail('The stored configuration could not be encoded as JSON.');
    }
    echo $encoded . "\n";
}

$verb = $argv[1] ?? '';

if ($verb === 'import') {
    try {
        /* An object even when empty, without manufacturing missing defaults. */
        emit((object)frpStoredFields());
    } catch (\Throwable $error) {
        fail('The stored configuration could not be read.');
    }
    exit(0);
}

if ($verb !== 'export') {
    fail('usage: config_mirror.php export|import');
}

$raw = stream_get_contents(STDIN, LIMIT + 1);
if ($raw === false || strlen($raw) > LIMIT) {
    fail('The configuration to mirror is missing or larger than this plugin handles.');
}
$payload = json_decode($raw, false, 32);
if (!$payload instanceof stdClass) {
    fail('The configuration to mirror must be one JSON object.');
}

$config = Config::getInstance();
$locked = false;
$exitStatus = 0;
try {
    backup_lock_current($config);
    $locked = true;
    $stored = frpStoredFields();
    if (property_exists($payload, '_expected')) {
        $expected = $payload->_expected;
        unset($payload->_expected);
        if (!is_string($expected) || !preg_match('/^[a-f0-9]{64}$/D', $expected)) {
            throw new RuntimeException('Invalid expected snapshot.');
        }
        ksort($stored, SORT_STRING);
        $encoded = json_encode((object)$stored, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
        /* Match Python ensure_ascii for DEL, which PHP otherwise emits literally. */
        $current = hash('sha256', str_replace("\x7f", '\u007f', $encoded));
        if (!hash_equals($expected, $current)) {
            throw new RuntimeException('The configuration snapshot changed.');
        }
    }
    $model = new Backup();
    $updates = [];
    foreach ($payload as $name => $value) {
        if (!is_scalar($value)) {
            throw new RuntimeException('Invalid payload.');
        }
        $value = is_bool($value) ? ($value ? '1' : '0') : (string)$value;
        if (preg_match('/[^\x{9}\x{A}\x{D}\x{20}-\x{D7FF}\x{E000}-\x{FFFD}\x{10000}-\x{10FFFF}]/u', $value)) {
            throw new RuntimeException('Invalid payload.');
        }
        $node = $model->getNodeByReference((string)$name);
        if ($node !== null && !$node->isContainer() &&
            (!array_key_exists($name, $stored) || $stored[$name] !== $value)) {
            $updates[$name] = $value;
        }
    }
    $changed = !empty($updates);
    if ($changed) {
        $root = $config->object();
        if (!isset($root->OPNsense)) {
            $root->addChild('OPNsense');
        }
        if (!isset($root->OPNsense->Frp)) {
            $root->OPNsense->addChild('Frp');
        }
        if (!isset($root->OPNsense->Frp->backup)) {
            $root->OPNsense->Frp->addChild('backup');
        }
        $parent = dom_import_simplexml($root->OPNsense->Frp->backup);
        /* Change known text only. Preserve absent defaults, future fields and
           attributes instead of replacing the entire model mount. */
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
        $config->save(['description' => gettext('frp: mirror configuration for backup')]);
    }
    emit(['changed' => $changed]);
} catch (\Throwable $error) {
    fwrite(STDERR, "The configuration could not be mirrored.\n");
    $exitStatus = 1;
} finally {
    if ($locked) {
        $config->unlock();
    }
}
exit($exitStatus);
