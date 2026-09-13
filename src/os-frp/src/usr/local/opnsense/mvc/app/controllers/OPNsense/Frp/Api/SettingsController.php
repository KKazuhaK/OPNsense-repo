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

namespace OPNsense\Frp\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;

/**
 * The settings of each daemon are that daemon's TOML document and nothing
 * else: manage.py reads the live .toml and hands it back as a JSON object,
 * and set-settings takes a JSON object and writes the TOML again. There is no
 * second schema here to drift away from the file on disk.
 *
 * Two shapes of the same document reach this controller. The form tabs post
 * it as JSON, which carries the integers and booleans frp's strict decoding
 * insists on. The Advanced tab posts it as TOML text, which is turned into
 * the same object here rather than in the browser, so both routes end up in
 * one validate-then-apply path. The reverse direction, object to TOML text,
 * is what fills the Advanced editor; comments do not survive a save because
 * the backend rewrites the file from the object whichever tab was used.
 *
 * Credentials arrive from the backend as the string "__KEEP__" and go back
 * unchanged when the operator does not retype them, so no secret is ever sent
 * to the browser and none has to be re-entered to change a neighbouring field.
 */
class SettingsController extends ApiControllerBase
{
    /* The side is the configd command group; the path is shown in the editor
       so the operator knows which file is being rewritten. */
    private const SIDES = [
        'frps' => '/usr/local/etc/frp/frps.toml',
        'frpc' => '/usr/local/etc/frp/frpc.toml',
    ];
    private const LIMIT = 1048576;
    /* Lists of tables written as [[name]] blocks. Every other list of tables
       is written inline, which is how frp's own examples spell allowPorts. */
    private const TABLE_LISTS = ['proxies', 'visitors', 'httpPlugins'];

    /* Parser cursor. One controller instance serves one request. */
    private string $text = '';
    private int $cursor = 0;

    public function getAction(string $side = ''): array
    {
        if (!isset(self::SIDES[$side])) {
            return ['status' => 'failed', 'error' => gettext('Unknown frp side.')];
        }
        $answer = $this->run($side, 'settings');
        if ($answer['status'] !== 'ok') {
            return $answer;
        }
        /* The backend answers with an envelope around the document: the
           document itself under "config", the same document as TOML text under
           "toml", and the paths that hold a credential beside them. Handing the
           envelope on as the settings would show the page bindPort under
           "config" and write the envelope back into frps.toml on the next save. */
        $result = is_array($answer['result'] ?? null) ? $answer['result'] : [];
        $document = is_array($result['config'] ?? null) ? $result['config'] : [];
        $rendered = $result['toml'] ?? null;
        return [
            'status' => 'ok',
            'settings' => $document,
            /* The same document as text, so the Advanced tab needs no second
               read and cannot disagree with the form tabs. The backend renders
               it with the emitter that writes the live file; rendering it here
               is the fallback for an older backend that sends none. */
            'document' => is_string($rendered) && $rendered !== '' ? $rendered : $this->render($document),
            'path' => self::SIDES[$side],
        ];
    }

    public function setAction(string $side = ''): array
    {
        return $this->change($side, true);
    }

    public function verifyAction(string $side = ''): array
    {
        return $this->change($side, false);
    }

    /**
     * Stage the submitted document once and let the backend check it before
     * anything is written. The same file is handed to both verbs, so what was
     * validated is exactly what gets applied.
     */
    private function change(string $side, bool $apply): array
    {
        if (!isset(self::SIDES[$side])) {
            return ['status' => 'failed', 'error' => gettext('Unknown frp side.')];
        }
        if ($this->request->getMethod() !== 'POST') {
            return ['status' => 'failed', 'error' => gettext('A POST is required.')];
        }
        /* A read-only operator has no business submitting a document, even
           one that would only be validated. */
        $this->throwReadOnly();
        try {
            $document = $this->incoming();
        } catch (\Exception $error) {
            return ['status' => 'failed', 'error' => $error->getMessage()];
        }
        $encoded = json_encode($document, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if ($encoded === false) {
            return ['status' => 'failed', 'error' => gettext('Unable to stage the configuration.')];
        }
        /* configdpRun quotes its parameters and the action takes a path, not a
           value: the document holds credentials and would otherwise appear in
           a command line. The file is private and goes away either way. The
           backend accepts a hand-off only from /tmp and only under the "frp_"
           prefix, so the name is part of the contract, not decoration. */
        $staged = tempnam('/tmp', 'frp_api_');
        if ($staged === false) {
            return ['status' => 'failed', 'error' => gettext('Unable to stage the configuration.')];
        }
        try {
            if (!chmod($staged, 0600) || file_put_contents($staged, $encoded, LOCK_EX) === false) {
                return ['status' => 'failed', 'error' => gettext('Unable to stage the configuration.')];
            }
            $checked = $this->run($side, 'verify', $staged);
            if ($checked['status'] !== 'ok' || !$apply) {
                return $checked;
            }
            return $this->run($side, 'set-settings', $staged);
        } finally {
            @unlink($staged);
        }
    }

    /**
     * The document as submitted, from either tab. Errors name what is wrong
     * without quoting the submitted text back, because that text carries the
     * authentication token.
     */
    private function incoming(): array
    {
        $json = $this->posted('settings');
        $toml = $this->posted('document');
        if ($json === '' && $toml === '') {
            throw new \Exception(gettext('Nothing was submitted.'));
        }
        if (strlen($json) > self::LIMIT || strlen($toml) > self::LIMIT) {
            throw new \Exception(gettext('The configuration is too large.'));
        }
        $document = $json !== '' ? json_decode($json, true, 64) : $this->parse($toml);
        if (!is_array($document)) {
            throw new \Exception(gettext('The configuration could not be read.'));
        }
        if ($document === [] || array_is_list($document)) {
            /* An empty frps.toml has no token and no dashboard credentials,
               which is the one state this plugin exists to prevent. */
            throw new \Exception(gettext('The configuration is empty or is not a table of settings.'));
        }
        return $document;
    }

    private function posted(string $field): string
    {
        $value = $this->request->getPost($field, null, '');
        if (is_string($value) && $value !== '') {
            return $value;
        }
        /* Kept for a caller that sends a JSON body instead of a form body;
           the page itself posts a form. */
        try {
            $body = $this->request->getJsonRawBody(true);
        } catch (\Throwable $error) {
            $body = null;
        }
        return is_array($body) && is_string($body[$field] ?? null) ? $body[$field] : '';
    }

    private function run(string $side, string $action, ?string $argument = null): array
    {
        $backend = new Backend();
        $raw = $argument === null
            ? $backend->configdRun($side . ' ' . $action)
            : $backend->configdpRun($side . ' ' . $action, [$argument]);
        $answer = json_decode((string)$raw, true);
        if (!is_array($answer)) {
            return ['status' => 'failed', 'error' => gettext('The backend did not answer.')];
        }
        return !empty($answer['ok'])
            ? ['status' => 'ok', 'result' => $answer['result'] ?? null]
            : ['status' => 'failed', 'error' => (string)($answer['error'] ?? gettext('The operation failed.'))];
    }

    /* ---------------------------------------------------------------------
     * Document to TOML text.
     *
     * Top level keys are written with dots -- auth.token, transport.tls.enable
     * -- which is the spelling frp's own documentation uses, and [[proxies]]
     * blocks follow them. Nothing here invents a key: every name comes from
     * the document the backend read.
     * ------------------------------------------------------------------- */

    private function render(array $document): string
    {
        $lines = [];
        $blocks = [];
        foreach ($document as $key => $value) {
            if (in_array((string)$key, self::TABLE_LISTS, true) && $this->isTableList($value)) {
                $blocks[(string)$key] = $value;
                continue;
            }
            $lines = array_merge($lines, $this->flatten($this->key((string)$key), $value));
        }
        foreach ($blocks as $key => $rows) {
            foreach ($rows as $row) {
                $lines[] = '';
                $lines[] = '[[' . $this->key($key) . ']]';
                foreach ((array)$row as $inner => $value) {
                    $lines = array_merge($lines, $this->flatten($this->key((string)$inner), $value));
                }
            }
        }
        return $lines === [] ? '' : implode("\n", $lines) . "\n";
    }

    private function isTableList($value): bool
    {
        if (!is_array($value) || $value === [] || !array_is_list($value)) {
            return false;
        }
        foreach ($value as $entry) {
            if (!is_array($entry) || ($entry !== [] && array_is_list($entry))) {
                return false;
            }
        }
        return true;
    }

    private function flatten(string $path, $value): array
    {
        if ($value === null) {
            return [];
        }
        if (is_array($value) && !array_is_list($value)) {
            $lines = [];
            foreach ($value as $key => $nested) {
                $lines = array_merge(
                    $lines,
                    $this->flatten($path . '.' . $this->key((string)$key), $nested)
                );
            }
            return $lines;
        }
        if ($value === []) {
            /* Once JSON has been decoded an empty table and an empty array are
               the same PHP value, and to frp both mean "not set". Writing
               neither is the only reading that cannot break a decode. */
            return [];
        }
        return [$path . ' = ' . $this->value($value)];
    }

    private function key(string $key): string
    {
        return preg_match('/^[A-Za-z0-9_-]+$/', $key) === 1 ? $key : $this->quoted($key);
    }

    private function value($value): string
    {
        if (is_bool($value)) {
            return $value ? 'true' : 'false';
        }
        if (is_int($value)) {
            return (string)$value;
        }
        if (is_float($value)) {
            $text = var_export($value, true);
            return strpbrk($text, '.eEnN') === false ? $text . '.0' : $text;
        }
        if (is_array($value)) {
            if (array_is_list($value)) {
                return '[' . implode(', ', array_map(fn($entry) => $this->value($entry), $value)) . ']';
            }
            $parts = [];
            foreach ($value as $key => $nested) {
                $parts[] = $this->key((string)$key) . ' = ' . $this->value($nested);
            }
            return $parts === [] ? '{}' : '{ ' . implode(', ', $parts) . ' }';
        }
        return $this->quoted((string)$value);
    }

    private function quoted(string $text): string
    {
        $escaped = '';
        $length = strlen($text);
        for ($index = 0; $index < $length; $index++) {
            $char = $text[$index];
            $code = ord($char);
            if ($char === '"' || $char === '\\') {
                $escaped .= '\\' . $char;
            } elseif ($char === "\n") {
                $escaped .= '\\n';
            } elseif ($char === "\r") {
                $escaped .= '\\r';
            } elseif ($char === "\t") {
                $escaped .= '\\t';
            } elseif ($code < 0x20 || $code === 0x7f) {
                $escaped .= sprintf('\\u%04X', $code);
            } else {
                /* Bytes above 0x7f are UTF-8 continuation bytes of a character
                   TOML allows unescaped, so they pass through untouched. */
                $escaped .= $char;
            }
        }
        return '"' . $escaped . '"';
    }

    /* ---------------------------------------------------------------------
     * TOML text to document.
     *
     * The subset frp configurations actually use: tables, arrays of tables,
     * dotted keys, strings, integers, floats, booleans, arrays and inline
     * tables. Everything else -- multi-line strings, dates, times -- is
     * refused by line number rather than guessed at, because a document that
     * parses to the wrong thing would be applied without anyone noticing.
     * ------------------------------------------------------------------- */

    private function parse(string $text): array
    {
        $this->text = $text;
        $this->cursor = 0;
        $length = strlen($text);
        $document = [];
        $table = [];
        while (true) {
            $this->skip(true);
            if ($this->cursor >= $length) {
                return $document;
            }
            if ($this->look('[[')) {
                $this->cursor += 2;
                $this->skip(false);
                $path = $this->path();
                $this->skip(false);
                $this->expect(']]');
                /* Only the last name is the list being appended to; anything
                   before it is resolved the way a sub-table header is. */
                $whole = array_merge(
                    $this->physical($document, array_slice($path, 0, -1)),
                    [$path[count($path) - 1]]
                );
                $existing = $this->fetch($document, $whole);
                if ($existing !== null && (!is_array($existing) || !array_is_list($existing))) {
                    $this->fail(gettext('a key was reused as a table'));
                }
                $index = is_array($existing) ? count($existing) : 0;
                $this->assign($document, array_merge($whole, [$index]), [], true);
                $table = array_merge($whole, [$index]);
            } elseif ($this->look('[')) {
                $this->cursor += 1;
                $this->skip(false);
                $path = $this->path();
                $this->skip(false);
                $this->expect(']');
                $path = $this->physical($document, $path);
                if ($this->fetch($document, $path) === null) {
                    $this->assign($document, $path, [], true);
                }
                $table = $path;
            } else {
                $path = $this->path();
                $this->skip(false);
                $this->expect('=');
                $this->skip(false);
                $this->assign($document, array_merge($table, $path), $this->parseValue());
            }
            $this->endOfLine();
        }
    }

    /**
     * Where a table header actually lands. A name that already holds an array
     * of tables means the last table in it, which is what makes
     *
     *   [[proxies]]
     *   [proxies.plugin]
     *
     * -- the spelling frp's own documentation uses for a proxy backed by a
     * plugin -- attach to the proxy above it instead of turning the list into
     * something neither TOML nor frp would recognise.
     */
    private function physical(array $document, array $path): array
    {
        $resolved = [];
        $node = $document;
        foreach ($path as $segment) {
            $resolved[] = $segment;
            $node = is_array($node) && array_key_exists($segment, $node) ? $node[$segment] : null;
            if (is_array($node) && $node !== [] && array_is_list($node)) {
                $last = count($node) - 1;
                $resolved[] = $last;
                $node = $node[$last];
            }
        }
        return $resolved;
    }

    private function path(): array
    {
        $path = [];
        while (true) {
            $path[] = $this->segment();
            $this->skip(false);
            if (!$this->look('.')) {
                return $path;
            }
            $this->cursor += 1;
            $this->skip(false);
        }
    }

    private function segment(): string
    {
        $char = $this->text[$this->cursor] ?? '';
        if ($char === '"' || $char === "'") {
            return $this->parseString();
        }
        if (preg_match('/[A-Za-z0-9_-]+/A', $this->text, $found, 0, $this->cursor) !== 1) {
            $this->fail(gettext('a key was expected'));
        }
        $this->cursor += strlen($found[0]);
        return $found[0];
    }

    private function parseValue()
    {
        $char = $this->text[$this->cursor] ?? '';
        if ($char === '"' || $char === "'") {
            return $this->parseString();
        }
        if ($char === '[') {
            return $this->parseArray();
        }
        if ($char === '{') {
            return $this->parseInline();
        }
        if (preg_match('/(?:true|false)(?![A-Za-z0-9_-])/A', $this->text, $found, 0, $this->cursor) === 1) {
            $this->cursor += strlen($found[0]);
            return $found[0] === 'true';
        }
        $number = '/[+-]?(?:0x[0-9A-Fa-f_]+|0o[0-7_]+|0b[01_]+'
            . '|[0-9][0-9_]*(?:\.[0-9_]+)?(?:[eE][+-]?[0-9_]+)?)/A';
        if (preg_match($number, $this->text, $found, 0, $this->cursor) === 1) {
            $next = $this->text[$this->cursor + strlen($found[0])] ?? '';
            if ($next === '-' || $next === ':') {
                $this->fail(gettext('dates and times are not supported here'));
            }
            if ($next !== '' && preg_match('/[A-Za-z0-9_.]/', $next) === 1) {
                $this->fail(gettext('the value could not be read'));
            }
            $this->cursor += strlen($found[0]);
            return $this->number($found[0]);
        }
        $this->fail(gettext('the value could not be read'));
    }

    private function number(string $raw)
    {
        $body = str_replace('_', '', $raw);
        $sign = 1;
        if ($body !== '' && ($body[0] === '+' || $body[0] === '-')) {
            $sign = $body[0] === '-' ? -1 : 1;
            $body = substr($body, 1);
        }
        $lower = strtolower($body);
        if (str_starts_with($lower, '0x')) {
            return $sign * (int)hexdec(substr($body, 2));
        }
        if (str_starts_with($lower, '0o')) {
            return $sign * (int)octdec(substr($body, 2));
        }
        if (str_starts_with($lower, '0b')) {
            return $sign * (int)bindec(substr($body, 2));
        }
        return strpbrk($body, '.eE') === false ? $sign * (int)$body : $sign * (float)$body;
    }

    private function parseString(): string
    {
        $quote = $this->text[$this->cursor];
        if ($this->look($quote . $quote . $quote)) {
            $this->fail(gettext('multi-line strings are not supported here'));
        }
        $this->cursor += 1;
        $value = '';
        $length = strlen($this->text);
        while ($this->cursor < $length) {
            $char = $this->text[$this->cursor];
            if ($char === $quote) {
                $this->cursor += 1;
                return $value;
            }
            if ($char === "\n") {
                break;
            }
            if ($quote === '"' && $char === '\\') {
                $this->cursor += 1;
                $value .= $this->escape();
                continue;
            }
            $value .= $char;
            $this->cursor += 1;
        }
        $this->fail(gettext('the string was not closed'));
    }

    private function escape(): string
    {
        $char = $this->text[$this->cursor] ?? '';
        $this->cursor += 1;
        $simple = ['b' => "\x08", 't' => "\t", 'n' => "\n", 'f' => "\x0c", 'r' => "\r",
                   'e' => "\x1b", '"' => '"', '\\' => '\\'];
        if (isset($simple[$char])) {
            return $simple[$char];
        }
        if ($char === 'u' || $char === 'U') {
            $width = $char === 'u' ? 4 : 8;
            $digits = substr($this->text, $this->cursor, $width);
            if (strlen($digits) !== $width || preg_match('/^[0-9A-Fa-f]+$/', $digits) !== 1) {
                $this->fail(gettext('an escape sequence is malformed'));
            }
            $this->cursor += $width;
            return $this->utf8((int)hexdec($digits));
        }
        $this->fail(gettext('an escape sequence is malformed'));
    }

    private function utf8(int $code): string
    {
        if ($code < 0x80) {
            return chr($code);
        }
        if ($code < 0x800) {
            return chr(0xc0 | $code >> 6) . chr(0x80 | $code & 0x3f);
        }
        if ($code < 0x10000) {
            return chr(0xe0 | $code >> 12) . chr(0x80 | ($code >> 6 & 0x3f)) . chr(0x80 | $code & 0x3f);
        }
        return chr(0xf0 | $code >> 18) . chr(0x80 | ($code >> 12 & 0x3f))
            . chr(0x80 | ($code >> 6 & 0x3f)) . chr(0x80 | $code & 0x3f);
    }

    private function parseArray(): array
    {
        $this->cursor += 1;
        $values = [];
        $length = strlen($this->text);
        while (true) {
            $this->skip(true);
            if ($this->cursor >= $length) {
                $this->fail(gettext('the array was not closed'));
            }
            if ($this->look(']')) {
                $this->cursor += 1;
                return $values;
            }
            $values[] = $this->parseValue();
            $this->skip(true);
            if ($this->look(',')) {
                $this->cursor += 1;
                continue;
            }
            if ($this->look(']')) {
                $this->cursor += 1;
                return $values;
            }
            $this->fail(gettext('a comma or a closing bracket was expected'));
        }
    }

    private function parseInline(): array
    {
        $this->cursor += 1;
        $table = [];
        $length = strlen($this->text);
        $this->skip(true);
        if ($this->look('}')) {
            $this->cursor += 1;
            return $table;
        }
        while (true) {
            $this->skip(true);
            if ($this->cursor >= $length) {
                $this->fail(gettext('the inline table was not closed'));
            }
            $path = $this->path();
            $this->skip(false);
            $this->expect('=');
            $this->skip(false);
            $this->assign($table, $path, $this->parseValue());
            $this->skip(true);
            if ($this->look(',')) {
                $this->cursor += 1;
                continue;
            }
            if ($this->look('}')) {
                $this->cursor += 1;
                return $table;
            }
            $this->fail(gettext('a comma or a closing brace was expected'));
        }
    }

    private function assign(array &$target, array $path, $value, bool $replace = false): void
    {
        $node = &$target;
        $last = array_pop($path);
        foreach ($path as $segment) {
            if (!isset($node[$segment])) {
                $node[$segment] = [];
            }
            if (!is_array($node[$segment])) {
                $this->fail(gettext('a key was reused as a table'));
            }
            $node = &$node[$segment];
        }
        if (array_key_exists($last, $node) && !$replace) {
            $this->fail(gettext('the key appears twice'));
        }
        $node[$last] = $value;
        unset($node);
    }

    private function fetch(array $target, array $path)
    {
        $node = $target;
        foreach ($path as $segment) {
            if (!is_array($node) || !array_key_exists($segment, $node)) {
                return null;
            }
            $node = $node[$segment];
        }
        return $node;
    }

    private function skip(bool $newlines): void
    {
        $length = strlen($this->text);
        while ($this->cursor < $length) {
            $char = $this->text[$this->cursor];
            if ($char === ' ' || $char === "\t") {
                $this->cursor += 1;
                continue;
            }
            if ($newlines && ($char === "\n" || $char === "\r")) {
                $this->cursor += 1;
                continue;
            }
            if ($newlines && $char === '#') {
                while ($this->cursor < $length && $this->text[$this->cursor] !== "\n") {
                    $this->cursor += 1;
                }
                continue;
            }
            return;
        }
    }

    private function endOfLine(): void
    {
        $length = strlen($this->text);
        $this->skip(false);
        if ($this->look('#')) {
            while ($this->cursor < $length && $this->text[$this->cursor] !== "\n") {
                $this->cursor += 1;
            }
        }
        if ($this->cursor >= $length) {
            return;
        }
        if ($this->text[$this->cursor] === "\r") {
            $this->cursor += 1;
        }
        if (($this->text[$this->cursor] ?? '') !== "\n") {
            $this->fail(gettext('the line carries more than one value'));
        }
        $this->cursor += 1;
    }

    private function look(string $token): bool
    {
        return substr($this->text, $this->cursor, strlen($token)) === $token;
    }

    private function expect(string $token): void
    {
        if (!$this->look($token)) {
            $this->fail(sprintf(gettext('%s was expected'), $token));
        }
        $this->cursor += strlen($token);
    }

    private function fail(string $reason): never
    {
        $line = substr_count(substr($this->text, 0, $this->cursor), "\n") + 1;
        /* The offending line is never quoted back: it may be the line that
           holds the authentication token. */
        throw new \Exception(sprintf(
            gettext('Line %d could not be read: %s.'),
            $line,
            $reason
        ));
    }
}
