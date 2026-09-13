{#
 # Copyright (C) 2026 Kazuha
 # All rights reserved.
 #
 # Redistribution and use in source and binary forms, with or without
 # modification, are permitted provided that the following conditions are met:
 #
 # 1. Redistributions of source code must retain the above copyright notice,
 #    this list of conditions and the following disclaimer.
 #
 # 2. Redistributions in binary form must reproduce the above copyright
 #    notice, this list of conditions and the following disclaimer in the
 #    documentation and/or other materials provided with the distribution.
 #
 # THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 # INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 # AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 # AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 # OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 # SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 # INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 # CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 # ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 # POSSIBILITY OF SUCH DAMAGE.
 #}

{#
 # The half of an frp page that does not depend on which daemon it drives.
 #
 # The server page and the client page are the same page twice over: one .toml
 # read into a form, the same document written back, a service to start and
 # stop, and a log to tail. Only the field list, the settings with no safe
 # default and -- on the client -- the proxy editor differ. Those arrive from
 # the page; everything else is written here once.
 #
 # The page sets the side it drives and then includes this partial with it, so
 # the daemon is rendered into the script rather than picked at runtime.
 # There is no list of sides left to walk and no call that can reach the other
 # daemon's .toml.
 #}

<style>
    /* Geometry only: the themes own every colour on these pages. */
    .frp-log {
        max-height: 360px;
        overflow: auto;
        font-size: 12px;
        margin-bottom: 12px;
        max-width: 100%;
        white-space: pre;
        word-break: normal;
    }
    .frp-document {
        font-family: monospace;
        font-size: 12px;
    }
</style>

<script>
/**
 * Build the shared half of this page.
 *
 * The page calls this once, from its own document-ready handler, and hands in
 * what only it knows:
 *
 *   fields         the descriptors of the .toml keys its settings tab draws
 *   required       the settings of this daemon that have no safe default
 *   requiredIntro  the sentence that introduces them when one is missing
 *   onSettings     called with the stored document after every read
 *   onStatus       called with the service state after every poll
 *   extend         called with the document about to be saved from the form,
 *                  for anything the field list does not cover
 *
 * and gets back the handful of helpers its own code needs, plus start().
 */
window.frpCommon = function (page) {
    /* The daemon this page drives, rendered in by the template. */
    const SIDE = '{{ side }}';

    /* What the backend puts in place of a stored credential, in both
       directions: a field that still reads __KEEP__ when it is submitted keeps
       whatever is on disk. */
    const KEEP = '__KEEP__';
    /* What the shipped sample files carry where a value has no safe default.
       The rc script refuses to start while one is still in place, so the page
       treats it as "not set yet" rather than as a value. */
    const PLACEHOLDER = 'CHANGE_ME';

    /* Every endpoint this page uses, with the side already in it. */
    const api = {
        settings: '/api/frp/settings/get/' + SIDE,
        apply: '/api/frp/settings/set/' + SIDE,
        check: '/api/frp/settings/verify/' + SIDE,
        status: '/api/frp/service/status/' + SIDE,
        log: '/api/frp/service/log/' + SIDE,
        service: '/api/frp/service/'
    };

    const FIELDS = page.fields || [];
    const REQUIRED = page.required || [];

    /* The document last read from this daemon's .toml. Every save starts from
       a copy of it, so a key this page has no field for -- and there are many,
       frp has hundreds -- survives a save instead of being dropped. */
    let stored = {};
    /* Whether the raw editor has unsaved typing in it, so a refresh caused by
       the poll cannot overwrite it. */
    let editing = false;

    /* The framework HTML-escapes every array response on the way out, so a
       value is only intact once it is decoded on arrival. Decoding the whole
       response in one place rather than at each element is the difference
       between a log that reads "--&gt;" and a configuration whose escaped
       text gets written straight back into the daemon's file on the next
       save. */
    function decoded(value) {
        if (typeof value === 'string') { return htmlDecode(value); }
        if (Array.isArray(value)) { return value.map(decoded); }
        if (value !== null && typeof value === 'object') {
            const plain = {};
            Object.keys(value).forEach(function (key) { plain[key] = decoded(value[key]); });
            return plain;
        }
        return value;
    }

    /* The one read on this page. Everything that reads goes through it, so the
       decode above cannot be forgotten the next time a call is added. */
    function get(url, done) {
        ajaxGet(url, {}, function (data) { done(decoded(data)); });
    }

    function report(state, text) {
        $('#frp-message').attr('class', 'alert alert-' + state).text(text).show();
        $(window).scrollTop(0);
    }

    /* Restarting a daemon takes seconds. Without a state of its own the page
       looks identical the whole time, so the operator cannot tell a slow
       success from a click that did nothing. */
    function spin(button) {
        if (button.data('idle-label') === undefined) { button.data('idle-label', button.html()); }
        button.prop('disabled', true)
              .html('<i class="fa fa-spinner fa-spin"></i> ' + button.data('idle-label'));
    }

    function busy(button, text) {
        spin(button);
        report('info', text);
    }

    function idle(button) {
        button.prop('disabled', false).html(button.data('idle-label'));
    }

    function call(url, payload, done, button, after) {
        button = button || $();
        busy(button, '{{ lang._('Working...') }}');
        /* ajaxCall reports through jQuery's complete, so this runs on a failed
           request as much as a successful one and the button always comes
           back. A failure carries no JSON body, so say plainly that it failed
           rather than leaving the operator with a spinner and no answer. */
        ajaxCall(url, payload || {}, function (data) {
            idle(button);
            data = decoded(data) || {};
            if (data.status === 'ok') {
                report('success', done);
                if (after) { after(); }
            } else {
                report('danger', data.error
                    || '{{ lang._('The operation failed. The Log tab may say why.') }}');
            }
        });
    }

    /* One pass over a message so a value carrying a dollar sign cannot be read
       as a replacement pattern. */
    function fill(template, values) {
        return template.replace(/%[a-z]/g, function (token) {
            return values[token] === undefined ? token : String(values[token]);
        });
    }

    /* ---- the document ------------------------------------------------- */

    function pick(object, path) {
        return path.split('.').reduce(function (node, key) {
            return node !== null && typeof node === 'object' ? node[key] : undefined;
        }, object);
    }

    function place(object, path, value) {
        const keys = path.split('.');
        const last = keys.pop();
        let node = object;
        keys.forEach(function (key) {
            if (node[key] === null || typeof node[key] !== 'object' || Array.isArray(node[key])) {
                node[key] = {};
            }
            node = node[key];
        });
        if (value === undefined) { delete node[last]; } else { node[last] = value; }
    }

    /* An empty table is not the same as an absent one to a strict decoder, and
       clearing the last field of a group leaves one behind. Drop them before
       the document is sent. */
    function prune(node) {
        if (node === null || typeof node !== 'object') { return node; }
        if (Array.isArray(node)) { node.forEach(prune); return node; }
        Object.keys(node).forEach(function (key) {
            prune(node[key]);
            const value = node[key];
            if (value !== null && typeof value === 'object' && !Array.isArray(value)
                && Object.keys(value).length === 0) {
                delete node[key];
            }
        });
        return node;
    }

    function copy(value) {
        return JSON.parse(JSON.stringify(value === undefined ? null : value));
    }

    /* ---- the settings with no safe default ---------------------------- */

    function blank(value) {
        if (value === undefined || value === null) { return true; }
        if (Array.isArray(value)) { return value.length === 0; }
        return String(value).trim() === '' || String(value) === PLACEHOLDER;
    }

    /* What "needs" asks about is always a port, and frp spells a port that is
       switched off as 0 rather than by leaving it out. port_of() in manage.py
       draws the same line, which is why a dashboard bound to port 0 raises no
       guard there: treating that 0 as a value set would warn about credentials
       for a listener that does not exist, on the same page whose Status tab
       says it does not exist. */
    function off(value) {
        return blank(value) || String(value).trim() === '0';
    }

    function renderRequired() {
        const missing = REQUIRED.filter(function (entry) {
            if (!blank(pick(stored, entry.path))) { return false; }
            return !entry.needs || !off(pick(stored, entry.needs));
        });
        const box = $('#frp-required').empty();
        if (!missing.length) { box.hide(); return; }
        const level = missing.some(function (entry) { return entry.level === 'danger'; })
            ? 'danger' : 'warning';
        box.attr('class', 'alert alert-' + level).show();
        box.append($('<p>').text(page.requiredIntro || ''));
        const list = $('<ul>');
        missing.forEach(function (entry) {
            list.append($('<li>').append($('<strong>').text(entry.label)).append(' — ').append(
                document.createTextNode(entry.risk)));
        });
        box.append(list);
    }

    /* ---- reading and writing one field -------------------------------- */

    function ports(text, label) {
        return text.split(/[\s,]+/).filter(Boolean).map(function (entry) {
            const range = entry.split('-');
            if (range.length === 1 && /^[0-9]+$/.test(range[0])) {
                return {single: parseInt(range[0], 10)};
            }
            if (range.length === 2 && /^[0-9]+$/.test(range[0]) && /^[0-9]+$/.test(range[1])) {
                return {start: parseInt(range[0], 10), end: parseInt(range[1], 10)};
            }
            throw new Error(label + ': '
                + '{{ lang._('write ports as 6000-6100 or 7000, separated by commas.') }}');
        });
    }

    function portText(value) {
        if (!Array.isArray(value)) { return value === undefined || value === null ? '' : String(value); }
        return value.map(function (entry) {
            if (entry === null || typeof entry !== 'object') { return String(entry); }
            if (entry.single !== undefined) { return String(entry.single); }
            if (entry.start !== undefined && entry.end !== undefined) {
                return entry.start + '-' + entry.end;
            }
            if (entry.start !== undefined) { return String(entry.start); }
            return '';
        }).filter(Boolean).join(', ');
    }

    function readField(field) {
        const element = $('#' + field.id);
        const current = element.val();
        const raw = current === null || current === undefined ? '' : String(current).trim();
        if (field.kind === 'bool') { return element.is(':checked') ? true : undefined; }
        if (field.kind === 'tri') { return raw === '' ? undefined : raw === 'true'; }
        if (field.kind === 'int' || field.kind === 'number') {
            if (raw === '') { return undefined; }
            const pattern = field.kind === 'int' ? /^[0-9]+$/ : /^-?[0-9]+$/;
            if (!pattern.test(raw)) {
                throw new Error(field.label + ': ' + '{{ lang._('a whole number is expected.') }}');
            }
            return parseInt(raw, 10);
        }
        if (field.kind === 'list') {
            return raw === '' ? undefined : raw.split(/[\s,]+/).filter(Boolean);
        }
        if (field.kind === 'ports') {
            return raw === '' ? undefined : ports(raw, field.label);
        }
        if (field.kind === 'secret') {
            if (raw !== '') { return raw; }
            /* An untouched box changes nothing: it sends back exactly what
               arrived at this path, placeholder or value, so a save on a
               neighbouring field can never empty a credential. Removing one
               outright is done on the Advanced tab, by deleting its line. */
            return pick(stored, field.path);
        }
        return raw === '' ? undefined : raw;
    }

    function writeField(field) {
        const element = $('#' + field.id);
        const value = pick(stored, field.path);
        if (field.kind === 'bool') {
            element.prop('checked', value === true);
            return;
        }
        if (field.kind === 'tri') {
            element.val(value === undefined || value === null ? '' : (value ? 'true' : 'false'));
            return;
        }
        if (field.kind === 'ports') {
            element.val(portText(value));
            return;
        }
        if (field.kind === 'list') {
            element.val(Array.isArray(value) ? value.join(', ') : (value === undefined ? '' : String(value)));
            return;
        }
        if (field.kind === 'secret') {
            element.val('');
            element.attr('placeholder', value === KEEP || (value !== undefined && value !== '')
                ? '{{ lang._('A value is stored. Leave empty to keep it.') }}'
                : '{{ lang._('Nothing is stored yet.') }}');
            return;
        }
        const text = value === undefined || value === null ? '' : String(value);
        /* A stored value this page offers no option for -- a log level frp
           accepts and the list omits -- is added as an option of its own.
           Without it the box would show the first option instead, and saving
           would quietly change a setting nobody touched. */
        if (element.is('select')) {
            let known = false;
            element.find('option').each(function () {
                if ($(this).val() === text) { known = true; }
            });
            if (!known) { element.append($('<option>').val(text).text(text)); }
        }
        element.val(text);
    }

    /* ---- loading and saving ------------------------------------------- */

    function documentFor() {
        const payload = copy(stored || {});
        FIELDS.forEach(function (field) {
            place(payload, field.path, readField(field));
        });
        /* Anything the field list cannot express -- the client's [[proxies]]
           table -- is added by the page that owns it. It may throw, and the
           caller reports that the same way it reports a bad port. */
        if (page.extend) { page.extend(payload); }
        return prune(payload);
    }

    function load(done) {
        get(api.settings, function (data) {
            if (!data || data.status !== 'ok') {
                report('danger', (data || {}).error
                    || '{{ lang._('The stored configuration could not be read.') }}');
                return;
            }
            /* An empty file decodes to an empty list rather than an empty
               table; treating it as one would lose every key on the next
               save, because a list keeps no named properties. */
            stored = data.settings && typeof data.settings === 'object'
                && !Array.isArray(data.settings) ? data.settings : {};
            FIELDS.forEach(writeField);
            renderRequired();
            $('#frp-path').text(data.path || '');
            if (!editing) {
                $('#frp-document').val(data.document || '');
                $('#frp-editing').hide();
            }
            $('.selectpicker').selectpicker('refresh');
            if (page.onSettings) { page.onSettings(stored); }
            if (done) { done(); }
        });
    }

    function saveForm(button, apply) {
        let payload;
        try {
            payload = documentFor();
        } catch (error) {
            report('danger', error.message);
            return;
        }
        call(apply ? api.apply : api.check,
             {settings: JSON.stringify(payload)},
             apply ? '{{ lang._('The configuration was written. A daemon that is already running keeps the old one until it is restarted.') }}'
                   : '{{ lang._('The configuration is valid. Nothing was written.') }}',
             button,
             function () { if (apply) { load(); refresh(); } });
    }

    function saveDocument(button, apply) {
        call(apply ? api.apply : api.check,
             {document: $('#frp-document').val()},
             apply ? '{{ lang._('The configuration was written. A daemon that is already running keeps the old one until it is restarted.') }}'
                   : '{{ lang._('The configuration is valid. Nothing was written.') }}',
             button,
             function () {
                 if (apply) { editing = false; load(); refresh(); }
             });
    }

    /* ---- the service --------------------------------------------------- */

    function refresh() {
        get(api.status, function (data) {
            const answered = data && data.status === 'ok';
            const state = (answered && data.result && typeof data.result === 'object')
                ? data.result : {};
            $('#frp-run')
                .attr('class', 'label label-' + (state.running ? 'success' : 'default'))
                .text(state.running ? '{{ lang._('Running') }}' : '{{ lang._('Stopped') }}');
            $('#frp-boot')
                .attr('class', 'label label-' + (state.enabled ? 'success' : 'default'))
                .text(state.enabled ? '{{ lang._('Starts at boot') }}'
                                    : '{{ lang._('Does not start at boot') }}');
            $('#frp-pid').text(state.pid ? String(state.pid) : '-');
            $('#frp-version').text(state.version ? String(state.version) : '-');
            /* The backend states its verdict on the stored file in
               config_message and the settings with no safe default in
               guards; there is no "message" beside them to fall back on. */
            const blocking = (Array.isArray(state.guards) ? state.guards : [])
                .map(function (item) { return item && item.message ? String(item.message) : ''; })
                .filter(Boolean);
            const trouble = (answered ? '' : ((data || {}).error || ''))
                || (state.config_valid === false ? String(state.config_message || '') : '')
                || blocking.join(' ');
            $('#frp-note').toggle(trouble !== '').text(trouble);
            if (page.onStatus) { page.onStatus(state); }
        });
    }

    function loadLog(done) {
        get(api.log, function (data) {
            data = data || {};
            const result = data.status === 'ok' ? data.result : null;
            const text = typeof result === 'string' ? result
                : (result && typeof result.log === 'string' ? result.log : '');
            $('#frp-log').text(text || data.error || '');
            if (done) { done(); }
        });
    }

    /* ---- events -------------------------------------------------------- */

    $('.frp-action').on('click', function () {
        const button = $(this);
        call(api.service + button.data('verb') + '/' + SIDE, {},
             button.data('done'), button, function () { refresh(); });
    });

    $('.frp-save').on('click', function () { saveForm($(this), true); });

    $('.frp-verify').on('click', function () { saveForm($(this), false); });

    $('.frp-document-save').on('click', function () { saveDocument($(this), true); });

    $('.frp-document-verify').on('click', function () { saveDocument($(this), false); });

    $('.frp-document-reload').on('click', function () {
        editing = false;
        load();
        report('info', '{{ lang._('The editor was reloaded from the stored configuration.') }}');
    });

    $('#frp-document').on('input', function () {
        editing = true;
        $('#frp-editing').show();
    });

    $('#frp-log-refresh').on('click', function () {
        const button = $(this);
        spin(button);
        loadLog(function () { idle(button); });
    });

    /* The forms exist so the whole-page help toggle has a scope to work in;
       they post nowhere, and Enter in a field would otherwise reload the page
       and lose what was typed. */
    $('form[id^="frm"]').on('submit', function (event) { event.preventDefault(); });

    function start() {
        load();
        refresh();
        loadLog();
        setInterval(function () {
            refresh();
            if ($('#log').hasClass('active')) { loadLog(); }
        }, 10000);
    }

    /* What the page's own half needs from this one. */
    return {
        KEEP: KEEP,
        PLACEHOLDER: PLACEHOLDER,
        stored: function () { return stored; },
        report: report,
        fill: fill,
        copy: copy,
        pick: pick,
        reload: load,
        start: start
    };
};
</script>
