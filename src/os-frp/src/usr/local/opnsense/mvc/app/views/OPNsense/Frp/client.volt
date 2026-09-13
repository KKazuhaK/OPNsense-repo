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

{# The daemon this page drives, named before the shared script is pulled in. #}
{% set side = 'frpc' %}
{{ partial("OPNsense/Frp/common", ['side': side]) }}

<style>
    /* Geometry only: the themes own every colour on this page. */
    .frp-proxy-table {
        margin-bottom: 0;
    }
    .frp-proxy-table td {
        vertical-align: top;
    }
    .frp-proxy-pair input {
        display: inline-block;
        width: 48%;
    }
</style>

<script>
$(function () {

    /* The keys of frpc.toml this page draws. The [[proxies]] table is not one
       of them: it is a list of tables, it is edited row by row on its own tab,
       and it reaches the document through the extend hook below. */
    const FIELDS = [
        {id: 'frpc_server_addr', path: 'serverAddr', kind: 'text', label: '{{ lang._('Server address') }}'},
        {id: 'frpc_server_port', path: 'serverPort', kind: 'int', label: '{{ lang._('Server port') }}'},
        {id: 'frpc_user', path: 'user', kind: 'text', label: '{{ lang._('Client name') }}'},
        {id: 'frpc_auth_method', path: 'auth.method', kind: 'text', label: '{{ lang._('Authentication method') }}'},
        {id: 'frpc_auth_token', path: 'auth.token', kind: 'secret', label: '{{ lang._('Token') }}'},
        {id: 'frpc_login_fail_exit', path: 'loginFailExit', kind: 'tri', label: '{{ lang._('Exit when the first login fails') }}'},
        {id: 'frpc_protocol', path: 'transport.protocol', kind: 'text', label: '{{ lang._('Protocol') }}'},
        {id: 'frpc_pool_count', path: 'transport.poolCount', kind: 'int', label: '{{ lang._('Connection pool') }}'},
        {id: 'frpc_tcp_mux', path: 'transport.tcpMux', kind: 'tri', label: '{{ lang._('Multiplex one connection') }}'},
        {id: 'frpc_heartbeat_interval', path: 'transport.heartbeatInterval', kind: 'number', label: '{{ lang._('Heartbeat interval') }}'},
        {id: 'frpc_heartbeat_timeout', path: 'transport.heartbeatTimeout', kind: 'number', label: '{{ lang._('Heartbeat timeout') }}'},
        {id: 'frpc_tls_enable', path: 'transport.tls.enable', kind: 'tri', label: '{{ lang._('Wrap the control connection in TLS') }}'},
        {id: 'frpc_tls_server_name', path: 'transport.tls.serverName', kind: 'text', label: '{{ lang._('Expected server name') }}'},
        {id: 'frpc_tls_cert', path: 'transport.tls.certFile', kind: 'text', label: '{{ lang._('Certificate file') }}'},
        {id: 'frpc_tls_key', path: 'transport.tls.keyFile', kind: 'text', label: '{{ lang._('Key file') }}'},
        {id: 'frpc_tls_ca', path: 'transport.tls.trustedCaFile', kind: 'text', label: '{{ lang._('Trusted CA file') }}'},
        {id: 'frpc_log_to', path: 'log.to', kind: 'text', label: '{{ lang._('Log destination') }}'},
        {id: 'frpc_log_level', path: 'log.level', kind: 'text', label: '{{ lang._('Log level') }}'},
        {id: 'frpc_log_maxdays', path: 'log.maxDays', kind: 'int', label: '{{ lang._('Days of log kept') }}'}
    ];

    /* The client is not held to the server's rules, but without these two it
       has nowhere to register and nothing the server will accept. */
    const REQUIRED = [
        {path: 'serverAddr', level: 'warning',
         label: '{{ lang._('Server address') }}',
         risk: '{{ lang._('the client has nowhere to register and will not start.') }}'},
        {path: 'auth.token', level: 'warning',
         label: '{{ lang._('Token') }}',
         risk: '{{ lang._('it must match the server token character for character or the server refuses the client.') }}'}
    ];

    /* Keys that belong to some proxy types and not others. frp decodes with
       strict_config on, so a key left behind from the previous type is not
       ignored: it aborts the client. */
    const TYPE_KEYS = {
        tcp: ['remotePort'],
        udp: ['remotePort'],
        http: ['customDomains', 'subdomain', 'locations', 'httpUser', 'httpPassword',
               'hostHeaderRewrite', 'requestHeaders', 'responseHeaders', 'routeByHTTPUser'],
        https: ['customDomains', 'subdomain'],
        stcp: ['secretKey', 'allowUsers'],
        xtcp: ['secretKey', 'allowUsers'],
        sudp: ['secretKey', 'allowUsers'],
        tcpmux: ['customDomains', 'subdomain', 'multiplexer', 'httpUser', 'httpPassword',
                 'routeByHTTPUser']
    };
    const EXCLUSIVE = [];
    Object.keys(TYPE_KEYS).forEach(function (type) {
        TYPE_KEYS[type].forEach(function (key) {
            if (EXCLUSIVE.indexOf(key) === -1) { EXCLUSIVE.push(key); }
        });
    });
    const TYPES = ['tcp', 'udp', 'http', 'https', 'stcp', 'xtcp'];

    /* The client's [[proxies]] while they are being edited, and which of them
       arrived holding a stored secret. */
    let proxies = [];
    let kept = [];
    let running = false;

    /* The sentence that belongs in every row: what this proxy hands to the
       outside. It is the whole risk of running a client, so it is stated where
       the row is edited rather than in help nobody opens. */
    function exposure(row) {
        row = row || {};
        const type = String(row.type || 'tcp');
        const address = String(row.localIP === undefined ? '' : row.localIP).trim() || '127.0.0.1';
        const portRaw = row.localPort === undefined ? '' : String(row.localPort).trim();
        const target = address + ':' + (portRaw === '' ? '?' : portRaw);
        const local = row.plugin !== undefined
            ? '{{ lang._('the plugin configured on this proxy') }}' : target;
        const configured = frp.stored().serverAddr;
        const server = String(configured === undefined || configured === null ? '' : configured).trim();
        const host = server === '' || server === frp.PLACEHOLDER
            ? '{{ lang._('the frp server') }}' : server;
        const remoteRaw = row.remotePort === undefined ? '' : String(row.remotePort).trim();
        if (type === 'tcp' || type === 'udp') {
            return frp.fill('{{ lang._('Makes %l on this router reachable by anyone who can open %t port %p on %h.') }}',
                {'%l': local, '%t': type.toUpperCase(), '%p': remoteRaw === '' ? '?' : remoteRaw, '%h': host});
        }
        if (type === 'http' || type === 'https') {
            const names = (Array.isArray(row.customDomains) ? row.customDomains.slice() : []);
            if (row.subdomain) {
                names.push(frp.fill('{{ lang._('the subdomain %s') }}', {'%s': row.subdomain}));
            }
            return frp.fill('{{ lang._('Makes %l on this router reachable by anyone whose %t request to %h matches %d.') }}',
                {'%l': local, '%t': type.toUpperCase(), '%h': host,
                 '%d': names.length ? names.join(', ') : '{{ lang._('any name the server routes here') }}'});
        }
        if (type === 'stcp' || type === 'xtcp' || type === 'sudp') {
            return frp.fill('{{ lang._('Makes %l on this router reachable by every visitor that presents the secret key of this proxy through %h. It holds no public port, but that key is all that stands in front of it.') }}',
                {'%l': local, '%h': host});
        }
        return frp.fill('{{ lang._('Makes %l on this router reachable through the %t proxy on %h.') }}',
            {'%l': local, '%t': type, '%h': host});
    }

    function proxyInput(index, path, value, mode, hint) {
        return $('<input>')
            .attr('type', mode === 'secret' ? 'password' : 'text')
            .addClass('form-control input-sm frp-proxy')
            .attr('data-index', index).attr('data-path', path).attr('data-mode', mode)
            .attr('autocomplete', mode === 'secret' ? 'new-password' : 'off')
            .attr('spellcheck', 'false')
            .attr('placeholder', hint || '')
            .val(mode === 'secret'
                ? ''
                : (Array.isArray(value) ? value.join(', ')
                    : (value === undefined || value === null ? '' : String(value))));
    }

    function renderProxies() {
        const rows = $('#frp-proxy-rows').empty();
        $('#frp-proxy-count').text(frp.fill('{{ lang._('%n configured') }}', {'%n': proxies.length}));
        if (!proxies.length) {
            rows.append($('<tr>').append($('<td colspan="5">').append($('<span class="text-muted">')
                .text('{{ lang._('Nothing is published. The client will connect and expose nothing.') }}'))));
            return;
        }
        proxies.forEach(function (row, index) {
            const type = String(row.type || 'tcp');
            const options = TYPES.slice();
            /* A type this page does not offer -- sudp, tcpmux -- is kept as an
               option of its own so opening the tab cannot silently change it. */
            if (options.indexOf(type) === -1) { options.push(type); }
            const picker = $('<select>').addClass('form-control input-sm frp-proxy')
                .attr('data-index', index).attr('data-path', 'type');
            options.forEach(function (name) {
                picker.append($('<option>').val(name).text(name));
            });
            picker.val(type);

            const entry = $('<tr>');
            entry.append($('<td>').append(
                proxyInput(index, 'name', row.name, 'text', '{{ lang._('name') }}')));
            entry.append($('<td>').append(picker));
            entry.append($('<td class="frp-proxy-pair">')
                .append(proxyInput(index, 'localIP', row.localIP, 'text', '127.0.0.1'))
                .append(' ')
                .append(proxyInput(index, 'localPort', row.localPort, 'text', '{{ lang._('port') }}')));

            const reach = $('<td>');
            if (type === 'tcp' || type === 'udp') {
                reach.append(proxyInput(index, 'remotePort', row.remotePort, 'text',
                    '{{ lang._('remote port on the server') }}'));
            } else if (type === 'http' || type === 'https' || type === 'tcpmux') {
                reach.append(proxyInput(index, 'customDomains', row.customDomains, 'list',
                    '{{ lang._('custom domains, comma separated') }}'));
                reach.append(proxyInput(index, 'subdomain', row.subdomain, 'text',
                    '{{ lang._('subdomain') }}').css('margin-top', '4px'));
            } else {
                reach.append(proxyInput(index, 'secretKey', row.secretKey, 'secret', '')
                    .attr('placeholder', kept[index] && kept[index].secretKey
                        ? '{{ lang._('A secret key is stored. Leave empty to keep it.') }}'
                        : '{{ lang._('secret key the visitor must present') }}'));
                reach.append(proxyInput(index, 'allowUsers', row.allowUsers, 'list',
                    '{{ lang._('allowed users, comma separated') }}').css('margin-top', '4px'));
            }
            entry.append(reach);
            entry.append($('<td>').append($('<button type="button" class="btn btn-default btn-xs frp-proxy-remove">')
                .attr('data-index', index)
                .attr('title', '{{ lang._('Remove this proxy') }}')
                .append($('<i class="fa fa-trash-o">'))));
            rows.append(entry);

            rows.append($('<tr>').append($('<td colspan="5">').append(
                $('<span class="text-warning frp-proxy-note">').attr('data-index', index)
                    .append($('<i class="fa fa-exclamation-triangle">')).append(' ')
                    .append(document.createTextNode(exposure(row))))));
        });
    }

    function noteFor(index) {
        const note = $('.frp-proxy-note[data-index="' + index + '"]');
        note.empty().append($('<i class="fa fa-exclamation-triangle">')).append(' ')
            .append(document.createTextNode(exposure(proxies[index])));
    }

    function cleanProxy(row, index) {
        const entry = frp.copy(row);
        const name = String(entry.name === undefined ? '' : entry.name).trim();
        const label = frp.fill('{{ lang._('Proxy %n') }}', {'%n': name === '' ? index + 1 : name});
        if (name === '') {
            throw new Error(label + ': ' + '{{ lang._('give the proxy a name.') }}');
        }
        entry.name = name;
        entry.type = String(entry.type || 'tcp');
        ['localPort', 'remotePort'].forEach(function (key) {
            if (entry[key] === undefined) { return; }
            const text = String(entry[key]).trim();
            if (text === '') { delete entry[key]; return; }
            const number = parseInt(text, 10);
            if (!/^[0-9]+$/.test(text) || number < 1 || number > 65535) {
                throw new Error(label + ': ' + frp.fill(
                    '{{ lang._('%k must be a port between 1 and 65535.') }}', {'%k': key}));
            }
            entry[key] = number;
        });
        ['localIP', 'subdomain', 'secretKey'].forEach(function (key) {
            if (entry[key] === undefined) { return; }
            const text = String(entry[key]).trim();
            if (text === '') { delete entry[key]; } else { entry[key] = text; }
        });
        /* A proxy backed by a plugin has no local port; every other one does,
           and without it the row publishes nothing. */
        if (entry.localPort === undefined && entry.plugin === undefined) {
            throw new Error(label + ': ' + '{{ lang._('give the local port this proxy forwards to.') }}');
        }
        return entry;
    }

    /* What the saved configuration hands out, as opposed to what the Proxies
       tab currently holds unsaved. The Status tab states it because a running
       client publishes all of it the moment it connects. */
    function renderExposed() {
        const rows = $('#frp-exposed-rows').empty();
        const saved = frp.stored().proxies;
        const list = Array.isArray(saved) ? saved : [];
        $('#frp-exposed-state')
            .attr('class', 'label label-' + (running && list.length ? 'warning' : 'default'))
            .text(running
                ? (list.length ? frp.fill('{{ lang._('%n reachable from outside right now') }}', {'%n': list.length})
                               : '{{ lang._('running, nothing published') }}')
                : '{{ lang._('the client is stopped, nothing is reachable') }}');
        if (!list.length) {
            rows.append($('<tr>').append($('<td colspan="3">').append($('<span class="text-muted">')
                .text('{{ lang._('The saved client configuration publishes nothing.') }}'))));
            return;
        }
        list.forEach(function (row) {
            rows.append($('<tr>')
                .append($('<td>').text(String(row.name === undefined ? '' : row.name)))
                .append($('<td>').text(String(row.type || 'tcp')))
                .append($('<td>').text(exposure(row))));
        });
    }

    const frp = window.frpCommon({
        fields: FIELDS,
        required: REQUIRED,
        requiredIntro: '{{ lang._('The client is not ready to connect:') }}',
        onSettings: function (settings) {
            proxies = Array.isArray(settings.proxies) ? frp.copy(settings.proxies) : [];
            /* Which rows arrived carrying a secret, masked or not: the box is
               a password field and shows neither, so it has to say whether
               there is something behind it. */
            kept = proxies.map(function (row) {
                return {secretKey: row.secretKey !== undefined};
            });
            renderProxies();
            renderExposed();
        },
        onStatus: function (state) {
            running = !!state.running;
            renderExposed();
        },
        extend: function (payload) {
            const rows = proxies.map(cleanProxy);
            if (rows.length) { payload.proxies = rows; } else { delete payload.proxies; }
        }
    });

    $('#frp-proxy-rows').on('input change', '.frp-proxy', function () {
        const element = $(this);
        const index = parseInt(element.attr('data-index'), 10);
        const path = element.attr('data-path');
        const row = proxies[index];
        if (!row) { return; }
        if (path === 'type') {
            const wanted = TYPE_KEYS[String(element.val())] || [];
            EXCLUSIVE.forEach(function (key) {
                if (wanted.indexOf(key) === -1) { delete row[key]; }
            });
            /* Switching away from a keyed type and back again must not throw
               the stored secret away: the row shows it as stored, so it has
               to still be asked for. */
            if (wanted.indexOf('secretKey') !== -1 && row.secretKey === undefined
                && kept[index] && kept[index].secretKey) {
                row.secretKey = frp.KEEP;
            }
            row.type = String(element.val());
            renderProxies();
            return;
        }
        const mode = element.attr('data-mode');
        const raw = String(element.val()).trim();
        if (mode === 'list') {
            if (raw === '') { delete row[path]; } else { row[path] = raw.split(/[\s,]+/).filter(Boolean); }
        } else if (mode === 'secret') {
            if (raw !== '') {
                row[path] = raw;
            } else if (kept[index] && kept[index][path]) {
                row[path] = frp.KEEP;
            } else {
                delete row[path];
            }
        } else if (raw === '') {
            delete row[path];
        } else {
            row[path] = raw;
        }
        noteFor(index);
    });

    $('#frp-proxy-rows').on('click', '.frp-proxy-remove', function () {
        const index = parseInt($(this).attr('data-index'), 10);
        proxies.splice(index, 1);
        kept.splice(index, 1);
        renderProxies();
    });

    $('#frp-proxy-add').on('click', function () {
        proxies.push({name: '', type: 'tcp', localIP: '127.0.0.1'});
        kept.push({});
        renderProxies();
    });

    frp.start();
});
</script>

<div class="alert" id="frp-message" style="display:none"></div>

<ul class="nav nav-tabs" role="tablist" id="maintabs">
    <li class="active"><a data-toggle="tab" href="#status">{{ lang._('Status') }}</a></li>
    <li><a data-toggle="tab" href="#settings">{{ lang._('Settings') }}</a></li>
    <li><a data-toggle="tab" href="#proxies">{{ lang._('Proxies') }}</a></li>
    <li><a data-toggle="tab" href="#advanced">{{ lang._('Advanced') }}</a></li>
    <li><a data-toggle="tab" href="#log">{{ lang._('Log') }}</a></li>
</ul>
<div class="tab-content content-box">

    <div id="status" class="tab-pane fade in active">
        <form id="frmstatus">
        <table class="table table-striped opnsense_standard_table_form">
            <thead>
                <tr><td style="width:22%"><strong>{{ lang._('frp client (frpc)') }}</strong></td>
                    <td style="width:78%; text-align:right">
                        <small>{{ lang._('full help') }} </small>
                        <i class="fa fa-toggle-off text-danger" style="cursor:pointer" id="show_all_help_status"></i>
                        &nbsp;&nbsp;
                    </td></tr>
            </thead>
            <tbody>
                <tr><td>{{ lang._('Service') }}</td>
                    <td><span id="frp-run" class="label label-default">-</span>
                        &nbsp;<span id="frp-boot" class="label label-default">-</span></td></tr>
                <tr><td>{{ lang._('Process id') }}</td><td><span id="frp-pid">-</span></td></tr>
                <tr><td>{{ lang._('Version') }}</td><td><span id="frp-version">-</span></td></tr>
                <tr><td></td><td><div class="alert alert-warning" id="frp-note" style="display:none"></div></td></tr>
                <tr>
                    <td><a id="help_for_frpc_control" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Control') }}</td>
                    <td>
                        <button type="button" class="btn btn-primary frp-action" data-verb="start"
                                data-done="{{ lang._('The client was started and will now start at boot.') }}">{{ lang._('Enable and start') }}</button>
                        <button type="button" class="btn btn-default frp-action" data-verb="stop"
                                data-done="{{ lang._('The client was stopped and will no longer start at boot.') }}">{{ lang._('Stop and disable') }}</button>
                        <button type="button" class="btn btn-default frp-action" data-verb="restart"
                                data-done="{{ lang._('The client was restarted.') }}">{{ lang._('Restart') }}</button>
                        <div class="hidden" data-for="help_for_frpc_control">
                            {{ lang._('Starting also sets frpc_enable in /etc/rc.conf.d/frpc, and stopping clears it. The client publishes every proxy listed below the moment it connects, so read that list before starting it. Anything blocking a start is named in the warning above.') }}
                        </div>
                    </td>
                </tr>
            </tbody>
        </table>
        <table class="table table-striped opnsense_standard_table_form">
            <thead><tr><td colspan="2"><strong>{{ lang._('What this client exposes') }}</strong>
                       &nbsp;<span id="frp-exposed-state" class="label label-default">-</span></td></tr></thead>
            <tbody>
                <tr><td colspan="2">
                    <div class="table-responsive">
                        <table class="table table-condensed">
                            <thead><tr>
                                <th style="width:20%">{{ lang._('Name') }}</th>
                                <th style="width:10%">{{ lang._('Type') }}</th>
                                <th>{{ lang._('Reach') }}</th>
                            </tr></thead>
                            <tbody id="frp-exposed-rows"></tbody>
                        </table>
                    </div>
                    <p class="text-muted">
                        {{ lang._('This is the saved client configuration. While the client runs, everything listed here is reachable from wherever the server is reachable. Rows edited on the Proxies tab appear here once they are saved.') }}
                    </p>
                </td></tr>
            </tbody>
        </table>
        </form>
    </div>

    <div id="settings" class="tab-pane fade in">
        <form id="frmsettings">
        <div class="alert" id="frp-required" style="display:none"></div>
        <table class="table table-striped opnsense_standard_table_form">
            <thead>
                <tr><td style="width:22%"><strong>{{ lang._('Server to register with') }}</strong></td>
                    <td style="width:78%; text-align:right">
                        <small>{{ lang._('full help') }} </small>
                        <i class="fa fa-toggle-off text-danger" style="cursor:pointer" id="show_all_help_settings"></i>
                        &nbsp;&nbsp;
                    </td></tr>
            </thead>
            <tbody>
                <tr>
                    <td><a id="help_for_frpc_server" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Server address') }}</td>
                    <td><input type="text" class="form-control" id="frpc_server_addr" style="width:320px" autocomplete="off" spellcheck="false">
                        <div class="hidden" data-for="help_for_frpc_server">
                            {{ lang._('Address or name of the frps this router registers with. A name is resolved again on every reconnect, which suits a server whose address changes.') }}
                        </div>
                    </td>
                </tr>
                <tr>
                    <td><a id="help_for_frpc_server_port" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Server port') }}</td>
                    <td><input type="text" class="form-control" id="frpc_server_port" style="width:160px" autocomplete="off" placeholder="7000">
                        <div class="hidden" data-for="help_for_frpc_server_port">
                            {{ lang._('The server\'s bind port, not the port of anything published through it.') }}
                        </div>
                    </td>
                </tr>
                <tr>
                    <td><a id="help_for_frpc_user" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Client name') }}</td>
                    <td><input type="text" class="form-control" id="frpc_user" style="width:240px" autocomplete="off" spellcheck="false">
                        <div class="hidden" data-for="help_for_frpc_user">
                            {{ lang._('Identifies this router on the server and prefixes every proxy name it publishes, so two routers can both publish a proxy called lan-ssh without colliding.') }}
                        </div>
                    </td>
                </tr>
                <tr>
                    <td><a id="help_for_frpc_auth_method" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Authentication method') }}</td>
                    <td>
                        <select id="frpc_auth_method" class="selectpicker" data-style="btn-default" data-width="240px">
                            <option value="">{{ lang._('default (token)') }}</option>
                            <option value="token">{{ lang._('token') }}</option>
                            <option value="oidc">{{ lang._('oidc') }}</option>
                        </select>
                        <div class="hidden" data-for="help_for_frpc_auth_method">
                            {{ lang._('It has to match what the server expects. The oidc settings live under auth.oidc and are edited on the Advanced tab.') }}
                        </div>
                    </td>
                </tr>
                <tr>
                    <td><a id="help_for_frpc_token" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Token') }}</td>
                    <td><input type="password" class="form-control" id="frpc_auth_token" autocomplete="new-password" spellcheck="false">
                        <div class="hidden" data-for="help_for_frpc_token">
                            {{ lang._('Must match the server token character for character, or the server drops the connection. The stored value is never sent back to this page, so an empty box keeps it.') }}
                        </div>
                    </td>
                </tr>
                <tr>
                    <td><a id="help_for_frpc_loginfail" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Exit when the first login fails') }}</td>
                    <td>
                        <select id="frpc_login_fail_exit" class="selectpicker" data-style="btn-default" data-width="220px">
                            <option value="">{{ lang._('default (yes)') }}</option>
                            <option value="true">{{ lang._('yes') }}</option>
                            <option value="false">{{ lang._('no') }}</option>
                        </select>
                        <div class="hidden" data-for="help_for_frpc_loginfail">
                            {{ lang._('The default makes frpc quit if the server is unreachable at startup, which on a router usually means it boots faster than its uplink. Set it to no to keep retrying instead.') }}
                        </div>
                    </td>
                </tr>
            </tbody>
        </table>
        <table class="table table-striped opnsense_standard_table_form">
            <thead><tr><td style="width:22%"><strong>{{ lang._('Transport') }}</strong></td><td style="width:78%"></td></tr></thead>
            <tbody>
                <tr>
                    <td><a id="help_for_frpc_protocol" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Protocol') }}</td>
                    <td>
                        <select id="frpc_protocol" class="selectpicker" data-style="btn-default" data-width="220px">
                            <option value="">{{ lang._('default (tcp)') }}</option>
                            <option value="tcp">{{ lang._('tcp') }}</option>
                            <option value="kcp">{{ lang._('kcp') }}</option>
                            <option value="quic">{{ lang._('quic') }}</option>
                            <option value="websocket">{{ lang._('websocket') }}</option>
                            <option value="wss">{{ lang._('wss') }}</option>
                        </select>
                        <div class="hidden" data-for="help_for_frpc_protocol">
                            {{ lang._('kcp and quic ride on UDP and need the matching bind port configured on the server; tcp needs nothing beyond the control port.') }}
                        </div>
                    </td>
                </tr>
                <tr>
                    <td><a id="help_for_frpc_pool" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Connection pool') }}</td>
                    <td><input type="text" class="form-control" id="frpc_pool_count" style="width:160px" autocomplete="off" placeholder="0">
                        <div class="hidden" data-for="help_for_frpc_pool">
                            {{ lang._('Connections held open to the server in advance, which removes the handshake from the first request. The server caps this with its own pool limit.') }}
                        </div>
                    </td>
                </tr>
                <tr>
                    <td><a id="help_for_frpc_tcpmux" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Multiplex one connection') }}</td>
                    <td>
                        <select id="frpc_tcp_mux" class="selectpicker" data-style="btn-default" data-width="220px">
                            <option value="">{{ lang._('default (yes)') }}</option>
                            <option value="true">{{ lang._('yes') }}</option>
                            <option value="false">{{ lang._('no') }}</option>
                        </select>
                        <div class="hidden" data-for="help_for_frpc_tcpmux">
                            {{ lang._('Carries every proxied stream over one connection to the server. It must be set the same way on both ends; leaving it at the default on both is the way to be sure.') }}
                        </div>
                    </td>
                </tr>
                <tr>
                    <td><a id="help_for_frpc_heartbeat" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Heartbeat interval') }}</td>
                    <td><input type="text" class="form-control" id="frpc_heartbeat_interval" style="width:160px" autocomplete="off" placeholder="30">
                        <div class="hidden" data-for="help_for_frpc_heartbeat">
                            {{ lang._('Seconds between keepalives, and how long the server waits before it considers this client gone. The timeout must be larger than the interval, and the server has a timeout of its own that has to agree.') }}
                        </div>
                    </td>
                </tr>
                <tr><td>{{ lang._('Heartbeat timeout') }}</td>
                    <td><input type="text" class="form-control" id="frpc_heartbeat_timeout" style="width:160px" autocomplete="off" placeholder="90"></td></tr>
            </tbody>
        </table>
        <table class="table table-striped opnsense_standard_table_form">
            <thead><tr><td style="width:22%"><strong>{{ lang._('Transport security') }}</strong></td><td style="width:78%"></td></tr></thead>
            <tbody>
                <tr>
                    <td><a id="help_for_frpc_tls" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Wrap in TLS') }}</td>
                    <td>
                        <select id="frpc_tls_enable" class="selectpicker" data-style="btn-default" data-width="220px">
                            <option value="">{{ lang._('default (yes)') }}</option>
                            <option value="true">{{ lang._('yes') }}</option>
                            <option value="false">{{ lang._('no') }}</option>
                        </select>
                        <div class="hidden" data-for="help_for_frpc_tls">
                            {{ lang._('frpc wraps the control connection in TLS by default, and a server set to require TLS accepts nothing else. Turning it off is only ever right against a server that cannot speak it.') }}
                        </div>
                    </td>
                </tr>
                <tr>
                    <td><a id="help_for_frpc_servername" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Expected server name') }}</td>
                    <td><input type="text" class="form-control" id="frpc_tls_server_name" style="width:320px" autocomplete="off" spellcheck="false">
                        <div class="hidden" data-for="help_for_frpc_servername">
                            {{ lang._('Only used together with a trusted CA file: it is the name the server certificate must carry. Without a CA file the certificate is not verified at all.') }}
                        </div>
                    </td>
                </tr>
                <tr>
                    <td><a id="help_for_frpc_tls_files" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Certificate file') }}</td>
                    <td><input type="text" class="form-control" id="frpc_tls_cert" autocomplete="off" spellcheck="false">
                        <div class="hidden" data-for="help_for_frpc_tls_files">
                            {{ lang._('Paths on this router, needed only when the server asks clients for a certificate of their own.') }}
                        </div>
                    </td>
                </tr>
                <tr><td>{{ lang._('Key file') }}</td>
                    <td><input type="text" class="form-control" id="frpc_tls_key" autocomplete="off" spellcheck="false"></td></tr>
                <tr><td>{{ lang._('Trusted CA file') }}</td>
                    <td><input type="text" class="form-control" id="frpc_tls_ca" autocomplete="off" spellcheck="false"></td></tr>
            </tbody>
        </table>
        <table class="table table-striped opnsense_standard_table_form">
            <thead><tr><td style="width:22%"><strong>{{ lang._('Logging') }}</strong></td><td style="width:78%"></td></tr></thead>
            <tbody>
                <tr>
                    <td><a id="help_for_frpc_log_to" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Destination') }}</td>
                    <td><input type="text" class="form-control" id="frpc_log_to" style="width:320px" autocomplete="off" spellcheck="false" placeholder="console">
                        <div class="hidden" data-for="help_for_frpc_log_to">
                            {{ lang._('Leave this on console. The rc script redirects the daemon output into /var/log/frpc.log, which is the file the Log tab reads.') }}
                        </div>
                    </td>
                </tr>
                <tr>
                    <td><a id="help_for_frpc_log_level" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Level') }}</td>
                    <td>
                        <select id="frpc_log_level" class="selectpicker" data-style="btn-default" data-width="200px">
                            <option value="">{{ lang._('default (info)') }}</option>
                            <option value="trace">{{ lang._('trace') }}</option>
                            <option value="debug">{{ lang._('debug') }}</option>
                            <option value="info">{{ lang._('info') }}</option>
                            <option value="warn">{{ lang._('warn') }}</option>
                            <option value="error">{{ lang._('error') }}</option>
                        </select>
                        <div class="hidden" data-for="help_for_frpc_log_level">
                            {{ lang._('debug is the level that shows why the server refused a proxy.') }}
                        </div>
                    </td>
                </tr>
                <tr><td>{{ lang._('Days kept') }}</td>
                    <td><input type="text" class="form-control" id="frpc_log_maxdays" style="width:160px" autocomplete="off" placeholder="3"></td></tr>
                <tr><td></td><td>
                    <button type="button" class="btn btn-primary frp-save">{{ lang._('Save and apply') }}</button>
                    <button type="button" class="btn btn-default frp-verify">{{ lang._('Verify only') }}</button>
                    <div class="text-muted" style="margin-top:6px">
                        {{ lang._('Saving rewrites /usr/local/etc/frp/frpc.toml with the settings from this tab and the proxies from the Proxies tab, and keeps every setting this page does not show. A running client keeps its old configuration until it is restarted.') }}
                    </div>
                </td></tr>
            </tbody>
        </table>
        </form>
    </div>

    <div id="proxies" class="tab-pane fade in">
        <form id="frmproxies">
        <table class="table table-striped opnsense_standard_table_form">
            <thead>
                <tr><td style="width:22%"><strong>{{ lang._('Published services') }}</strong>
                        &nbsp;<span class="text-muted" id="frp-proxy-count"></span></td>
                    <td style="width:78%; text-align:right">
                        <small>{{ lang._('full help') }} </small>
                        <i class="fa fa-toggle-off text-danger" style="cursor:pointer" id="show_all_help_proxies"></i>
                        &nbsp;&nbsp;
                    </td></tr>
            </thead>
            <tbody>
                <tr><td colspan="2">
                    <div class="alert alert-warning">
                        {{ lang._('Every row here hands a service on this router to the frp server, and from there to whoever can reach the server. Read the sentence under each row before saving: it names exactly what becomes reachable and from where.') }}
                    </div>
                    <div class="table-responsive">
                        <table class="table table-condensed frp-proxy-table">
                            <thead><tr>
                                <th style="width:18%">{{ lang._('Name') }}</th>
                                <th style="width:12%">{{ lang._('Type') }}</th>
                                <th style="width:26%">{{ lang._('Local address and port') }}</th>
                                <th style="width:34%">{{ lang._('Published as') }}</th>
                                <th style="width:10%"></th>
                            </tr></thead>
                            <tbody id="frp-proxy-rows"></tbody>
                        </table>
                    </div>
                    <button type="button" class="btn btn-default" id="frp-proxy-add" style="margin-top:8px">
                        <i class="fa fa-plus"></i> {{ lang._('Add proxy') }}</button>
                </td></tr>
                <tr>
                    <td><a id="help_for_proxy_rows" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('About the rows') }}</td>
                    <td>
                        <div class="hidden" data-for="help_for_proxy_rows">
                            {{ lang._('Name has to be unique on the server once the client name is prefixed to it. tcp and udp take a remote port, which must fall inside the range the server allows or the server rejects the proxy. http and https are routed by name instead and take custom domains, a subdomain, or both. stcp and xtcp open no port at all: only a visitor holding the secret key reaches them. Changing the type of a row drops the settings that belong only to the type it had. A stored secret key stays with its proxy as long as the name does not change.') }}
                        </div>
                    </td>
                </tr>
                <tr><td></td><td>
                    <button type="button" class="btn btn-primary frp-save" id="frp-proxy-save">{{ lang._('Save and apply') }}</button>
                    <button type="button" class="btn btn-default frp-verify" id="frp-proxy-check">{{ lang._('Verify only') }}</button>
                    <div class="text-muted" style="margin-top:6px">
                        {{ lang._('This writes the whole client configuration, so it also applies anything changed on the Settings tab. A running client keeps publishing what it already has until it is restarted.') }}
                    </div>
                </td></tr>
            </tbody>
        </table>
        </form>
    </div>

    <div id="advanced" class="tab-pane fade in">
        <form id="frmadvanced">
        <table class="table table-striped opnsense_standard_table_form">
            <thead>
                <tr><td style="width:22%"><strong>{{ lang._('frpc.toml') }}</strong></td>
                    <td style="width:78%; text-align:right">
                        <small>{{ lang._('full help') }} </small>
                        <i class="fa fa-toggle-off text-danger" style="cursor:pointer" id="show_all_help_advanced"></i>
                        &nbsp;&nbsp;
                    </td></tr>
            </thead>
            <tbody>
                <tr><td colspan="2">
                    <div class="alert alert-warning">
                        {{ lang._('frpc parses its file with strict_config on. One unknown or misspelled key is not a warning: the daemon exits and the service stays down. Verify before saving, and expect to restart the daemon to find out what it makes of the result.') }}
                    </div>
                </td></tr>
                <tr>
                    <td><a id="help_for_frpc_document" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Client configuration') }}
                        <div class="text-muted"><small id="frp-path"></small></div></td>
                    <td>
                        <textarea id="frp-document" rows="18"
                                  class="form-control frp-document" spellcheck="false"></textarea>
                        <div class="text-muted" id="frp-editing" style="display:none;margin-top:4px">
                            {{ lang._('This editor has unsaved changes, so it is no longer being refreshed. Reload to discard them.') }}
                        </div>
                        <div style="margin-top:8px">
                            <button type="button" class="btn btn-primary frp-document-save">{{ lang._('Save and apply') }}</button>
                            <button type="button" class="btn btn-default frp-document-verify">{{ lang._('Verify only') }}</button>
                            <button type="button" class="btn btn-default frp-document-reload">{{ lang._('Reload') }}</button>
                        </div>
                        <div class="hidden" data-for="help_for_frpc_document">
                            {{ lang._('The whole document, as the plugin stores it. Each [[proxies]] block here is one row of the Proxies tab, and saving this editor replaces the whole client configuration including those rows, so anything typed on the other tabs and not yet saved is lost. Comments are not kept and keys are written with dots rather than in [table] blocks; both spellings mean the same thing to frp. A credential reads __KEEP__ because its value is never sent to a browser: leave the placeholder where it is and the stored value is kept, and moving it to another key is refused rather than guessed at. Deleting the line is how a stored credential is removed.') }}
                        </div>
                    </td>
                </tr>
            </tbody>
        </table>
        </form>
    </div>

    <div id="log" class="tab-pane fade in">
        <form id="frmlog">
        <table class="table table-striped opnsense_standard_table_form">
            <thead>
                <tr><td style="width:22%"><strong>{{ lang._('Client log') }}</strong></td>
                    <td style="width:78%; text-align:right">
                        <small>{{ lang._('full help') }} </small>
                        <i class="fa fa-toggle-off text-danger" style="cursor:pointer" id="show_all_help_log"></i>
                        &nbsp;&nbsp;
                    </td></tr>
            </thead>
            <tbody>
                <tr>
                    <td><a id="help_for_logs" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('/var/log/frpc.log') }}</td>
                    <td>
                        <pre id="frp-log" class="frp-log"></pre>
                        <button type="button" class="btn btn-default" id="frp-log-refresh">
                            <i class="fa fa-refresh"></i> {{ lang._('Refresh the log') }}</button>
                        <div class="hidden" data-for="help_for_logs">
                            {{ lang._('The tail of the daemon\'s output. A proxy the server refused shows up here as the reason it was rejected, and a configuration the daemon rejects as the reason it exited. While this tab is open the tail is read again every ten seconds.') }}
                        </div>
                    </td>
                </tr>
            </tbody>
        </table>
        </form>
    </div>

</div>
