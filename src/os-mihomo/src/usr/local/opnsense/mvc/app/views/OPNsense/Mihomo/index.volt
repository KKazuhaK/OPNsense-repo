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

<style>
    /* A log line is arbitrarily long; let the box scroll rather than the page. */
    .mihomo-log {
        max-height: 340px;
        overflow: auto;
        font-size: 12px;
        margin-bottom: 12px;
        max-width: 100%;
        white-space: pre;
        word-break: normal;
    }
</style>

<script>
$(function () {
    const api = {
        get: '/api/mihomo/settings/get',
        set: '/api/mihomo/settings/set',
        merge: '/api/mihomo/settings/saveMerge',
        subscription: '/api/mihomo/settings/saveSubscription',
        preset: '/api/mihomo/settings/loadPreset',
        status: '/api/mihomo/service/status',
        update: '/api/mihomo/service/updateStatus',
        log: '/api/mihomo/service/log',
        subLog: '/api/mihomo/service/subLog',
        devices: '/api/mihomo/service/devices'
    };

    function report(state, text) {
        $('#mihomo-message').attr('class', 'alert alert-' + state).text(text).show();
        $(window).scrollTop(0);
    }

    /* The framework HTML-escapes every array response on the way out, so a
       value is only intact once it is decoded on arrival. Decoding the whole
       response in one place rather than at each element is the difference
       between a log that reads "--&gt;" and a dashboard link whose "&" became
       "&amp;", which sends the panel to its defaults with no secret -- and a
       subscription whose escaped text gets written back into the file on the
       next save. */
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

    function get(url, done) {
        ajaxGet(url, {}, function (data) { done(decoded(data)); });
    }

    /* A restart or a transparent routing change takes seconds. Without a state
       of its own the page looks identical the whole time, so the operator
       cannot tell a slow success from a click that did nothing. */
    function busy(button, text) {
        if (button.data('idle-label') === undefined) { button.data('idle-label', button.html()); }
        button.prop('disabled', true)
              .html('<i class="fa fa-spinner fa-spin"></i> ' + button.data('idle-label'));
        report('info', text);
    }

    function idle(button) {
        button.prop('disabled', false).html(button.data('idle-label'));
    }

    /* A save reloads nothing, so the tab has to be remembered only across a
       manual reload; the framework already puts the active tab in the hash. */
    function currentTab() { return $('#maintabs li.active a').attr('href') || '#status'; }

    function load() {
        get(api.get, function (data) {
            if (!data || !data.settings) { return; }
            const s = data.settings;
            $('#device').val(s.device || '');
            $('#subscription_url').attr('placeholder', data.has_url
                ? '{{ lang._('Leave empty to keep the stored URL') }}'
                : '{{ lang._('No subscription URL is stored yet') }}');
            ['dns_fallback', 'router_dns', 'ipv6', 'dns_hijack', 'dashboard_any',
             'allow_lan'].forEach(function (flag) {
                $('#' + flag).prop('checked', !!s[flag]);
            });
            ['dns_mode', 'geo_source', 'device_mode', 'tun_stack'].forEach(function (choice) {
                $('#' + choice).val(s[choice] || $('#' + choice + ' option:first').val());
            });
            /* A stored value fills the box; the placeholder already shows the
               default, so an empty box reads as "whatever the default is". */
            ['mixed_port', 'socks_port', 'tun_mtu', 'bind_address'].forEach(function (field) {
                $('#' + field).val(s[field] === undefined || s[field] === null ? '' : s[field]);
            });
            ['dns_default', 'dns_nameserver', 'dns_proxy_nameserver'].forEach(function (field) {
                $('#' + field).val((s[field] || []).join(', '));
                const inherited = (data.effective_dns || {})[$('#' + field).data('key')] || [];
                $('#' + field).attr('placeholder', inherited.length ? inherited.join(', ')
                    : '{{ lang._('from the subscription') }}');
            });
            $('#device_list').val((s.device_list || []).join('\n'));
            $('#merge_content').val(data.merge || '');
            $('#config_content').val(data.subscription || '');
            $('.selectpicker').selectpicker('refresh');

            const presets = $('#preset').empty();
            (data.presets || []).forEach(function (name) { presets.append($('<option>').val(name).text(name)); });
            presets.selectpicker('refresh');

            $('#mihomo-dashboard').toggle(!!data.dashboard).attr('href', data.dashboard || '#');
            $('#mihomo-dashboard-note').toggle(!data.dashboard);

            $('.mihomo-override').hide();
            (data.overrides || []).forEach(function (key) { $('#override_' + key).show(); });

            const orphans = data.policy_orphans || [];
            $('#mihomo-orphans').toggle(orphans.length > 0);
            $('#mihomo-orphan-list').empty();
            orphans.forEach(function (key) {
                $('#mihomo-orphan-list').append($('<li>').append($('<code>').text(key)));
            });
        });
    }

    /* The list below is what gets stored; the table is a way of editing it.
       Keeping one source of truth means the hand-written entries, the ones for
       devices that are switched off, cannot be lost by using the picker. */
    function listed() {
        return $('#device_list').val().split('\n').map(function (line) { return line.trim(); })
                 .filter(function (line) { return line !== ''; });
    }

    function setListed(entries) {
        $('#device_list').val(entries.join('\n'));
    }

    function renderDevices(found) {
        const chosen = listed();
        const rows = $('#mihomo-device-rows').empty();
        (found.devices || []).forEach(function (device) {
            const box = $('<input type="checkbox">').val(device.address)
                .prop('checked', chosen.indexOf(device.address) !== -1);
            const flags = $('<td>');
            if (device.randomised_mac) {
                flags.append($('<span class="label label-warning">')
                    .text('{{ lang._('Rotating hardware address') }}')
                    .attr('title', '{{ lang._('This device presents a different hardware address per network and changes it over time, so even a reservation cannot hold its address. Turn off the private address for this network on the device first.') }}'));
            }
            if (!device.reserved) {
                flags.append(' ').append($('<span class="label label-default">')
                    .text('{{ lang._('No DHCP reservation') }}')
                    .attr('title', '{{ lang._('Its address comes from the pool, so it can change and this rule would then apply to whatever took the address. Give it a reservation to make the address its identity.') }}'));
            }
            rows.append($('<tr>')
                .append($('<td>').append(box))
                .append($('<td>').text(device.hostname || '{{ lang._('unnamed') }}'))
                .append($('<td><code></code></td>').find('code').text(device.address).end())
                .append($('<td>').append($('<small class="text-muted">').text(device.mac || '')))
                .append(flags));
        });
        $('#mihomo-device-empty').toggle(!(found.devices || []).length);
        const rules = found.rules || [];
        $('#mihomo-device-rules').text(rules.length ? rules.join('\n')
            : '{{ lang._('Saved settings produce no device rules.') }}');
    }

    function loadDevices() {
        get(api.devices, renderDevices);
    }

    $('#mihomo-device-rows').on('change', 'input[type=checkbox]', function () {
        const address = $(this).val();
        const entries = listed().filter(function (entry) { return entry !== address; });
        if ($(this).is(':checked')) { entries.push(address); }
        setListed(entries);
    });

    $('#mihomo-refresh-devices').on('click', loadDevices);
    $('#device_list').on('input', function () {
        const chosen = listed();
        $('#mihomo-device-rows input[type=checkbox]').each(function () {
            $(this).prop('checked', chosen.indexOf($(this).val()) !== -1);
        });
    });

    function refresh() {
        get(api.status, function (state) {
            state = state || {};
            $('#mihomo-service').attr('class', 'label label-' + (state.running ? 'success' : 'default'))
                .text(state.running ? '{{ lang._('Running') }}' : '{{ lang._('Stopped') }}');
            $('#mihomo-transparent').attr('class', 'label label-' + (state.transparent ? 'success' : 'default'))
                .text(state.transparent ? '{{ lang._('Active') }}' : '{{ lang._('Off') }}');
            $('#mihomo-dns').attr('class', 'label label-' + (state.dns_active ? 'success' : 'default'))
                .text(state.dns_active ? '{{ lang._('Active') }}' : '{{ lang._('Off') }}');
            $('#mihomo-enable').toggle(!state.transparent);
            $('#mihomo-disable').toggle(!!state.transparent);
            $('#mihomo-warning').toggle(!!state.error).text(state.error || '');
        });
        get(api.log, function (d) { $('#mihomo-log').text((d || {}).log || ''); });
        get(api.subLog, function (d) { $('#mihomo-sub-log').text((d || {}).log || ''); });
        get(api.update, function (d) { $('#mihomo-update-status').text((d || {}).message || ''); });
    }

    function call(url, payload, done, button) {
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
                load();
                loadDevices();
            } else {
                report('danger', data.error || '{{ lang._('The operation failed. The log tab may say why.') }}');
            }
            refresh();
        });
    }

    $('.mihomo-action').on('click', function () {
        const verb = $(this).data('action');
        call('/api/mihomo/service/' + verb, {}, $(this).data('done'), $(this));
    });

    $('.mihomo-save').on('click', function () {
        const payload = {settings: {
            subscription_url: $('#subscription_url').val(),
            clear_url: $('#clear_url').is(':checked') ? 1 : 0,
            secret: $('#secret').val(),
            device: $('#device').val(),
            dns_mode: $('#dns_mode').val(),
            geo_source: $('#geo_source').val(),
            device_mode: $('#device_mode').val(),
            device_list: $('#device_list').val(),
            dns_default: $('#dns_default').val(),
            dns_nameserver: $('#dns_nameserver').val(),
            dns_proxy_nameserver: $('#dns_proxy_nameserver').val()
        }};
        ['mixed_port', 'socks_port', 'tun_mtu', 'bind_address', 'tun_stack'].forEach(function (field) {
            payload.settings[field] = $('#' + field).val();
        });
        ['dns_fallback', 'router_dns', 'ipv6', 'dns_hijack', 'dashboard_any',
         'allow_lan'].forEach(function (flag) {
            payload.settings[flag] = $('#' + flag).is(':checked') ? 1 : 0;
        });
        call(api.set, payload, '{{ lang._('Settings saved. The configuration was regenerated from the stored subscription.') }}', $(this));
        $('#secret,#subscription_url').val('');
        $('#clear_url').prop('checked', false);
    });

    $('#mihomo-save-merge').on('click', function () {
        call(api.merge, {merge: $('#merge_content').val()}, '{{ lang._('Merge YAML saved and applied.') }}', $(this));
    });
    $('#mihomo-save-subscription').on('click', function () {
        call(api.subscription, {subscription: $('#config_content').val()}, '{{ lang._('Subscription configuration saved and applied.') }}', $(this));
    });
    $('#mihomo-load-preset').on('click', function () {
        call(api.preset, {preset: $('#preset').val()}, '{{ lang._('Preset loaded and applied. It replaced the merge YAML.') }}', $(this));
    });

    load();
    refresh();
    loadDevices();
    setInterval(refresh, 10000);
});
</script>

<div class="alert" id="mihomo-message" style="display:none"></div>
<div class="alert alert-warning" id="mihomo-warning" style="display:none"></div>

<ul class="nav nav-tabs" role="tablist" id="maintabs">
    <li class="active"><a data-toggle="tab" href="#status">{{ lang._('Status') }}</a></li>
    <li><a data-toggle="tab" href="#subscription">{{ lang._('Subscription') }}</a></li>
    <li><a data-toggle="tab" href="#routing">{{ lang._('Routing') }}</a></li>
    <li><a data-toggle="tab" href="#dns">{{ lang._('DNS') }}</a></li>
    <li><a data-toggle="tab" href="#advanced">{{ lang._('Advanced') }}</a></li>
    <li><a data-toggle="tab" href="#log">{{ lang._('Log') }}</a></li>
</ul>
<div class="tab-content content-box">

    <div id="status" class="tab-pane fade in active">
        <table class="table table-striped opnsense_standard_table_form">
            <thead>
                <tr><td style="width:22%"><strong>{{ lang._('Service and transparent routing') }}</strong></td>
                    <td style="width:78%; text-align:right">
                        <small>{{ lang._('full help') }} </small>
                        <i class="fa fa-toggle-off text-danger" style="cursor:pointer" id="show_all_help_page"></i>
                        &nbsp;&nbsp;
                    </td></tr>
            </thead>
            <tbody>
                <tr><td>{{ lang._('Service') }}</td><td><span id="mihomo-service" class="label label-default">-</span></td></tr>
                <tr><td>{{ lang._('Transparent routing') }}</td><td><span id="mihomo-transparent" class="label label-default">-</span></td></tr>
                <tr><td>{{ lang._('DNS integration') }}</td><td><span id="mihomo-dns" class="label label-default">-</span></td></tr>
                <tr>
                    <td><a id="help_for_service" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Service control') }}</td>
                    <td>
                        <button type="button" class="btn btn-default mihomo-action" data-action="start" data-done="{{ lang._('Service started.') }}">{{ lang._('Start') }}</button>
                        <button type="button" class="btn btn-default mihomo-action" data-action="stop" data-done="{{ lang._('Service stopped.') }}">{{ lang._('Stop') }}</button>
                        <button type="button" class="btn btn-default mihomo-action" data-action="restart" data-done="{{ lang._('Service restarted.') }}">{{ lang._('Restart') }}</button>
                        <div class="hidden" data-for="help_for_service">
                            {{ lang._('Starts or stops the proxy core. Installation and upgrades start proxy ports only; the router keeps its own routing and DNS until transparent routing is enabled below.') }}
                        </div>
                    </td>
                </tr>
                <tr>
                    <td><a id="help_for_transparent" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Transparent routing') }}</td>
                    <td>
                        <button type="button" class="btn btn-primary mihomo-action" id="mihomo-enable" data-action="enableTransparent" data-done="{{ lang._('Transparent routing enabled. LAN traffic and DNS now pass through Mihomo.') }}">{{ lang._('Enable transparent routing') }}</button>
                        <button type="button" class="btn btn-default mihomo-action" id="mihomo-disable" style="display:none" data-action="disableTransparent" data-done="{{ lang._('Transparent routing disabled. Routing and DNS were returned to the router.') }}">{{ lang._('Disable transparent routing') }}</button>
                        <div class="hidden" data-for="help_for_transparent">
                            {{ lang._('Hands LAN traffic and DNS to Mihomo using the validated merge YAML, including its TUN and DNS mode. This changes forwarding for every client on the network.') }}
                        </div>
                    </td>
                </tr>
                <tr>
                    <td><a id="help_for_dashboard" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Dashboard') }}</td>
                    <td>
                        <a class="btn btn-default" id="mihomo-dashboard" target="_blank" rel="noopener noreferrer" href="#">{{ lang._('Open dashboard') }}</a>
                        <span class="text-muted" id="mihomo-dashboard-note">{{ lang._('The control API is bound to loopback. Turn on Reachable dashboard under Subscription, or forward the port over SSH.') }}</span>
                        <div class="hidden" data-for="help_for_dashboard">
                            {{ lang._('Opens the bundled dashboard already signed in, by carrying the address and secret in the link fragment. A fragment is never sent to a server and never appears in a referrer, but it does land in this browser history, so treat a shared machine accordingly.') }}
                        </div>
                    </td>
                </tr>
            </tbody>
        </table>
    </div>

    <div id="subscription" class="tab-pane fade in">
        <table class="table table-striped opnsense_standard_table_form">
            <thead><tr><td style="width:22%"><strong>{{ lang._('Subscription') }}</strong></td><td style="width:78%"></td></tr></thead>
            <tbody>
                <tr>
                    <td><a id="help_for_url" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Subscription URL') }}</td>
                    <td>
                        <input type="text" class="form-control" id="subscription_url" autocomplete="off" spellcheck="false">
                        <label><input type="checkbox" id="clear_url"> {{ lang._('Remove the stored URL') }}</label>
                        <div class="hidden" data-for="help_for_url">
                            {{ lang._('The complete YAML the provider serves, fetched as-is: its nodes, groups, rules and DNS policy are kept. The stored value is never sent back to this page, so leaving the field empty keeps it.') }}
                        </div>
                    </td>
                </tr>
                <tr>
                    <td><a id="help_for_device" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Device label') }}</td>
                    <td>
                        <input type="text" class="form-control" id="device" autocomplete="off">
                        <div class="hidden" data-for="help_for_device">
                            {{ lang._('Identifies this router to the provider when the subscription is fetched. Letters, digits, dots, underscores and hyphens only.') }}
                        </div>
                    </td>
                </tr>
                <tr>
                    <td><a id="help_for_secret" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Dashboard secret') }}</td>
                    <td>
                        <input type="password" class="form-control" id="secret" autocomplete="new-password" placeholder="{{ lang._('Leave empty to keep the current secret') }}">
                        <div class="hidden" data-for="help_for_secret">
                            {{ lang._('Protects the dashboard and its control API. Generated on install and preserved across subscription refreshes and package upgrades; it is never sent back to this page.') }}
                        </div>
                    </td>
                </tr>
                <tr>
                    <td><a id="help_for_reachable" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Reachable dashboard') }}</td>
                    <td>
                        <input type="checkbox" id="dashboard_any">
                        <div class="hidden" data-for="help_for_reachable">
                            {{ lang._('Binds the control API to every interface instead of loopback only, so it can be opened from the LAN. The firewall still decides who reaches it, and the dashboard secret is what authenticates callers.') }}
                        </div>
                    </td>
                </tr>
                <tr><td></td><td><button type="button" class="btn btn-primary mihomo-save" id="mihomo-save">{{ lang._('Save settings') }}</button></td></tr>
            </tbody>
        </table>
        <table class="table table-striped opnsense_standard_table_form">
            <thead><tr><td style="width:22%"><strong>{{ lang._('Subscription log') }}</strong></td>
                       <td style="width:78%"><span id="mihomo-update-status" class="text-muted"></span></td></tr></thead>
            <tbody>
                <tr>
                    <td><a id="help_for_fetch" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Update') }}</td>
                    <td>
                        <button type="button" class="btn btn-default mihomo-action" data-action="subUpdate" data-done="{{ lang._('Subscription update queued. Check its status below.') }}">{{ lang._('Fetch and apply subscription') }}</button>
                        <div class="hidden" data-for="help_for_fetch">
                            {{ lang._('Schedule recurring updates in System → Settings → Cron using Renew mihomo Subscription. HTTP 4xx responses stop immediately; only timeouts and HTTP 5xx responses permit retries or proxy fallback.') }}
                        </div>
                    </td>
                </tr>
                <tr><td></td><td>
                    <pre id="mihomo-sub-log" class="mihomo-log"></pre>
                    <button type="button" class="btn btn-default mihomo-action" data-action="clearSubLog" data-done="{{ lang._('Subscription log cleared.') }}">{{ lang._('Clear log') }}</button>
                </td></tr>
            </tbody>
        </table>
    </div>

    <div id="routing" class="tab-pane fade in">
        <table class="table table-striped opnsense_standard_table_form">
            <thead><tr><td style="width:22%"><strong>{{ lang._('Local proxy') }}</strong></td><td style="width:78%"></td></tr></thead>
            <tbody>
                <tr>
                    <td><a id="help_for_mixedport" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Mixed port') }}</td>
                    <td><input type="number" id="mixed_port" class="form-control" style="width:160px" min="1" max="65535" placeholder="7890">
                        <span class="label label-warning mihomo-override" id="override_mixed_port" style="display:none">{{ lang._('Overridden by the merge YAML') }}</span>
                        <div class="hidden" data-for="help_for_mixedport">
                            {{ lang._('Accepts HTTP and SOCKS on one port, for clients pointed at the proxy by hand. Transparent routing does not use it. Ports 53, 1053 and 9090 belong to the resolver, to Mihomo\'s own DNS and to the dashboard, so they are refused here.') }}
                        </div>
                    </td>
                </tr>
                <tr>
                    <td><a id="help_for_socksport" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('SOCKS port') }}</td>
                    <td><input type="number" id="socks_port" class="form-control" style="width:160px" min="1" max="65535" placeholder="7891">
                        <span class="label label-warning mihomo-override" id="override_socks_port" style="display:none">{{ lang._('Overridden by the merge YAML') }}</span>
                        <div class="hidden" data-for="help_for_socksport">
                            {{ lang._('SOCKS5 only, for clients that will not use the mixed port. It cannot be the same as the mixed port.') }}
                        </div>
                    </td>
                </tr>
                <tr>
                    <td><a id="help_for_allowlan" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Reachable from the LAN') }}</td>
                    <td><input type="checkbox" id="allow_lan">
                        <span class="label label-warning mihomo-override" id="override_allow_lan" style="display:none">{{ lang._('Overridden by the merge YAML') }}</span>
                        <div class="hidden" data-for="help_for_allowlan">
                            {{ lang._('Off means the two ports above answer only on the router itself. Turn it on to let other devices use the proxy directly, which is the way to proxy a single machine without turning on transparent routing for the whole network. The firewall still decides who reaches the port.') }}
                        </div>
                    </td>
                </tr>
                <tr>
                    <td><a id="help_for_bindaddress" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Bind address') }}</td>
                    <td><input type="text" id="bind_address" class="form-control" style="width:240px" placeholder="127.0.0.1">
                        <span class="label label-warning mihomo-override" id="override_bind_address" style="display:none">{{ lang._('Overridden by the merge YAML') }}</span>
                        <div class="hidden" data-for="help_for_bindaddress">
                            {{ lang._('Which address the two ports answer on. Use the router\'s LAN address to offer the proxy to that network alone, or * for every address. It only takes effect once Reachable from the LAN is on.') }}
                        </div>
                    </td>
                </tr>
                <tr><td></td><td><button type="button" class="btn btn-primary mihomo-save" id="mihomo-save-proxy">{{ lang._('Save settings') }}</button></td></tr>
            </tbody>
        </table>
        <table class="table table-striped opnsense_standard_table_form">
            <thead><tr><td style="width:22%"><strong>{{ lang._('Transparent routing') }}</strong></td><td style="width:78%"></td></tr></thead>
            <tbody>
                <tr>
                    <td><a id="help_for_tunstack" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('TUN stack') }}</td>
                    <td>
                        <select id="tun_stack" class="selectpicker" data-style="btn-default" data-width="240px">
                            <option value="gvisor">{{ lang._('gVisor (default)') }}</option>
                            <option value="system">{{ lang._('System') }}</option>
                            <option value="mixed">{{ lang._('Mixed') }}</option>
                        </select>
                        <span class="label label-warning mihomo-override" id="override_tun_stack" style="display:none">{{ lang._('Overridden by the merge YAML') }}</span>
                        <div class="hidden" data-for="help_for_tunstack">
                            {{ lang._('How the tunnel moves packets. gVisor runs in Mihomo and needs nothing from the host, which is why it is the default. System hands the work to the kernel and is faster where that works. Mixed uses the system stack for TCP and gVisor for UDP. Change it only if throughput is a problem, and watch that transparent routing still comes up afterwards.') }}
                        </div>
                    </td>
                </tr>
                <tr>
                    <td><a id="help_for_tunmtu" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('TUN MTU') }}</td>
                    <td><input type="number" id="tun_mtu" class="form-control" style="width:160px" min="576" max="9000" placeholder="1420">
                        <span class="label label-warning mihomo-override" id="override_tun_mtu" style="display:none">{{ lang._('Overridden by the merge YAML') }}</span>
                        <div class="hidden" data-for="help_for_tunmtu">
                            {{ lang._('Largest packet the tunnel carries. 1420 leaves room for the headers most nodes add. Too large and large packets vanish instead of being fragmented, which looks like some sites loading and others hanging.') }}
                        </div>
                    </td>
                </tr>
                <tr><td></td><td><button type="button" class="btn btn-primary mihomo-save" id="mihomo-save-tun">{{ lang._('Save settings') }}</button></td></tr>
            </tbody>
        </table>
        <table class="table table-striped opnsense_standard_table_form">
            <thead><tr><td style="width:22%"><strong>{{ lang._('Device policy') }}</strong></td><td style="width:78%"></td></tr></thead>
            <tbody>
                <tr>
                    <td><a id="help_for_devmode" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Mode') }}</td>
                    <td>
                        <select id="device_mode" class="selectpicker" data-style="btn-default" data-width="320px">
                            <option value="off">{{ lang._('Every device follows the subscription rules') }}</option>
                            <option value="whitelist">{{ lang._('Only the listed devices may use the proxy') }}</option>
                            <option value="blacklist">{{ lang._('The listed devices never use the proxy') }}</option>
                        </select>
                        <div class="hidden" data-for="help_for_devmode">
                            {{ lang._('Decides which sources the proxy is allowed to carry once transparent routing is on. Everything not covered goes out the ordinary way, so a device left off a whitelist keeps working -- it simply is not proxied. The router itself is never on the list, so with a whitelist its own traffic stays direct as well.') }}
                        </div>
                    </td>
                </tr>
                <tr>
                    <td><a id="help_for_devpick" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Devices on this network') }}</td>
                    <td>
                        <div class="table-responsive" style="max-height:280px;overflow:auto">
                            <table class="table table-condensed table-hover" style="margin-bottom:0">
                                <thead><tr>
                                    <th style="width:34px"></th>
                                    <th>{{ lang._('Device') }}</th>
                                    <th>{{ lang._('Address') }}</th>
                                    <th>{{ lang._('Hardware address') }}</th>
                                    <th></th>
                                </tr></thead>
                                <tbody id="mihomo-device-rows"></tbody>
                            </table>
                        </div>
                        <p class="text-muted" id="mihomo-device-empty" style="display:none;margin-top:6px">
                            {{ lang._('Nothing has spoken to the router yet. Add addresses by hand below.') }}</p>
                        <button type="button" class="btn btn-default btn-sm" id="mihomo-refresh-devices" style="margin-top:6px">
                            <i class="fa fa-refresh"></i> {{ lang._('Refresh') }}</button>
                        <div class="hidden" data-for="help_for_devpick">
                            {{ lang._('Everything the router has a DHCP lease or a neighbour entry for, minus its own addresses and whatever is on the uplink. Ticking a device writes its address into the list below, because an address is the only thing a rule can match: by the time a packet reaches Mihomo the hardware address is gone. The hardware address is shown so the device can be recognised, and so the two ways its address can stop identifying it are visible.') }}
                        </div>
                    </td>
                </tr>
                <tr>
                    <td><a id="help_for_devlist" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Addresses and networks') }}</td>
                    <td>
                        <textarea id="device_list" rows="4" class="form-control" spellcheck="false" style="font-family:monospace;font-size:12px" placeholder="192.168.10.50&#10;192.168.20.0/24"></textarea>
                        <div class="hidden" data-for="help_for_devlist">
                            {{ lang._('One address or network per line; a bare address means that host alone. Both IPv4 and IPv6 are accepted. A device that is switched off has no entry above, so it is written here by hand. An empty list leaves every device on the subscription rules whatever the mode says, so a half-finished list cannot cut the network off.') }}
                        </div>
                    </td>
                </tr>
                <tr>
                    <td><a id="help_for_devrules" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Rules this produces') }}</td>
                    <td>
                        <pre id="mihomo-device-rules" class="mihomo-log" style="max-height:120px">{{ lang._('Saved settings produce no device rules.') }}</pre>
                        <div class="hidden" data-for="help_for_devrules">
                            {{ lang._('What the saved settings put in front of the subscription rules, generated by the same code that writes the configuration. Matching stops at the first rule that matches, so a whitelist cannot be written as a match on the listed devices; it is written as a match on everything else, which is why it reads inverted.') }}
                        </div>
                    </td>
                </tr>
                <tr><td></td><td><button type="button" class="btn btn-primary mihomo-save" id="mihomo-save-routing">{{ lang._('Save settings') }}</button></td></tr>
            </tbody>
        </table>
    </div>

    <div id="dns" class="tab-pane fade in">
        <table class="table table-striped opnsense_standard_table_form">
            <thead><tr><td style="width:22%"><strong>{{ lang._('DNS policy') }}</strong></td><td style="width:78%"></td></tr></thead>
            <tbody>
                <tr id="mihomo-orphans" style="display:none">
                    <td><i class="fa fa-exclamation-triangle text-warning"></i> {{ lang._('Unmatched DNS policy') }}</td>
                    <td><div class="alert alert-warning" style="margin-bottom:0">
                        {{ lang._('These per-domain rules in the merge YAML match no entry the subscription states, so each was added beside the one it was meant to replace rather than replacing it. Both stay in force.') }}
                        <ul id="mihomo-orphan-list" style="margin:6px 0 0 0"></ul>
                    </div></td>
                </tr>
                <tr>
                    <td><a id="help_for_fallback" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Restore direct DNS on exit') }}</td>
                    <td><input type="checkbox" id="dns_fallback">
                        <div class="hidden" data-for="help_for_fallback">
                            {{ lang._('This policy is local to this router. Turning it off keeps proxy DNS forwarding in place after an unexpected exit. An explicit Stop always restores the original DNS configuration.') }}
                        </div>
                    </td>
                </tr>
                <tr>
                    <td><a id="help_for_ipv6" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('IPv6 support') }}</td>
                    <td><input type="checkbox" id="ipv6"> <span class="label label-warning mihomo-override" id="override_ipv6" style="display:none">{{ lang._('Overridden by the merge YAML') }}</span>
                        <div class="hidden" data-for="help_for_ipv6">
                            {{ lang._('Default off. Lets Mihomo answer AAAA queries and carry IPv6 traffic through the tunnel. Leave it off unless the upstream nodes are known to work over IPv6, otherwise clients may prefer a v6 path that never completes.') }}
                        </div>
                    </td>
                </tr>
                <tr>
                    <td><a id="help_for_dnsmode" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('DNS mode') }}</td>
                    <td>
                        <select id="dns_mode" class="selectpicker" data-style="btn-default" data-width="260px">
                            <option value="fake-ip">{{ lang._('fake-ip (recommended)') }}</option>
                            <option value="redir-host">{{ lang._('redir-host') }}</option>
                            <option value="normal">{{ lang._('normal') }}</option>
                        </select>
                        <span class="label label-warning mihomo-override" id="override_dns_mode" style="display:none">{{ lang._('Overridden by the merge YAML') }}</span>
                        <div class="hidden" data-for="help_for_dnsmode">
                            {{ lang._('fake-ip answers with a placeholder address and resolves the real name at connection time; it is the fastest and the default. redir-host resolves upstream and rewrites the destination. normal performs no rewriting and disables rule matching by domain for routed traffic.') }}
                        </div>
                    </td>
                </tr>
                <tr>
                    <td><a id="help_for_hijack" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Capture client DNS') }}</td>
                    <td><input type="checkbox" id="dns_hijack"> <span class="label label-warning mihomo-override" id="override_dns_hijack" style="display:none">{{ lang._('Overridden by the merge YAML') }}</span>
                        <div class="hidden" data-for="help_for_hijack">
                            {{ lang._('Default on. Redirects DNS queries that enter the tunnel to Mihomo. Required for fake-ip. This switch only takes effect while transparent routing is enabled.') }}
                        </div>
                    </td>
                </tr>
                <tr>
                    <td><a id="help_for_dns_default" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Bootstrap servers') }}</td>
                    <td><input type="text" class="form-control" id="dns_default" data-key="default-nameserver" autocomplete="off" spellcheck="false">
                        <span class="label label-warning mihomo-override" id="override_dns_default" style="display:none">{{ lang._('Overridden by the merge YAML') }}</span>
                        <div class="hidden" data-for="help_for_dns_default">
                            {{ lang._('Resolves the other servers below, so every entry must be a literal IP address: a name here has nothing left to resolve it. Leave empty to use what the subscription provides.') }}
                        </div>
                    </td>
                </tr>
                <tr>
                    <td><a id="help_for_dns_nameserver" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Nameservers') }}</td>
                    <td><input type="text" class="form-control" id="dns_nameserver" data-key="nameserver" autocomplete="off" spellcheck="false">
                        <span class="label label-warning mihomo-override" id="override_dns_nameserver" style="display:none">{{ lang._('Overridden by the merge YAML') }}</span>
                        <div class="hidden" data-for="help_for_dns_nameserver">
                            {{ lang._('The upstreams used for names no per-domain policy matches. Accepts a plain address, https:// for DoH, tls:// for DoT, quic://, or system to hand the query to the router resolver. Leave empty to use what the subscription provides.') }}
                        </div>
                    </td>
                </tr>
                <tr>
                    <td><a id="help_for_dns_proxy" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Proxy node servers') }}</td>
                    <td><input type="text" class="form-control" id="dns_proxy_nameserver" data-key="proxy-server-nameserver" autocomplete="off" spellcheck="false">
                        <span class="label label-warning mihomo-override" id="override_dns_proxy_nameserver" style="display:none">{{ lang._('Overridden by the merge YAML') }}</span>
                        <div class="hidden" data-for="help_for_dns_proxy">
                            {{ lang._('Resolves the proxy nodes themselves. This lookup has to succeed over the direct path before any proxy can be reached, so keep it on an upstream that works without the tunnel. Leave empty to use what the subscription provides.') }}
                        </div>
                    </td>
                </tr>
                <tr>
                    <td><a id="help_for_geo" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Rule database') }}</td>
                    <td>
                        <select id="geo_source" class="selectpicker" data-style="btn-default" data-width="320px">
                            <option value="metacubex">{{ lang._('MetaCubeX (GitHub, official)') }}</option>
                            <option value="loyalsoldier-cdn">{{ lang._('Loyalsoldier (jsDelivr CDN)') }}</option>
                            <option value="loyalsoldier">{{ lang._('Loyalsoldier (GitHub)') }}</option>
                        </select>
                        <span class="label label-warning mihomo-override" id="override_geo_source" style="display:none">{{ lang._('Overridden by the merge YAML') }}</span>
                        <div class="hidden" data-for="help_for_geo">
                            {{ lang._('Where the geoip and geosite databases that GEOSITE and GEOIP rules match against are downloaded from, refreshed every 24 hours. The two projects do not publish the same categories, so switching can invalidate a rule that names a category the new source lacks.') }}
                        </div>
                    </td>
                </tr>
                <tr>
                    <td><a id="help_for_routerdns" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Resolve through the router DNS') }}</td>
                    <td><input type="checkbox" id="router_dns">
                        <div class="hidden" data-for="help_for_routerdns">
                            {{ lang._('Default off. Uses the router resolver and pins its DNS transport DIRECT. Activation is refused if clients are offered IPv6 while Mihomo IPv6 is disabled.') }}
                        </div>
                    </td>
                </tr>
                <tr><td></td><td><button type="button" class="btn btn-primary mihomo-save" id="mihomo-save-dns">{{ lang._('Save settings') }}</button></td></tr>
            </tbody>
        </table>
    </div>

    <div id="advanced" class="tab-pane fade in">
        <table class="table table-striped opnsense_standard_table_form">
            <thead><tr><td style="width:22%"><strong>{{ lang._('Local merge YAML') }}</strong></td><td style="width:78%"></td></tr></thead>
            <tbody>
                <tr>
                    <td><a id="help_for_merge" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Merge YAML') }}</td>
                    <td>
                        <textarea id="merge_content" rows="14" class="form-control" spellcheck="false" style="font-family:monospace;font-size:12px"></textarea>
                        <button type="button" class="btn btn-primary" id="mihomo-save-merge" style="margin-top:8px">{{ lang._('Save merge YAML') }}</button>
                        <div class="hidden" data-for="help_for_merge">
                            {{ lang._('Applied over the subscription, so a value written here wins over the switches on the other tabs and is marked there where it does.') }}
                        </div>
                    </td>
                </tr>
                <tr>
                    <td><a id="help_for_preset" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Preset') }}</td>
                    <td>
                        <select id="preset" class="selectpicker" data-style="btn-default" data-width="260px"></select>
                        <button type="button" class="btn btn-default" id="mihomo-load-preset" style="margin-left:6px">{{ lang._('Load preset') }}</button>
                        <div class="hidden" data-for="help_for_preset">
                            {{ lang._('Loading a preset replaces the entire merge file above. Save a copy of custom settings first.') }}
                        </div>
                    </td>
                </tr>
            </tbody>
        </table>
        <table class="table table-striped opnsense_standard_table_form">
            <thead><tr><td style="width:22%"><strong>{{ lang._('Subscription configuration') }}</strong></td><td style="width:78%"></td></tr></thead>
            <tbody>
                <tr>
                    <td><a id="help_for_config" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Subscription YAML') }}</td>
                    <td>
                        <textarea id="config_content" rows="20" class="form-control" spellcheck="false" style="font-family:monospace;font-size:12px"></textarea>
                        <button type="button" class="btn btn-primary" id="mihomo-save-subscription" style="margin-top:8px">{{ lang._('Save subscription YAML') }}</button>
                        <div class="hidden" data-for="help_for_config">
                            {{ lang._('The provider configuration as stored. A refresh replaces it; edit it to try a change without refetching.') }}
                        </div>
                    </td>
                </tr>
            </tbody>
        </table>
    </div>


    <div id="log" class="tab-pane fade in">
        <table class="table table-striped opnsense_standard_table_form">
            <thead><tr><td style="width:22%"><strong>{{ lang._('Log viewer') }}</strong></td><td style="width:78%"></td></tr></thead>
            <tbody>
                <tr><td></td><td>
                    <pre id="mihomo-log" class="mihomo-log"></pre>
                    <button type="button" class="btn btn-default mihomo-action" data-action="clearLog" data-done="{{ lang._('Log cleared.') }}">{{ lang._('Clear log') }}</button>
                </td></tr>
            </tbody>
        </table>
    </div>

</div>
