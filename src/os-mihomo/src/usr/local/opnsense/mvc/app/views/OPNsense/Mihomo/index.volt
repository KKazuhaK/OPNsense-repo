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
            ['dns_fallback', 'router_dns', 'dns_override', 'ipv6', 'dns_hijack', 'dashboard_any',
             'allow_lan', 'tcp_redirect'].forEach(function (flag) {
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
                $('#effective_' + field).text(inherited.length ? inherited.join(', ')
                    : '{{ lang._('not present') }}');
            });
            updateDnsControls();
            $('#device_list').val((s.device_list || []).join('\n'));
            /* The stored selection wins over whatever the picker showed. */
            storedCapture = s.capture_interfaces || [];
            captureReady = false;
            renderCaptureInterfaces(captureCandidates);
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

    let lastDevices = {devices: [], rules: []};

    /* Settings and candidates arrive in separate responses, in either order.
       Until the stored selection has been applied the picker must not report
       its own (empty) state back, or a save would clear the selection. */
    let storedCapture = [];
    let captureCandidates = [];
    let captureReady = false;

    function renderCaptureInterfaces(list) {
        captureCandidates = Array.isArray(list) ? list : [];
        const select = $('#capture_interfaces');
        const current = captureReady ? (select.val() || []) : storedCapture;
        const known = {};
        select.empty();
        captureCandidates.forEach(function (item) {
            known[item.name] = true;
            const networks = (item.networks || []).filter(function (net) { return !/^fe80:/i.test(net); });
            select.append($('<option>').val(item.name)
                .text(item.descr + ' (' + item.name + ', ' + item.device + ')')
                .attr('data-subtext', networks.length ? networks.join(', ') : '{{ lang._('no address') }}'));
        });
        /* A selected interface that is gone, disabled or now WAN-like stays
           visible and selected, so saving never drops it silently. */
        current.forEach(function (name) {
            if (!known[name]) {
                select.append($('<option>').val(name).text(name)
                    .attr('data-subtext', '{{ lang._('unavailable: missing, disabled or WAN-like') }}'));
            }
        });
        select.val(current);
        select.selectpicker('refresh');
        captureReady = true;
    }

    function updateDnsControls() {
        const editable = $('#dns_override').is(':checked') && !$('#router_dns').is(':checked');
        $('#dns_default,#dns_nameserver,#dns_proxy_nameserver').prop('disabled', !editable);
    }

    $('#dns_override,#router_dns').on('change', updateDnsControls);

    /* One entry can cover a whole segment, and a segment keeps covering it as
       devices come and go, which an address picked from a lease cannot. With
       many devices that is the difference between one line and eighty, so the
       segment is offered as a choice of its own rather than only as a heading. */
    function segmentOf(address) {
        if (address.indexOf(':') !== -1) {
            const parts = address.split(':');
            return parts.slice(0, 4).join(':') + '::/64';
        }
        const octets = address.split('.');
        return octets.length === 4 ? octets.slice(0, 3).join('.') + '.0/24' : '';
    }

    function coveredBy(address, chosen) {
        const segment = segmentOf(address);
        return segment && chosen.indexOf(segment) !== -1 ? segment : '';
    }

    function renderDevices(found) {
        const devices = (found.devices || []).slice();
        const chosen = listed();
        const needle = $('#mihomo-device-search').val().trim().toLowerCase();
        const onlyChosen = $('#mihomo-device-selected-only').is(':checked');
        const rows = $('#mihomo-device-rows').empty();

        const segments = [];
        const grouped = {};
        devices.forEach(function (device) {
            const segment = segmentOf(device.address) || '{{ lang._('Other') }}';
            if (!grouped[segment]) { grouped[segment] = []; segments.push(segment); }
            grouped[segment].push(device);
        });

        let shown = 0;
        let picked = 0;
        segments.forEach(function (segment) {
            const wholeSegment = chosen.indexOf(segment) !== -1;
            const members = grouped[segment].filter(function (device) {
                const covered = wholeSegment || chosen.indexOf(device.address) !== -1;
                if (onlyChosen && !covered) { return false; }
                if (!needle) { return true; }
                return (device.hostname + ' ' + device.address + ' ' + device.mac)
                    .toLowerCase().indexOf(needle) !== -1;
            });
            grouped[segment].forEach(function (device) {
                if (wholeSegment || chosen.indexOf(device.address) !== -1) { picked += 1; }
            });
            if (!members.length && !(wholeSegment && !needle)) { return; }

            const header = $('<tr class="active">');
            const segmentBox = $('<input type="checkbox" class="mihomo-segment">')
                .val(segment).prop('checked', wholeSegment);
            header.append($('<td>').append(segment.indexOf('/') !== -1 ? segmentBox : ''));
            header.append($('<td colspan="4">').append($('<strong>').text(segment))
                .append(' ').append($('<span class="text-muted">')
                    .text('{{ lang._('%s devices') }}'.replace('%s', grouped[segment].length))));
            rows.append(header);

            members.forEach(function (device) {
                shown += 1;
                const covered = coveredBy(device.address, chosen);
                const box = $('<input type="checkbox" class="mihomo-device">').val(device.address)
                    .prop('checked', !!covered || chosen.indexOf(device.address) !== -1)
                    .prop('disabled', !!covered);
                const flags = $('<td>');
                if (covered) {
                    flags.append($('<span class="text-muted">')
                        .text('{{ lang._('covered by %s') }}'.replace('%s', covered)));
                } else {
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
                }
                rows.append($('<tr>')
                    .append($('<td>').append(box))
                    .append($('<td>').text(device.hostname || '{{ lang._('unnamed') }}'))
                    .append($('<td><code></code></td>').find('code').text(device.address).end())
                    .append($('<td>').append($('<small class="text-muted">').text(device.mac || '')))
                    .append(flags));
            });
        });

        $('#mihomo-device-empty').toggle(!devices.length);
        const entries = chosen.length;
        $('#mihomo-device-count').text(
            '{{ lang._('%p of %t devices, from %e entries') }}'
                .replace('%p', picked).replace('%t', devices.length).replace('%e', entries)
            + (shown < devices.length ? ' \u00b7 ' + '{{ lang._('%s shown') }}'.replace('%s', shown) : ''));
        const preview = Array.isArray(found.routing) ? found.routing
            : (Array.isArray(found.rules) ? found.rules : []);
        $('#mihomo-device-rules').text(preview.length ? preview.join('\n')
            : '{{ lang._('No saved device policy preview is available.') }}');
        lastDevices = found;
    }

    function loadDevices() {
        get(api.devices, function (found) {
            renderDevices(found);
            renderCaptureInterfaces((found || {}).interfaces);
        });
    }

    $('#mihomo-device-rows').on('change', '.mihomo-device', function () {
        const address = $(this).val();
        const entries = listed().filter(function (entry) { return entry !== address; });
        if ($(this).is(':checked')) { entries.push(address); }
        setListed(entries);
        renderDevices(lastDevices);
    });

    $('#mihomo-device-rows').on('change', '.mihomo-segment', function () {
        const segment = $(this).val();
        let entries = listed().filter(function (entry) { return entry !== segment; });
        if ($(this).is(':checked')) {
            /* Remove individual addresses already covered by the segment. */
            entries = entries.filter(function (entry) {
                return entry.indexOf('/') !== -1 || segmentOf(entry) !== segment;
            });
            entries.push(segment);
        }
        setListed(entries);
        renderDevices(lastDevices);
    });

    $('#mihomo-refresh-devices').on('click', loadDevices);
    $('#mihomo-device-search, #mihomo-device-selected-only').on('input change', function () {
        renderDevices(lastDevices);
    });
    $('#device_list').on('input', function () { renderDevices(lastDevices); });

    function refresh() {
        get(api.status, function (state) {
            state = state || {};
            $('#mihomo-service').attr('class', 'label label-' + (state.running ? 'success' : 'default'))
                .text(state.running ? '{{ lang._('Running') }}' : '{{ lang._('Stopped') }}');
            const routed = state.routing_active === true;
            $('#mihomo-transparent').attr('class', 'label label-' + (routed ? 'success' : 'default'))
                .text(routed ? '{{ lang._('Active') }}' : '{{ lang._('Off') }}');
            $('#mihomo-dns').attr('class', 'label label-' + (state.dns_active ? 'success' : 'default'))
                .text(state.dns_active ? '{{ lang._('Active') }}' : '{{ lang._('Off') }}');
            $('#mihomo-dns-note').text(state.dns_note || '');
            $('#mihomo-tcp-redirect').attr('class', 'label label-' + (state.tcp_redirect ? 'success' : 'default'))
                .text(state.tcp_redirect ? '{{ lang._('Active') }}' : '{{ lang._('Off') }}');
            $('#mihomo-tcp-redirect-note').text(state.tcp_redirect_note || '');
            $('#mihomo-enable').toggle(!state.transparent);
            $('#mihomo-disable').toggle(!!state.transparent);
            const warnings = [state.error, state.backup_warning].filter(Boolean).join(' ');
            $('#mihomo-warning').toggle(!!warnings).text(warnings);
            $('#mihomo-repair-backup').toggle(!!state.backup_warning || !state.running);
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
                const warning = data.warning || (data.result || {}).warning;
                report(warning ? 'warning' : 'success', warning || done);
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
            capture_interfaces: ($('#capture_interfaces').val() || []).join(','),
            dns_default: $('#dns_default').val(),
            dns_nameserver: $('#dns_nameserver').val(),
            dns_proxy_nameserver: $('#dns_proxy_nameserver').val()
        }};
        ['mixed_port', 'socks_port', 'tun_mtu', 'bind_address', 'tun_stack'].forEach(function (field) {
            // Preserve an existing disabled stack choice while TUN is off.
            payload.settings[field] = $('#' + field).prop('value');
        });
        ['dns_fallback', 'router_dns', 'dns_override', 'ipv6', 'dns_hijack', 'dashboard_any',
         'allow_lan', 'tcp_redirect'].forEach(function (flag) {
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

    /* These forms exist only so the framework's whole-page help toggle can
       find a scope; they post nowhere, and Enter in a field would otherwise
       reload the page and lose what was typed. */
    $('form[id^="frm"]').on('submit', function (event) { event.preventDefault(); });

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
    <li><a data-toggle="tab" href="#devices">{{ lang._('Devices') }}</a></li>
    <li><a data-toggle="tab" href="#dns">{{ lang._('DNS') }}</a></li>
    <li><a data-toggle="tab" href="#advanced">{{ lang._('Advanced') }}</a></li>
    <li><a data-toggle="tab" href="#log">{{ lang._('Log') }}</a></li>
</ul>
<div class="tab-content content-box">

    <div id="status" class="tab-pane fade in active">
        <form id="frmstatus">
        <table class="table table-striped opnsense_standard_table_form">
            <thead>
                <tr><td style="width:22%"><strong>{{ lang._('Service and transparent routing') }}</strong></td>
                    <td style="width:78%; text-align:right">
                        <small>{{ lang._('full help') }} </small>
                        <i class="fa fa-toggle-off text-danger" style="cursor:pointer" id="show_all_help_status"></i>
                        &nbsp;&nbsp;
                    </td></tr>
            </thead>
            <tbody>
                <tr><td>{{ lang._('Service') }}</td><td><span id="mihomo-service" class="label label-default">-</span></td></tr>
                <tr><td>{{ lang._('Transparent routing') }}</td><td><span id="mihomo-transparent" class="label label-default">-</span></td></tr>
                <tr><td>{{ lang._('DNS integration') }}</td><td><span id="mihomo-dns" class="label label-default">-</span> <small id="mihomo-dns-note" class="text-muted"></small></td></tr>
                <tr><td>{{ lang._('Fast TCP path') }}</td><td><span id="mihomo-tcp-redirect" class="label label-default">-</span> <small id="mihomo-tcp-redirect-note" class="text-muted"></small></td></tr>
                <tr>
                    <td><a id="help_for_service" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Service control') }}</td>
                    <td>
                        <button type="button" class="btn btn-default mihomo-action" data-action="start" data-done="{{ lang._('Service started.') }}">{{ lang._('Start') }}</button>
                        <button type="button" class="btn btn-default mihomo-action" data-action="stop" data-done="{{ lang._('Service stopped.') }}">{{ lang._('Stop') }}</button>
                        <button type="button" class="btn btn-default mihomo-action" data-action="restart" data-done="{{ lang._('Service restarted.') }}">{{ lang._('Restart') }}</button>
                        <button id="mihomo-repair-backup" type="button" class="btn btn-warning mihomo-action" style="display:none" data-action="repairBackup" data-done="{{ lang._('Saved backup validated and restored. Transparent routing remains off.') }}">{{ lang._('Repair saved backup') }}</button>
                        <div class="help-block">{{ lang._('Stop the service before repairing an edited saved backup. Repair validates and imports its saved configuration, then updates its checksum.') }}</div>
                        <div class="hidden" data-for="help_for_service">
                            {{ lang._('Starts or stops the proxy core. Installation and upgrades start proxy ports only; the router keeps its own routing and DNS until transparent routing is enabled below.') }}
                        </div>
                    </td>
                </tr>
                <tr>
                    <td><a id="help_for_transparent" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Transparent routing') }}</td>
                    <td>
                        <button type="button" class="btn btn-primary mihomo-action" id="mihomo-enable" data-action="enableTransparent" data-done="{{ lang._('Transparent routing enabled. LAN traffic now follows the saved device policy.') }}">{{ lang._('Enable transparent routing') }}</button>
                        <button type="button" class="btn btn-default mihomo-action" id="mihomo-disable" style="display:none" data-action="disableTransparent" data-done="{{ lang._('Transparent routing disabled. Routing and DNS were returned to the router.') }}">{{ lang._('Disable transparent routing') }}</button>
                        <div class="hidden" data-for="help_for_transparent">
                            {{ lang._('Sends eligible LAN traffic through Mihomo according to the saved device policy. Bypassed devices keep their existing routes. Firewall rules still apply. The router itself and incoming WAN connections, including port forwards, keep their existing routing. Transparent routing requires DNS answers with real addresses. The device policy selects traffic only: with the full preset and router DNS off, bypassed devices that use the router DNS are answered by Mihomo too (see Capture client DNS).') }}
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
        </form>
    </div>

    <div id="subscription" class="tab-pane fade in">
        <form id="frmsubscription">
        <table class="table table-striped opnsense_standard_table_form">
            <thead><tr><td style="width:22%"><strong>{{ lang._('Subscription') }}</strong></td><td style="width:78%; text-align:right">
                        <small>{{ lang._('full help') }} </small>
                        <i class="fa fa-toggle-off text-danger" style="cursor:pointer" id="show_all_help_subscription"></i>
                        &nbsp;&nbsp;
                    </td></tr></thead>
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
        </form>
    </div>

    <div id="routing" class="tab-pane fade in">
        <form id="frmrouting">
        <table class="table table-striped opnsense_standard_table_form">
            <thead><tr><td style="width:22%"><strong>{{ lang._('Local proxy') }}</strong></td><td style="width:78%; text-align:right">
                        <small>{{ lang._('full help') }} </small>
                        <i class="fa fa-toggle-off text-danger" style="cursor:pointer" id="show_all_help_routing"></i>
                        &nbsp;&nbsp;
                    </td></tr></thead>
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
                            {{ lang._('Off means the two ports above answer only on the router itself. Turn it on to let other devices use explicitly configured HTTP/SOCKS proxies. Device policy applies to transparent traffic. The firewall still decides who reaches the proxy ports.') }}
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
                            <option value="system" disabled>{{ lang._('System (unavailable on this build)') }}</option>
                            <option value="mixed" disabled>{{ lang._('Mixed (unavailable on this build)') }}</option>
                        </select>
                        <span class="label label-warning mihomo-override" id="override_tun_stack" style="display:none">{{ lang._('Overridden by the merge YAML') }}</span>
                        <div class="hidden" data-for="help_for_tunstack">
                            {{ lang._('This FreeBSD core supports gVisor for transparent routing. System and Mixed are unavailable because their TCP forwarding does not work on this build.') }}
                        </div>
                    </td>
                </tr>
                <tr>
                    <td><a id="help_for_tcpredirect" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Fast TCP path') }}</td>
                    <td><input type="checkbox" id="tcp_redirect">
                        <div class="hidden" data-for="help_for_tcpredirect">
                            {{ lang._('Send captured IPv4 TCP to Mihomo through a firewall redirect instead of the gVisor TUN. The TUN caps each TCP connection at about 20 KB in flight, which on Wi-Fi limits a single download to a few tens of Mbps; the redirect uses the kernel TCP stack instead. UDP, QUIC, DNS and IPv6 stay on the TUN, and TCP falls back to the TUN whenever the redirect is not ready.') }}<br>
                            {{ lang._('Firewall rules see redirected TCP as addressed to 127.0.0.1 port 7894. Block rules that match a destination host or port no longer apply to captured TCP, and pass rules limited to destination hosts or ports no longer match it, so it falls to the default block. A LAN rule that sets a gateway still matches and sends the redirected connection toward that gateway, where it is lost. Before enabling this, place a rule without a gateway that passes TCP from the captured sources to 127.0.0.1 port 7894 above any such rules, or keep those sources out of capture.') }}
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
        </form>
    </div>

    <div id="devices" class="tab-pane fade in">
        <form id="frmdevices">
        <table class="table table-striped opnsense_standard_table_form">
            <thead><tr><td style="width:22%"><strong>{{ lang._('Device policy') }}</strong></td><td style="width:78%; text-align:right">
                        <small>{{ lang._('full help') }} </small>
                        <i class="fa fa-toggle-off text-danger" style="cursor:pointer" id="show_all_help_devices"></i>
                        &nbsp;&nbsp;
                    </td></tr></thead>
            <tbody>
                <tr>
                    <td><a id="help_for_captureif" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Capture interfaces') }}</td>
                    <td>
                        <select id="capture_interfaces" class="selectpicker" multiple data-style="btn-default" data-width="320px"
                                data-live-search="true" data-show-subtext="true"
                                data-none-selected-text="{{ lang._('Automatic (all internal interfaces)') }}"></select>
                        <div class="hidden" data-for="help_for_captureif">
                            {{ lang._('Limits transparent routing to traffic arriving on the selected interfaces. Leave it empty to use every internal interface, which is the behaviour of earlier versions. WAN-like interfaces are never captured and are not offered: an interface counts as WAN-like when it is the WAN or OPNsense resolves a gateway for it, which covers every uplink of a multi-WAN setup, PPPoE links and VPN exits with a gateway. For a bridged LAN select the bridge interface, not its members, because member ports carry no address. A VPN server appears here only once its tunnel is assigned as an interface. The device policy below then selects addresses within these interfaces. Traffic to any local network, on any interface, always bypasses the tunnel.') }}
                        </div>
                    </td>
                </tr>
                <tr>
                    <td><a id="help_for_devmode" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Mode') }}</td>
                    <td>
                        <select id="device_mode" class="selectpicker" data-style="btn-default" data-width="320px">
                            <option value="off">{{ lang._('All eligible LAN devices enter the tunnel') }}</option>
                            <option value="whitelist">{{ lang._('Only listed LAN devices enter the tunnel') }}</option>
                            <option value="blacklist">{{ lang._('Listed LAN devices bypass the tunnel') }}</option>
                        </select>
                        <div class="hidden" data-for="help_for_devmode">
                            {{ lang._('Selects LAN source addresses before traffic enters the tunnel. A blacklist bypasses the listed sources; a whitelist sends only the listed sources through Mihomo. Bypassed traffic uses existing routes. Off or an empty list sends all eligible LAN sources through Mihomo. Existing firewall rules and user routing policies still apply. Router traffic and incoming WAN connections, including port forwards, are excluded in every mode. This setting does not restrict manually configured proxy clients.') }}
                        </div>
                    </td>
                </tr>
                <tr>
                    <td><a id="help_for_devpick" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Devices on this network') }}</td>
                    <td>
                        <div style="margin-bottom:8px">
                            <input type="text" id="mihomo-device-search" class="form-control input-sm"
                                   style="width:260px;display:inline-block" spellcheck="false"
                                   placeholder="{{ lang._('Filter by name, address or hardware address') }}">
                            <label style="margin-left:12px;font-weight:normal">
                                <input type="checkbox" id="mihomo-device-selected-only"> {{ lang._('Selected only') }}</label>
                            <span class="text-muted" id="mihomo-device-count" style="margin-left:12px"></span>
                        </div>
                        <div class="table-responsive" style="max-height:360px;overflow:auto">
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
                            {{ lang._('Shows devices from DHCP leases and neighbour entries, excluding router and uplink addresses. Selecting a device adds its IP address to the list below. Selection follows the address, so use a stable address or DHCP reservation. The hardware address helps identify the device; it is not used to select its traffic.') }}
                        </div>
                    </td>
                </tr>
                <tr>
                    <td><a id="help_for_devlist" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Addresses and networks') }}</td>
                    <td>
                        <textarea id="device_list" rows="4" class="form-control" spellcheck="false" style="font-family:monospace;font-size:12px" placeholder="192.168.10.50&#10;192.168.20.0/24"></textarea>
                        <div class="hidden" data-for="help_for_devlist">
                            {{ lang._('One address or network per line; a bare address selects that host alone. Both IPv4 and IPv6 are accepted; IPv6 forwarding also requires IPv6 support. Add devices that are offline by hand. An empty list sends all eligible LAN sources through Mihomo in every mode. Include every address a device uses if it must follow one policy.') }}
                        </div>
                    </td>
                </tr>
                <tr>
                    <td><a id="help_for_devrules" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Saved device policy') }}</td>
                    <td>
                        <pre id="mihomo-device-rules" class="mihomo-log" style="max-height:120px">{{ lang._('No saved device policy preview is available.') }}</pre>
                        <div class="hidden" data-for="help_for_devrules">
                            {{ lang._('Shows the saved policy for selecting LAN traffic before it enters the tunnel. Save settings to refresh this preview. Traffic that enters Mihomo then follows the subscription and merge rules.') }}
                        </div>
                    </td>
                </tr>
                <tr><td></td><td><button type="button" class="btn btn-primary mihomo-save" id="mihomo-save-devices">{{ lang._('Save settings') }}</button></td></tr>
            </tbody>
        </table>
        </form>
    </div>

    <div id="dns" class="tab-pane fade in">
        <form id="frmdns">
        <table class="table table-striped opnsense_standard_table_form">
            <thead><tr><td style="width:22%"><strong>{{ lang._('DNS policy') }}</strong></td><td style="width:78%; text-align:right">
                        <small>{{ lang._('full help') }} </small>
                        <i class="fa fa-toggle-off text-danger" style="cursor:pointer" id="show_all_help_dns"></i>
                        &nbsp;&nbsp;
                    </td></tr></thead>
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
                            {{ lang._('Default off. Lets Mihomo answer AAAA queries and carry IPv6 traffic through the tunnel. Leave it off unless the upstream nodes are known to work over IPv6, otherwise clients may prefer a v6 path that never completes. While Unbound forwards to Mihomo, this switch also decides whether devices that use the router DNS receive AAAA records for forwarded names.') }}
                        </div>
                    </td>
                </tr>
                <tr>
                    <td><a id="help_for_dnsmode" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('DNS mode') }}</td>
                    <td>
                        <select id="dns_mode" class="selectpicker" data-style="btn-default" data-width="260px">
                            <option value="redir-host">{{ lang._('redir-host (recommended)') }}</option>
                            <option value="normal">{{ lang._('normal') }}</option>
                            <option value="fake-ip">{{ lang._('fake-ip (legacy)') }}</option>
                        </select>
                        <span class="label label-warning mihomo-override" id="override_dns_mode" style="display:none">{{ lang._('Overridden by the merge YAML') }}</span>
                        <div class="hidden" data-for="help_for_dnsmode">
                            {{ lang._('redir-host is the default and returns real addresses while retaining domain mappings. normal also returns real addresses. Real DNS answers are required so bypassed devices can connect without entering Mihomo. Legacy fake-ip may be saved while transparent routing is off. Enabling transparent routing or applying configuration while it is active converts an effective fake-ip mode, including a merge override, to redir-host and saves that choice in settings.') }}
                        </div>
                    </td>
                </tr>
                <tr>
                    <td><a id="help_for_hijack" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Capture client DNS') }}</td>
                    <td><input type="checkbox" id="dns_hijack"> <span class="label label-warning mihomo-override" id="override_dns_hijack" style="display:none">{{ lang._('Overridden by the merge YAML') }}</span>
                        <div class="hidden" data-for="help_for_hijack">
                            {{ lang._('Default on. Redirects DNS queries that enter the tunnel to Mihomo. This switch only takes effect while transparent routing is enabled. Queries addressed to the router DNS do not depend on this switch: while transparent routing uses the full preset and router DNS is off, Unbound forwards every name it does not answer from local data or a more specific forward zone to Mihomo, unless Unbound validates DNSSEC. Every device that uses the router DNS is then answered by Mihomo, including bypassed devices, interfaces outside capture and VPN clients. Any other resolver that bypassed devices use must return real addresses.') }}
                        </div>
                    </td>
                </tr>
                <tr>
                    <td><a id="help_for_dns_override" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Override subscription DNS') }}</td>
                    <td><input type="checkbox" id="dns_override">
                        <div class="hidden" data-for="help_for_dns_override">
                            {{ lang._('Default off. When enabled, each nonempty manual field below replaces its counterpart in the generated runtime configuration. The stored subscription YAML is never rewritten. Router DNS takes priority while its switch is enabled.') }}
                        </div>
                    </td>
                </tr>
                <tr>
                    <td><a id="help_for_dns_default" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Bootstrap servers') }}</td>
                    <td><input type="text" class="form-control" id="dns_default" data-key="default-nameserver" autocomplete="off" spellcheck="false">
                        <span class="label label-warning mihomo-override" id="override_dns_default" style="display:none">{{ lang._('Overridden by the merge YAML') }}</span>
                        <div class="text-muted"><small>{{ lang._('Effective in the saved runtime configuration:') }} <code id="effective_dns_default"></code></small></div>
                        <div class="hidden" data-for="help_for_dns_default">
                            {{ lang._('Resolves the other servers below, so every entry must be a literal IP address: a name here has nothing left to resolve it. A copied tls://IP#TLS-hostname value is stored here as its literal IP; use tls://hostname below for encrypted queries. Leave empty to use what the subscription provides.') }}
                        </div>
                    </td>
                </tr>
                <tr>
                    <td><a id="help_for_dns_nameserver" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Nameservers') }}</td>
                    <td><input type="text" class="form-control" id="dns_nameserver" data-key="nameserver" autocomplete="off" spellcheck="false">
                        <span class="label label-warning mihomo-override" id="override_dns_nameserver" style="display:none">{{ lang._('Overridden by the merge YAML') }}</span>
                        <div class="text-muted"><small>{{ lang._('Effective in the saved runtime configuration:') }} <code id="effective_dns_nameserver"></code></small></div>
                        <div class="hidden" data-for="help_for_dns_nameserver">
                            {{ lang._('The upstreams used for names no per-domain policy matches. Accepts a plain address, https:// for DoH, tls:// for DoT, quic://, or system to hand the query to the router resolver. A pasted tls://IP#TLS-hostname endpoint is normalized to tls://TLS-hostname because Mihomo otherwise treats # as a proxy or interface. Leave empty to use what the subscription provides.') }}
                        </div>
                    </td>
                </tr>
                <tr>
                    <td><a id="help_for_dns_proxy" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Proxy node servers') }}</td>
                    <td><input type="text" class="form-control" id="dns_proxy_nameserver" data-key="proxy-server-nameserver" autocomplete="off" spellcheck="false">
                        <span class="label label-warning mihomo-override" id="override_dns_proxy_nameserver" style="display:none">{{ lang._('Overridden by the merge YAML') }}</span>
                        <div class="text-muted"><small>{{ lang._('Effective in the saved runtime configuration:') }} <code id="effective_dns_proxy_nameserver"></code></small></div>
                        <div class="hidden" data-for="help_for_dns_proxy">
                            {{ lang._('Resolves the proxy nodes themselves. This lookup has to succeed over the direct path before any proxy can be reached, so keep it on an upstream that works without the tunnel. A pasted tls://IP#TLS-hostname endpoint is normalized to Mihomo hostname form. Leave empty to use what the subscription provides.') }}
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
                            {{ lang._('Default off. Uses the router resolver and pins its DNS transport DIRECT. Activation is refused if clients are offered IPv6 while Mihomo IPv6 is disabled. While transparent routing uses the full preset, this switch also decides who answers devices that use the router DNS: on, Unbound\'s own upstreams; off, Mihomo, unless Unbound validates DNSSEC.') }}
                        </div>
                    </td>
                </tr>
                <tr><td></td><td><button type="button" class="btn btn-primary mihomo-save" id="mihomo-save-dns">{{ lang._('Save settings') }}</button></td></tr>
            </tbody>
        </table>
        </form>
    </div>

    <div id="advanced" class="tab-pane fade in">
        <form id="frmadvanced">
        <table class="table table-striped opnsense_standard_table_form">
            <thead><tr><td style="width:22%"><strong>{{ lang._('Local merge YAML') }}</strong></td><td style="width:78%; text-align:right">
                        <small>{{ lang._('full help') }} </small>
                        <i class="fa fa-toggle-off text-danger" style="cursor:pointer" id="show_all_help_advanced"></i>
                        &nbsp;&nbsp;
                    </td></tr></thead>
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
        </form>
    </div>


    <div id="log" class="tab-pane fade in">
        <form id="frmlog">
        <table class="table table-striped opnsense_standard_table_form">
            <thead><tr><td style="width:22%"><strong>{{ lang._('Log viewer') }}</strong></td><td style="width:78%; text-align:right">
                        <small>{{ lang._('full help') }} </small>
                        <i class="fa fa-toggle-off text-danger" style="cursor:pointer" id="show_all_help_log"></i>
                        &nbsp;&nbsp;
                    </td></tr></thead>
            <tbody>
                <tr><td></td><td>
                    <pre id="mihomo-log" class="mihomo-log"></pre>
                    <button type="button" class="btn btn-default mihomo-action" data-action="clearLog" data-done="{{ lang._('Log cleared.') }}">{{ lang._('Clear log') }}</button>
                </td></tr>
            </tbody>
        </table>
        </form>
    </div>

</div>
