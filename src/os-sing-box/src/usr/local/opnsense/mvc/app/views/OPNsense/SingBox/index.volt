{# Copyright (C) 2026 Kazuha. All rights reserved. #}
<style>
    .singbox-editor, .singbox-log {
        max-width: 100%;
        font-family: Menlo, Monaco, Consolas, monospace;
        white-space: pre;
        overflow: auto;
        word-break: normal;
    }
    .singbox-editor { resize: vertical; }
    .singbox-log { max-height: 340px; font-size: 12px; }
    .singbox-toolbar .btn { margin-right: 4px; }
</style>
<script>
$(function () {
    let configRevision = '';
    function report(state, message) {
        $('#singbox-message').attr('class', 'alert alert-' + state).text(htmlDecode(message || '')).show();
    }
    function load() {
        ajaxGet('/api/singbox/settings/get', {}, function (data) {
            if (!data || data.status !== 'ok') {
                report('danger', (data || {}).error || '{{ lang._('Unable to read settings.') }}');
                return;
            }
            $('#singbox-config').val(htmlDecode(data.config || ''));
            configRevision = data.revision || '';
            const integration = data.integration || {};
            $('#singbox-transparent').prop('checked', !!integration.transparent);
            $('#singbox-consent').prop('checked', !!integration.transparent_consent);
            $('#singbox-ipv6').prop('checked', !!integration.ipv6);
            $('#singbox-device-mode').val(integration.device_mode || 'off');
            $('#singbox-device-list').val((integration.device_list || []).join('\n'));
            $('#singbox-url').val('').attr('placeholder', data.has_url
                ? '{{ lang._('Leave empty to keep the stored URL') }}'
                : '{{ lang._('Enter a direct Sing-box JSON subscription URL') }}');
            $('#singbox-clear-url').prop('checked', false);
        });
    }
    function refresh() {
        ajaxGet('/api/singbox/service/status', {}, function (data) {
            data = data || {};
            $('#singbox-service').attr('class', 'label label-' + (data.paused || data.restart_required || data.recovery_pending ? 'warning' : data.running ? 'success' : 'default'))
                .text(data.status !== 'ok' ? '{{ lang._('Unavailable') }}'
                    : data.recovery_pending ? '{{ lang._('Routing recovery pending') }}'
                    : data.paused ? (data.routing_fallback ? '{{ lang._('Suspended; native routing') }}' : '{{ lang._('Suspended; routing recovery in progress') }}')
                    : data.restart_required ? '{{ lang._('Running; restart to resume capture') }}'
                    : data.running ? '{{ lang._('Running') }}' : '{{ lang._('Stopped') }}');
            $('#singbox-warning').toggle(data.status !== 'ok' || !!data.routing_error)
                .text(htmlDecode(data.error || data.routing_error || ''));
        });
        ajaxGet('/api/singbox/service/updateStatus', {}, function (data) {
            data = data || {};
            $('#singbox-update-status').text(htmlDecode(data.message || data.error || ''));
            $('#singbox-update').prop('disabled', !!data.running);
        });
        ajaxGet('/api/singbox/service/log', {}, function (data) {
            $('#singbox-log').text(htmlDecode((data || {}).log || ''));
        });
        ajaxGet('/api/singbox/service/subLog', {}, function (data) {
            $('#singbox-sub-log').text(htmlDecode((data || {}).log || ''));
        });
    }
    function call(button, url, payload, message, reload) {
        button.prop('disabled', true);
        ajaxCall(url, payload || {}, function (data) {
            button.prop('disabled', false);
            data = data || {};
            report(data.status === 'ok' ? (data.warning ? 'warning' : 'success') : 'danger', data.status === 'ok'
                ? message + (data.warning ? ' ' + data.warning : '') : data.error || '{{ lang._('Operation failed.') }}');
            if (data.status === 'ok' && reload) { load(); }
            refresh();
        });
    }
    $('.singbox-action').on('click', function () {
        const button = $(this);
        call(button, '/api/singbox/service/' + button.data('action'), {}, button.data('done'), false);
    });
    $('#singbox-save-config').on('click', function () {
        call($(this), '/api/singbox/settings/saveConfig', {config: $('#singbox-config').val(), revision: configRevision},
            '{{ lang._('Configuration validated and saved. Restart the service to apply it.') }}', true);
    });
    $('#singbox-save-settings').on('click', function () {
        call($(this), '/api/singbox/settings/set', {settings: {
            subscription_url: $('#singbox-url').val(),
            clear_url: $('#singbox-clear-url').is(':checked') ? 1 : 0
        }}, '{{ lang._('Subscription settings saved.') }}', true);
    });
    $('#singbox-save-integration').on('click', function () {
        call($(this), '/api/singbox/settings/setIntegration', {integration: {
            transparent: $('#singbox-transparent').is(':checked') ? 1 : 0,
            transparent_consent: $('#singbox-consent').is(':checked') ? 1 : 0,
            ipv6: $('#singbox-ipv6').is(':checked') ? 1 : 0,
            device_mode: $('#singbox-device-mode').val(),
            device_list: $('#singbox-device-list').val()
        }}, '{{ lang._('LAN capture settings saved. Restart the service to apply them.') }}', true);
    });
    load();
    refresh();
    setInterval(function () { if (!document.hidden) { refresh(); } }, 10000);
});
</script>

<div id="singbox-message" class="alert" style="display:none"></div>
<div id="singbox-warning" class="alert alert-warning" style="display:none"></div>
<ul class="nav nav-tabs" role="tablist" id="maintabs">
    <li class="active"><a data-toggle="tab" href="#singbox-status">{{ lang._('Service and configuration') }}</a></li>
    <li><a data-toggle="tab" href="#singbox-subscription">{{ lang._('Subscription') }}</a></li>
    <li><a data-toggle="tab" href="#singbox-logs">{{ lang._('Logs') }}</a></li>
</ul>
<div class="tab-content content-box">
    <div id="singbox-status" class="tab-pane fade in active">
        <form id="frm_singbox_config">
            <table class="table table-striped opnsense_standard_table_form">
                <thead><tr>
                    <td style="width:22%"><strong>{{ lang._('Service and configuration') }}</strong></td>
                    <td style="width:78%;text-align:right"><small>{{ lang._('full help') }} </small>
                        <a href="#"><i class="fa fa-toggle-off text-danger" id="show_all_help_singbox_config"></i></a></td>
                </tr></thead>
                <tbody>
                    <tr><td>{{ lang._('Service status') }}</td><td><span id="singbox-service" class="label label-default">-</span></td></tr>
                    <tr>
                        <td><a id="help_for_singbox_service" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Service control') }}</td>
                        <td class="singbox-toolbar">
                            <button type="button" class="btn btn-default singbox-action" data-action="start" data-done="{{ lang._('Service started.') }}"><i class="fa fa-play"></i> {{ lang._('Start') }}</button>
                            <button type="button" class="btn btn-default singbox-action" data-action="stop" data-done="{{ lang._('Service stopped.') }}"><i class="fa fa-stop"></i> {{ lang._('Stop') }}</button>
                            <button type="button" class="btn btn-default singbox-action" data-action="restart" data-done="{{ lang._('Service restarted.') }}"><i class="fa fa-refresh"></i> {{ lang._('Restart') }}</button>
                            <div class="hidden" data-for="help_for_singbox_service">{{ lang._('Start uses a private runtime copy of the saved JSON. Proxy-only mode leaves router routing and DNS unchanged. Restart applies saved settings; Stop restores native routing. Transparent capture cannot run while Mihomo is running.') }}</div>
                        </td>
                    </tr>
                    <tr><td>{{ lang._('Transparent LAN capture') }}</td><td>
                        <label><input type="checkbox" id="singbox-transparent"> {{ lang._('Enable transparent LAN capture') }}</label>
                        <p>{{ lang._('Default is proxy only. Capture uses a separate routing table and preserves router traffic, WAN replies and native firewall policy. Saved JSON must contain one gVisor TUN inbound with real-address DNS.') }}</p>
                        <label><input type="checkbox" id="singbox-consent"> {{ lang._('I want the selected LAN devices to use transparent capture') }}</label>
                    </td></tr>
                    <tr><td>{{ lang._('Device policy') }}</td><td>
                        <select id="singbox-device-mode" class="form-control">
                            <option value="off">{{ lang._('All LAN devices') }}</option>
                            <option value="whitelist">{{ lang._('Proxy only listed devices') }}</option>
                            <option value="blacklist">{{ lang._('Bypass listed devices') }}</option>
                        </select>
                        <textarea id="singbox-device-list" rows="4" class="form-control" spellcheck="false"></textarea>
                        <p>{{ lang._('Enter device IP addresses or CIDRs, one per line. Excluded devices bypass TUN before capture. An empty list selects all LAN devices. Existing captured connections are cleared when applying changed policy.') }}</p>
                    </td></tr>
                    <tr><td>{{ lang._('IPv6 capture') }}</td><td>
                        <label><input type="checkbox" id="singbox-ipv6"> {{ lang._('Include selected IPv6 device traffic') }}</label>
                        <p>{{ lang._('Requires an IPv6 address on the saved TUN inbound. IPv6 otherwise keeps the native path; DHCP and router advertisements are unchanged.') }}</p>
                        <button type="button" class="btn btn-primary" id="singbox-save-integration">{{ lang._('Save capture settings') }}</button>
                    </td></tr>
                    <tr>
                        <td><a id="help_for_singbox_config" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Configuration') }}</td>
                        <td>
                            <textarea id="singbox-config" rows="20" class="form-control singbox-editor" spellcheck="false" autocapitalize="off" autocomplete="off" autocorrect="off"></textarea>
                            <p>{{ lang._('Protected values start with __SING_BOX_KEEP_STORED_VALUE__. Leave the entire placeholder unchanged to keep a stored credential, or enter a new value.') }}</p>
                            <div class="hidden" data-for="help_for_singbox_config">{{ lang._('Saving validates this complete JSON configuration with the installed Sing-box core and retains a private backup before replacing the active file. Tagged proxy entries keep their credentials when reordered. Save first, then restart the service to apply your changes. If another operation changed the configuration, reload the page before saving again.') }}</div>
                            <button type="button" class="btn btn-primary" id="singbox-save-config"><i class="fa fa-save"></i> {{ lang._('Save configuration') }}</button>
                        </td>
                    </tr>
                </tbody>
            </table>
        </form>
    </div>
    <div id="singbox-subscription" class="tab-pane fade">
        <form id="frm_singbox_subscription">
            <table class="table table-striped opnsense_standard_table_form">
                <thead><tr>
                    <td style="width:22%"><strong>{{ lang._('Subscription management') }}</strong></td>
                    <td style="width:78%;text-align:right"><small>{{ lang._('full help') }} </small>
                        <a href="#"><i class="fa fa-toggle-off text-danger" id="show_all_help_singbox_subscription"></i></a></td>
                </tr></thead>
                <tbody>
                    <tr>
                        <td><a id="help_for_singbox_url" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Subscription URL') }}</td>
                        <td>
                            <input type="password" id="singbox-url" class="form-control" autocomplete="new-password" spellcheck="false">
                            <div class="hidden" data-for="help_for_singbox_url">{{ lang._('Enter an HTTP or HTTPS subscription URL on a public host that returns a complete Sing-box JSON configuration. Private or reserved addresses are refused. The stored URL is kept private and is never shown here or sent to a third-party converter. Leave this field empty to keep it, or enter a replacement and save settings.') }}</div>
                        </td>
                    </tr>
                    <tr>
                        <td><a id="help_for_singbox_clear_url" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Clear the stored URL') }}</td>
                        <td>
                            <input type="checkbox" id="singbox-clear-url" aria-label="{{ lang._('Clear the stored URL') }}">
                            <div class="hidden" data-for="help_for_singbox_clear_url">{{ lang._('Select this option and save settings to remove the stored subscription URL. This takes priority over any replacement URL entered above. The active configuration remains unchanged.') }}</div>
                        </td>
                    </tr>
                    <tr><td><a id="help_for_singbox_subscription_control" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Subscription control') }}</td><td class="singbox-toolbar">
                        <button type="button" class="btn btn-primary" id="singbox-save-settings"><i class="fa fa-save"></i> {{ lang._('Save settings') }}</button>
                        <button type="button" class="btn btn-default singbox-action" id="singbox-update" data-action="subUpdate" data-done="{{ lang._('Subscription update started.') }}"><i class="fa fa-refresh"></i> {{ lang._('Update subscription') }}</button>
                        <p id="singbox-update-status" class="text-muted"></p>
                        <div class="hidden" data-for="help_for_singbox_subscription_control">{{ lang._('Save settings stores the URL without downloading a subscription. Update subscription uses the saved URL to download and validate a complete configuration, then replaces the active configuration and restarts the service. Only one update can run at a time. Follow its progress below and check the subscription log for the result.') }}</div>
                    </td></tr>
                </tbody>
            </table>
        </form>
    </div>
    <div id="singbox-logs" class="tab-pane fade">
        <table class="table table-striped opnsense_standard_table_form">
            <thead><tr><td><strong>{{ lang._('Service log') }}</strong></td></tr></thead>
            <tbody><tr><td>
                <button type="button" class="btn btn-default singbox-action" data-action="clearLog" data-done="{{ lang._('Service log cleared.') }}"><i class="fa fa-trash"></i> {{ lang._('Clear log') }}</button>
                <pre id="singbox-log" class="singbox-log"></pre>
            </td></tr></tbody>
        </table>
        <table class="table table-striped opnsense_standard_table_form">
            <thead><tr><td><strong>{{ lang._('Subscription log') }}</strong></td></tr></thead>
            <tbody><tr><td>
                <button type="button" class="btn btn-default singbox-action" data-action="clearSubLog" data-done="{{ lang._('Subscription log cleared.') }}"><i class="fa fa-trash"></i> {{ lang._('Clear log') }}</button>
                <pre id="singbox-sub-log" class="singbox-log"></pre>
            </td></tr></tbody>
        </table>
    </div>
</div>
