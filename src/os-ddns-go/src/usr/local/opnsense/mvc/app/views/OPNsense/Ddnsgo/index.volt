<style>
.ddnsgo-editor { width:100%; max-width:100%; min-height:360px; resize:vertical; font-family:monospace; }
.ddnsgo-log { max-width:100%; max-height:300px; overflow:auto; white-space:pre; }
</style>
<script>
$(function () {
    let revision = '';
    function report(data) {
        data = data || {};
        $('#ddnsgo-message').attr('class', 'alert alert-' + (data.status === 'ok' ? (data.warning ? 'warning' : 'success') : 'danger'))
            .text(data.status === 'ok' ? htmlDecode(data.warning || '{{ lang._('Operation completed.') }}') : htmlDecode(data.error || '{{ lang._('Operation failed.') }}')).show();
    }
    function refresh() {
        ajaxGet('/api/ddnsgo/service/status', {}, function (data) {
            const running = !!(data || {}).running;
            $('#ddnsgo-status').attr('class', 'label label-' + (running ? 'success' : 'default'))
                .text(running ? '{{ lang._('Running') }}' : '{{ lang._('Stopped') }}');
            $('#ddnsgo-start').prop('disabled', running); $('#ddnsgo-stop').prop('disabled', !running);
        });
        ajaxGet('/api/ddnsgo/service/log', {}, function (data) {
            $('#ddnsgo-log').text(htmlDecode((data || {}).log || ''));
        });
    }
    function load() {
        ajaxGet('/api/ddnsgo/settings/get', {}, function (data) {
            if (!data || !data.settings) { report(data); return; }
            const settings = data.settings;
            revision = settings.revision;
            $('#ddnsgo-content').val(htmlDecode(settings.config_content || ''));
            const match = (settings.listen || ':9876').match(/:(\d+)$/);
            const url = 'http://' + window.location.hostname + ':' + (match ? match[1] : '9876') + '/';
            $('#ddnsgo-link').attr('href', url).text(url);
        });
    }
    $('.ddnsgo-action').on('click', function () {
        const button = $(this).prop('disabled', true);
        ajaxCall('/api/ddnsgo/service/' + button.data('action'), {}, function (data) {
            report(data); refresh(); button.prop('disabled', false);
        });
    });
    $('#ddnsgo-save').on('click', function () {
        const button = $(this).prop('disabled', true);
        ajaxCall('/api/ddnsgo/settings/set', {settings: {config_content: $('#ddnsgo-content').val(), revision: revision}}, function (data) {
            report(data); if (data && data.status === 'ok') { load(); } refresh(); button.prop('disabled', false);
        });
    });
    load(); refresh(); setInterval(refresh, 5000);
});
</script>
<div id="ddnsgo-message" class="alert" role="alert" style="display:none"></div>
<form id="frm_ddnsgo">
<table class="table table-striped opnsense_standard_table_form">
    <thead><tr><td style="width:22%"><strong>{{ lang._('Service Status') }}</strong></td><td style="width:78%"><small>{{ lang._('full help') }}</small> <a href="#"><i class="fa fa-toggle-off text-danger" id="show_all_help_ddnsgo"></i></a></td></tr></thead>
    <tbody>
        <tr><td>{{ lang._('Status') }}</td><td><span id="ddnsgo-status" class="label label-default">{{ lang._('Loading...') }}</span></td></tr>
        <tr><td><a id="help_for_ddnsgo_link" class="showhelp" href="#"><i class="fa fa-info-circle"></i></a> {{ lang._('Access URL') }}</td><td><a id="ddnsgo-link" target="_blank" rel="noopener"></a>
            <div class="hidden" data-for="help_for_ddnsgo_link">{{ lang._('Open the DDNS-Go web interface to manage provider accounts and domain settings. The port is read from the saved listen setting.') }}</div>
        </td></tr>
        <tr><td><a id="help_for_ddnsgo_service" class="showhelp" href="#"><i class="fa fa-info-circle"></i></a> {{ lang._('Service Control') }}</td><td>
            <button id="ddnsgo-start" type="button" class="btn btn-success ddnsgo-action" data-action="start">{{ lang._('Start') }}</button>
            <button id="ddnsgo-stop" type="button" class="btn btn-danger ddnsgo-action" data-action="stop">{{ lang._('Stop') }}</button>
            <button type="button" class="btn btn-default ddnsgo-action" data-action="restart">{{ lang._('Restart') }}</button>
            <div class="hidden" data-for="help_for_ddnsgo_service">{{ lang._('Start, stop, or restart DDNS-Go using its saved configuration. Unsaved YAML edits are not applied by these commands.') }}</div>
        </td></tr>
    </tbody>
</table>
<table class="table table-striped opnsense_standard_table_form">
    <thead><tr><td><strong>{{ lang._('Configuration') }}</strong></td><td></td></tr></thead>
    <tbody><tr><td><a id="help_for_ddnsgo_config" class="showhelp" href="#"><i class="fa fa-info-circle"></i></a> <label for="ddnsgo-content">{{ lang._('YAML configuration') }}</label></td><td>
        <p>{{ lang._('Stored text and numeric values are masked. Keep each __DDNSGO_KEEP_ marker in its original field to preserve the stored value, or replace it with a new value. Use the DDNS-Go web interface to view provider configuration.') }}</p>
        <textarea id="ddnsgo-content" class="form-control ddnsgo-editor" spellcheck="false"></textarea>
        <div class="hidden" data-for="help_for_ddnsgo_config">{{ lang._('Saving validates the YAML and restarts DDNS-Go. Stored credentials are never returned by this API.') }}</div>
    </td></tr><tr><td></td><td><button id="ddnsgo-save" type="button" class="btn btn-primary">{{ lang._('Save configuration') }}</button></td></tr></tbody>
</table>
<table class="table table-striped opnsense_standard_table_form">
    <thead><tr><td><a id="help_for_ddnsgo_log" class="showhelp" href="#"><i class="fa fa-info-circle"></i></a> <strong>{{ lang._('Log') }}</strong></td></tr></thead>
    <tbody><tr><td><pre id="ddnsgo-log" class="ddnsgo-log"></pre>
        <div class="hidden" data-for="help_for_ddnsgo_log">{{ lang._('Recent DDNS-Go log messages refresh every five seconds. Values stored in the configuration are masked in this view.') }}</div>
    </td></tr></tbody>
</table>
</form>
