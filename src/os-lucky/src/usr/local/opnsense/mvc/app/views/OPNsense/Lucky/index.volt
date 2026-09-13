<script>
$(function () {
    function report(data) {
        data = data || {};
        $('#lucky-message').attr('class', 'alert alert-' + (data.status === 'ok' ? 'success' : 'danger'))
            .text(data.status === 'ok' ? '{{ lang._('Settings saved and service command completed.') }}' : htmlDecode(data.error || '{{ lang._('Operation failed.') }}')).show();
    }
    function refresh() {
        ajaxGet('/api/lucky/service/status', {}, function (data) {
            const running = !!(data || {}).running;
            $('#lucky-status').attr('class', 'label label-' + (running ? 'success' : 'default'))
                .text(running ? '{{ lang._('Running') }}' : '{{ lang._('Stopped') }}');
            $('#lucky-start').prop('disabled', running);
            $('#lucky-stop').prop('disabled', !running);
        });
    }
    function load() {
        ajaxGet('/api/lucky/settings/get', {}, function (data) {
            if (!data || !data.settings) { report(data); return; }
            const settings = data.settings;
            $('#lucky-enabled').prop('checked', !!settings.enabled);
            $('#lucky-conf-dir').val(htmlDecode(settings.conf_dir || ''));
            $('#lucky-web-port').val(settings.web_port);
            const url = 'http://' + window.location.hostname + ':' + settings.web_port + '/';
            $('#lucky-link').attr('href', url).text(url);
        });
    }
    $('.lucky-action').on('click', function () {
        const button = $(this).prop('disabled', true);
        ajaxCall('/api/lucky/service/' + button.data('action'), {}, function (data) {
            report(data); refresh(); button.prop('disabled', false);
        });
    });
    $('#lucky-save').on('click', function () {
        const button = $(this).prop('disabled', true);
        ajaxCall('/api/lucky/settings/set', {settings: {enabled: $('#lucky-enabled').is(':checked') ? 1 : 0,
            conf_dir: $('#lucky-conf-dir').val(), web_port: $('#lucky-web-port').val()}}, function (data) {
            report(data); if (data && data.status === 'ok') { load(); } refresh(); button.prop('disabled', false);
        });
    });
    load(); refresh(); setInterval(refresh, 5000);
});
</script>
<div id="lucky-message" class="alert" role="alert" style="display:none"></div>
<form id="frm_lucky">
<table class="table table-striped opnsense_standard_table_form">
    <thead><tr><td style="width:22%"><strong>{{ lang._('General Settings') }}</strong></td><td style="width:78%"><small>{{ lang._('full help') }}</small> <a href="#"><i class="fa fa-toggle-off text-danger" id="show_all_help_lucky"></i></a></td></tr></thead>
    <tbody>
        <tr><td>{{ lang._('Service Status') }}</td><td><span id="lucky-status" class="label label-default">{{ lang._('Loading...') }}</span></td></tr>
        <tr><td>{{ lang._('Link Address') }}</td><td><a id="lucky-link" target="_blank" rel="noopener"></a></td></tr>
        <tr><td><a id="help_for_lucky_service" class="showhelp" href="#"><i class="fa fa-info-circle"></i></a> {{ lang._('Service Control') }}</td><td>
            <button id="lucky-start" type="button" class="btn btn-success lucky-action" data-action="start">{{ lang._('Start') }}</button>
            <button id="lucky-stop" type="button" class="btn btn-danger lucky-action" data-action="stop">{{ lang._('Stop') }}</button>
            <button type="button" class="btn btn-default lucky-action" data-action="restart">{{ lang._('Restart') }}</button>
            <div class="hidden" data-for="help_for_lucky_service">{{ lang._('Start, stop, or restart Lucky using the saved settings. These commands do not change whether Lucky starts at boot.') }}</div>
        </td></tr>
    </tbody>
</table>
<table class="table table-striped opnsense_standard_table_form">
    <thead><tr><td><strong>{{ lang._('Advanced Settings') }}</strong></td><td></td></tr></thead>
    <tbody>
        <tr><td><a id="help_for_lucky_enable" class="showhelp" href="#"><i class="fa fa-info-circle"></i></a> <label for="lucky-enabled">{{ lang._('Enable') }}</label></td><td><input id="lucky-enabled" type="checkbox">
            <div class="hidden" data-for="help_for_lucky_enable">{{ lang._('Enable Lucky at boot. Saving restarts Lucky when enabled or stops it when disabled.') }}</div>
        </td></tr>
        <tr><td><a id="help_for_lucky_config" class="showhelp" href="#"><i class="fa fa-info-circle"></i></a> <label for="lucky-conf-dir">{{ lang._('Configuration directory') }}</label></td><td>
            <input id="lucky-conf-dir" type="text" class="form-control">
            <div class="hidden" data-for="help_for_lucky_config">{{ lang._('Absolute directory containing the existing Lucky configuration.') }}</div>
        </td></tr>
        <tr><td><a id="help_for_lucky_port" class="showhelp" href="#"><i class="fa fa-info-circle"></i></a> <label for="lucky-web-port">{{ lang._('Port') }}</label></td><td>
            <input id="lucky-web-port" type="number" min="1" max="65535" class="form-control">
            <div class="hidden" data-for="help_for_lucky_port">{{ lang._('HTTP port for the Lucky web interface, from 1 to 65535. The link address uses this port after saving.') }}</div>
        </td></tr>
        <tr><td></td><td><button id="lucky-save" type="button" class="btn btn-primary">{{ lang._('Save') }}</button></td></tr>
    </tbody>
</table>
</form>
