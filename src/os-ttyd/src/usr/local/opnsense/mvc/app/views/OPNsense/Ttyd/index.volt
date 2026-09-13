<style>
.ttyd-terminal {display: block; width: 100%; height: calc(100vh - 340px); min-height: 460px; border: 0;}
.ttyd-actions {padding: 12px 15px;}
.ttyd-status td {word-break: break-all;}
@media (max-width: 991px) {.ttyd-terminal {height: 65vh;}}
</style>
<form id="frmTtyd">
<div class="alert alert-warning hidden" id="ttyd-message" role="alert"></div>
<div class="content-box"><table class="table table-condensed table-striped ttyd-status"><thead><tr><th colspan="4" class="text-right"><small>{{ lang._('full help') }} </small><a href="#"><i class="fa fa-toggle-off text-danger" id="show_all_help_ttyd"></i></a></th></tr><tr><th><a href="#" class="showhelp" id="help_for_ttyd_url"><i class="fa fa-info-circle"></i></a> {{ lang._('URL') }}</th><th><a href="#" class="showhelp" id="help_for_ttyd_listen"><i class="fa fa-info-circle"></i></a> {{ lang._('Listen address') }}</th><th><a href="#" class="showhelp" id="help_for_ttyd_target"><i class="fa fa-info-circle"></i></a> {{ lang._('Target') }}</th><th><a href="#" class="showhelp" id="help_for_ttyd_status"><i class="fa fa-info-circle"></i></a> {{ lang._('Status') }}</th></tr></thead><tbody><tr>
<td><a id="ttyd-url" href="/ttyd/" target="_blank" rel="noopener"></a><div class="hidden" data-for="help_for_ttyd_url">{{ lang._('Opens the terminal through the WebGUI reverse proxy at /ttyd/ using the current WebGUI address and port.') }}</div></td><td><span id="ttyd-listen">-</span><div class="hidden" data-for="help_for_ttyd_listen">{{ lang._('The internal address where ttyd listens. The WebGUI proxy connects to this service; the default is loopback.') }}</div></td><td><span id="ttyd-target">-</span><div class="hidden" data-for="help_for_ttyd_target">{{ lang._('The default terminal asks for an SSH account and uses password or keyboard-interactive authentication on the configured local SSH port. Allow that authentication in Secure Shell settings; your WebGUI session is separate. A custom command replaces this default.') }}</div></td><td><span class="label label-default" id="ttyd-running">-</span><div class="hidden" data-for="help_for_ttyd_status">{{ lang._('Shows whether the ttyd process is running and refreshes every five seconds. Complete SSH authentication inside the terminal.') }}</div></td>
</tr></tbody></table><div class="ttyd-actions"><p><a href="#" class="showhelp" id="help_for_ttyd_service"><i class="fa fa-info-circle"></i></a> {{ lang._('Service control') }}</p><div class="hidden" data-for="help_for_ttyd_service">{{ lang._('Start opens the terminal service. Stop closes current terminal sessions, and Restart disconnects them before starting again. Opening this page automatically starts the service when it is stopped.') }}</div><button type="button" class="btn btn-success ttyd-service" data-action="start">{{ lang._('Start') }}</button> <button type="button" class="btn btn-danger ttyd-service" data-action="stop">{{ lang._('Stop') }}</button> <button type="button" class="btn btn-warning ttyd-service" data-action="restart">{{ lang._('Restart') }}</button></div></div>
<div class="content-box hidden" id="ttyd-panel"><table class="table table-condensed"><thead><tr><th><i class="fa fa-terminal fa-fw"></i> ttyd <small class="text-muted" id="ttyd-panel-target"></small></th></tr></thead></table><iframe class="ttyd-terminal" id="ttyd-terminal" title="{{ lang._('SSH terminal') }}"></iframe></div>
</form>
<script>
$(function () {
    var starting = false, first = true, backupWarning = '';
    var warning = '{{ lang._("The terminal service could not be started. Make sure ttyd is installed and Secure Shell is enabled in System > Settings > Administration.") }}';
    $('#ttyd-url').text(window.location.origin + '/ttyd/');
    function mutate(action) {
        starting = true; $('.ttyd-service').prop('disabled', true);
        if (action !== 'start') {$('#ttyd-terminal').removeAttr('src');}
        ajaxCall('/api/ttyd/service/' + action, {}, function (data) {
            starting = false; $('.ttyd-service').prop('disabled', false);
            if ((data || {}).status !== 'ok') {$('#ttyd-message').removeClass('hidden').text(htmlDecode((data || {}).error || warning));}
            else {backupWarning = data.warning || ''; $('#ttyd-message').toggleClass('hidden', !backupWarning).text(htmlDecode(backupWarning));}
            refresh();
        });
    }
    function refresh() {
        ajaxGet('/api/ttyd/service/status', {}, function (data) {
            data = data || {};
            if (data.status !== 'ok') {$('#ttyd-message').removeClass('hidden').text(htmlDecode(data.error || warning)); return;}
            $('#ttyd-listen').text(htmlDecode(data.listen || '-')); $('#ttyd-target,#ttyd-panel-target').text(htmlDecode(data.target || '-'));
            $('#ttyd-running').removeClass('label-default label-success label-danger').addClass(data.running ? 'label-success' : 'label-danger').text(data.running ? '{{ lang._("Running") }}' : '{{ lang._("Stopped") }}');
            $('#ttyd-panel').toggleClass('hidden', !data.running);
            if (data.running && !backupWarning) {$('#ttyd-message').addClass('hidden').empty();}
            if (data.running && !$('#ttyd-terminal').attr('src')) {$('#ttyd-terminal').attr('src', '/ttyd/');}
            if (!data.running) {$('#ttyd-terminal').removeAttr('src');}
            if (!starting) {$('.ttyd-service[data-action="start"]').prop('disabled', !!data.running); $('.ttyd-service[data-action="stop"],.ttyd-service[data-action="restart"]').prop('disabled', !data.running);}
            // Preserve the old page's automatic startup through an authenticated POST.
            if (first) {first = false; if (!data.running) {mutate('start');}}
        });
    }
    $('.ttyd-service').click(function () {mutate($(this).data('action'));});
    refresh(); window.setInterval(function () {if (!starting) {refresh();}}, 5000);
});
</script>
