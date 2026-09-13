<style>
.staticarp-editors { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:12px; }
.staticarp-editor { width:100%; max-width:100%; min-height:248px; resize:vertical; font-family:monospace; }
.staticarp-interfaces { overflow-x:auto; max-width:100%; }
.staticarp-interfaces td { vertical-align:middle !important; }
@media(max-width:767px) { .staticarp-editors { grid-template-columns:1fr; } }
</style>
<script>
$(function () {
    const labels = {normal: '{{ lang._('Normal Reply') }}', staticarp: '{{ lang._('Static Reply') }}', '-arp': '{{ lang._('No Reply') }}'};
    function report(data) {
        data = data || {};
        $('#staticarp-message').attr('class', 'alert alert-' + (data.status === 'ok' ? (data.warning ? 'warning' : 'success') : 'danger'))
            .text(data.status === 'ok' ? htmlDecode(data.warning || '{{ lang._('Configuration saved and applied.') }}') : htmlDecode(data.error || '{{ lang._('Operation failed.') }}')).show();
    }
    function load() {
        ajaxGet('/api/staticarp/settings/get', {}, function (data) {
            if (!data || !data.settings) { report(data); return; }
            const settings = data.settings;
            $('#staticarp-enabled').prop('checked', !!settings.enabled);
            $('#staticarp-entries').val(htmlDecode(settings.entries || ''));
            $('#staticarp-arp').val(htmlDecode(data.arp || ''));
            const body = $('#staticarp-interface-rows').empty();
            (data.interfaces || []).forEach(function (item) {
                const row = $('<tr>');
                ['descr', 'device', 'ipaddr', 'mac', 'status'].forEach(function (key) {
                    row.append($('<td>').text(htmlDecode(item[key] || '')));
                });
                const select = $('<select>').attr({class:'selectpicker staticarp-mode', 'data-style':'btn-default',
                    'data-interface':item.name, 'aria-label':labels.normal + ': ' + htmlDecode(item.descr || '')});
                Object.keys(labels).forEach(function (key) { select.append($('<option>').val(key).text(labels[key])); });
                select.val((settings.modes || {})[item.name] || 'normal');
                row.append($('<td>').append(select));
                row.append($('<td>').append($('<button>').attr({type:'button', class:'btn btn-default staticarp-download',
                    'data-interface':item.name, title:'{{ lang._('Download Windows ARP helper script') }}'})
                    .append($('<i>').attr({class:'fa fa-download', 'aria-hidden':'true'}))));
                body.append(row);
            });
            $('.staticarp-mode').selectpicker();
        });
    }
    $('#staticarp-copy').on('click', function () { $('#staticarp-entries').val($('#staticarp-arp').val()); });
    $('#staticarp-save').on('click', function () {
        const button = $(this).prop('disabled', true), modes = {};
        $('.staticarp-mode').each(function () { modes[$(this).data('interface')] = $(this).val(); });
        ajaxCall('/api/staticarp/settings/set', {settings:{enabled:$('#staticarp-enabled').is(':checked') ? 1 : 0,
            entries:$('#staticarp-entries').val(), modes:modes}}, function (data) {
            report(data); if (data && data.status === 'ok') { load(); } button.prop('disabled', false);
        });
    });
    $('#staticarp-reset').on('click', function () {
        ajaxCall('/api/staticarp/service/reset', {}, function (data) {
            data = data || {};
            $('#staticarp-message').attr('class', 'alert alert-' + (data.status === 'ok' ? 'warning' : 'danger'))
                .text(data.status === 'ok' ? htmlDecode(data.warning || '{{ lang._('Static binding has been reset.') }}') : htmlDecode(data.error || '{{ lang._('Operation failed.') }}')).show();
        });
    });
    $(document).on('click', '.staticarp-download', function () {
        ajaxGet('/api/staticarp/settings/script', {interface:$(this).data('interface')}, function (data) {
            if (!data || data.status !== 'ok') { report(data); return; }
            const url = URL.createObjectURL(new Blob([htmlDecode(data.script)], {type:'application/octet-stream'}));
            const link = $('<a>').attr({href:url,download:data.filename}).appendTo('body');
            link[0].click(); link.remove(); URL.revokeObjectURL(url);
        });
    });
    load();
});
</script>
<div id="staticarp-message" class="alert" role="alert" style="display:none"></div>
<form id="frm_staticarp">
<div class="staticarp-interfaces">
<table class="table table-striped table-condensed">
    <thead>
        <tr><th colspan="7">{{ lang._('Interface Settings') }} <span class="pull-right"><small>{{ lang._('full help') }}</small> <a href="#"><i class="fa fa-toggle-off text-danger" id="show_all_help_staticarp"></i></a></span>
            <div class="hidden" data-for="help_for_staticarp_mode">{{ lang._('Normal Reply enables normal ARP handling. Static Reply enables the interface static ARP mode. No Reply disables ARP on the interface. Modes are applied when binding is enabled and saved.') }}</div>
            <div class="hidden" data-for="help_for_staticarp_script">{{ lang._('Download a Windows helper script that adds the selected router interface address and MAC address to the client ARP table.') }}</div>
        </th></tr>
        <tr><th>{{ lang._('Interface') }}</th><th>{{ lang._('Device') }}</th><th>{{ lang._('IP Address') }}</th><th>{{ lang._('MAC Address') }}</th><th>{{ lang._('Status') }}</th><th><a id="help_for_staticarp_mode" class="showhelp" href="#"><i class="fa fa-info-circle"></i></a> {{ lang._('Reply Mode') }}</th><th><a id="help_for_staticarp_script" class="showhelp" href="#"><i class="fa fa-info-circle"></i></a> {{ lang._('Script') }}</th></tr>
    </thead>
    <tbody id="staticarp-interface-rows"></tbody>
</table>
</div>
<table class="table table-striped opnsense_standard_table_form">
    <thead><tr><td style="width:22%"><strong>{{ lang._('Binding Configuration') }}</strong></td><td style="width:78%"></td></tr></thead>
    <tbody>
        <tr><td><a id="help_for_staticarp_enable" class="showhelp" href="#"><i class="fa fa-info-circle"></i></a> <label for="staticarp-enabled">{{ lang._('Enable static ARP binding') }}</label></td><td>
            <input id="staticarp-enabled" type="checkbox">
            <div class="hidden" data-for="help_for_staticarp_enable">{{ lang._('When enabled, entries from the binding list are loaded into the system ARP table and each interface reply mode is applied.') }}</div>
        </td></tr>
        <tr><td><a id="help_for_staticarp_entries" class="showhelp" href="#"><i class="fa fa-info-circle"></i></a> {{ lang._('Binding records') }}</td><td>
            <div class="staticarp-editors">
                <div><label for="staticarp-entries">{{ lang._('Binding List') }}</label><textarea id="staticarp-entries" class="form-control staticarp-editor" spellcheck="false"></textarea></div>
                <div><a id="help_for_staticarp_arp" class="showhelp" href="#"><i class="fa fa-info-circle"></i></a> <label for="staticarp-arp">{{ lang._('Current ARP Table') }}</label><textarea id="staticarp-arp" class="form-control staticarp-editor" readonly></textarea>
                    <div class="hidden" data-for="help_for_staticarp_arp">{{ lang._('Current system ARP entries are shown for reference. Copying them replaces the editable binding list without saving it.') }}</div>
                </div>
            </div>
            <div class="hidden" data-for="help_for_staticarp_entries">{{ lang._('One entry per line, in IP MAC format. Local router addresses are excluded. Copy the current ARP table and edit as needed.') }}</div>
            <button id="staticarp-copy" type="button" class="btn btn-default">{{ lang._('Copy Current ARP Table') }}</button>
        </td></tr>
        <tr><td><a id="help_for_staticarp_actions" class="showhelp" href="#"><i class="fa fa-info-circle"></i></a> {{ lang._('Apply configuration') }}</td><td><button id="staticarp-save" type="button" class="btn btn-primary">{{ lang._('Save') }}</button> <button id="staticarp-reset" type="button" class="btn btn-default">{{ lang._('Reset') }}</button>
            <div class="hidden" data-for="help_for_staticarp_actions">{{ lang._('Save stores and immediately applies the configuration. Reset clears the system ARP table and restores normal interface ARP handling without changing the saved configuration.') }}</div>
        </td></tr>
    </tbody>
</table>
</form>
