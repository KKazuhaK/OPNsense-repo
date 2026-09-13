<style>
.pftop-controls { display:flex; flex-wrap:wrap; gap:12px; align-items:flex-start; }
.pftop-control { min-width:150px; max-width:220px; }
.pftop-filter { flex:1 1 320px; max-width:none; }
.pftop-output { max-width:100%; min-height:300px; max-height:600px; overflow:auto; white-space:pre; font-size:12px; }
</style>
<script>
$(function () {
    let timer = null, busy = false;
    function refresh() {
        clearTimeout(timer);
        timer = setTimeout(function () {
            if (busy) { return; } busy = true;
            ajaxGet('/api/pftop/service/snapshot', {view: $('#pftop-view').val(), sort: $('#pftop-sort').val(),
                count: $('#pftop-count').val(), filter: $('#pftop-filter').val()}, function (data) {
                busy = false; data = data || {};
                $('#pftop-output').text(htmlDecode(data.output || ''));
                $('#pftop-error').text(htmlDecode(data.error || '')).toggle(data.status !== 'ok');
            });
        }, 250);
    }
    $('#frm_pftop').on('submit', function (event) { event.preventDefault(); refresh(); });
    $('#frm_pftop select,input').on('change', refresh);
    $('#pftop-refresh').on('click', refresh);
    $('.selectpicker').selectpicker('refresh'); refresh(); setInterval(refresh, 5000);
});
</script>
<form id="frm_pftop">
<table class="table table-striped opnsense_standard_table_form">
    <thead><tr><td><strong>pfTop</strong> <span class="pull-right"><small>{{ lang._('full help') }}</small> <a href="#"><i class="fa fa-toggle-off text-danger" id="show_all_help_pftop"></i></a></span></td></tr></thead>
    <tbody><tr><td><div class="pftop-controls">
        <div class="pftop-control"><a id="help_for_pftop_view" class="showhelp" href="#"><i class="fa fa-info-circle"></i></a> <label for="pftop-view">{{ lang._('View') }}</label><br><select id="pftop-view" class="selectpicker" data-style="btn-default" data-width="100%"><option value="default" selected>{{ lang._('Default') }}</option>
<option value="label">{{ lang._('Label') }}</option>
<option value="long">{{ lang._('Long') }}</option>
<option value="queue">{{ lang._('Queue') }}</option>
<option value="rules">{{ lang._('Rules') }}</option>
<option value="size">{{ lang._('Size') }}</option>
<option value="speed">{{ lang._('Speed') }}</option>
<option value="state">{{ lang._('State') }}</option>
<option value="time">{{ lang._('Time') }}</option></select>
            <div class="hidden" data-for="help_for_pftop_view">{{ lang._('Choose the pfTop display, such as connection states, firewall rules, or queue statistics. Default shows the standard connection overview.') }}</div>
        </div>
        <div class="pftop-control"><a id="help_for_pftop_sort" class="showhelp" href="#"><i class="fa fa-info-circle"></i></a> <label for="pftop-sort">{{ lang._('Sort by') }}</label><br><select id="pftop-sort" class="selectpicker" data-style="btn-default" data-width="100%"><option value="age">{{ lang._('Age') }}</option>
<option value="bytes" selected>{{ lang._('Bytes') }}</option>
<option value="dest">{{ lang._('Destination') }}</option>
<option value="dport">{{ lang._('Destination port') }}</option>
<option value="exp">{{ lang._('Expiration') }}</option>
<option value="none">{{ lang._('None') }}</option>
<option value="pkt">{{ lang._('Packets') }}</option>
<option value="sport">{{ lang._('Source port') }}</option>
<option value="src">{{ lang._('Source') }}</option></select>
            <div class="hidden" data-for="help_for_pftop_sort">{{ lang._('Choose the field used to order the output. Bytes highlights traffic volume; None leaves the entries unsorted.') }}</div>
        </div>
        <div class="pftop-control"><a id="help_for_pftop_count" class="showhelp" href="#"><i class="fa fa-info-circle"></i></a> <label for="pftop-count">{{ lang._('Rows') }}</label><br><select id="pftop-count" class="selectpicker" data-style="btn-default" data-width="100%"><option value="20">{{ lang._('20') }}</option>
<option value="30">{{ lang._('30') }}</option>
<option value="40">{{ lang._('40') }}</option>
<option value="55">{{ lang._('55') }}</option>
<option value="100" selected>{{ lang._('100') }}</option>
<option value="all">{{ lang._('All') }}</option></select>
            <div class="hidden" data-for="help_for_pftop_count">{{ lang._('Limit the number of output rows, or choose All to include every matching entry.') }}</div>
        </div>
        <div class="pftop-control pftop-filter"><a id="help_for_pftop_filter" class="showhelp" href="#"><i class="fa fa-info-circle"></i></a> <label for="pftop-filter">{{ lang._('Filter') }}</label><input id="pftop-filter" type="text" class="form-control" maxlength="160" placeholder="tcp, ip6, dst net 208.123.73.0/24">
            <div class="hidden" data-for="help_for_pftop_filter">{{ lang._('Enter a packet filter expression, such as tcp, ip6, or dst net 208.123.73.0/24. Leave blank to show all traffic. The maximum length is 160 characters.') }}</div>
        </div>
        <div class="pftop-control"><a id="help_for_pftop_refresh" class="showhelp" href="#"><i class="fa fa-info-circle"></i></a> <label for="pftop-refresh">{{ lang._('Update') }}</label><br><button id="pftop-refresh" type="button" class="btn btn-default">{{ lang._('Refresh') }}</button>
            <div class="hidden" data-for="help_for_pftop_refresh">{{ lang._('Fetch a new snapshot using the selected options. The output also refreshes automatically every five seconds.') }}</div>
        </div>
    </div></td></tr></tbody>
</table>
</form>
<div id="pftop-error" class="alert alert-danger" role="alert" style="display:none"></div>
<table class="table table-striped opnsense_standard_table_form">
    <thead><tr><td><strong>{{ lang._('Output') }}</strong></td></tr></thead>
    <tbody><tr><td><pre id="pftop-output" class="pftop-output">{{ lang._('Loading...') }}</pre></td></tr></tbody>
</table>
