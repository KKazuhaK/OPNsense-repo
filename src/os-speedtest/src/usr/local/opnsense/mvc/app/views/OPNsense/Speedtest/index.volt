<style>
.speedtest-summary {display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:12px;margin-bottom:15px}
.speedtest-metric {padding:15px;margin-bottom:0}
.speedtest-metric span {display:block;font-size:12px}
.speedtest-metric strong {display:block;font-size:25px;margin-top:5px}
.speedtest-control {max-width:480px;width:100%}
.speedtest-icon {margin-right:6px}
.speedtest-stages {list-style:none;margin:8px 0 0;padding:0}
.speedtest-stages li {font-family:monospace;font-size:12px;padding:1px 0;overflow-wrap:anywhere}
@media(max-width:800px) {.speedtest-summary {grid-template-columns:1fr 1fr}}
</style>
<div class="content-box">
<div class="alert alert-danger hidden" id="speedtest-error" role="alert"></div>
<div class="alert alert-info hidden" id="speedtest-status"><i class="fa fa-spinner fa-spin speedtest-icon"></i><strong data-t="running"></strong><ul id="speedtest-stages" class="speedtest-stages"></ul></div>
<div class="speedtest-summary hidden" id="speedtest-summary">
<div class="panel panel-default speedtest-metric"><span class="text-muted" data-t="latency"></span><strong id="metric-latency"></strong></div>
<div class="panel panel-default speedtest-metric"><span class="text-muted" data-t="jitter"></span><strong id="metric-jitter"></strong></div>
<div class="panel panel-default speedtest-metric"><span class="text-muted" data-t="loss"></span><strong id="metric-loss"></strong></div>
<div class="panel panel-default speedtest-metric"><span class="text-muted" data-t="download"></span><strong id="metric-download"></strong></div>
<div class="panel panel-default speedtest-metric"><span class="text-muted" data-t="upload"></span><strong id="metric-upload"></strong></div>
</div>
<table class="table table-striped table-condensed hidden" id="speedtest-result"><thead><tr><th colspan="2" data-t="result"></th></tr></thead><tbody>
<tr><th data-t="time"></th><td id="result-time"></td></tr>
<tr><th data-t="isp"></th><td id="result-isp"></td></tr>
<tr><th data-t="test_server"></th><td id="result-server"></td></tr>
<tr><th data-t="distance"></th><td id="result-distance"></td></tr>
<tr><th data-t="engine"></th><td>speedtest-go 1.7.10</td></tr>
</tbody></table>
<form id="frm_speedtest"><table class="table table-striped table-condensed"><thead><tr><th colspan="2"><span data-t="settings"></span><span class="pull-right"><small data-t="full_help">{{ lang._('full help') }}</small> <a href="#"><i class="fa fa-toggle-off text-danger" id="speedtest_show_all_help"></i></a></span></th></tr></thead><tbody>
<tr><td><a id="help_for_speedtest_interface" class="showhelp"><i class="fa fa-info-circle"></i></a> <label for="speedtest-interface" data-t="interface"></label></td><td>
<select id="speedtest-interface" class="selectpicker speedtest-control" data-style="btn-default" data-width="100%"><option value="auto" data-t="automatic"></option></select>
<div class="hidden" data-for="help_for_speedtest_interface" data-t="interface_help"></div></td></tr>
<tr><td><a id="help_for_speedtest_server" class="showhelp"><i class="fa fa-info-circle"></i></a> <label for="speedtest-server" data-t="server"></label></td><td>
<select id="speedtest-server" class="selectpicker speedtest-control" data-style="btn-default" data-width="100%"><option value="" data-t="server_auto"></option></select>
<p><button class="btn btn-default" type="button" id="refresh-servers"><i class="fa fa-refresh speedtest-icon"></i><span data-t="refresh"></span></button></p>
<div class="hidden" data-for="help_for_speedtest_server" data-t="server_help"></div></td></tr>
<tr><td><a id="help_for_speedtest_threads" class="showhelp"><i class="fa fa-info-circle"></i></a> <label for="speedtest-threads" data-t="threads"></label></td><td><input class="form-control speedtest-control" type="number" min="1" max="16" id="speedtest-threads" value="4"><div class="hidden" data-for="help_for_speedtest_threads" data-t="threads_help"></div></td></tr>
</tbody></table>
<div><button class="btn btn-primary" type="submit" id="run-test"><i class="fa fa-tachometer speedtest-icon"></i><span data-t="run"></span></button> <button class="btn btn-default" type="button" id="clear-result"><i class="fa fa-trash speedtest-icon"></i><span data-t="clear"></span></button></div>
</form></div>
<script>
$(function () {
    var messages = {"en": {"diagnostics": "Diagnostics", "title": "Speedtest", "run": "Start Test", "clear": "Clear Result", "settings": "Test Settings", "interface": "Outbound Interface", "interface_help": "Only enabled interfaces with an IPv4 gateway are shown.", "automatic": "Automatic", "server": "Test Server", "server_auto": "Automatic selection", "server_help": "Refresh the server list after changing the outbound interface.", "refresh": "Refresh Servers", "refreshing": "Retrieving test servers.", "server_list_failed": "Unable to retrieve available test servers.", "threads": "Connections", "result": "Test Result", "time": "Test Time", "isp": "ISP / Public IP", "test_server": "Test Server", "latency": "Latency", "jitter": "Jitter", "loss": "Packet Loss", "download": "Download", "upload": "Upload", "running": "Testing, please wait.......", "failed": "The speed test failed.", "invalid_server": "Select a valid test server.", "invalid_threads": "Connections must be between 1 and 16.", "engine": "Engine", "distance": "Distance", "full_help": "full help", "threads_help": "Number of parallel download and upload connections, from 1 to 16. More connections may improve throughput and consume more router CPU and bandwidth."}, "zh_Hans": {"diagnostics": "诊断", "title": "Speedtest", "run": "开始测速", "clear": "清除结果", "settings": "测速设置", "interface": "出站接口", "interface_help": "仅显示已启用且配置 IPv4 网关的接口。", "automatic": "自动选择", "server": "测速服务器", "server_auto": "自动选择", "server_help": "更改出站接口后，请刷新服务器列表。", "refresh": "刷新服务器", "refreshing": "正在获取测速服务器。", "server_list_failed": "无法获取可用测速服务器。", "threads": "并发连接", "result": "测速结果", "time": "测试时间", "isp": "运营商 / 公网 IP", "test_server": "测速服务器", "latency": "延迟", "jitter": "抖动", "loss": "丢包率", "download": "下载", "upload": "上传", "running": "正在测速，请等待.......", "failed": "互联网测速失败。", "invalid_server": "请选择有效的测速服务器。", "invalid_threads": "并发连接必须在 1 到 16 之间。", "engine": "测速引擎", "distance": "距离", "full_help": "完整帮助", "threads_help": "下载和上传的并发连接数，范围为 1 到 16。增加连接可能提高测速吞吐量，也会占用更多路由器 CPU 和带宽。"}, "zh_Hant": {"diagnostics": "診斷", "title": "Speedtest", "run": "開始測速", "clear": "清除結果", "settings": "測速設定", "interface": "出站介面", "interface_help": "僅顯示已啟用且設定 IPv4 閘道的介面。", "automatic": "自動選擇", "server": "測速伺服器", "server_auto": "自動選擇", "server_help": "變更出站介面後，請重新整理伺服器清單。", "refresh": "重新整理伺服器", "refreshing": "正在取得測速伺服器。", "server_list_failed": "無法取得可用測速伺服器。", "threads": "並行連線", "result": "測速結果", "time": "測試時間", "isp": "電信業者 / 公網 IP", "test_server": "測速伺服器", "latency": "延遲", "jitter": "抖動", "loss": "封包遺失率", "download": "下載", "upload": "上傳", "running": "正在測速，請等待.......", "failed": "網際網路測速失敗。", "invalid_server": "請選擇有效的測速伺服器。", "invalid_threads": "並行連線必須介於 1 到 16 之間。", "engine": "測速引擎", "distance": "距離", "full_help": "完整說明", "threads_help": "下載與上傳的並行連線數，範圍為 1 到 16。增加連線可能提高測速吞吐量，也會使用更多路由器 CPU 與頻寬。"}};
    var language = 'en', timer = null, watched = false;
    function t(key) {return (messages[language] || messages.en)[key] || messages.en[key] || key;}
    function translate() {$('[data-t]').each(function () {$(this).text(t($(this).attr('data-t')));});$('.selectpicker').selectpicker('refresh');}
    function error(text) {$('#speedtest-error').text(htmlDecode(text || t('failed'))).removeClass('hidden');}
    function call(path, method, input, success) {
        $.ajax({url:'/api/speedtest/' + path, type:method, data:input || {}, dataType:'json'}).done(function (data) {
            if (data.status === 'failed') {error(data.error); busy(false); return;}
            success(data);
        }).fail(function () {error(t('failed'));busy(false);});
    }
    function busy(value) {$('#run-test,#refresh-servers,#clear-result').prop('disabled',value);}
    function settings() {return {interface:$('#speedtest-interface').val(),server_id:$('#speedtest-server').val(),threads:$('#speedtest-threads').val()};}
    function servers(items, selected) {
        var select=$('#speedtest-server').empty().append($('<option>').val('').text(t('server_auto')));
        (items || []).forEach(function (item) {select.append($('<option>').val(item.id).text(htmlDecode('['+item.id+'] '+item.name+' - '+item.sponsor+' / '+item.latency+' / '+Number(item.distance).toFixed(1)+' km')));});
        if (selected && !select.find('option').toArray().some(function (option) {return option.value === String(selected);})) {
            select.append($('<option>').val(selected).text('['+selected+']'));
        }
        select.val(selected || '').selectpicker('refresh');
    }
    function result(data) {
        var server=((data || {}).servers || [])[0];
        $('#speedtest-summary,#speedtest-result').toggleClass('hidden',!server);
        if (!server) return;
        $('#metric-latency').text((Number(server.latency || 0)/1e6).toFixed(2)+' ms');
        $('#metric-jitter').text((Number(server.jitter || 0)/1e6).toFixed(2)+' ms');
        var loss=server.packet_loss, percentage=loss && loss.sent > 0 && loss.max >= 0 ? Math.max(0,(1-(loss.sent-loss.dup)/(loss.max+1))*100).toFixed(2)+' %' : 'N/A';
        $('#metric-loss').text(percentage);
        $('#metric-download').text((Number(server.dl_speed || 0)*8/1e6).toFixed(2)+' Mbps');
        $('#metric-upload').text((Number(server.ul_speed || 0)*8/1e6).toFixed(2)+' Mbps');
        var user=data.user_info || {};
        $('#result-time').text(htmlDecode(data.timestamp || ''));
        $('#result-isp').text(htmlDecode((user.isp || user.Isp || '')+' / '+(user.IP || user.ip || '')));
        $('#result-server').text(htmlDecode('['+server.id+'] '+server.name+' - '+server.sponsor));
        $('#result-distance').text(Number(server.distance || 0).toFixed(2)+' km');
    }
    function load() {call('settings/get','GET',{},function (data) {
        language=data.language || 'en';translate();
        var chosen=data.settings || {}, select=$('#speedtest-interface').find('option:not([value="auto"])').remove().end();
        Object.keys(data.interfaces || {}).forEach(function (name) {select.append($('<option>').val(name).text(htmlDecode(data.interfaces[name].description)+' ('+name+')'));});
        select.val(chosen.interface || 'auto').selectpicker('refresh');servers(data.servers,chosen.server_id);$('#speedtest-threads').val(chosen.threads || '4');result(data.result);
    });}
    function poll() {call('service/progress','GET',{},function (data) {
        if (data.state === 'running') {
            watched=true;busy(true);$('#speedtest-status').removeClass('hidden');$('#speedtest-status strong').text(t('running'));
            var list=$('#speedtest-stages').empty();(data.stages || []).forEach(function (stage) {list.append($('<li>').append($('<i class="fa fa-check text-success speedtest-icon">')).append(document.createTextNode(htmlDecode(stage.text || ''))));});
            if (!timer) timer=setInterval(poll,1000);
        } else {
            if (timer) clearInterval(timer);timer=null;busy(false);$('#speedtest-status').addClass('hidden');
            if (watched) {watched=false;if (data.state === 'failed') error(data.error);load();}
        }
    });}
    $('#frm_speedtest').on('submit',function (event) {event.preventDefault();$('#speedtest-error').addClass('hidden');busy(true);call('service/run','POST',{settings:settings()},function () {watched=true;poll();});});
    $('#refresh-servers').on('click',function () {busy(true);$('#speedtest-error').addClass('hidden');$('#speedtest-status').removeClass('hidden').find('strong').text(t('refreshing'));call('settings/refresh','POST',{interface:$('#speedtest-interface').val()},function (data) {servers(data.servers,'');busy(false);$('#speedtest-status').addClass('hidden');});});
    $('#speedtest-interface').on('change',function () {call('settings/servers','GET',{interface:$(this).val()},function (data) {servers(data.servers,'');});});
    $('#clear-result').on('click',function () {call('service/clear','POST',{},function () {result(null);});});
    translate();load();poll();
});
</script>
