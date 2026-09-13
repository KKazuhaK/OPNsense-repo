<style>
.et-actions {padding: 12px 15px;}
.et-actions .btn {margin-right: 6px; margin-bottom: 5px;}
.et-config {width: 100%; max-width: 100%; min-height: 460px; font-family: monospace; resize: vertical;}
.et-log {min-height: 300px; max-height: 540px; max-width: 100%; overflow: auto; white-space: pre-wrap;}
.et-summary th {width: 220px;}
.et-path {font-family: monospace;}
.et-content {margin-top: 15px;}
</style>
<ul class="nav nav-tabs" id="et-tabs">
  <li class="active"><a data-toggle="tab" href="#et-status" data-et-label="Status">{{ lang._('Status') }}</a></li>
  <li><a data-toggle="tab" href="#et-config-tab" data-et-label="Configuration">{{ lang._('Configuration') }}</a></li>
  <li><a data-toggle="tab" href="#et-peers" data-et-label="Peers">{{ lang._('Peers') }}</a></li>
  <li><a data-toggle="tab" href="#et-log-tab" data-et-label="Log">{{ lang._('Log') }}</a></li>
</ul>
<div class="alert hidden et-content" id="et-message" role="alert"></div>
<div class="tab-content et-content">
  <div class="tab-pane active" id="et-status">
    <form id="frm_easytier_status"><div class="content-box"><table class="table table-condensed table-striped et-summary">
      <thead><tr><th colspan="2"><span data-et-label="EasyTier service status">{{ lang._('EasyTier service status') }}</span><span class="pull-right"><small>{{ lang._('full help') }}</small> <a href="#"><i class="fa fa-toggle-off text-danger" id="show_all_help_easytier_status"></i></a></span></th></tr></thead><tbody>
      <tr><th><a id="help_for_et_service" class="showhelp"><i class="fa fa-info-circle"></i></a> <span data-et-label="Service status">{{ lang._('Service status') }}</span></th><td><span class="label label-default" id="et-running">-</span><div class="hidden" data-for="help_for_et_service">{{ lang._('Start uses the saved configuration. Restart interrupts peer connections while applying it. Status refreshes every five seconds.') }}</div></td></tr>
      <tr><th data-et-label="Version">{{ lang._('Version') }}</th><td id="et-version">-</td></tr>
      <tr><th data-et-label="Process ID">{{ lang._('Process ID') }}</th><td id="et-pid">-</td></tr>
      <tr><th data-et-label="Node name">{{ lang._('Node name') }}</th><td id="et-hostname">-</td></tr>
      <tr><th data-et-label="Virtual address">{{ lang._('Virtual address') }}</th><td id="et-ipv4">-</td></tr>
      <tr><th data-et-label="Network name">{{ lang._('Network name') }}</th><td id="et-network_name">-</td></tr>
      <tr><th data-et-label="Configuration file">{{ lang._('Configuration file') }}</th><td><span class="et-path">/usr/local/etc/easytier/config.toml</span></td></tr>
      </tbody></table><div class="et-actions">
      <button type="button" class="btn btn-success et-service" data-action="start" data-et-label="Start">{{ lang._('Start') }}</button>
      <button type="button" class="btn btn-danger et-service" data-action="stop" data-et-label="Stop">{{ lang._('Stop') }}</button>
      <button type="button" class="btn btn-warning et-service" data-action="restart" data-et-label="Restart">{{ lang._('Restart') }}</button>
      </div></div></form>
    <div class="alert alert-info" data-et-label="EasyTier uses a dynamic interface. Do not assign easytier0 under Interfaces > Assignments.">{{ lang._('EasyTier uses a dynamic interface. Do not assign easytier0 under Interfaces > Assignments.') }}</div>
  </div>
  <div class="tab-pane" id="et-config-tab">
    <form id="frm_easytier_settings"><div class="content-box"><table class="table table-condensed">
      <thead><tr><th><span data-et-label="EasyTier configuration">{{ lang._('EasyTier configuration') }}</span><span class="pull-right"><small>{{ lang._('full help') }}</small> <a href="#"><i class="fa fa-toggle-off text-danger" id="show_all_help_easytier"></i></a></span></th></tr></thead>
      <tbody><tr><td><label for="et-config"><a id="help_for_et_config" class="showhelp"><i class="fa fa-info-circle"></i></a> <span data-et-label="Configuration file">{{ lang._('Configuration file') }}</span></label>
      <div class="hidden" data-for="help_for_et_config">{{ lang._('The configuration stays in the existing TOML file. Secret placeholders preserve credentials in their original fields. Replace a placeholder to change that credential. Reload if another session changed the credentials.') }}</div>
      <textarea id="et-config" name="config" class="form-control et-config" spellcheck="false"></textarea>
      <p class="help-block" data-et-label="The configuration is stored with mode 0600. Protect the network secret.">{{ lang._('The configuration is stored with mode 0600. Protect the network secret.') }}</p></td></tr></tbody>
      </table><div class="et-actions"><a id="help_for_et_save" class="showhelp"><i class="fa fa-info-circle"></i></a> <button type="button" class="btn btn-primary et-save" data-restart="0" data-et-label="Save">{{ lang._('Save') }}</button><button type="button" class="btn btn-warning et-save" data-restart="1" data-et-label="Save & Restart">{{ lang._('Save & Restart') }}</button><div class="hidden" data-for="help_for_et_save">{{ lang._('Save writes the TOML file without changing the running service. Save & Restart applies it immediately by restarting EasyTier.') }}</div></div></div></form>
  </div>
  <div class="tab-pane" id="et-peers"><div class="content-box"><div class="table-responsive"><table class="table table-condensed table-striped table-hover">
    <thead><tr><th colspan="10" data-et-label="EasyTier peer connection status">{{ lang._('EasyTier peer connection status') }}</th></tr><tr>
<th data-et-label="Virtual IP">{{ lang._("Virtual IP") }}</th><th data-et-label="Hostname">{{ lang._("Hostname") }}</th><th data-et-label="Connection status">{{ lang._("Connection status") }}</th><th data-et-label="Latency">{{ lang._("Latency") }}</th><th data-et-label="Packet loss">{{ lang._("Packet loss") }}</th><th data-et-label="Received">{{ lang._("Received") }}</th><th data-et-label="Sent">{{ lang._("Sent") }}</th><th data-et-label="Tunnel">{{ lang._("Tunnel") }}</th><th data-et-label="NAT type">{{ lang._("NAT type") }}</th><th data-et-label="Version">{{ lang._("Version") }}</th></tr></thead><tbody id="et-peer-rows"></tbody></table></div><div class="alert alert-info hidden" id="et-peer-message"></div></div></div>
  <div class="tab-pane" id="et-log-tab"><div class="content-box"><table class="table table-condensed"><thead><tr><th data-et-label="EasyTier log">{{ lang._('EasyTier log') }}</th></tr></thead><tbody><tr><td>
    <pre class="et-log" id="et-log"></pre><p class="help-block" data-et-label="Showing the last 100 lines. Network secrets are redacted.">{{ lang._('Showing the last 100 lines. Network secrets are redacted.') }}</p>
    </td></tr></tbody></table><div class="et-actions"><button type="button" class="btn btn-danger" id="et-clear-log" data-et-label="Clear log">{{ lang._('Clear log') }}</button></div></div></div>
</div>
<script>
$(function () {
    var messages = {"zh_cn": {"Status": "状态", "Configuration": "配置", "Peers": "节点", "Log": "日志", "EasyTier service status": "EasyTier 服务状态", "Service status": "服务状态", "Running": "运行中", "Stopped": "已停止", "Version": "版本", "Process ID": "进程 ID", "Node name": "节点名称", "Virtual address": "虚拟地址", "Network name": "网络名称", "Configuration file": "配置文件", "Start": "启动", "Stop": "停止", "Restart": "重启", "EasyTier configuration": "EasyTier 配置", "Save": "保存", "Save & Restart": "保存并重启", "EasyTier peer connection status": "EasyTier 节点连接状态", "Virtual IP": "虚拟 IP", "Hostname": "主机名", "Connection status": "连接状态", "Latency": "延迟", "Packet loss": "丢包率", "Received": "接收", "Sent": "发送", "Tunnel": "隧道", "NAT type": "NAT 类型", "Local": "本机", "Relay": "中继", "EasyTier log": "EasyTier 日志", "No peer information is currently available.": "当前没有可用的节点信息。", "Clear log": "清除日志", "Log cleared.": "日志已清除。", "Are you sure you want to clear the EasyTier log?": "确定要清除 EasyTier 日志吗？", "EasyTier is stopped. Start the service to view peer connections.": "EasyTier 已停止，请启动服务后查看节点连接。", "Unable to query EasyTier peers. Check that the RPC portal is 127.0.0.1:15888.": "无法查询 EasyTier 节点，请确认 RPC 门户为 127.0.0.1:15888。", "Configuration saved.": "配置已保存。", "Configuration saved and restart submitted.": "配置已保存，并已提交重启。", "The configuration cannot be empty.": "配置不能为空。", "The configuration contains invalid data.": "配置包含无效数据。", "Service command submitted.": "服务命令已提交。", "CSRF validation failed.": "CSRF 校验失败。", "The configuration is stored with mode 0600. Protect the network secret.": "配置文件以 0600 权限保存，请妥善保护网络密钥。", "EasyTier uses a dynamic interface. Do not assign easytier0 under Interfaces > Assignments.": "EasyTier 使用动态接口，请勿在“接口 > 分配”中添加 easytier0。", "Showing the last 100 lines. Network secrets are redacted.": "显示最近 100 行，网络密钥已隐藏。", "Unable to save configuration.": "无法保存配置。"}, "zh_tw": {"Status": "狀態", "Configuration": "設定", "Peers": "節點", "Log": "日誌", "EasyTier service status": "EasyTier 服務狀態", "Service status": "服務狀態", "Running": "執行中", "Stopped": "已停止", "Version": "版本", "Process ID": "處理程序 ID", "Node name": "節點名稱", "Virtual address": "虛擬位址", "Network name": "網路名稱", "Configuration file": "設定檔", "Start": "啟動", "Stop": "停止", "Restart": "重新啟動", "EasyTier configuration": "EasyTier 設定", "Save": "儲存", "Save & Restart": "儲存並重新啟動", "EasyTier peer connection status": "EasyTier 節點連線狀態", "Virtual IP": "虛擬 IP", "Hostname": "主機名稱", "Connection status": "連線狀態", "Latency": "延遲", "Packet loss": "封包遺失率", "Received": "接收", "Sent": "傳送", "Tunnel": "通道", "NAT type": "NAT 類型", "Local": "本機", "Relay": "中繼", "EasyTier log": "EasyTier 日誌", "Clear log": "清除日誌", "Log cleared.": "日誌已清除。", "Are you sure you want to clear the EasyTier log?": "確定要清除 EasyTier 日誌嗎？", "No peer information is currently available.": "目前沒有可用的節點資訊。", "EasyTier is stopped. Start the service to view peer connections.": "EasyTier 已停止，請啟動服務後查看節點連線。", "Unable to query EasyTier peers. Check that the RPC portal is 127.0.0.1:15888.": "無法查詢 EasyTier 節點，請確認 RPC 入口為 127.0.0.1:15888。", "Configuration saved.": "設定已儲存。", "Configuration saved and restart submitted.": "設定已儲存，並已送出重新啟動要求。", "The configuration cannot be empty.": "設定內容不可為空。", "The configuration contains invalid data.": "設定包含無效資料。", "Service command submitted.": "服務命令已送出。", "CSRF validation failed.": "CSRF 驗證失敗。", "The configuration is stored with mode 0600. Protect the network secret.": "設定檔以 0600 權限儲存，請妥善保護網路密鑰。", "EasyTier uses a dynamic interface. Do not assign easytier0 under Interfaces > Assignments.": "EasyTier 使用動態介面，請勿在「介面 > 指派」中加入 easytier0。", "Showing the last 100 lines. Network secrets are redacted.": "顯示最近 100 行，網路密鑰已隱藏。", "Unable to save configuration.": "無法儲存設定。"}}, language = '', loaded = false, busy = false;
    function t(value) {return (messages[language] || {})[value] || value;}
    function message(value, success, warning) {$('#et-message').removeClass('hidden alert-success alert-danger alert-warning').addClass(warning ? 'alert-warning' : (success ? 'alert-success' : 'alert-danger')).text(htmlDecode(t(value)));}
    function mutate(action, done) {
        busy = true; $('.et-service,.et-save,#et-clear-log').prop('disabled', true);
        ajaxCall('/api/easytier/service/' + action, {}, function (data) {
            busy = false; $('.et-service,.et-save,#et-clear-log').prop('disabled', false);
            if ((data || {}).status !== 'ok') {message((data || {}).error || '{{ lang._("Operation failed.") }}', false);}
            else {message(data.warning || 'Service command submitted.', true, !!data.warning);}
            refreshStatus(); if (done) {done(data);}
        });
    }
    function loadSettings() {
        ajaxGet('/api/easytier/settings/get', {}, function (data) {
            if ((data || {}).status === 'ok') {$('#et-config').val(htmlDecode(data.config || '')); loaded = true;}
            else {message((data || {}).error || '{{ lang._("Unable to load configuration.") }}', false);}
        });
    }
    function refreshStatus() {
        ajaxGet('/api/easytier/service/status', {}, function (data) {
            if ((data || {}).status !== 'ok') {message((data || {}).error || '{{ lang._("Unable to query service.") }}', false); return;}
            var current = htmlDecode(data.language || '').toLowerCase().replace('-', '_');
            language = /zh_(tw|hk|mo)|hant/.test(current) ? 'zh_tw' : (/^zh($|_(cn|sg))|hans/.test(current) ? 'zh_cn' : '');
            $('[data-et-label]').each(function () {if (language) {$(this).text(t($(this).attr('data-et-label')));}});
            $('#et-running').removeClass('label-default label-success label-danger').addClass(data.running ? 'label-success' : 'label-danger').text(t(data.running ? 'Running' : 'Stopped'));
            ['version','pid','hostname','ipv4','network_name'].forEach(function (key) {$('#et-' + key).text(htmlDecode(data[key] || '-'));});
            if (!busy) {$('.et-service[data-action="start"]').prop('disabled', !!data.running); $('.et-service[data-action="stop"],.et-service[data-action="restart"]').prop('disabled', !data.running);}
        });
    }
    function refreshPeers() {
        ajaxGet('/api/easytier/service/peers', {}, function (data) {
            var rows = (data || {}).rows || []; $('#et-peer-rows').empty();
            rows.forEach(function (row) {var tr = $('<tr/>'); row.forEach(function (cell) {tr.append($('<td/>').text(htmlDecode(cell)));}); $('#et-peer-rows').append(tr);});
            var text = (data || {}).status !== 'ok' ? (data || {}).error : (!data.running ? 'EasyTier is stopped. Start the service to view peer connections.' : (!rows.length ? 'No peer information is currently available.' : ''));
            $('#et-peer-message').toggleClass('hidden', !text).text(htmlDecode(t(text || '')));
        });
    }
    function refreshLog() {ajaxGet('/api/easytier/service/log', {}, function (data) {$('#et-log').text(htmlDecode((data || {}).log || ''));});}
    $('.et-service').click(function () {mutate($(this).data('action'));});
    $('.et-save').click(function () {
        if (!loaded || busy) {return;}
        var restart = $(this).data('restart') === 1; busy = true; $('.et-save').prop('disabled', true);
        ajaxCall('/api/easytier/settings/set', {config: $('#et-config').val()}, function (data) {
            busy = false; $('.et-save').prop('disabled', false);
            if ((data || {}).status !== 'ok') {message((data || {}).error || '{{ lang._("Unable to save configuration.") }}', false); return;}
            message(data.warning || 'Configuration saved.', true, !!data.warning); loadSettings(); if (restart) {mutate('restart');}
        });
    });
    $('#et-clear-log').click(function () {if (window.confirm(t('Are you sure you want to clear the EasyTier log?'))) {mutate('clearLog', refreshLog);}});
    $('#et-tabs a').on('shown.bs.tab', function (event) {var tab = $(event.target).attr('href'); if (tab === '#et-peers') {refreshPeers();} if (tab === '#et-log-tab') {refreshLog();}});
    var currentLanguage = String($('html').attr('lang') || '').toLowerCase().replace('-', '_');
    language = /zh_(tw|hk|mo)|hant/.test(currentLanguage) ? 'zh_tw' : (/^zh($|_(cn|sg))|hans/.test(currentLanguage) ? 'zh_cn' : '');
    $('[data-et-label]').each(function () {if (language) {$(this).text(t($(this).attr('data-et-label')));}});
    loadSettings(); refreshStatus();
    window.setInterval(function () {if (!busy) {refreshStatus(); if ($('#et-peers').hasClass('active')) {refreshPeers();} if ($('#et-log-tab').hasClass('active')) {refreshLog();}}}, 5000);
});
</script>
