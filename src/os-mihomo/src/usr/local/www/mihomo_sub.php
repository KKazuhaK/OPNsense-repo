<?php

/*
 * Copyright (C) 2014-2026 Deciso B.V.
 * Copyright (C) 2010 Erik Fonnesbeck
 * Copyright (C) 2008-2010 Ermal Luçi
 * Copyright (C) 2004-2008 Scott Ullrich <sullrich@gmail.com>
 * Copyright (C) 2006 Daniel S. Haischt
 * Copyright (C) 2003-2004 Manuel Kasper <mk@neon1.net>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
/* Subscription settings are persisted outside the package-owned filesystem. */
require_once('guiconfig.inc');
require_once('/usr/local/etc/inc/mihomo.inc.php');
$csrf = mihomo_csrf();
if (isset($_GET['ajax']) && $_GET['ajax'] === 'status') {
    header('Content-Type: application/json; charset=UTF-8');
    $status = @file_get_contents('/var/run/mihomo-update.json');
    echo is_string($status) ? $status : '{}';
    exit;
}
$message = '';
$ok = false;
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!mihomo_verify_csrf($_POST['csrf_token'] ?? null)) {
        $message = 'CSRF validation failed. Refresh the page and try again.';
    } else {
        $action = (string)($_POST['action'] ?? '');
        if ($action === 'set-settings') {
            $settings = mihomo_settings();
            $secret = trim((string)($_POST['secret'] ?? ''));
            $payload = ['subscription_url' => trim((string)($_POST['subscription_url'] ?? '')),
                        'secret' => $secret !== '' ? $secret : ($settings['secret'] ?? ''),
                        'controller' => trim((string)($_POST['controller'] ?? '')),
                        'device' => trim((string)($_POST['device'] ?? '')),
                        'dns_fallback' => isset($_POST['dns_fallback'])];
            $result = mihomo_action($action, json_encode($payload));
        } elseif ($action === 'sub-update' || $action === 'clear-sub-log') {
            $result = mihomo_action($action);
        } else {
            $result = ['ok' => false, 'error' => 'Invalid action.'];
        }
        $ok = ($result['ok'] ?? false) === true;
        $message = $ok ? ($action === 'sub-update' ? 'Subscription update queued. Check its status below.' : 'Operation completed successfully.') : ($result['error'] ?? 'Operation failed.');
    }
}
$settings = mihomo_settings();
include('head.inc');
include('fbegin.inc');
?>
<section class="page-content-main">
  <div class="container-fluid">
    <h2><?=gettext('Mihomo subscription')?></h2>
    <?php if ($message !== ''): ?><div class="alert alert-<?=$ok ? 'success' : 'danger'?>"><?=mihomo_escape($message)?></div><?php endif; ?>
    <div class="content-box">
      <p><?=gettext('Fetch a complete Mihomo YAML subscription directly. The subscription URL and dashboard secret are never written to logs.')?></p>
      <form method="post">
        <input type="hidden" name="csrf_token" value="<?=mihomo_escape($csrf)?>">
        <?php foreach (['subscription_url' => 'Subscription URL', 'controller' => 'Dashboard IPv4 address and port', 'device' => 'Device label'] as $key => $label): ?>
          <div class="form-group"><label for="<?=$key?>"><?=gettext($label)?></label>
            <input class="form-control" id="<?=$key?>" name="<?=$key?>" value="<?=mihomo_escape($settings[$key] ?? '')?>" required autocomplete="off">
          </div>
        <?php endforeach; ?>
        <div class="form-group"><label for="secret"><?=gettext('New dashboard secret')?></label>
          <input type="password" class="form-control" id="secret" name="secret" autocomplete="new-password" placeholder="<?=gettext('Leave empty to keep the current secret')?>">
        </div>
        <label><input type="checkbox" name="dns_fallback" value="1" <?=!empty($settings['dns_fallback']) ? 'checked' : ''?>>
          <?=gettext('Restore direct DNS automatically if Mihomo exits')?></label>
        <p><?=gettext('This policy is local to this router. Turning it off keeps proxy DNS forwarding in place after an unexpected exit. Explicit Stop always restores the original DNS configuration.')?></p>
        <button type="submit" class="btn btn-primary" name="action" value="set-settings"><?=gettext('Save settings')?></button>
      </form>
      <form method="post">
        <input type="hidden" name="csrf_token" value="<?=mihomo_escape($csrf)?>">
        <button type="submit" class="btn btn-success" name="action" value="sub-update"><?=gettext('Fetch and apply subscription')?></button>
        <button type="submit" class="btn btn-default" name="action" value="clear-sub-log"><?=gettext('Clear log')?></button>
      </form>
      <p><?=gettext('User-Agent')?>: <code><?=mihomo_escape('OPNsense-Mihomo/1 (' . ($settings['device'] ?? 'router') . ')')?></code></p>
      <p><?=gettext('Schedule updates in System → Settings → Cron using Renew mihomo Subscription. HTTP 4xx responses stop immediately; only timeouts and HTTP 5xx responses permit retries or proxy fallback.')?></p>
    </div>
    <div class="content-box"><h3><?=gettext('Subscription log')?></h3><p id="mihomo-update-status"></p><pre id="mihomo-sub-log"></pre></div>
  </div>
</section>
<script>
$(function () {
    function refresh() {
        $.getJSON('mihomo_sub.php?ajax=status', function (state) { $('#mihomo-update-status').text(state.error || state.status || ''); });
        $.get('mihomo_sub_log.php', function (text) { $('#mihomo-sub-log').text(text); });
    }
    refresh();
    setInterval(refresh, 10000);
});
</script>
<?php include('foot.inc'); ?>
