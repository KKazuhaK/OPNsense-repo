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
/* Mihomo service controls use the same policy manager as boot and WAN events. */
require_once('guiconfig.inc');
require_once('/usr/local/etc/inc/mihomo.inc.php');

$csrf = mihomo_csrf();
if (isset($_GET['ajax']) && $_GET['ajax'] === 'status') {
    header('Content-Type: application/json; charset=UTF-8');
    echo json_encode(mihomo_status());
    exit;
}
$message = '';
$ok = false;
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!mihomo_verify_csrf($_POST['csrf_token'] ?? null)) {
        $message = 'CSRF validation failed. Refresh the page and try again.';
    } else {
        $action = (string)($_POST['action'] ?? '');
        if ($action === 'save-config' || $action === 'save-merge') {
            $result = mihomo_action($action, (string)($_POST[$action === 'save-merge' ? 'merge_content' : 'config_content'] ?? ''));
        } elseif ($action === 'load-preset') {
            $preset = (string)($_POST['preset'] ?? '');
            $result = preg_match('/^[a-z0-9-]+\.yaml$/', $preset) ? mihomo_action($action, $preset) : ['ok' => false, 'error' => 'Invalid preset.'];
        } else {
            $result = mihomo_action($action);
        }
        $ok = ($result['ok'] ?? false) === true;
        $message = $ok ? 'Operation completed successfully.' : ($result['error'] ?? 'Operation failed.');
    }
}
$status = mihomo_status();
$settings = mihomo_settings();
$source = @file_get_contents('/var/db/os-mihomo/subscription.yaml');
$merge = @file_get_contents('/var/db/os-mihomo/merge.yaml');
include('head.inc');
include('fbegin.inc');
?>
<section class="page-content-main">
  <div class="container-fluid">
    <h2><?=gettext('Mihomo')?></h2>
    <?php if ($message !== ''): ?>
      <div class="alert alert-<?=$ok ? 'success' : 'danger'?>"><?=mihomo_escape($message)?></div>
    <?php endif; ?>
    <div class="content-box">
      <h3><?=gettext('Service and transparent routing')?></h3>
      <p id="mihomo-status"><?=mihomo_escape($status['running'] ? 'Mihomo is running.' : 'Mihomo is stopped.')?></p>
      <p><?=gettext('Installation and upgrades start proxy ports only. Explicit transparent activation uses the validated merge YAML, including its TUN and DNS mode.')?></p>
      <p><?=gettext('Transparent routing configured')?>: <?=!empty($settings['transparent']) ? gettext('Yes') : gettext('No')?>.
         <?=gettext('DNS integration active')?>: <?=!empty($status['dns_active']) ? gettext('Yes') : gettext('No')?>.</p>
      <?php if (!empty($status['error'])): ?><div class="alert alert-warning"><?=mihomo_escape($status['error'])?></div><?php endif; ?>
      <form method="post">
        <input type="hidden" name="csrf_token" value="<?=mihomo_escape($csrf)?>">
        <?php foreach (['start' => 'Start', 'stop' => 'Stop', 'restart' => 'Restart', 'enable-transparent' => 'Enable transparent routing', 'disable-transparent' => 'Disable transparent routing', 'clear-log' => 'Clear log'] as $action => $label): ?>
          <button type="submit" class="btn btn-default" name="action" value="<?=$action?>"><?=gettext($label)?></button>
        <?php endforeach; ?>
      </form>
    </div>
    <div class="content-box">
      <h3><?=gettext('Local merge YAML')?></h3>
      <p><?=gettext('Mappings deep-merge. Plain values replace; prepend/append-rules, -proxy-groups and -proxies extend lists. This file controls the dashboard address and proxy ports. TUN device, the stored secret and the port 53 restriction are enforced. Loading a preset replaces this entire file; save a copy of custom settings first.')?></p>
      <form method="post">
        <input type="hidden" name="csrf_token" value="<?=mihomo_escape($csrf)?>">
        <textarea name="merge_content" rows="18" class="form-control" spellcheck="false"><?=mihomo_escape($merge ?: '')?></textarea>
        <button type="submit" class="btn btn-primary" name="action" value="save-merge"><?=gettext('Validate and apply merge')?></button>
        <select name="preset"><?php foreach (glob('/usr/local/share/mihomo/presets/*.yaml') as $path): ?><option value="<?=mihomo_escape(basename($path))?>"><?=mihomo_escape(basename($path))?></option><?php endforeach; ?></select>
        <button type="submit" class="btn btn-default" name="action" value="load-preset"><?=gettext('Load preset')?></button>
      </form>
    </div>
    <div class="content-box">
      <h3><?=gettext('Subscription configuration')?></h3>
      <p><?=gettext('Edit the complete subscription YAML. Local listeners, dashboard credentials, TUN, and DNS integration are managed by the plugin. Changes are validated before application, with rollback on service failure.')?></p>
      <form method="post">
        <input type="hidden" name="csrf_token" value="<?=mihomo_escape($csrf)?>">
        <textarea name="config_content" rows="24" class="form-control" spellcheck="false"><?=mihomo_escape($source ?: '')?></textarea>
        <button type="submit" class="btn btn-primary" name="action" value="save-config"><?=gettext('Validate and apply configuration')?></button>
      </form>
    </div>
    <div class="content-box"><h3><?=gettext('Log viewer')?></h3><pre id="mihomo-log"></pre></div>
  </div>
</section>
<script>
$(function () {
    function refresh() {
        $.getJSON('mihomo.php?ajax=status', function (state) {
            $('#mihomo-status').text(state.error || (state.running ? 'Mihomo is running.' : 'Mihomo is stopped.'));
        });
        $.get('mihomo_logs.php', function (text) { $('#mihomo-log').text(text); });
    }
    refresh();
    setInterval(refresh, 10000);
});
</script>
<?php include('foot.inc'); ?>
