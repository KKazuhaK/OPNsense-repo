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
    <?php if ($message !== ''): ?>
      <div class="alert alert-<?=$ok ? 'success' : 'danger'?>"><?=mihomo_escape($message)?></div>
    <?php endif; ?>
    <?php if (!empty($status['error'])): ?>
      <div class="alert alert-warning"><?=mihomo_escape($status['error'])?></div>
    <?php endif; ?>

    <form method="post">
      <input type="hidden" name="csrf_token" value="<?=mihomo_escape($csrf)?>">
      <div class="content-box tab-content table-responsive __mb">
        <table class="table table-striped opnsense_standard_table_form">
          <tr>
            <td style="width:22%"><strong><?=gettext('Service and transparent routing')?></strong></td>
            <td style="width:78%"></td>
          </tr>
          <tr>
            <td><?=gettext('Service')?></td>
            <td id="mihomo-status-cell">
              <span class="label label-<?=$status['running'] ? 'success' : 'default'?>"><?=$status['running'] ? gettext('Running') : gettext('Stopped')?></span>
            </td>
          </tr>
          <tr>
            <td><?=gettext('Transparent routing')?></td>
            <td><span class="label label-<?=!empty($settings['transparent']) ? 'success' : 'default'?>"><?=!empty($settings['transparent']) ? gettext('Active') : gettext('Off')?></span></td>
          </tr>
          <tr>
            <td><?=gettext('DNS integration')?></td>
            <td><span class="label label-<?=!empty($status['dns_active']) ? 'success' : 'default'?>"><?=!empty($status['dns_active']) ? gettext('Active') : gettext('Off')?></span></td>
          </tr>
          <tr>
            <td><a id="help_for_service" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> <?=gettext('Service control')?></td>
            <td>
              <button type="submit" class="btn btn-default" name="action" value="start"><?=gettext('Start')?></button>
              <button type="submit" class="btn btn-default" name="action" value="stop"><?=gettext('Stop')?></button>
              <button type="submit" class="btn btn-default" name="action" value="restart"><?=gettext('Restart')?></button>
              <div class="hidden" data-for="help_for_service">
                <?=gettext('Starts or stops the proxy core. Installation and upgrades start proxy ports only; the router keeps its own routing and DNS until transparent routing is enabled below.')?>
              </div>
            </td>
          </tr>
          <tr>
            <td><a id="help_for_transparent" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> <?=gettext('Transparent routing')?></td>
            <td>
              <?php if (empty($settings['transparent'])): ?>
                <button type="submit" class="btn btn-primary" name="action" value="enable-transparent"><?=gettext('Enable transparent routing')?></button>
              <?php else: ?>
                <button type="submit" class="btn btn-default" name="action" value="disable-transparent"><?=gettext('Disable transparent routing')?></button>
              <?php endif; ?>
              <div class="hidden" data-for="help_for_transparent">
                <?=gettext('Hands LAN traffic and DNS to Mihomo using the validated merge YAML, including its TUN and DNS mode. This changes forwarding for every client on the network.')?>
              </div>
            </td>
          </tr>
          <tr>
            <td><a id="help_for_advanced" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> <?=gettext('Advanced options')?></td>
            <td>
              <input type="checkbox" id="mihomo-advanced-toggle">
              <div class="hidden" data-for="help_for_advanced">
                <?=gettext('Reveals the raw configuration editors. Everyday settings live under Subscription; edit the YAML only to express something the switches there cannot. A value written by hand keeps winning over the matching switch.')?>
              </div>
            </td>
          </tr>
        </table>
      </div>

      <div id="mihomo-advanced" class="hidden">

      <div class="content-box tab-content table-responsive __mb">
        <table class="table table-striped opnsense_standard_table_form">
          <tr>
            <td style="width:22%"><strong><?=gettext('Local merge YAML')?></strong></td>
            <td style="width:78%"></td>
          </tr>
          <tr>
            <td><a id="help_for_merge" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> <?=gettext('Merge YAML')?></td>
            <td>
              <textarea name="merge_content" rows="14" class="form-control" spellcheck="false" style="font-family:monospace;font-size:12px"><?=mihomo_escape($merge ?: '')?></textarea>
              <div class="hidden" data-for="help_for_merge">
                <?=gettext('Mappings deep-merge. Plain values replace; prepend/append-rules, -proxy-groups and -proxies extend lists. The TUN device name, the stored dashboard secret and the port 53 restriction are enforced and cannot be overridden here.')?>
              </div>
            </td>
          </tr>
          <tr>
            <td></td>
            <td><button type="submit" class="btn btn-primary" name="action" value="save-merge"><?=gettext('Validate and apply merge')?></button></td>
          </tr>
          <tr>
            <td><a id="help_for_preset" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> <?=gettext('Preset')?></td>
            <td>
              <select name="preset" class="selectpicker" data-style="btn-default" data-width="260px">
                <?php foreach (glob('/usr/local/share/mihomo/presets/*.yaml') as $path): ?>
                  <option value="<?=mihomo_escape(basename($path))?>"><?=mihomo_escape(basename($path))?></option>
                <?php endforeach; ?>
              </select>
              <button type="submit" class="btn btn-default" style="margin-left:6px" name="action" value="load-preset"><?=gettext('Load preset')?></button>
              <div class="hidden" data-for="help_for_preset">
                <?=gettext('Loading a preset replaces the entire merge file above. Save a copy of custom settings first.')?>
              </div>
            </td>
          </tr>
        </table>
      </div>

      <div class="content-box tab-content table-responsive __mb">
        <table class="table table-striped opnsense_standard_table_form">
          <tr>
            <td style="width:22%"><strong><?=gettext('Subscription configuration')?></strong></td>
            <td style="width:78%"></td>
          </tr>
          <tr>
            <td><a id="help_for_config" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> <?=gettext('Subscription YAML')?></td>
            <td>
              <textarea name="config_content" rows="20" class="form-control" spellcheck="false" style="font-family:monospace;font-size:12px"><?=mihomo_escape($source ?: '')?></textarea>
              <div class="hidden" data-for="help_for_config">
                <?=gettext('Local listeners, dashboard credentials, TUN and DNS integration are managed by the plugin. Changes are validated before they are applied, and the previous configuration is restored if the service fails to start.')?>
              </div>
            </td>
          </tr>
          <tr>
            <td></td>
            <td><button type="submit" class="btn btn-primary" name="action" value="save-config"><?=gettext('Validate and apply configuration')?></button></td>
          </tr>
        </table>
      </div>

      </div>

      <div class="content-box tab-content table-responsive __mb">
        <table class="table table-striped opnsense_standard_table_form">
          <tr>
            <td style="width:22%"><strong><?=gettext('Log viewer')?></strong></td>
            <td style="width:78%"></td>
          </tr>
          <tr>
            <td></td>
            <td>
              <pre id="mihomo-log" style="max-height:340px;overflow:auto;font-size:12px;margin-bottom:12px"></pre>
              <button type="submit" class="btn btn-default" name="action" value="clear-log"><?=gettext('Clear log')?></button>
            </td>
          </tr>
        </table>
      </div>
    </form>
  </div>
</section>
<script>
$(function () {
    function refresh() {
        $.getJSON('mihomo.php?ajax=status', function (state) {
            var cls = state.running ? 'label label-success' : 'label label-danger';
            var txt = state.running ? '<?=gettext('Running')?>' : '<?=gettext('Stopped')?>';
            $('#mihomo-status-cell').html($('<span>').attr('class', cls).text(txt));
        });
        $.get('mihomo_logs.php', function (text) { $('#mihomo-log').text(text); });
    }
    var toggle = $('#mihomo-advanced-toggle');
    var open = false;
    try { open = localStorage.getItem('mihomo:advanced') === '1'; } catch (e) { open = false; }
    toggle.prop('checked', open);
    $('#mihomo-advanced').toggleClass('hidden', !open);
    toggle.on('change', function () {
        var on = $(this).is(':checked');
        $('#mihomo-advanced').toggleClass('hidden', !on);
        try { localStorage.setItem('mihomo:advanced', on ? '1' : '0'); } catch (e) { /* private mode */ }
    });
    refresh();
    setInterval(refresh, 10000);
});
</script>
<?php include('foot.inc'); ?>
