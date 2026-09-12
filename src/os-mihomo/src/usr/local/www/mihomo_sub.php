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
            $url = trim((string)($_POST['subscription_url'] ?? ''));
            $payload = ['subscription_url' => isset($_POST['clear_url']) ? '' : ($url !== '' ? $url : ($settings['subscription_url'] ?? '')),
                        'secret' => $secret !== '' ? $secret : ($settings['secret'] ?? ''),
                        'device' => trim((string)($_POST['device'] ?? '')),
                        'dns_fallback' => isset($_POST['dns_fallback']),
                        'router_dns' => isset($_POST['router_dns']),
                        'ipv6' => isset($_POST['ipv6']),
                        'dns_hijack' => isset($_POST['dns_hijack']),
                        'dns_mode' => (string)($_POST['dns_mode'] ?? 'fake-ip'),
                        'dashboard_any' => isset($_POST['dashboard_any']),
                        'geo_source' => (string)($_POST['geo_source'] ?? 'metacubex')];
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
$overrides = mihomo_overrides();
include('head.inc');
include('fbegin.inc');
?>
<section class="page-content-main">
  <div class="container-fluid">
    <?php if ($message !== ''): ?>
      <div class="alert alert-<?=$ok ? 'success' : 'danger'?>"><?=mihomo_escape($message)?></div>
    <?php endif; ?>

    <form method="post">
      <input type="hidden" name="csrf_token" value="<?=mihomo_escape($csrf)?>">
      <div class="content-box tab-content table-responsive __mb">
        <table class="table table-striped opnsense_standard_table_form">
          <tr>
            <td style="width:22%"><strong><?=gettext('Subscription')?></strong></td>
            <td style="width:78%"></td>
          </tr>
          <tr>
            <td><a id="help_for_url" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> <?=gettext('Subscription URL')?></td>
            <td>
              <input type="password" class="form-control" id="subscription_url" name="subscription_url" autocomplete="new-password" placeholder="<?=gettext('Leave empty to keep the stored URL')?>">
              <label style="font-weight:normal;margin-top:6px">
                <input type="checkbox" name="clear_url" value="1"> <?=gettext('Remove the stored URL')?>
              </label>
              <div class="hidden" data-for="help_for_url">
                <?=!empty($settings['subscription_url']) ? gettext('A subscription URL is stored.') : gettext('No subscription URL is stored.')?>
                <?=gettext('The complete Mihomo YAML is fetched directly from this address. The URL and the dashboard secret are never written to logs.')?>
              </div>
            </td>
          </tr>
          <tr>
            <td><a id="help_for_device" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> <?=gettext('Device label')?></td>
            <td>
              <input type="text" class="form-control" id="device" name="device" value="<?=mihomo_escape($settings['device'] ?? '')?>" required autocomplete="off">
              <div class="hidden" data-for="help_for_device">
                <?=gettext('Identifies this router in the subscription request. Sent as')?>
                <code><?=mihomo_escape('OPNsense-Mihomo/1 (' . ($settings['device'] ?? 'router') . ')')?></code>
              </div>
            </td>
          </tr>
          <tr>
            <td><a id="help_for_secret" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> <?=gettext('Dashboard secret')?></td>
            <td>
              <input type="password" class="form-control" id="secret" name="secret" autocomplete="new-password" placeholder="<?=gettext('Leave empty to keep the current secret')?>">
              <div class="hidden" data-for="help_for_secret">
                <?=gettext('Protects the Mihomo dashboard and its control API. The stored value is preserved across subscription refreshes and package upgrades.')?>
              </div>
            </td>
          </tr>
          <tr>
            <td><a id="help_for_dashboard" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> <?=gettext('Reachable dashboard')?></td>
            <td>
              <input type="checkbox" name="dashboard_any" value="1" <?=strpos((string)($settings['controller'] ?? '127.0.0.1:9090'), '127.0.0.1:') !== 0 ? 'checked="checked"' : ''?>>
              <div class="hidden" data-for="help_for_dashboard">
                <?=gettext('Binds the control API and dashboard to every interface instead of loopback only, so it can be opened from the LAN at http://<router>:9090/ui/. The firewall still decides who reaches it, and the random dashboard secret above is what authenticates callers. Leave it off and reach the dashboard through an SSH tunnel if the WAN rules are permissive or untrusted devices share the LAN.')?>
              </div>
            </td>
          </tr>
          <tr>
            <td style="width:22%"><strong><?=gettext('DNS policy')?></strong></td>
            <td style="width:78%"></td>
          </tr>
          <tr>
            <td><a id="help_for_fallback" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> <?=gettext('Restore direct DNS on exit')?></td>
            <td>
              <input type="checkbox" name="dns_fallback" value="1" <?=!empty($settings['dns_fallback']) ? 'checked="checked"' : ''?>>
              <div class="hidden" data-for="help_for_fallback">
                <?=gettext('This policy is local to this router. Turning it off keeps proxy DNS forwarding in place after an unexpected exit. An explicit Stop always restores the original DNS configuration.')?>
              </div>
            </td>
          </tr>
          <tr>
            <td><a id="help_for_ipv6" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> <?=gettext('IPv6 support')?></td>
            <td>
              <input type="checkbox" name="ipv6" value="1" <?=!empty($settings['ipv6']) ? 'checked="checked"' : ''?>>
              <?=mihomo_override_badge($overrides, 'ipv6')?>
              <div class="hidden" data-for="help_for_ipv6">
                <?=gettext('Default off. Lets Mihomo answer AAAA queries and carry IPv6 traffic through the tunnel. Leave it off unless the upstream nodes are known to work over IPv6, otherwise clients may prefer a v6 path that never completes.')?>
              </div>
            </td>
          </tr>
          <tr>
            <td><a id="help_for_dnsmode" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> <?=gettext('DNS mode')?></td>
            <td>
              <select name="dns_mode" class="selectpicker" data-style="btn-default" data-width="260px">
                <?php foreach (['fake-ip' => gettext('fake-ip (recommended)'), 'redir-host' => gettext('redir-host'), 'normal' => gettext('normal')] as $value => $label): ?>
                  <option value="<?=mihomo_escape($value)?>" <?=($settings['dns_mode'] ?? 'fake-ip') === $value ? 'selected="selected"' : ''?>><?=mihomo_escape($label)?></option>
                <?php endforeach; ?>
              </select>
              <?=mihomo_override_badge($overrides, 'dns_mode')?>
              <div class="hidden" data-for="help_for_dnsmode">
                <?=gettext('fake-ip answers with a placeholder address and resolves the real name at connection time; it is the fastest and the default. redir-host resolves upstream and rewrites the destination. normal performs no rewriting and disables rule matching by domain for routed traffic.')?>
              </div>
            </td>
          </tr>
          <tr>
            <td><a id="help_for_hijack" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> <?=gettext('Capture client DNS')?></td>
            <td>
              <input type="checkbox" name="dns_hijack" value="1" <?=!empty($settings['dns_hijack']) ? 'checked="checked"' : ''?>>
              <?=mihomo_override_badge($overrides, 'dns_hijack')?>
              <div class="hidden" data-for="help_for_hijack">
                <?=gettext('Default on. Redirects DNS queries that enter the tunnel to Mihomo. Required for fake-ip. Turn it off to leave client DNS entirely to the router resolver. This switch only takes effect while transparent routing is enabled.')?>
              </div>
            </td>
          </tr>
          <tr>
            <td><a id="help_for_geo" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> <?=gettext('Rule database')?></td>
            <td>
              <select name="geo_source" class="selectpicker" data-style="btn-default" data-width="320px">
                <?php foreach (['metacubex' => gettext('MetaCubeX (GitHub, official)'),
                                'loyalsoldier-cdn' => gettext('Loyalsoldier (jsDelivr CDN)'),
                                'loyalsoldier' => gettext('Loyalsoldier (GitHub)')] as $value => $label): ?>
                  <option value="<?=mihomo_escape($value)?>" <?=($settings['geo_source'] ?? 'metacubex') === $value ? 'selected="selected"' : ''?>><?=mihomo_escape($label)?></option>
                <?php endforeach; ?>
              </select>
              <?=mihomo_override_badge($overrides, 'geo_source')?>
              <div class="hidden" data-for="help_for_geo">
                <?=gettext('Where the geoip and geosite databases that GEOSITE and GEOIP rules match against are downloaded from, refreshed every 24 hours. Pick a source reachable from this router before any proxy is up: MetaCubeX is the set Mihomo is built around, and the jsDelivr option exists because that CDN reaches networks GitHub does not. The two projects do not publish the same categories, so switching can invalidate a rule that names a category the new source lacks; check the log after changing it.')?>
              </div>
            </td>
          </tr>
          <tr>
            <td><a id="help_for_routerdns" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> <?=gettext('Resolve through the router DNS')?></td>
            <td>
              <input type="checkbox" name="router_dns" value="1" <?=!empty($settings['router_dns']) ? 'checked="checked"' : ''?>>
              <div class="hidden" data-for="help_for_routerdns">
                <?=gettext('Default off. Uses the router resolver and pins its DNS transport DIRECT. It leaves DNS hijacking, enhanced mode, and the router AAAA policy unchanged. Activation is refused if clients are offered IPv6 while Mihomo IPv6 is disabled.')?>
              </div>
            </td>
          </tr>
          <tr>
            <td></td>
            <td><button type="submit" class="btn btn-primary" name="action" value="set-settings"><?=gettext('Save settings')?></button></td>
          </tr>
        </table>
      </div>
    </form>

    <form method="post">
      <input type="hidden" name="csrf_token" value="<?=mihomo_escape($csrf)?>">
      <div class="content-box tab-content table-responsive __mb">
        <table class="table table-striped opnsense_standard_table_form">
          <tr>
            <td style="width:22%"><strong><?=gettext('Subscription log')?></strong></td>
            <td style="width:78%"><span id="mihomo-update-status" class="text-muted"></span></td>
          </tr>
          <tr>
            <td><a id="help_for_fetch" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> <?=gettext('Update')?></td>
            <td>
              <button type="submit" class="btn btn-default" name="action" value="sub-update"><?=gettext('Fetch and apply subscription')?></button>
              <div class="hidden" data-for="help_for_fetch">
                <?=gettext('Schedule recurring updates in System → Settings → Cron using Renew mihomo Subscription. HTTP 4xx responses stop immediately; only timeouts and HTTP 5xx responses permit retries or proxy fallback.')?>
              </div>
            </td>
          </tr>
          <tr>
            <td></td>
            <td>
              <pre id="mihomo-sub-log" style="max-height:340px;overflow:auto;font-size:12px;margin-bottom:12px"></pre>
              <button type="submit" class="btn btn-default" name="action" value="clear-sub-log"><?=gettext('Clear log')?></button>
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
        $.getJSON('mihomo_sub.php?ajax=status', function (state) { $('#mihomo-update-status').text(state.error || state.status || ''); });
        $.get('mihomo_sub_log.php', function (text) { $('#mihomo-sub-log').text(text); });
    }
    refresh();
    setInterval(refresh, 10000);
});
</script>
<?php include('foot.inc'); ?>
