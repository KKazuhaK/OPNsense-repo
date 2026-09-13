{#
 # Copyright (C) 2026 Kazuha
 # All rights reserved.
 #
 # Redistribution and use in source and binary forms, with or without
 # modification, are permitted provided that the following conditions are met:
 #
 # 1. Redistributions of source code must retain the above copyright notice,
 #    this list of conditions and the following disclaimer.
 #
 # 2. Redistributions in binary form must reproduce the above copyright
 #    notice, this list of conditions and the following disclaimer in the
 #    documentation and/or other materials provided with the distribution.
 #
 # THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 # INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 # AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 # AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 # OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 # SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 # INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 # CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 # ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 # POSSIBILITY OF SUCH DAMAGE.
 #}

{# The daemon this page drives, named before the shared script is pulled in. #}
{% set side = 'frps' %}
{{ partial("OPNsense/Frp/common", ['side': side]) }}

<script>
$(function () {

    /* The keys of frps.toml this page draws. Everything not listed here still
       survives a save: the shared script starts from the stored document and
       only replaces these paths. */
    const FIELDS = [
        {id: 'frps_bind_addr', path: 'bindAddr', kind: 'text', label: '{{ lang._('Bind address') }}'},
        {id: 'frps_bind_port', path: 'bindPort', kind: 'int', label: '{{ lang._('Bind port') }}'},
        {id: 'frps_auth_method', path: 'auth.method', kind: 'text', label: '{{ lang._('Authentication method') }}'},
        {id: 'frps_auth_token', path: 'auth.token', kind: 'secret', label: '{{ lang._('Token') }}'},
        {id: 'frps_web_addr', path: 'webServer.addr', kind: 'text', label: '{{ lang._('Dashboard address') }}'},
        {id: 'frps_web_port', path: 'webServer.port', kind: 'int', label: '{{ lang._('Dashboard port') }}'},
        {id: 'frps_web_user', path: 'webServer.user', kind: 'text', label: '{{ lang._('Dashboard user') }}'},
        {id: 'frps_web_password', path: 'webServer.password', kind: 'secret', label: '{{ lang._('Dashboard password') }}'},
        {id: 'frps_vhost_http', path: 'vhostHTTPPort', kind: 'int', label: '{{ lang._('HTTP virtual host port') }}'},
        {id: 'frps_vhost_https', path: 'vhostHTTPSPort', kind: 'int', label: '{{ lang._('HTTPS virtual host port') }}'},
        {id: 'frps_subdomain_host', path: 'subDomainHost', kind: 'text', label: '{{ lang._('Subdomain host') }}'},
        {id: 'frps_allow_ports', path: 'allowPorts', kind: 'ports', label: '{{ lang._('Allowed remote ports') }}'},
        {id: 'frps_max_ports', path: 'maxPortsPerClient', kind: 'int', label: '{{ lang._('Remote ports per client') }}'},
        {id: 'frps_tls_force', path: 'transport.tls.force', kind: 'bool', label: '{{ lang._('Require TLS') }}'},
        {id: 'frps_tls_cert', path: 'transport.tls.certFile', kind: 'text', label: '{{ lang._('Certificate file') }}'},
        {id: 'frps_tls_key', path: 'transport.tls.keyFile', kind: 'text', label: '{{ lang._('Key file') }}'},
        {id: 'frps_tls_ca', path: 'transport.tls.trustedCaFile', kind: 'text', label: '{{ lang._('Trusted CA file') }}'},
        {id: 'frps_log_to', path: 'log.to', kind: 'text', label: '{{ lang._('Log destination') }}'},
        {id: 'frps_log_level', path: 'log.level', kind: 'text', label: '{{ lang._('Log level') }}'},
        {id: 'frps_log_maxdays', path: 'log.maxDays', kind: 'int', label: '{{ lang._('Days of log kept') }}'}
    ];

    /* The values frps has no safe default for. Nothing here is a matter of
       taste: each one has a stated consequence when it is left empty, and the
       daemon refuses to start until it is set. */
    const REQUIRED = [
        {path: 'auth.token', level: 'danger',
         label: '{{ lang._('Server token') }}',
         risk: '{{ lang._('an empty token authenticates every client that sends an empty token, so anyone who reaches the bind port can publish a proxy through this router.') }}'},
        /* Only while a dashboard port is bound: with no port there is no admin
           API to leave unauthenticated, and the backend lets that start. */
        {path: 'webServer.user', level: 'danger', needs: 'webServer.port',
         label: '{{ lang._('Dashboard user') }}',
         risk: '{{ lang._('with the dashboard user and password both empty frps skips its authentication middleware entirely, and the admin API can then list and delete proxies without any credential.') }}'},
        {path: 'webServer.password', level: 'danger', needs: 'webServer.port',
         label: '{{ lang._('Dashboard password') }}',
         risk: '{{ lang._('with the dashboard user and password both empty frps skips its authentication middleware entirely, and the admin API can then list and delete proxies without any credential.') }}'},
        {path: 'allowPorts', level: 'danger',
         label: '{{ lang._('Allowed remote ports') }}',
         risk: '{{ lang._('without an allowed range a client may bind any remote port on this firewall, including the ports OPNsense services already answer on.') }}'}
    ];

    /* Where the dashboard answers, if it answers at all. It is the one part of
       the stored server configuration that is worth knowing on Status: the
       same listener serves the admin API, so an operator has to be able to see
       at a glance whether it is bound and where. */
    function renderDashboard() {
        const web = frp.stored().webServer;
        const settings = (web !== null && typeof web === 'object' && !Array.isArray(web)) ? web : {};
        const port = String(settings.port === undefined || settings.port === null ? '' : settings.port).trim();
        if (port === '' || port === '0') {
            $('#frp-dashboard').text(
                '{{ lang._('No dashboard port is set, so frps serves neither a dashboard nor an admin API.') }}');
            return;
        }
        const address = String(settings.addr === undefined || settings.addr === null ? '' : settings.addr).trim()
            || '127.0.0.1';
        $('#frp-dashboard').text(frp.fill(
            '{{ lang._('http://%a:%p/ — this is the saved configuration, and a running server answers there only after a restart.') }}',
            {'%a': address, '%p': port}));
    }

    const frp = window.frpCommon({
        fields: FIELDS,
        required: REQUIRED,
        requiredIntro: '{{ lang._('The server will not start until these are set:') }}',
        onSettings: function () { renderDashboard(); }
    });

    frp.start();
});
</script>

<div class="alert" id="frp-message" style="display:none"></div>

<ul class="nav nav-tabs" role="tablist" id="maintabs">
    <li class="active"><a data-toggle="tab" href="#status">{{ lang._('Status') }}</a></li>
    <li><a data-toggle="tab" href="#settings">{{ lang._('Settings') }}</a></li>
    <li><a data-toggle="tab" href="#advanced">{{ lang._('Advanced') }}</a></li>
    <li><a data-toggle="tab" href="#log">{{ lang._('Log') }}</a></li>
</ul>
<div class="tab-content content-box">

    <div id="status" class="tab-pane fade in active">
        <form id="frmstatus">
        <table class="table table-striped opnsense_standard_table_form">
            <thead>
                <tr><td style="width:22%"><strong>{{ lang._('frp server (frps)') }}</strong></td>
                    <td style="width:78%; text-align:right">
                        <small>{{ lang._('full help') }} </small>
                        <i class="fa fa-toggle-off text-danger" style="cursor:pointer" id="show_all_help_status"></i>
                        &nbsp;&nbsp;
                    </td></tr>
            </thead>
            <tbody>
                <tr><td>{{ lang._('Service') }}</td>
                    <td><span id="frp-run" class="label label-default">-</span>
                        &nbsp;<span id="frp-boot" class="label label-default">-</span></td></tr>
                <tr><td>{{ lang._('Process id') }}</td><td><span id="frp-pid">-</span></td></tr>
                <tr><td>{{ lang._('Version') }}</td><td><span id="frp-version">-</span></td></tr>
                <tr><td></td><td><div class="alert alert-warning" id="frp-note" style="display:none"></div></td></tr>
                <tr>
                    <td><a id="help_for_frps_control" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Control') }}</td>
                    <td>
                        <button type="button" class="btn btn-primary frp-action" data-verb="start"
                                data-done="{{ lang._('The server was started and will now start at boot.') }}">{{ lang._('Enable and start') }}</button>
                        <button type="button" class="btn btn-default frp-action" data-verb="stop"
                                data-done="{{ lang._('The server was stopped and will no longer start at boot.') }}">{{ lang._('Stop and disable') }}</button>
                        <button type="button" class="btn btn-default frp-action" data-verb="restart"
                                data-done="{{ lang._('The server was restarted.') }}">{{ lang._('Restart') }}</button>
                        <div class="hidden" data-for="help_for_frps_control">
                            {{ lang._('Starting also sets frps_enable in /etc/rc.conf.d/frps, and stopping clears it, so the button and the boot setting can never disagree. Restart goes through the same start, so it sets frps_enable as well. The server refuses to start while the token, the dashboard credentials or the allowed port range are still unset; the warning above says which, and the Settings tab is where they are set.') }}
                        </div>
                    </td>
                </tr>
                <tr>
                    <td><a id="help_for_frps_dashboard" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Dashboard') }}</td>
                    <td><span id="frp-dashboard">-</span>
                        <div class="hidden" data-for="help_for_frps_dashboard">
                            {{ lang._('Where the built-in dashboard and the admin API answer, taken from webServer in the stored configuration. The admin API can list and delete a client\'s proxies, so an address other than 127.0.0.1 is a management interface to be firewalled deliberately. Leaving the port empty on the Settings tab switches both off.') }}
                        </div>
                    </td>
                </tr>
            </tbody>
        </table>
        </form>
    </div>

    <div id="settings" class="tab-pane fade in">
        <form id="frmsettings">
        <div class="alert" id="frp-required" style="display:none"></div>
        <table class="table table-striped opnsense_standard_table_form">
            <thead>
                <tr><td style="width:22%"><strong>{{ lang._('Control connection') }}</strong></td>
                    <td style="width:78%; text-align:right">
                        <small>{{ lang._('full help') }} </small>
                        <i class="fa fa-toggle-off text-danger" style="cursor:pointer" id="show_all_help_settings"></i>
                        &nbsp;&nbsp;
                    </td></tr>
            </thead>
            <tbody>
                <tr>
                    <td><a id="help_for_frps_bind" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Bind address') }}</td>
                    <td><input type="text" class="form-control" id="frps_bind_addr" style="width:240px" autocomplete="off" spellcheck="false" placeholder="0.0.0.0">
                        <div class="hidden" data-for="help_for_frps_bind">
                            {{ lang._('Which address the control port answers on. Empty means every address, which is what a server reached from the internet needs. This plugin adds no firewall rule: allow the port yourself under Firewall - Rules.') }}
                        </div>
                    </td>
                </tr>
                <tr>
                    <td><a id="help_for_frps_bind_port" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Bind port') }}</td>
                    <td><input type="text" class="form-control" id="frps_bind_port" style="width:160px" autocomplete="off" placeholder="7000">
                        <div class="hidden" data-for="help_for_frps_bind_port">
                            {{ lang._('The port every frp client connects to. It carries the control connection only; published services get their own remote ports out of the allowed range below.') }}
                        </div>
                    </td>
                </tr>
                <tr>
                    <td><a id="help_for_frps_auth_method" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Authentication method') }}</td>
                    <td>
                        <select id="frps_auth_method" class="selectpicker" data-style="btn-default" data-width="240px">
                            <option value="">{{ lang._('default (token)') }}</option>
                            <option value="token">{{ lang._('token') }}</option>
                            <option value="oidc">{{ lang._('oidc') }}</option>
                        </select>
                        <div class="hidden" data-for="help_for_frps_auth_method">
                            {{ lang._('token compares a shared secret. oidc validates a token from an identity provider and is configured under auth.oidc, which this page does not edit: use the Advanced tab for it.') }}
                        </div>
                    </td>
                </tr>
                <tr>
                    <td><a id="help_for_frps_token" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a>
                        {{ lang._('Token') }} <span class="label label-danger">{{ lang._('required') }}</span></td>
                    <td><input type="password" class="form-control" id="frps_auth_token" autocomplete="new-password" spellcheck="false">
                        <div class="hidden" data-for="help_for_frps_token">
                            {{ lang._('The shared secret every client must present. There is no safe default: if this is left empty, frps authenticates any client that also sends an empty token, which is anybody who can reach the bind port, and that client may then publish services from this router. Use a long random value and set the same one on each client. The stored value is never sent back to this page, so an empty box keeps it.') }}
                        </div>
                    </td>
                </tr>
            </tbody>
        </table>
        <table class="table table-striped opnsense_standard_table_form">
            <thead><tr><td style="width:22%"><strong>{{ lang._('Dashboard and admin API') }}</strong></td><td style="width:78%"></td></tr></thead>
            <tbody>
                <tr>
                    <td><a id="help_for_frps_web_addr" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Address') }}</td>
                    <td><input type="text" class="form-control" id="frps_web_addr" style="width:240px" autocomplete="off" spellcheck="false" placeholder="127.0.0.1">
                        <div class="hidden" data-for="help_for_frps_web_addr">
                            {{ lang._('Keep this on 127.0.0.1 unless the dashboard has to be opened from another machine. The same listener serves the admin API, which can list and delete proxies.') }}
                        </div>
                    </td>
                </tr>
                <tr>
                    <td><a id="help_for_frps_web_port" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Port') }}</td>
                    <td><input type="text" class="form-control" id="frps_web_port" style="width:160px" autocomplete="off" placeholder="7500">
                        <div class="hidden" data-for="help_for_frps_web_port">
                            {{ lang._('Leave the port empty to switch the dashboard off entirely. Nothing else on this page needs it.') }}
                        </div>
                    </td>
                </tr>
                <tr>
                    <td><a id="help_for_frps_web_user" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a>
                        {{ lang._('User') }} <span class="label label-danger">{{ lang._('required') }}</span></td>
                    <td><input type="text" class="form-control" id="frps_web_user" style="width:240px" autocomplete="off" spellcheck="false">
                        <div class="hidden" data-for="help_for_frps_web_user">
                            {{ lang._('There is no safe default. When the user and the password are both empty frps skips its authentication middleware altogether: the dashboard opens without asking, and so does the admin API, which can delete a client\'s proxies.') }}
                        </div>
                    </td>
                </tr>
                <tr>
                    <td><a id="help_for_frps_web_password" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a>
                        {{ lang._('Password') }} <span class="label label-danger">{{ lang._('required') }}</span></td>
                    <td><input type="password" class="form-control" id="frps_web_password" autocomplete="new-password" spellcheck="false">
                        <div class="hidden" data-for="help_for_frps_web_password">
                            {{ lang._('Set together with the user above; either one left empty leaves the admin API unauthenticated. The stored value is never sent back to this page, so an empty box keeps it.') }}
                        </div>
                    </td>
                </tr>
            </tbody>
        </table>
        <table class="table table-striped opnsense_standard_table_form">
            <thead><tr><td style="width:22%"><strong>{{ lang._('Virtual hosts') }}</strong></td><td style="width:78%"></td></tr></thead>
            <tbody>
                <tr>
                    <td><a id="help_for_frps_vhost" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('HTTP port') }}</td>
                    <td><input type="text" class="form-control" id="frps_vhost_http" style="width:160px" autocomplete="off" placeholder="8080">
                        <div class="hidden" data-for="help_for_frps_vhost">
                            {{ lang._('One shared port through which clients publish "http" proxies, routed by the requested name instead of one port each. Empty means http proxies are refused.') }}
                        </div>
                    </td>
                </tr>
                <tr>
                    <td><a id="help_for_frps_vhosts" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('HTTPS port') }}</td>
                    <td><input type="text" class="form-control" id="frps_vhost_https" style="width:160px" autocomplete="off" placeholder="8443">
                        <div class="hidden" data-for="help_for_frps_vhosts">
                            {{ lang._('The same for "https" proxies. frps passes the encrypted stream through; the certificate is the published service\'s own.') }}
                        </div>
                    </td>
                </tr>
                <tr>
                    <td><a id="help_for_frps_subdomain" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Subdomain host') }}</td>
                    <td><input type="text" class="form-control" id="frps_subdomain_host" style="width:320px" autocomplete="off" spellcheck="false" placeholder="frp.example.com">
                        <div class="hidden" data-for="help_for_frps_subdomain">
                            {{ lang._('The parent name clients build on when they set a subdomain rather than a full domain. With frp.example.com here, a client asking for "home" is published as home.frp.example.com. The DNS wildcard for it is yours to create.') }}
                        </div>
                    </td>
                </tr>
            </tbody>
        </table>
        <table class="table table-striped opnsense_standard_table_form">
            <thead><tr><td style="width:22%"><strong>{{ lang._('What clients may bind') }}</strong></td><td style="width:78%"></td></tr></thead>
            <tbody>
                <tr>
                    <td><a id="help_for_frps_allow" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a>
                        {{ lang._('Allowed remote ports') }} <span class="label label-danger">{{ lang._('required') }}</span></td>
                    <td><input type="text" class="form-control" id="frps_allow_ports" style="width:420px" autocomplete="off" spellcheck="false" placeholder="6000-6100, 7001">
                        <div class="hidden" data-for="help_for_frps_allow">
                            {{ lang._('Ranges and single ports, separated by commas: 6000-6100, 7001. There is no safe default. Left empty, a client may bind any remote port on this firewall, including ports OPNsense services already answer on, and it can do that at any time without touching this page. Keep the range as narrow as the deployment allows.') }}
                        </div>
                    </td>
                </tr>
                <tr>
                    <td><a id="help_for_frps_maxports" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Remote ports per client') }}</td>
                    <td><input type="text" class="form-control" id="frps_max_ports" style="width:160px" autocomplete="off" placeholder="8">
                        <div class="hidden" data-for="help_for_frps_maxports">
                            {{ lang._('How many remote ports one client may hold at once. Empty means no limit beyond the allowed range itself.') }}
                        </div>
                    </td>
                </tr>
            </tbody>
        </table>
        <table class="table table-striped opnsense_standard_table_form">
            <thead><tr><td style="width:22%"><strong>{{ lang._('Transport security') }}</strong></td><td style="width:78%"></td></tr></thead>
            <tbody>
                <tr>
                    <td><a id="help_for_frps_tls_force" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Require TLS') }}</td>
                    <td><input type="checkbox" id="frps_tls_force">
                        <div class="hidden" data-for="help_for_frps_tls_force">
                            {{ lang._('Refuse clients that do not wrap the control connection in TLS. Clients enable TLS by default and frps generates its own certificate when none is given, so this costs nothing to turn on.') }}
                        </div>
                    </td>
                </tr>
                <tr>
                    <td><a id="help_for_frps_tls_files" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Certificate file') }}</td>
                    <td><input type="text" class="form-control" id="frps_tls_cert" autocomplete="off" spellcheck="false">
                        <div class="hidden" data-for="help_for_frps_tls_files">
                            {{ lang._('A path on this router. Leave the three file fields empty to let frps use a certificate of its own making, which clients accept without verifying it.') }}
                        </div>
                    </td>
                </tr>
                <tr><td>{{ lang._('Key file') }}</td>
                    <td><input type="text" class="form-control" id="frps_tls_key" autocomplete="off" spellcheck="false"></td></tr>
                <tr>
                    <td><a id="help_for_frps_tls_ca" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Trusted CA file') }}</td>
                    <td><input type="text" class="form-control" id="frps_tls_ca" autocomplete="off" spellcheck="false">
                        <div class="hidden" data-for="help_for_frps_tls_ca">
                            {{ lang._('Set this to require every client to present a certificate signed by that authority, on top of the token.') }}
                        </div>
                    </td>
                </tr>
            </tbody>
        </table>
        <table class="table table-striped opnsense_standard_table_form">
            <thead><tr><td style="width:22%"><strong>{{ lang._('Logging') }}</strong></td><td style="width:78%"></td></tr></thead>
            <tbody>
                <tr>
                    <td><a id="help_for_frps_log_to" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Destination') }}</td>
                    <td><input type="text" class="form-control" id="frps_log_to" style="width:320px" autocomplete="off" spellcheck="false" placeholder="console">
                        <div class="hidden" data-for="help_for_frps_log_to">
                            {{ lang._('Leave this on console. The rc script redirects the daemon output into /var/log/frps.log, which is the file the Log tab reads; naming that file here as well would give it two writers.') }}
                        </div>
                    </td>
                </tr>
                <tr>
                    <td><a id="help_for_frps_log_level" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Level') }}</td>
                    <td>
                        <select id="frps_log_level" class="selectpicker" data-style="btn-default" data-width="200px">
                            <option value="">{{ lang._('default (info)') }}</option>
                            <option value="trace">{{ lang._('trace') }}</option>
                            <option value="debug">{{ lang._('debug') }}</option>
                            <option value="info">{{ lang._('info') }}</option>
                            <option value="warn">{{ lang._('warn') }}</option>
                            <option value="error">{{ lang._('error') }}</option>
                        </select>
                        <div class="hidden" data-for="help_for_frps_log_level">
                            {{ lang._('trace and debug record every connection a client makes, which is worth turning off again once a problem is understood.') }}
                        </div>
                    </td>
                </tr>
                <tr>
                    <td><a id="help_for_frps_log_days" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Days kept') }}</td>
                    <td><input type="text" class="form-control" id="frps_log_maxdays" style="width:160px" autocomplete="off" placeholder="3">
                        <div class="hidden" data-for="help_for_frps_log_days">
                            {{ lang._('Only applies when the destination above is a file of the daemon\'s own. With console output the rc script owns /var/log/frps.log, this setting does nothing, and nothing rotates that file: the package ships no newsyslog entry for it.') }}
                        </div>
                    </td>
                </tr>
                <tr><td></td><td>
                    <button type="button" class="btn btn-primary frp-save">{{ lang._('Save and apply') }}</button>
                    <button type="button" class="btn btn-default frp-verify">{{ lang._('Verify only') }}</button>
                    <div class="text-muted" style="margin-top:6px">
                        {{ lang._('Saving rewrites /usr/local/etc/frp/frps.toml and keeps every setting this page does not show. A running server keeps its old configuration until it is restarted.') }}
                    </div>
                </td></tr>
            </tbody>
        </table>
        </form>
    </div>

    <div id="advanced" class="tab-pane fade in">
        <form id="frmadvanced">
        <table class="table table-striped opnsense_standard_table_form">
            <thead>
                <tr><td style="width:22%"><strong>{{ lang._('frps.toml') }}</strong></td>
                    <td style="width:78%; text-align:right">
                        <small>{{ lang._('full help') }} </small>
                        <i class="fa fa-toggle-off text-danger" style="cursor:pointer" id="show_all_help_advanced"></i>
                        &nbsp;&nbsp;
                    </td></tr>
            </thead>
            <tbody>
                <tr><td colspan="2">
                    <div class="alert alert-warning">
                        {{ lang._('frps parses its file with strict_config on. One unknown or misspelled key is not a warning: the daemon exits and the service stays down. Verify before saving, and expect to restart the daemon to find out what it makes of the result.') }}
                    </div>
                </td></tr>
                <tr>
                    <td><a id="help_for_frps_document" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Server configuration') }}
                        <div class="text-muted"><small id="frp-path"></small></div></td>
                    <td>
                        <textarea id="frp-document" rows="18"
                                  class="form-control frp-document" spellcheck="false"></textarea>
                        <div class="text-muted" id="frp-editing" style="display:none;margin-top:4px">
                            {{ lang._('This editor has unsaved changes, so it is no longer being refreshed. Reload to discard them.') }}
                        </div>
                        <div style="margin-top:8px">
                            <button type="button" class="btn btn-primary frp-document-save">{{ lang._('Save and apply') }}</button>
                            <button type="button" class="btn btn-default frp-document-verify">{{ lang._('Verify only') }}</button>
                            <button type="button" class="btn btn-default frp-document-reload">{{ lang._('Reload') }}</button>
                        </div>
                        <div class="hidden" data-for="help_for_frps_document">
                            {{ lang._('The whole document, as the plugin stores it. Saving from either tab rewrites the file from its settings, so comments are not kept and keys are written with dots rather than in [table] blocks; both spellings mean the same thing to frp. A credential reads __KEEP__ because its value is never sent to a browser: leave the placeholder where it is and the stored value is kept, and moving it to another key is refused rather than guessed at. Deleting the line is how a stored credential is removed, since an empty box on the Settings tab keeps what is there.') }}
                        </div>
                    </td>
                </tr>
            </tbody>
        </table>
        </form>
    </div>

    <div id="log" class="tab-pane fade in">
        <form id="frmlog">
        <table class="table table-striped opnsense_standard_table_form">
            <thead>
                <tr><td style="width:22%"><strong>{{ lang._('Server log') }}</strong></td>
                    <td style="width:78%; text-align:right">
                        <small>{{ lang._('full help') }} </small>
                        <i class="fa fa-toggle-off text-danger" style="cursor:pointer" id="show_all_help_log"></i>
                        &nbsp;&nbsp;
                    </td></tr>
            </thead>
            <tbody>
                <tr>
                    <td><a id="help_for_logs" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('/var/log/frps.log') }}</td>
                    <td>
                        <pre id="frp-log" class="frp-log"></pre>
                        <button type="button" class="btn btn-default" id="frp-log-refresh">
                            <i class="fa fa-refresh"></i> {{ lang._('Refresh the log') }}</button>
                        <div class="hidden" data-for="help_for_logs">
                            {{ lang._('The tail of the daemon\'s output. A configuration the daemon rejects shows up here as the reason it exited, which is the fastest way to find a key strict parsing refused. While this tab is open the tail is read again every ten seconds.') }}
                        </div>
                    </td>
                </tr>
            </tbody>
        </table>
        </form>
    </div>

</div>
