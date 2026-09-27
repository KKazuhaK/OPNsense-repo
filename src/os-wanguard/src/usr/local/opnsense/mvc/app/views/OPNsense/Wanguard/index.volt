<div class="content-box">
    {{ partial("layout_partials/base_form", ['fields': generalForm, 'id': 'frm_general_settings']) }}
</div>

{{ partial('layout_partials/base_apply_button', {'data_endpoint': '/api/wanguard/service/reconfigure', 'data_service_widget': 'wanguard'}) }}

<div class="content-box __mt">
    <div id="wanguard_notice" class="alert alert-info hidden" role="alert"></div>
    <div class="table-responsive">
        <table class="table table-striped table-condensed" id="wanguard_status">
            <thead>
                <tr>
                    <th>{{ lang._('Interface') }}</th>
                    <th>{{ lang._('Address') }}</th>
                    <th>{{ lang._('State') }}</th>
                    <th>{{ lang._('Attempts') }}</th>
                    <th>{{ lang._('Last action') }}</th>
                    <th>{{ lang._('Next retry') }}</th>
                    <th></th>
                </tr>
            </thead>
            <tbody id="wanguard_rows">
                <tr><td colspan="7">{{ lang._('Loading...') }}</td></tr>
            </tbody>
        </table>
    </div>
</div>

<script>
$(function () {
    const labels = {
        disabled: "{{ lang._('Disabled') }}",
        stopped: "{{ lang._('Service stopped') }}",
        booting: "{{ lang._('Waiting for boot to finish') }}",
        ignored: "{{ lang._('Ignored: not an enabled DHCP interface') }}",
        no_address: "{{ lang._('No IPv4 address') }}",
        ok: "{{ lang._('OK') }}",
        confirming: "{{ lang._('Unwanted, confirming') }}",
        backoff: "{{ lang._('Unwanted, waiting to retry') }}",
        rate_limited: "{{ lang._('Unwanted, hourly limit reached') }}",
        no_carrier: "{{ lang._('Unwanted, no carrier') }}",
        no_client: "{{ lang._('Unwanted, no DHCP client') }}"
    };
    const classes = {
        ok: 'label-success', confirming: 'label-warning', backoff: 'label-warning',
        rate_limited: 'label-danger', no_carrier: 'label-danger', no_client: 'label-danger'
    };
    let timer = null;

    function when(epoch) {
        return epoch ? new Date(epoch * 1000).toLocaleString() : '';
    }

    function text(value) {
        return $('<span/>').text(htmlDecode(value === null || value === undefined ? '' : String(value)));
    }

    function render(data) {
        const rows = $('#wanguard_rows').empty();
        const notice = $('#wanguard_notice').addClass('hidden').empty();
        if (!data || data.status !== 'ok') {
            notice.removeClass('hidden').text(htmlDecode((data && data.message) || "{{ lang._('The status is unavailable.') }}"));
            return;
        }
        if (data.enabled && data.rules && data.rules.empty) {
            notice.removeClass('hidden').text("{{ lang._('Nothing is considered unwanted: add a network or enable private ranges.') }}");
        }
        if (!data.interfaces.length) {
            rows.append($('<tr/>').append($('<td colspan="7"/>').text("{{ lang._('No interface is watched.') }}")));
            return;
        }
        data.interfaces.forEach(function (row) {
            const state = $('<span class="label label-opnsense"/>').addClass(classes[row.state] || 'label-default')
                .text(labels[row.state] || row.state);
            const address = text(row.address || '');
            if (row.rule) {
                address.append(document.createTextNode(' (' + row.rule + ')'));
            }
            const last = $('<span/>');
            if (row.last_action) {
                last.append(text(when(row.last_action.at) + ', ' + row.last_action.trigger + ', ' +
                    row.last_action.result)).append('<br/>').append($('<small class="text-muted"/>')
                    .text(htmlDecode(row.last_action.reason || '')));
            }
            let next = '';
            if (row.next_retry_at) {
                next = row.next_retry_at * 1000 <= Date.now() ? "{{ lang._('at the next check') }}" : when(row.next_retry_at);
            }
            const retry = $('<button type="button" class="btn btn-xs btn-default wanguard-retry"/>')
                .attr('data-interface', row.name).prop('disabled', row.verdict !== 'unwanted' || !data.running)
                .text("{{ lang._('Retry now') }}");
            rows.append($('<tr/>')
                .append($('<td/>').append(text(row.descr + ' (' + row.name + ', ' + row.device + ')')))
                .append($('<td/>').append(address))
                .append($('<td/>').append(state))
                .append($('<td/>').text(row.attempts))
                .append($('<td/>').append(last))
                .append($('<td/>').text(next))
                .append($('<td/>').append(retry)));
        });
    }

    function refresh(delay) {
        clearTimeout(timer);
        timer = setTimeout(function () {
            ajaxGet('/api/wanguard/service/state', {}, function (data) {
                render(data);
                refresh(10000);
            });
        }, delay || 0);
    }

    $('#wanguard_rows').on('click', '.wanguard-retry', function () {
        const button = $(this).prop('disabled', true);
        ajaxCall('/api/wanguard/service/retry', {'interface': button.attr('data-interface')}, function (data) {
            BootstrapDialog.show({
                type: data.status === 'queued' ? BootstrapDialog.TYPE_INFO : BootstrapDialog.TYPE_WARNING,
                title: "{{ lang._('Retry now') }}",
                message: $('<div/>').text(htmlDecode(data.message || data.status || '')).html()
            });
            refresh(3000);
        });
    });

    mapDataToFormUI({'frm_general_settings': '/api/wanguard/settings/get'}).done(function () {
        formatTokenizersUI();
        $('.selectpicker').selectpicker('refresh');
        updateServiceControlUI('wanguard');
    });

    $('#reconfigureAct').SimpleActionButton({
        onPreAction: function () {
            const done = new $.Deferred();
            saveFormToEndpoint('/api/wanguard/settings/set', 'frm_general_settings', function () {
                done.resolve();
            }, false, function () {
                done.reject();
            });
            return done;
        },
        onAction: function () {
            refresh(1500);
        }
    });

    refresh(0);
});
</script>
