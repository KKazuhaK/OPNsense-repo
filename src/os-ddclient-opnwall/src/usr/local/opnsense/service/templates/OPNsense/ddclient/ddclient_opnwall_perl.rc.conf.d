{% if not helpers.empty('OPNsense.DynDNS.general.enabled') and OPNsense.DynDNS.general.backend == 'ddclient' %}
ddclient_opnwall_perl_enable="YES"
ddclient_opnwall_perl_setup="/usr/local/opnsense/scripts/ddclient/setup.sh"
ddclient_opnwall_perl_delay="{{ OPNsense.DynDNS.general.daemon_delay|default('300') }}"
{% else %}
ddclient_opnwall_perl_enable="NO"
{% endif %}
