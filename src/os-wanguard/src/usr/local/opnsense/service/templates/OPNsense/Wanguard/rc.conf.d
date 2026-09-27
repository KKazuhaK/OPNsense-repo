{% if helpers.exists('OPNsense.wanguard.general.enabled') and OPNsense.wanguard.general.enabled == '1' %}
wanguard_enable="YES"
{% else %}
wanguard_enable="NO"
{% endif %}
