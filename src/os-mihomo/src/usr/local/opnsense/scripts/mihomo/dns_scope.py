#!/usr/local/bin/python3
"""Decide which clients Mihomo answers when they ask the router for DNS.

The manager and the routing adapter both act on this decision: the manager
writes the Unbound forward zone for every client, and the adapter redirects
router-bound DNS from captured sources. They must never disagree about it.
"""
import ipaddress
import re

# Where the full preset has Mihomo DNS listen, and so where both the forward
# zone and the redirect send queries.
DNS_LISTEN = '127.0.0.1:1053'
DNS_PORT = 1053
DNS_SCOPES = ('all', 'captured', 'off')
# An upgrade keeps answering every client, as every earlier release did; only a
# fresh installation starts with the narrower scope.
DNS_SCOPE_DEFAULT = 'all'
DNS_SCOPE_FRESH = 'captured'

ROUTER_DNS_NOTE = ('Router DNS is selected, so answering every device through Mihomo would loop back to '
                   'the router DNS; that choice is treated as off.')
IPV6_NOTE = ('"Only devices captured by transparent routing" is running as "All devices": this router '
             'is giving devices on a captured interface IPv6 addresses while Mihomo IPv6 is off, so '
             'captured devices asking the router DNS would get IPv6 answers and leave the tunnel over IPv6. '
             'It switches back on its own once they no longer get IPv6 addresses, or when Mihomo IPv6 is '
             'turned on.')
# Every device cannot be answered while Unbound validates DNSSEC, so a captured
# scope stays as it is rather than falling back to nobody.
IPV6_DNSSEC_NOTE = ('This router is giving devices on a captured interface IPv6 addresses while Mihomo IPv6 '
                    'is off. Answering every device instead is not possible while Unbound validates DNSSEC, '
                    'so captured devices asking the router DNS over IPv6 get IPv6 answers and can leave the '
                    'tunnel over IPv6.')
IPV6_ROUTER_DNS_NOTE = ('Captured devices may be getting IPv6 addresses while Mihomo IPv6 is off, and with '
                        'router DNS selected Mihomo cannot answer every device instead, so the router DNS '
                        'answers captured devices too.')
PRESET_NOTE = ('Mihomo DNS does not listen on %s in the generated configuration, so the router DNS '
               'is left alone.' % DNS_LISTEN)
# The administrator's declaration that this router gives IPv6 only to devices
# transparent routing does not capture (ipv6_clients_restricted): an offer
# router DNS would refuse and a captured scope would fall back over is shown
# instead, and every device answered without IPv6 undoes what it is for.
IPV6_RESTRICTED_NOTE = ('This router offers devices IPv6 while Mihomo IPv6 is off. That is allowed because '
                        '"IPv6 only for uncaptured devices" declares that captured devices get no IPv6; the '
                        'plugin does not check it.')
IPV6_RESTRICTED_ALL_NOTE = ('"IPv6 only for uncaptured devices" is on, but Mihomo answers every device without '
                            'IPv6 answers, so the devices given IPv6 get no AAAA records from the router DNS '
                            'either. Choose "Only devices captured by transparent routing" or "No devices", or '
                            'turn on router DNS.')

# Only an address a device can use on the Internet counts: global unicast
# 2000::/3, less the documentation, 6to4, Teredo and other special ranges
# ipaddress does not call global. Link-local and unique local addresses never do.
GLOBAL_UNICAST = ipaddress.ip_network('2000::/3')
IFCONFIG_HEADER = re.compile(r'([A-Za-z][A-Za-z0-9_.:-]{0,63}):\s')
IFCONFIG_INET6 = re.compile(r'\s+inet6\s+([0-9A-Fa-f:.]+)(?:%\S+)?\s')
# The watchdog looks at the interfaces this often while the answer holds, and
# every tick while a new answer waits for its confirmation.
IPV6_POLL = 30.0
IPV6_CONFIRM = 2
# At most one scope change this often, except towards answering every device,
# which is the safe answer and follows as soon as it is confirmed.
SCOPE_CHANGE_INTERVAL = 600.0
# How long a change that failed towards every device waits before it is tried
# again, doubling with each failure in a row up to SCOPE_RETRY_MAX; one towards
# captured devices waits at least SCOPE_CHANGE_INTERVAL.
SCOPE_RETRY = 60.0
SCOPE_RETRY_MAX = 3600.0


def ipv6_restricted(settings):
    """Whether the administrator declared that captured devices get no IPv6 from this router.

    The setting ipv6_clients_restricted, off unless stored as true. It is a
    promise the plugin takes at its word and never checks.
    """
    return settings.get('ipv6_clients_restricted') is True


def carries_ipv6(generated):
    """Whether a generated configuration has Mihomo carry IPv6 and answer AAAA."""
    dns = generated.get('dns') if isinstance(generated.get('dns'), dict) else {}
    return generated.get('ipv6') is True and dns.get('ipv6') is True


def effective_dns_scope(settings, generated, ipv6_reaching=False):
    """Return the scope actually in force, and why when it differs from the chosen one.

    Only the full preset's shape answers anybody: the TUN on and Mihomo DNS
    listening where the zone and the redirect send queries. With router DNS
    Mihomo asks Unbound, so Unbound forwarding everything back would loop, and
    'all' counts as 'off' without the stored choice changing. A captured scope
    whose devices are given IPv6 that Mihomo does not carry falls back to
    'all', which keeps AAAA records from every client as before, rather than
    refusing transparent routing; with router DNS that fallback is 'off' too.
    Whether IPv6 reaches them is the manager's reach answer: offered by this
    router, held as a global address by an interface transparent routing
    captures, and not while Unbound validates DNSSEC, which declines 'all'.
    An administrator who declared that captured devices get no IPv6
    (ipv6_restricted()) has no fallback, whatever an answer says.
    """
    tun = generated.get('tun') if isinstance(generated.get('tun'), dict) else {}
    dns = generated.get('dns') if isinstance(generated.get('dns'), dict) else {}
    chosen = settings.get('dns_scope', DNS_SCOPE_DEFAULT)
    if not (tun.get('enable') and dns.get('enable') and dns.get('listen') == DNS_LISTEN):
        return 'off', PRESET_NOTE if tun.get('enable') and chosen != 'off' else ''
    scope, note = chosen, ''
    if (scope == 'captured' and ipv6_reaching and not ipv6_restricted(settings)
            and not carries_ipv6(generated)):
        scope, note = 'all', IPV6_NOTE
    if scope == 'all' and settings.get('router_dns'):
        # Router DNS refuses to start while IPv6 is offered, and a declared
        # offer never falls back above, so only an offer nobody could read
        # ends here: the IPv6 reason is the one to give.
        return 'off', IPV6_ROUTER_DNS_NOTE if note else ROUTER_DNS_NOTE
    return scope, note


def ipv6_matters(settings, generated):
    """Whether IPv6 reaching captured devices changes the scope of this configuration.

    Router DNS answers an IPv6 offer on its own terms instead: an error, or
    a note while the administrator declares that captured devices get no
    IPv6, which leaves a captured scope nothing to change either.
    """
    return (not settings.get('router_dns')
            and effective_dns_scope(settings, generated, True)[0]
            != effective_dns_scope(settings, generated, False)[0])


def global_ipv6(value):
    """Whether an address is global unicast IPv6 that a device can reach the Internet with."""
    try:
        address = ipaddress.ip_address(value.split('%', 1)[0])
    except (AttributeError, ValueError):
        return False
    return address.version == 6 and address in GLOBAL_UNICAST and address.is_global


def interface_ipv6(text):
    """Each interface's IPv6 addresses, read from ifconfig -a output."""
    found, device = {}, None
    for line in text.splitlines():
        header = IFCONFIG_HEADER.match(line)
        if header:
            device = header.group(1)
            found.setdefault(device, [])
            continue
        address = IFCONFIG_INET6.match(line)
        if address and device is not None:
            found[device].append(address.group(1))
    return found


def reach_verdict(current, observed, confirmed, now, changed, retry_at=None):
    """Whether a new answer about IPv6 reaching captured devices changes the scope now.

    current is the answer the running scope was decided with, observed this
    look's answer, and confirmed how many looks in a row before this one gave
    it. changed is when the scope last changed and retry_at when a failed
    change may be tried again, both on the monotonic clock; None, or a time
    ahead of now, holds nothing back. A time from before a reboot that is not
    ahead of the new clock still counts, so for at most SCOPE_CHANGE_INTERVAL
    after boot it can keep every device answered, the safe side. Returns the
    new count and one of 'stay', 'confirm' (look again next tick), 'hold'
    (confirmed, but held back) or 'move'.
    """
    if observed == current:
        return 0, 'stay'
    count = confirmed + 1
    if count < IPV6_CONFIRM:
        return count, 'confirm'
    if retry_at is not None and now < retry_at:
        return count, 'hold'
    # Towards reaching is towards every device, the safer scope.
    if not observed and changed is not None and changed <= now < changed + SCOPE_CHANGE_INTERVAL:
        return count, 'hold'
    return count, 'move'


def retry_delay(failures, reaching):
    """How long a scope change waits after failing failures times in a row.

    Towards every device, the safe answer, it starts at SCOPE_RETRY; back to
    captured devices it is never sooner than SCOPE_CHANGE_INTERVAL. Either way
    it doubles with each failure up to SCOPE_RETRY_MAX, so a change that keeps
    failing does not keep restarting the service.
    """
    delay = min(SCOPE_RETRY_MAX, SCOPE_RETRY * 2 ** min(max(failures, 1) - 1, 16))
    return delay if reaching else max(delay, SCOPE_CHANGE_INTERVAL)
