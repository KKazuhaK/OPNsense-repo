#!/usr/local/bin/python3
"""Ask a DNS listener one question, and judge whether captured devices may use Mihomo DNS.

The redirect that sends captured devices' router-bound DNS to Mihomo must be
withdrawn when Mihomo cannot answer, and must never be withdrawn because the
rest of the Internet cannot. A wrong verdict may only ever cost captured
devices a temporary return to the router DNS. The manager runs the probes and
keeps the verdict in a private file; the routing adapter arms the redirect only
for a fresh, healthy verdict about the core that is running now. Standard
library only, because both import it.
"""
import ipaddress
import re
import secrets
import socket
import struct
import time


MIHOMO = ('127.0.0.1', 1053)
ROUTER = ('127.0.0.1', 53)
# Where the manager keeps the verdict for the routing adapter: runtime state,
# rewritten every watchdog tick and about one core's lifetime, which a reboot
# clears.
HEALTH_FILE = '/var/run/mihomo-dns-health.json'
NOERROR, SERVFAIL, NXDOMAIN = 0, 2, 3

# Mihomo answers this from its built-in hosts without asking any upstream, so
# a reply proves the listener works whatever the WAN does.
LIVENESS_NAME = 'localhost'
LIVENESS_TIMEOUT = 1.0
WITHDRAW_AFTER = 2
REARM_AFTER = 3
# An armed core's first unanswered liveness query is asked again this long
# after it, in the same tick, rather than a whole watchdog tick later: on a
# busy router a tick lasts well beyond its five-second sleep, and captured
# devices wait on a stalled core all that time.
CONFIRM_PAUSE = 1.0
# Random labels under zones of three different operators: one operator's
# authoritative outage fails the router DNS too and so is never mistaken for
# Mihomo's. Withdrawing needs Mihomo failing where the router DNS succeeds on
# at least two of them, within the rounds since Mihomo last succeeded.
UPSTREAM_DOMAINS = ('example.com', 'cloudflare.com', 'microsoft.com')
UPSTREAM_QUORUM = 2
UPSTREAM_ROUNDS = 3
UPSTREAM_TIMEOUT = 3.0
UPSTREAM_INTERVAL = 60.0
# The watchdog probes about every five seconds; a verdict older than this is
# from a watchdog that stopped, and arms nothing.
HEALTH_FRESH = 15.0
START_BUDGET = 3.0
# Captured sources active this long with no DNS reaching the redirect suggest
# a rule on their interface intercepts it.
HINT_AFTER = 300.0
ACTIVITY_INTERVAL = 60.0
HEALTH_VERSION = 1
REASONS = ('', 'starting', 'liveness', 'upstream')
VERDICTS = ('ok', 'fail', 'other')
BIRTH = re.compile(r'[1-9][0-9]*:[0-9]{1,6}')


class ProbeError(Exception):
    """No valid reply arrived in time: a timeout, a refused port or a malformed answer."""


def encode_name(name):
    labels = name.rstrip('.').split('.')
    if not name or any(not label or len(label) > 63 or not label.isascii() for label in labels):
        raise ValueError('The DNS probe name is invalid.')
    encoded = b''.join(bytes([len(label)]) + label.encode('ascii') for label in labels) + b'\x00'
    if len(encoded) > 255:
        raise ValueError('The DNS probe name is too long.')
    return encoded


def build_query(name, qtype=1):
    """A recursive query for one name, with a random identifier."""
    header = struct.pack('!HHHHHH', secrets.randbits(16), 0x0100, 1, 0, 0, 0)
    return header + encode_name(name) + struct.pack('!HH', qtype, 1)


def answer_rcode(response, query):
    """The response code of the reply to this query, or None when it answers something else.

    The identifier must match and the reply bit be set; a question section,
    when the server echoes one, must be this question.
    """
    if len(response) < 12 or response[:2] != query[:2] or not response[2] & 0x80:
        return None
    count = struct.unpack('!H', response[4:6])[0]
    question = query[12:]
    if count and response[12:12 + len(question)].lower() != question.lower():
        return None
    return response[3] & 0x0F


def query(host, port, name, transport='udp', timeout=LIVENESS_TIMEOUT, qtype=1):
    """Return the response code a listener gives for name, within timeout seconds in total.

    Over UDP a datagram answering another question is ignored until the
    deadline; over TCP the one reply must be the answer.
    """
    if transport not in ('udp', 'tcp'):
        raise ValueError('The DNS probe transport is invalid.')
    packet = build_query(name, qtype)
    deadline = time.monotonic() + timeout
    try:
        if transport == 'udp':
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.connect((host, port))
                client.send(packet)
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise ProbeError('The DNS listener did not answer in time.')
                    client.settimeout(remaining)
                    rcode = answer_rcode(client.recv(4096), packet)
                    if rcode is not None:
                        return rcode
        with socket.create_connection((host, port), timeout=timeout) as client:
            def receive(size):
                data = b''
                while len(data) < size:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise ProbeError('The DNS listener did not answer in time.')
                    client.settimeout(remaining)
                    part = client.recv(size - len(data))
                    if not part:
                        raise ProbeError('The DNS listener closed the connection.')
                    data += part
                return data

            client.settimeout(max(deadline - time.monotonic(), 0.001))
            client.sendall(struct.pack('!H', len(packet)) + packet)
            rcode = answer_rcode(receive(struct.unpack('!H', receive(2))[0]), packet)
            if rcode is None:
                raise ProbeError('The DNS listener answered another question.')
            return rcode
    except OSError:
        raise ProbeError('The DNS listener did not answer.') from None


def verdict(ask, server, name, timeout):
    """'ok' for NOERROR or NXDOMAIN, 'fail' for SERVFAIL or no answer, 'other' for anything else.

    A random label rightly does not exist, so NXDOMAIN is an answer; an empty
    NOERROR is what some zones return for it instead.
    """
    try:
        rcode = ask(server, name, timeout)
    except ProbeError:
        return 'fail'
    return 'ok' if rcode in (NOERROR, NXDOMAIN) else 'fail' if rcode == SERVFAIL else 'other'


def core_identity(child):
    """The fields of the core's recorded child identity that name one process lifetime."""
    if (not isinstance(child, dict) or type(child.get('pid')) is not int
            or not isinstance(child.get('birth'), str) or not BIRTH.fullmatch(child['birth'])):
        return None
    return {'pid': child['pid'], 'birth': child['birth']}


def fresh(identity, now):
    """What is known about a core nobody has probed yet: nothing, so it is not trusted."""
    return {'version': HEALTH_VERSION, 'core': identity, 'healthy': False, 'reason': 'starting',
            'passes': 0, 'failures': 0, 'rounds': [], 'upstream': '', 'domain': 0,
            'next_upstream': now, 'checked': now,
            'armed_since': None, 'dns_seen': None, 'next_activity': None, 'hint': False}


def valid(record):
    number = (int, float)
    return bool(
        isinstance(record, dict) and record.get('version') == HEALTH_VERSION
        and (record.get('core') is None or core_identity(record.get('core')) == record.get('core'))
        and type(record.get('healthy')) is bool and record.get('reason') in REASONS
        and all(type(record.get(key)) is int and record[key] >= 0 for key in ('passes', 'failures', 'domain'))
        and isinstance(record.get('rounds'), list) and len(record['rounds']) <= UPSTREAM_ROUNDS
        and all(isinstance(item, dict) and item.get('domain') in UPSTREAM_DOMAINS
                and item.get('mihomo') in VERDICTS and item.get('router') in VERDICTS + (None,)
                for item in record['rounds'])
        and record.get('upstream') in VERDICTS + ('',)
        and all(isinstance(record.get(key), number) and not isinstance(record.get(key), bool)
                for key in ('next_upstream', 'checked'))
        and all(record.get(key) is None or (isinstance(record.get(key), number)
                                            and not isinstance(record.get(key), bool))
                for key in ('armed_since', 'dns_seen', 'next_activity'))
        # Armed or not, all three are known together.
        and len({record.get(key) is None for key in ('armed_since', 'dns_seen', 'next_activity')}) == 1
        and type(record.get('hint')) is bool)


def redirect_allowed(record, identity, now):
    """Whether this verdict lets the redirect be armed for the core running now."""
    if identity is None or not valid(record) or record['core'] != identity or not record['healthy']:
        return False
    return 0 <= now - record['checked'] <= HEALTH_FRESH


def evidence(record):
    """Probe zones where Mihomo failed and the router DNS answered, since Mihomo last succeeded."""
    return {item['domain'] for item in record['rounds']
            if item['mihomo'] == 'fail' and item['router'] == 'ok'}


def alive(ask, timeout=LIVENESS_TIMEOUT):
    return verdict(ask, MIHOMO, LIVENESS_NAME, timeout) == 'ok'


def upstream_round(record, ask, label):
    """Ask Mihomo one random name, and the router DNS the same name only when Mihomo fails."""
    domain = UPSTREAM_DOMAINS[record['domain'] % len(UPSTREAM_DOMAINS)]
    record['domain'] = (record['domain'] + 1) % len(UPSTREAM_DOMAINS)
    name = label() + '.' + domain
    mihomo = verdict(ask, MIHOMO, name, UPSTREAM_TIMEOUT)
    router = verdict(ask, ROUTER, name, UPSTREAM_TIMEOUT) if mihomo == 'fail' else None
    record['upstream'] = mihomo
    if mihomo == 'ok':
        record['rounds'] = []
    else:
        record['rounds'] = (record['rounds'] + [
            {'domain': domain, 'mihomo': mihomo, 'router': router}])[-UPSTREAM_ROUNDS:]
    return mihomo


def random_label():
    # A plain random label: the probe names nothing about this router.
    return secrets.token_hex(8)


def arm(record):
    record.update(healthy=True, reason='')


def tick(record, identity, clock, ask, label=random_label, sleep=time.sleep):
    """One watchdog probe: a liveness query every time, an upstream round about once a minute.

    Withdraw after two liveness failures in a row, or when the upstream rounds
    since Mihomo last succeeded show it failing while the router DNS answers on
    two probe zones. When both fail -- the WAN is down, or one zone's servers
    are -- nothing changes. An armed core's first failure is confirmed or
    cleared by a second query CONFIRM_PAUSE later in the same tick, which then
    skips its upstream round, so a stalled core is withdrawn within one tick
    of the stall and no tick probes for longer than an upstream round. Re-arm
    after three liveness passes in a row, or, after an upstream withdrawal,
    once Mihomo resolves a probe name again. A new core starts untrusted and
    is armed at its first pass.
    """
    now = clock()
    if not valid(record) or record['core'] != identity:
        record = fresh(identity, now)
    record = dict(record, rounds=list(record['rounds']))
    passed = alive(ask)
    rechecked = not passed and record['healthy'] and record['failures'] < WITHDRAW_AFTER - 1
    if rechecked:
        record.update(passes=0, failures=record['failures'] + 1)
        sleep(CONFIRM_PAUSE)
        passed = alive(ask)
    recovered = passed and record['failures'] > 0 and not record['healthy']
    if passed:
        record.update(passes=record['passes'] + 1, failures=0)
    else:
        record.update(passes=0, failures=record['failures'] + 1)
    upstream = None
    # A listener that has just come back is checked upstream at once too, so
    # it is not re-armed only to be withdrawn a minute later.
    if passed and not rechecked and (now >= record['next_upstream'] or recovered):
        upstream = upstream_round(record, ask, label)
        record['next_upstream'] = clock() + UPSTREAM_INTERVAL
    failing = len(evidence(record)) >= UPSTREAM_QUORUM
    if record['healthy']:
        if record['failures'] >= WITHDRAW_AFTER:
            record.update(healthy=False, reason='liveness')
        elif failing:
            record.update(healthy=False, reason='upstream')
    elif record['failures'] >= WITHDRAW_AFTER:
        record['reason'] = 'liveness'
    elif record['reason'] in ('starting', 'liveness'):
        if record['passes'] >= (1 if record['reason'] == 'starting' else REARM_AFTER):
            if failing:
                record['reason'] = 'upstream'
            else:
                arm(record)
    elif record['reason'] == 'upstream' and upstream == 'ok' and record['passes']:
        arm(record)
    record['checked'] = clock()
    return record


def start(identity, clock, ask, sleep, budget=START_BUDGET):
    """Probe a core that has just started, for at most budget seconds.

    A pass lets the first routing enable arm the redirect; otherwise the core
    is left untrusted for the watchdog, whose first pass arms it.
    """
    record = fresh(identity, clock())
    deadline = record['checked'] + budget
    while True:
        remaining = deadline - clock()
        if remaining <= 0:
            break
        if alive(ask, min(LIVENESS_TIMEOUT, remaining)):
            record['passes'] = 1
            arm(record)
            break
        sleep(min(0.2, max(deadline - clock(), 0)))
    record['checked'] = clock()
    return record


def observe_arming(record, armed, now):
    """Remember since when the redirect is armed, which the rule hint measures from."""
    record = dict(record)
    if not armed:
        record.update(armed_since=None, dns_seen=None, next_activity=None, hint=False)
    elif record['armed_since'] is None:
        record.update(armed_since=now, dns_seen=now, next_activity=now + ACTIVITY_INTERVAL, hint=False)
    return record


def activity_due(record, now):
    return record['armed_since'] is not None and now >= record['next_activity']


def observe_activity(record, activity, now):
    """Fold one look at the state table into the rule hint.

    activity is (translated, active): whether any query reached the redirect,
    and whether captured sources had any other state. The hint stands while
    captured sources stay active and none of their DNS has reached the redirect
    for HINT_AFTER seconds; it is a hint only and withdraws nothing.
    """
    record = dict(record, next_activity=now + ACTIVITY_INTERVAL)
    if activity is None:
        return record
    translated, active = activity
    if translated:
        record['dns_seen'] = now
    record['hint'] = bool(active and not translated and now - record['dns_seen'] >= HINT_AFTER)
    return record


STATE_LINE = re.compile(r'(?m)^\S+\s+(?:tcp|udp)\s+(\S+)\s+(?:\((\S+)\)\s+)?(<-|->)\s+(\S+)\s')


def redirect_activity(states, sources, port):
    """Whether pfctl -ss shows DNS translated to the core's port, and captured sources otherwise active.

    Only inbound states count as a source's own: their address follows the
    left arrow. States translated to the core's loopback DNS port are the
    redirect's own evidence and not activity.
    """
    translated, active = False, False
    seen = set()
    for found in STATE_LINE.finditer(states):
        target, original, arrow, peer = found.groups()
        if original is not None and target == '127.0.0.1:%d' % port and arrow == '<-':
            translated = True
            continue
        if arrow != '<-' or active:
            continue
        address = peer.rsplit(':', 1)[0]
        if address in seen:
            continue
        seen.add(address)
        try:
            value = ipaddress.ip_address(address)
        except ValueError:
            continue
        active = any(value in network for network in sources)
        if translated and active:
            break
    return translated, active
