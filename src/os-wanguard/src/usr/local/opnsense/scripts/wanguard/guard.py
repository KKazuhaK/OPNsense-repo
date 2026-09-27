"""WAN Guard decisions: classify addresses, confirm them, back off and persist.

Nothing in this module touches the system. The daemon in wanguard.py feeds it
observations taken by helper.php and hands it an actor that re-requests DHCP;
the tests feed it fakes. Every rule that decides whether a WAN is touched lives
here, so it can be exercised without a router.
"""
import ipaddress
import json
import os
import re
import stat
import tempfile
import time

# Loop tick: the stop flag, wake and retry requests are checked this often.
POLL = 1
# Periodic observation; the timer restarts after every observation.
OBSERVE_INTERVAL = 30
# At most one wake-driven observation in this many seconds, so a burst of
# newwanip events costs one observation.
WAKE_GAP = 5
# Consecutive unwanted observations needed before an automatic action.
STREAK_NEEDED = 2
# An unwanted observation adds to the streak only this long after the previous
# counted one, so a wake followed by a tick cannot count twice within a second.
STREAK_GAP = 20
# ... and only while the previous counted one is at most this old. After a
# longer gap (a stopped service, an upgrade, failed observations) nothing is
# known about the time in between, so the confirmation starts over.
STREAK_WINDOW = 2 * OBSERVE_INTERVAL + WAKE_GAP
# Minimum delay after action 1, 2, 3 and 4 or later; the last value is the cap.
BACKOFF = (60, 120, 300, 900)
# Hard floor between any two actions on one interface, manual ones included.
MIN_ACTION_GAP = 60
# Hard cap per interface in any rolling hour. The schedule alone gives 7.
HOURLY_CAP = 8
HOUR = 3600
OBSERVE_TIMEOUT = 20
ACTION_TIMEOUT = 60
REPAIR_GAP = 300
CORRUPT_COOLDOWN = 300
WARN_REPEAT = 300

MAX_NETWORKS = 32
MIN_PREFIX = 8
STATE_MAX = 64 * 1024
SCHEMA = 1

# The exact ranges of core's is_private_ipv4() in util.inc; a native test keeps
# the two in step.
PRIVATE_RANGES = tuple(ipaddress.IPv4Network(network) for network in (
    '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16',
    '127.0.0.0/8', '100.64.0.0/10', '169.254.0.0/16'))

INTERFACE = re.compile(r'[a-z0-9_]{1,32}')
DEVICE = re.compile(r'[a-zA-Z][a-zA-Z0-9_.]{0,31}')

NONE = 'none'
WANTED = 'wanted'
UNWANTED = 'unwanted'

# Refusal codes a manual retry can end with, and how the log words them.
REFUSALS = {
    'disabled': 'the plugin is disabled',
    'stopped': 'the service is not running',
    'stopping': 'the service is stopping',
    'not-watched': 'the interface is not watched',
    'not-eligible': 'the interface is the LAN or not an enabled DHCP interface',
    'booting': 'the system is still booting',
    'no-carrier': 'the interface has no carrier',
    'no-client': 'no IPv4 DHCP client is running on the interface',
    'wanted': 'the address is wanted',
    'no-address': 'the interface has no IPv4 address',
    'too-soon': 'the previous action was less than %d s ago' % MIN_ACTION_GAP,
    'hourly-cap': 'the interface reached %d actions in the last hour' % HOURLY_CAP,
    'unavailable': 'the interfaces could not be observed',
    'repairing': 'the DHCP client stopped by the last action is being repaired',
}


class ObserveError(Exception):
    """An observation that cannot be trusted; the cycle is skipped."""


def _is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def _is_number(value):
    return (_is_int(value) or isinstance(value, float)) and value == value


def parse_networks(values):
    """Return the usable networks and the entries that were dropped.

    The model already validates these; this is the defence in depth for a
    hand-edited config.xml: IPv4 only, network notation with a mask, no host
    bits, nothing wider than /8 and at most MAX_NETWORKS entries.
    """
    if isinstance(values, str):
        values = values.split(',')
    if not isinstance(values, (list, tuple)):
        return [], []
    networks, dropped = [], []
    for value in values:
        if not isinstance(value, str):
            dropped.append(repr(value))
            continue
        text = value.strip()
        if not text:
            continue
        try:
            network = ipaddress.IPv4Network(text, strict=True)
        except ValueError:
            dropped.append(text)
            continue
        if '/' not in text or network.prefixlen < MIN_PREFIX or len(networks) >= MAX_NETWORKS:
            dropped.append(text)
            continue
        if network not in networks:
            networks.append(network)
    return networks, dropped


class Rules:
    """What makes an address unwanted: listed networks, optionally private ranges."""

    def __init__(self, networks=(), private_ranges=False):
        self.networks = list(networks)
        self.private_ranges = private_ranges is True

    def empty(self):
        return not self.networks and not self.private_ranges

    def classify(self, address):
        """Return (verdict, rule); rule is the matching network for logging."""
        if not isinstance(address, str) or not address:
            return NONE, None
        try:
            parsed = ipaddress.IPv4Address(address)
        except ValueError:
            return NONE, None
        if int(parsed) == 0:
            return NONE, None
        for network in self.networks:
            if parsed in network:
                return UNWANTED, str(network)
        if self.private_ranges:
            for network in PRIVATE_RANGES:
                if parsed in network:
                    return UNWANTED, str(network)
        return WANTED, None


def parse_snapshot(data):
    """Validate what helper.php observe printed. Anything odd is an ObserveError.

    Unknown data must never count as unwanted, so a malformed answer does not
    produce a partial snapshot: the whole cycle is skipped instead.
    """
    if not isinstance(data, dict):
        raise ObserveError('the observation is not an object')
    for key in ('enabled', 'booting', 'private_ranges'):
        if not isinstance(data.get(key), bool):
            raise ObserveError('the observation has no valid %s flag' % key)
    watched = data.get('watched')
    networks = data.get('networks')
    rows = data.get('interfaces')
    if not isinstance(watched, list) or not all(isinstance(name, str) for name in watched):
        raise ObserveError('the observation has no valid interface list')
    if not isinstance(networks, list) or not all(isinstance(network, str) for network in networks):
        raise ObserveError('the observation has no valid network list')
    if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
        raise ObserveError('the observation has no valid interface details')
    interfaces = {}
    for row in rows:
        name = row.get('name')
        if not isinstance(name, str) or not INTERFACE.fullmatch(name):
            raise ObserveError('the observation names an invalid interface')
        address = row.get('address')
        if address is not None and not isinstance(address, str):
            raise ObserveError('the observation has an invalid address for ' + name)
        detail = {'name': name, 'address': address}
        for key in ('descr', 'device', 'ipaddr'):
            value = row.get(key, '')
            detail[key] = value if isinstance(value, str) else ''
        for key in ('exists', 'enabled', 'eligible', 'carrier', 'dhclient_running'):
            detail[key] = row.get(key) is True
        interfaces[name] = detail
    names = []
    for name in watched:
        if INTERFACE.fullmatch(name) and name not in names:
            names.append(name)
    return {'enabled': data['enabled'], 'booting': data['booting'], 'watched': names,
            'networks': list(networks), 'private_ranges': data['private_ranges'],
            'interfaces': interfaces}


def eligibility(info):
    """G2: return None when the interface may be acted on, else why not."""
    if not info or not info.get('exists'):
        return 'it does not exist'
    if info.get('name') == 'lan':
        # Re-requesting the management LAN's lease could lock the operator out.
        return 'it is the LAN'
    if not info.get('enabled'):
        return 'it is disabled'
    if info.get('ipaddr') != 'dhcp':
        return 'its IPv4 type is not DHCP'
    if not DEVICE.fullmatch(info.get('device') or ''):
        return 'its device name is invalid'
    if not info.get('eligible'):
        return 'the helper does not consider it a DHCP interface'
    return None


def new_tracker(device):
    return {'device': device, 'streak': 0, 'counted_at': None, 'stage': 0, 'next_retry': None,
            'actions': [], 'last_action': None, 'last_manual': None, 'last_observation': None,
            'repair_at': None, 'owned': False, 'repair_due': False}


def new_state(boot):
    # recent: the last hour's actions of interfaces whose record was dropped,
    # so a configuration change cannot reset the rate limits.
    return {'schema': SCHEMA, 'boot': boot, 'saved': None, 'cooldown_until': None, 'interfaces': {}, 'recent': {}}


def within_hour(moments, now):
    return [moment for moment in moments if now - moment < HOUR]


def backoff(stage):
    return BACKOFF[min(max(stage, 1), len(BACKOFF)) - 1]


class Guard:
    """The only place that decides; the daemon is the only caller.

    actor.redhcp(name, address, reason) and actor.restore(name) return result
    strings such as 'requested', 'busy', 'refused:<why>' or 'failed:<why>'.
    log(level, message) records one line; persist() saves the state before a
    helper runs, so a crash in the middle of an action cannot erase it.
    stopping() turns true once the daemon was asked to stop; from then on no
    helper call starts.
    """

    def __init__(self, state, actor, log, clock=time.monotonic, wall=time.time, persist=None, stopping=None):
        self.state = state
        self.actor = actor
        self.log = log
        self.clock = clock
        self.wall = wall
        self.persist = persist or (lambda: None)
        self.stopping = stopping or (lambda: False)
        self.warned = {}
        self.reported = set()

    def warn(self, key, message, now, level='warning'):
        """Log one line per key at most once every WARN_REPEAT seconds."""
        last = self.warned.get(key)
        if last is None or now - last >= WARN_REPEAT:
            self.warned[key] = now
            self.log(level, message)

    def rules(self, snapshot):
        networks, dropped = parse_networks(snapshot['networks'])
        for entry in dropped:
            if entry not in self.reported:
                self.reported.add(entry)
                self.log('warning', 'ignoring the unwanted network setting %s: it is not an IPv4 '
                         'network of /%d or longer, or the list is over %d entries'
                         % (entry, MIN_PREFIX, MAX_NETWORKS))
        return Rules(networks, snapshot['private_ranges'])

    def apply(self, snapshot, manual=()):
        """Take one observation; act at most once per interface."""
        now, wall = self.clock(), self.wall()
        manual = set(manual)
        interfaces = self.state['interfaces']
        if not snapshot['enabled']:
            # G1: a disabled plugin keeps its history but never acts.
            for name in sorted(manual):
                self.refuse(name, interfaces.get(name), 'disabled', wall)
            return
        rules = self.rules(snapshot)
        recent = self.state['recent']
        for name in list(recent):
            recent[name] = within_hour(recent[name], now)
            if not recent[name]:
                del recent[name]
        watched = snapshot['watched']
        for name in sorted(set(interfaces) - set(watched)):
            self.forget(name, now)
            self.log('notice', '%s is no longer watched; its state was dropped' % name)
        for name in sorted(manual - set(watched)):
            self.refuse(name, None, 'not-watched', wall)
        for name in watched:
            info = snapshot['interfaces'].get(name)
            why = eligibility(info)
            if why is not None:
                # G2: never act on anything but an enabled DHCP interface.
                if self.forget(name, now):
                    self.warned[('ignored', name)] = now
                    self.log('notice', '%s is ignored because %s; its state was dropped' % (name, why))
                else:
                    self.warn(('ignored', name), '%s is ignored because %s' % (name, why), now, 'notice')
                if name in manual:
                    self.refuse(name, None, 'not-eligible', wall)
                continue
            tracker = interfaces.get(name)
            if tracker is None or tracker['device'] != info['device']:
                tracker = self.fresh(name, info['device'], now)
            self.observe(name, tracker, info, rules, snapshot, name in manual, now, wall)

    def forget(self, name, now):
        """Drop an interface's record; its last hour of actions stays behind."""
        tracker = self.state['interfaces'].pop(name, None)
        if tracker is None:
            return False
        actions = within_hour(tracker['actions'], now)
        if actions:
            self.state['recent'][name] = actions
        return True

    def fresh(self, name, device, now):
        """Start a new record that still carries the interface's recent actions."""
        previous = self.state['interfaces'].get(name)
        carried = (previous['actions'] if previous else []) + self.state['recent'].pop(name, [])
        tracker = self.state['interfaces'][name] = new_tracker(device)
        tracker['actions'] = sorted(within_hour(carried, now))
        return tracker

    def observe(self, name, tracker, info, rules, snapshot, manual, now, wall):
        address = info['address']
        verdict, rule = rules.classify(address)
        seen = {'address': address, 'verdict': verdict, 'rule': rule}
        previous = tracker['last_observation'] or {}
        if any(previous.get(key) != value for key, value in seen.items()):
            tracker['last_observation'] = dict(seen, since=wall)
        if verdict == WANTED:
            if tracker['stage'] or tracker['streak']:
                self.log('notice', '%s now has wanted address %s; state reset after %d attempt(s)'
                         % (name, address, tracker['stage']))
                # Recent actions stay listed, so the hourly cap still holds.
                tracker.update(streak=0, counted_at=None, stage=0, next_retry=None)
        elif verdict == NONE:
            # The backoff survives a flapping link; only the streak restarts.
            tracker.update(streak=0, counted_at=None)
        else:
            if tracker['streak'] == 0 and tracker['stage'] == 0:
                self.log('notice', '%s has unwanted address %s (%s), confirming' % (name, address, rule))
            counted = tracker['counted_at']
            if counted is None or now - counted > STREAK_WINDOW:
                tracker.update(streak=1, counted_at=now)
            elif now - counted >= STREAK_GAP:
                tracker['streak'] += 1
                tracker['counted_at'] = now
        self.repair(name, tracker, info, snapshot, now)
        if tracker['repair_due']:
            # Our own action left no client running. Until one is seen again
            # the bounded repair is the only thing that may touch it.
            if manual:
                self.refuse(name, tracker, 'repairing', wall)
            return
        if verdict == UNWANTED:
            due = tracker['next_retry'] is None or now >= tracker['next_retry']
            if manual or (tracker['streak'] >= STREAK_NEEDED and due):
                self.act(name, tracker, info, address, rule, 'manual' if manual else 'auto', snapshot, now, wall)
        elif manual:
            self.refuse(name, tracker, 'wanted' if verdict == WANTED else 'no-address', wall)

    def refuse(self, name, tracker, code, wall):
        if tracker is not None:
            tracker['last_manual'] = {'wall': wall, 'result': 'refused:' + code}
        self.log('notice', 'manual retry on %s refused: %s' % (name, REFUSALS.get(code, code)))

    def act(self, name, tracker, info, address, rule, trigger, snapshot, now, wall):
        manual = trigger == 'manual'
        if self.stopping():
            # A stop request must not be followed by a new action.
            if manual:
                self.refuse(name, tracker, 'stopping', wall)
            return
        if snapshot['booting']:
            # G3: observe during boot, act only afterwards.
            if manual:
                self.refuse(name, tracker, 'booting', wall)
            return
        if not info['carrier']:
            # G5: a re-request on a dead link would only drop the fallback lease.
            self.warn(('carrier', name), '%s has unwanted address %s but no carrier; waiting' % (name, address), now)
            if manual:
                self.refuse(name, tracker, 'no-carrier', wall)
            return
        if not info['dhclient_running']:
            # Without a running client the address did not come from a lease
            # this plugin may renew: the interface may still wait for an
            # interface apply, or core stopped the client on purpose. Starting
            # one here would be a change nobody asked for.
            self.warn(('no-client', name), '%s has unwanted address %s but no IPv4 DHCP client is running; '
                      'waiting' % (name, address), now)
            if manual:
                self.refuse(name, tracker, 'no-client', wall)
            return
        cooldown = self.state.get('cooldown_until')
        if not manual and cooldown is not None and now < cooldown:
            self.warn(('cooldown',), 'the saved state was unreadable; automatic actions wait until the '
                      'cooldown ends', now)
            return
        # G7: rate limits that nothing, a manual request included, may exceed.
        actions = within_hour(tracker['actions'], now)
        tracker['actions'] = actions
        if actions and now - actions[-1] < MIN_ACTION_GAP:
            if manual:
                self.refuse(name, tracker, 'too-soon', wall)
            return
        if len(actions) >= HOURLY_CAP:
            self.warn(('cap', name), '%s reached %d actions in the last hour; waiting' % (name, HOURLY_CAP), now)
            if manual:
                self.refuse(name, tracker, 'hourly-cap', wall)
            return
        attempt = tracker['stage'] + 1
        reason = 'address %s is in %s' % (address, rule)
        self.log('notice', 're-requesting IPv4 DHCP on %s (%s): attempt %d, trigger %s, %s'
                 % (name, info['device'], attempt, trigger, reason))
        # Counted and owned before the helper runs, so a crash in the middle
        # can neither erase the action from the rate limits nor leave a client
        # it stopped without the repair.
        owned = (tracker['owned'], tracker['repair_due'])
        actions.append(now)
        tracker.update(owned=True, repair_due=True)
        self.persist()
        try:
            result = self.actor.redhcp(name, address, reason)
        except Exception as error:  # noqa: BLE001 -- an unknown outcome is a failed action
            self.log('error', '%s: the helper call failed: %s: %s' % (name, type(error).__name__, error))
            result = 'failed:helper'
        if result == 'busy' or result.startswith('refused:'):
            # Nothing was touched.
            actions.pop()
            tracker['owned'], tracker['repair_due'] = owned
            self.log('notice', '%s: result %s; not counted' % (name, result))
            if manual:
                tracker['last_manual'] = {'wall': wall, 'result': result}
            return
        tracker['stage'] = attempt
        delay = backoff(attempt)
        tracker.update(next_retry=now + delay, streak=0, counted_at=None)
        tracker['last_action'] = {'wall': wall, 'mono': now, 'address': address, 'rule': rule,
                                  'reason': reason, 'result': result, 'trigger': trigger, 'attempt': attempt}
        if manual:
            tracker['last_manual'] = {'wall': wall, 'result': result}
        # Our action stopped the old client, or at least sent it TERM; until a
        # client is seen running again it is ours to repair. After a
        # confirmed start that needs one observation without a client first.
        tracker['owned'] = True
        tracker['repair_due'] = result not in ('requested', 'failed:old-client')
        level = 'notice' if result == 'requested' else 'error'
        self.log(level, '%s: result %s, next retry in %d s' % (name, result, delay))

    def repair(self, name, tracker, info, snapshot, now):
        """Restart a DHCP client that our own action left stopped (bounded).

        Returns True when the helper was called. A client this plugin did not
        stop is never touched: ownership starts with our action and ends as
        soon as an observation sees a client running again.
        """
        if not tracker['owned']:
            return False
        if info['dhclient_running']:
            tracker.update(owned=False, repair_due=False)
            return False
        tracker['repair_due'] = True
        if snapshot['booting'] or self.stopping():
            # The next start takes the repair over: ownership is saved.
            return False
        if tracker['repair_at'] is not None and now - tracker['repair_at'] < REPAIR_GAP:
            return False
        tracker['repair_at'] = now
        self.log('warning', 'the IPv4 DHCP client on %s (%s) is not running after our action; restarting it'
                 % (name, info['device']))
        self.persist()
        result = self.actor.restore(name)
        if result in ('restored', 'running'):
            self.log('notice', '%s: DHCP client repair result %s' % (name, result))
        else:
            self.log('error', '%s: DHCP client repair result %s; trying again in %d s' % (name, result, REPAIR_GAP))
        return True


def display_state(enabled, running, booting, eligible, verdict, carrier, client, tracker, now):
    """The one word the status page shows for an interface."""
    if not enabled:
        return 'disabled'
    if not running:
        return 'stopped'
    if booting:
        return 'booting'
    if not eligible:
        return 'ignored'
    if verdict == NONE:
        return 'no_address'
    if verdict == WANTED:
        return 'ok'
    if not carrier:
        return 'no_carrier'
    if not client:
        return 'no_client'
    tracker = tracker or {}
    if len(within_hour(tracker.get('actions', []), now)) >= HOURLY_CAP:
        return 'rate_limited'
    if tracker.get('stage'):
        return 'backoff'
    return 'confirming'


def _valid_record(value):
    if value is None:
        return True
    return isinstance(value, dict) and len(value) <= 16 and all(
        isinstance(key, str) and (value[key] is None or isinstance(value[key], (str, bool)) or _is_number(value[key]))
        for key in value)


def valid_tracker(value):
    if not isinstance(value, dict) or set(value) != set(new_tracker('')):
        return False
    if not isinstance(value['device'], str) or not DEVICE.fullmatch(value['device']):
        return False
    for key in ('streak', 'stage'):
        if not _is_int(value[key]) or value[key] < 0:
            return False
    for key in ('counted_at', 'next_retry', 'repair_at'):
        if value[key] is not None and not _is_number(value[key]):
            return False
    for key in ('owned', 'repair_due'):
        if not isinstance(value[key], bool):
            return False
    actions = value['actions']
    if not isinstance(actions, list) or len(actions) > 64 or not all(_is_number(moment) for moment in actions):
        return False
    return all(_valid_record(value[key]) for key in ('last_action', 'last_manual', 'last_observation'))


def valid_state(value):
    if not isinstance(value, dict) or set(value) != set(new_state('')):
        return False
    if value['schema'] != SCHEMA or not isinstance(value['boot'], str):
        return False
    if value['saved'] is not None and not _is_number(value['saved']):
        return False
    if value['cooldown_until'] is not None and not _is_number(value['cooldown_until']):
        return False
    recent = value['recent']
    if not isinstance(recent, dict) or len(recent) > 64 or not all(
            isinstance(name, str) and INTERFACE.fullmatch(name) and isinstance(moments, list)
            and len(moments) <= 64 and all(_is_number(moment) for moment in moments)
            for name, moments in recent.items()):
        return False
    interfaces = value['interfaces']
    return isinstance(interfaces, dict) and len(interfaces) <= 64 and all(
        isinstance(name, str) and INTERFACE.fullmatch(name) and valid_tracker(tracker)
        for name, tracker in interfaces.items())


class Store:
    """state.json: private, atomically replaced, scoped to one boot."""

    def __init__(self, path, boot):
        self.path = path
        self.boot = boot

    def read(self):
        """Return the stored state or None, without changing anything on disk."""
        try:
            info = os.lstat(self.path)
        except FileNotFoundError:
            return None
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_mode & 0o077 or info.st_size > STATE_MAX):
            raise ValueError('the state file is not a private regular file of at most %d bytes' % STATE_MAX)
        descriptor = os.open(self.path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
        with os.fdopen(descriptor, 'rb') as source:
            content = source.read(STATE_MAX + 1)
        if len(content) > STATE_MAX:
            raise ValueError('the state file is too large')
        value = json.loads(content)
        if not valid_state(value):
            raise ValueError('the state file has an unexpected shape')
        return value

    def load(self):
        """Return (state, status); status is fresh, loaded, reboot or corrupt."""
        try:
            value = self.read()
        except (ValueError, OSError, UnicodeDecodeError) as error:
            try:
                os.replace(self.path, str(self.path) + '.bad')
            except OSError:
                pass
            return new_state(self.boot), 'corrupt: ' + str(error)
        if value is None:
            return new_state(self.boot), 'fresh'
        if value['boot'] != self.boot:
            # Monotonic times from another boot mean nothing in this one.
            return new_state(self.boot), 'reboot'
        return value, 'loaded'

    def save(self, state):
        state['saved'] = time.time()
        parent = os.path.dirname(self.path)
        if os.path.islink(parent):
            raise OSError('the state directory must not be a symbolic link')
        os.makedirs(parent, mode=0o700, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(prefix='.state-', dir=parent)
        try:
            with os.fdopen(descriptor, 'w') as output:
                os.fchmod(output.fileno(), 0o600)
                json.dump(state, output, sort_keys=True)
                output.write('\n')
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, self.path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
