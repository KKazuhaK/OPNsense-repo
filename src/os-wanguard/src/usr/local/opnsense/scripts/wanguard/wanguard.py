#!/usr/local/bin/python3
"""WAN Guard: re-request IPv4 DHCP when a watched interface holds an unwanted address.

    wanguard.py run          the supervised daemon, the only process that acts
    wanguard.py state        JSON status for the GUI (read only)
    wanguard.py retry <if>   queue a manual retry for the daemon
    wanguard.py wake         ask the daemon for an observation now

Only the daemon calls helper.php to change anything, and every change it asks
for passes the rules in guard.py first.
"""
import errno
import fcntl
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import syslog
import time
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import guard  # noqa: E402

HELPER = ('/usr/local/bin/php', '/usr/local/opnsense/scripts/wanguard/helper.php')
RETRY = re.compile(r'retry-([a-z0-9_]{1,32})')


class Paths:
    def __init__(self, run='/var/run/wanguard', db='/var/db/os-wanguard', pidfile='/var/run/wanguard.pid'):
        self.run = Path(run)
        self.db = Path(db)
        self.pidfile = Path(pidfile)
        self.daemon_lock = self.run / 'daemon.lock'
        self.wake = self.run / 'wake'
        self.observed = self.run / 'observed.json'
        self.state = self.db / 'state.json'
        self.boot_marker = self.run / 'boot-id'


class Logger:
    LEVELS = {'error': syslog.LOG_ERR, 'warning': syslog.LOG_WARNING,
              'notice': syslog.LOG_NOTICE, 'info': syslog.LOG_INFO}

    def __init__(self):
        syslog.openlog('wanguard', 0, syslog.LOG_DAEMON)

    def __call__(self, level, message):
        syslog.syslog(self.LEVELS.get(level, syslog.LOG_NOTICE), message)


class Helper:
    """Run helper.php; every answer is one JSON object on stdout."""

    def __init__(self, command=HELPER):
        self.command = list(command)

    def call(self, arguments, timeout):
        try:
            # An odd byte in a PHP warning must not cost the answer.
            result = subprocess.run(self.command + list(arguments), capture_output=True, encoding='utf-8',
                                    errors='replace', timeout=timeout,
                                    env={'PATH': '/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin',
                                         'LC_ALL': 'C'})
        except subprocess.TimeoutExpired:
            raise guard.ObserveError('the helper did not answer within %d s' % timeout)
        except OSError as error:
            raise guard.ObserveError('the helper could not run: %s' % error.strerror)
        # PHP prints warnings to stdout, before or after the answer; the answer
        # is the last line that is a JSON object.
        for line in reversed(result.stdout.splitlines()):
            try:
                value = json.loads(line)
            except (ValueError, RecursionError):
                continue
            if isinstance(value, dict):
                return value
        raise guard.ObserveError('the helper gave no usable answer (exit %d)' % result.returncode)

    def observe(self):
        return guard.parse_snapshot(self.call(['observe'], guard.OBSERVE_TIMEOUT))

    def _result(self, arguments, allowed):
        try:
            value = self.call(arguments, guard.ACTION_TIMEOUT)
        except guard.ObserveError:
            # Nobody knows how far the helper got, so it counts as an action
            # that may have left the client stopped; the repair path checks.
            return 'failed:helper'
        result = value.get('result')
        if not isinstance(result, str) or not re.fullmatch(r'[a-z]+(?::[a-z-]+)?', result):
            return 'failed:helper'
        if result in allowed or result.startswith(('refused:', 'failed:')):
            return result
        return 'failed:helper'

    def redhcp(self, name, address, reason):
        return self._result(['redhcp', name, address, reason], {'requested', 'busy'})

    def restore(self, name):
        return self._result(['restore', name], {'restored', 'running', 'busy'})


def daemon_running(pidfile):
    try:
        pid = int(Path(pidfile).read_text().strip())
    except (OSError, ValueError):
        return False
    if pid <= 1:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


BOOT_MARKER = re.compile(r'[0-9a-f]{32}')


def _read_boot_marker(path):
    """Return the marker's value, or None if it is missing or unreadable.

    O_NOFOLLOW matches the paranoia of every other private file this plugin
    reads (Store.read, write_private): the run directory is 0700 and owned by
    root, but a symlink placed there before that mode was set must still not
    be followed.
    """
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    except OSError:
        return None
    try:
        with os.fdopen(descriptor) as source:
            content = source.read().strip()
    except OSError:
        return None
    return content if BOOT_MARKER.fullmatch(content) else None


def boot_id(paths):
    """A marker that identifies the current boot, kept in /var/run.

    kern.boottime looks like a boot identity but is not one: it is "now minus
    uptime", and FreeBSD recomputes it on every clock step (NTP's first
    correction after boot, a manual time set), with no reboot involved. A
    daemon restart or a status query taken right after such a step would then
    treat this boot's own state.json as belonging to "another boot" and
    discard or hide it.

    /var/run is cleared only at reboot, so a random token stored there instead
    survives every clock step and disappears exactly when state.json's
    CLOCK_MONOTONIC values stop meaning anything. Whichever caller runs first
    in a boot -- the daemon, or a status/retry query before it has ever
    started -- creates the token; every later caller, including one racing to
    create it at the same time, reads that same value back.
    """
    existing = _read_boot_marker(paths.boot_marker)
    if existing is not None:
        return existing
    private_directory(paths.run)
    token = uuid.uuid4().hex
    temporary = paths.boot_marker.with_name('.%s.%d' % (paths.boot_marker.name, os.getpid()))
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    try:
        with os.fdopen(descriptor, 'w') as output:
            output.write(token + '\n')
            output.flush()
            os.fsync(output.fileno())
        try:
            # Atomic and, unlike os.replace, fails instead of overwriting: the
            # first caller's token wins, and only it may ever be linked in.
            os.link(temporary, paths.boot_marker)
        except FileExistsError:
            # Ordinarily another caller's valid token is already there, and
            # it is read back below. A marker that exists but fails
            # validation is not that: nothing here ever wrote it in that
            # shape, and leaving it would make every future call regenerate a
            # token that never persists. Replace it instead of getting stuck.
            if _read_boot_marker(paths.boot_marker) is None:
                os.replace(temporary, paths.boot_marker)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
    # Read back rather than trusting our own token: if another caller won the
    # race, its value -- not ours -- is what every future caller must agree on.
    return _read_boot_marker(paths.boot_marker) or token


def private_directory(path):
    if path.is_symlink():
        raise OSError('%s must not be a symbolic link' % path)
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path, 0o700)


def write_private(path, value):
    temporary = path.with_name('.' + path.name + '.%d' % os.getpid())
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    try:
        with os.fdopen(descriptor, 'w') as output:
            json.dump(value, output, sort_keys=True)
            output.write('\n')
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def wake(paths):
    """Drop a wake request; the daemon's poll picks it up within a second."""
    if not paths.run.is_dir() or paths.run.is_symlink():
        return False
    descriptor = os.open(paths.wake, os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    with os.fdopen(descriptor, 'a') as output:
        fcntl.flock(output, fcntl.LOCK_EX)
        output.write('reload\n')
    return True


class Daemon:
    def __init__(self, paths, helper, log, boot, clock=time.monotonic, wall=time.time, sleep=time.sleep):
        self.paths = paths
        self.helper = helper
        self.log = log
        self.boot = boot
        self.clock = clock
        self.wall = wall
        self.sleep = sleep
        self.stopping = False
        self.warned = {}
        self.summary = None

    def stop(self, signum=None, frame=None):
        self.stopping = True

    def warn(self, key, message):
        now = self.clock()
        last = self.warned.get(key)
        if last is None or now - last >= guard.WARN_REPEAT:
            self.warned[key] = now
            self.log('warning', message)

    def consume_wake(self):
        try:
            consumed = self.paths.run / 'wake.consumed'
            os.replace(self.paths.wake, consumed)
            consumed.unlink()
            return True
        except FileNotFoundError:
            return False

    def consume_retries(self):
        names = set()
        for entry in os.listdir(self.paths.run):
            if not entry.startswith('retry-'):
                continue
            try:
                (self.paths.run / entry).unlink()
            except FileNotFoundError:
                continue
            match = RETRY.fullmatch(entry)
            if match:
                names.add(match[1])
        return names

    def cleanup(self):
        self.consume_wake()
        self.consume_retries()

    def describe(self, snapshot):
        summary = 'enabled %s; watching %s; unwanted networks %s; private ranges %s' % (
            'yes' if snapshot['enabled'] else 'no', ', '.join(snapshot['watched']) or 'nothing',
            ', '.join(snapshot['networks']) or 'none', 'on' if snapshot['private_ranges'] else 'off')
        if summary != self.summary:
            self.summary = summary
            self.log('notice', 'settings: ' + summary)
            if snapshot['enabled'] and not snapshot['networks'] and not snapshot['private_ranges']:
                self.log('notice', 'nothing is considered unwanted; no interface will be touched')

    def cycle(self, store, state, core, manual):
        try:
            snapshot = self.helper.observe()
        except guard.ObserveError as error:
            self.warn('observe', 'observation failed: %s; skipping this cycle' % error)
            for name in sorted(manual):
                self.log('notice', 'manual retry on %s refused: %s' % (name, guard.REFUSALS['unavailable']))
            return
        self.describe(snapshot)
        before = json.dumps(state, sort_keys=True)
        try:
            core.apply(snapshot, manual)
        finally:
            observed = {'wall': self.wall(), 'interfaces': {}}
            for name, tracker in state['interfaces'].items():
                seen = dict(tracker['last_observation'] or {})
                seen['wall'] = observed['wall']
                observed['interfaces'][name] = seen
            try:
                write_private(self.paths.observed, observed)
            except OSError as error:
                self.warn('observed', 'the observation time could not be recorded: %s' % error)
            if json.dumps(state, sort_keys=True) != before:
                store.save(state)

    def run(self):
        private_directory(self.paths.run)
        private_directory(self.paths.db)
        descriptor = os.open(self.paths.daemon_lock, os.O_RDWR | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0), 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            os.close(descriptor)
            if error.errno in (errno.EWOULDBLOCK, errno.EAGAIN):
                self.log('notice', 'another WAN Guard daemon is already running')
                return 0
            raise
        try:
            return self.loop()
        finally:
            os.close(descriptor)

    def loop(self):
        store = guard.Store(str(self.paths.state), self.boot)
        state, status = store.load()
        if status.startswith('corrupt'):
            state['cooldown_until'] = self.clock() + guard.CORRUPT_COOLDOWN
            self.log('warning', 'the saved state was unreadable (%s) and was set aside as state.json.bad; '
                     'automatic actions wait %d s' % (status[len('corrupt: '):], guard.CORRUPT_COOLDOWN))
        elif status == 'reboot':
            self.log('notice', 'the saved state belongs to an earlier boot and was discarded')
        core = guard.Guard(state, self.helper, self.log, self.clock, self.wall, persist=lambda: store.save(state),
                           stopping=lambda: self.stopping)
        self.cleanup()
        self.log('notice', 'started; observing every %d s' % guard.OBSERVE_INTERVAL)
        next_observe = self.clock()
        last_wake = None
        pending_wake = False
        while not self.stopping:
            try:
                now = self.clock()
                manual = self.consume_retries()
                if self.consume_wake():
                    pending_wake = True
                wake_ready = pending_wake and (last_wake is None or now - last_wake >= guard.WAKE_GAP)
                if manual or wake_ready or now >= next_observe:
                    if wake_ready:
                        last_wake = now
                    pending_wake = False
                    self.cycle(store, state, core, manual)
                    next_observe = self.clock() + guard.OBSERVE_INTERVAL
            except Exception as error:  # noqa: BLE001 -- the loop must outlive any single cycle
                self.warn('cycle', 'a cycle failed: %s: %s' % (type(error).__name__, error))
                next_observe = self.clock() + guard.OBSERVE_INTERVAL
            self.sleep(guard.POLL)
        self.log('notice', 'stopped')
        return 0


def report(paths, helper, boot, clock=time.monotonic, wall=time.time):
    """The status page's JSON. Reads only; never repairs or renames anything."""
    now, now_wall = clock(), wall()
    running = daemon_running(paths.pidfile)
    try:
        snapshot = helper.observe()
    except guard.ObserveError as error:
        return {'status': 'failed', 'message': 'The interfaces could not be observed: %s.' % error,
                'running': running, 'interfaces': []}
    try:
        stored = guard.Store(str(paths.state), boot).read()
    except (ValueError, OSError, UnicodeDecodeError):
        stored = None
    trackers = stored['interfaces'] if stored and stored['boot'] == boot else {}
    try:
        observed = json.loads(paths.observed.read_text())['interfaces']
    except (OSError, ValueError, KeyError, TypeError):
        observed = {}

    def at(moment):
        return None if moment is None else round(now_wall + (moment - now))

    networks, _ = guard.parse_networks(snapshot['networks'])
    rules = guard.Rules(networks, snapshot['private_ranges'])
    rows = []
    for name in snapshot['watched']:
        info = snapshot['interfaces'].get(name) or {}
        eligible = guard.eligibility(info) is None
        verdict, rule = rules.classify(info.get('address')) if eligible else (guard.NONE, None)
        tracker = trackers.get(name) if eligible else None
        tracker = tracker if tracker and tracker['device'] == info.get('device') else None
        seen = observed.get(name) if isinstance(observed, dict) else None
        last = (tracker or {}).get('last_action')
        rows.append({
            'name': name, 'descr': info.get('descr') or name.upper(), 'device': info.get('device', ''),
            'eligible': eligible, 'address': info.get('address'), 'verdict': verdict, 'rule': rule,
            'carrier': info.get('carrier', False),
            'state': guard.display_state(snapshot['enabled'], running, snapshot['booting'], eligible,
                                         verdict, info.get('carrier'), info.get('dhclient_running'), tracker, now),
            'streak': (tracker or {}).get('streak', 0), 'attempts': (tracker or {}).get('stage', 0),
            'actions_last_hour': len(guard.within_hour((tracker or {}).get('actions', []), now)),
            'observed_at': round(seen['wall']) if isinstance(seen, dict) and guard._is_number(seen.get('wall')) else None,
            'last_action': None if not last else {
                'at': round(last['wall']), 'trigger': last.get('trigger'), 'reason': last.get('reason'),
                'result': last.get('result'), 'attempt': last.get('attempt')},
            'last_manual': None if not tracker or not tracker.get('last_manual') else {
                'at': round(tracker['last_manual']['wall']), 'result': tracker['last_manual'].get('result')},
            'next_retry_at': at((tracker or {}).get('next_retry')) if (tracker or {}).get('stage') else None,
        })
    return {'status': 'ok', 'enabled': snapshot['enabled'], 'running': running, 'booting': snapshot['booting'],
            'rules': {'networks': [str(network) for network in networks],
                      'private_ranges': snapshot['private_ranges'], 'empty': rules.empty()},
            'interfaces': rows}


def request_retry(paths, helper, name, log):
    """Queue a manual retry; the daemon applies every rule when it takes it."""
    def refused(code):
        log('notice', 'manual retry on %s refused: %s' % (name, guard.REFUSALS.get(code, code)))
        return {'status': 'refused', 'code': code}
    if not guard.INTERFACE.fullmatch(name or ''):
        return {'status': 'refused', 'code': 'invalid'}
    try:
        snapshot = helper.observe()
    except guard.ObserveError:
        return refused('unavailable')
    if not snapshot['enabled']:
        return refused('disabled')
    if not daemon_running(paths.pidfile) or not paths.run.is_dir() or paths.run.is_symlink():
        return refused('stopped')
    if name not in snapshot['watched']:
        return refused('not-watched')
    try:
        descriptor = os.open(paths.run / ('retry-' + name),
                             os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    except FileExistsError:
        return {'status': 'refused', 'code': 'queued-already'}
    os.close(descriptor)
    log('notice', 'manual retry requested for %s' % name)
    return {'status': 'queued', 'code': 'queued'}


def main(argv=None, paths=None, helper=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    paths = paths or Paths()
    helper = helper or Helper()
    command = argv[0] if argv else ''
    if command == 'run' and len(argv) == 1:
        log = Logger()
        daemon = Daemon(paths, helper, log, boot_id(paths))
        signal.signal(signal.SIGTERM, daemon.stop)
        signal.signal(signal.SIGINT, daemon.stop)
        return daemon.run()
    if command == 'state' and len(argv) == 1:
        print(json.dumps(report(paths, helper, boot_id(paths))))
        return 0
    if command == 'retry' and len(argv) == 2:
        print(json.dumps(request_retry(paths, helper, argv[1], Logger())))
        return 0
    if command == 'wake' and len(argv) == 1:
        wake(paths)
        return 0
    print('usage: wanguard.py run | state | retry <interface> | wake', file=sys.stderr)
    return 2


if __name__ == '__main__':
    sys.exit(main())
